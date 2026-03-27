#!/usr/bin/env python3

import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional, Set, Tuple
from urllib.parse import parse_qs, urlparse

from telegram_otp_listener import force_restore_csv_from_google_sheet, generate_totp_code, load_csv_rows, process_getotp_query


def _bool_from_env(name: str, default: bool = True) -> bool:
	raw = os.environ.get(name, "1" if default else "0").strip().lower()
	return raw in {"1", "true", "yes", "on"}


def _parse_csv_set(value: str) -> Set[str]:
	items = [item.strip() for item in (value or "").split(",")]
	return {item for item in items if item}


def _parse_hhmm(value: str) -> Optional[int]:
	try:
		h, m = value.split(":", 1)
		hh = int(h)
		mm = int(m)
		if hh < 0 or hh > 23 or mm < 0 or mm > 59:
			return None
		return hh * 60 + mm
	except Exception:
		return None


def _parse_allowed_window(raw: str) -> Optional[Tuple[int, int]]:
	text = (raw or "").strip()
	if not text or "-" not in text:
		return None
	left, right = [x.strip() for x in text.split("-", 1)]
	start = _parse_hhmm(left)
	end = _parse_hhmm(right)
	if start is None or end is None:
		return None
	return start, end


def _load_user_passwords() -> Dict[str, str]:
	"""Load web users from env OTP_WEB_USERS.

	Format:
	  OTP_WEB_USERS=user1:pass1,user2:pass2
	"""
	raw = os.environ.get("OTP_WEB_USERS", "").strip()
	out: Dict[str, str] = {}
	if not raw:
		return out
	for item in raw.split(","):
		pair = item.strip()
		if not pair or ":" not in pair:
			continue
		user, pwd = pair.split(":", 1)
		user = user.strip()
		pwd = pwd.strip()
		if user and pwd:
			out[user] = pwd
	return out


WEB_HOST = os.environ.get("OTP_WEB_HOST", "0.0.0.0")
WEB_PORT = int(os.environ.get("OTP_WEB_PORT", "8787"))
WEB_API_KEY = os.environ.get("OTP_WEB_API_KEY", "").strip()
WEB_USERS = _load_user_passwords()

CSV_PATH = os.environ.get("OTP_WEB_WPS_FILE", "otp_wps.csv").strip() or "otp_wps.csv"
AUDIT_LOG_FILE = os.environ.get("OTP_WEB_AUDIT_LOG", ".runtime/otp_web_access.log").strip() or ".runtime/otp_web_access.log"

WEB_REQUIRE_KEY = _bool_from_env("OTP_WEB_REQUIRE_KEY", True)
WEB_TRUST_PROXY = _bool_from_env("OTP_WEB_TRUST_PROXY", False)
WEB_ALLOWED_IPS = _parse_csv_set(os.environ.get("OTP_WEB_ALLOWED_IPS", "").strip())
WEB_SESSION_TTL_SECONDS = max(int(os.environ.get("OTP_WEB_SESSION_TTL_SECONDS", "1800") or "1800"), 60)
WEB_ALLOWED_TIME_WINDOW = _parse_allowed_window(os.environ.get("OTP_WEB_ALLOWED_TIME_WINDOW", "").strip())
WEB_SHEET_REFRESH_SECONDS = max(int(os.environ.get("OTP_WEB_SHEET_REFRESH_SECONDS", "15") or "15"), 5)
WEB_TIMEZONE = os.environ.get("OTP_WEB_TIMEZONE", "Asia/Ho_Chi_Minh").strip() or "Asia/Ho_Chi_Minh"
WEB_SESSION_BIND_IP = _bool_from_env("OTP_WEB_SESSION_BIND_IP", False)

GOOGLE_SHEET_ID = os.environ.get("GOOGLE_SHEET_ID", "").strip()
GOOGLE_SHEET_NAME = (
	os.environ.get("GOOGLE_SHEET_GID", "").strip()
	or os.environ.get("GOOGLE_SHEET_NAME", "OTP").strip()
	or "OTP"
)
GOOGLE_SERVICE_ACCOUNT_FILE = os.environ.get("GOOGLE_SERVICE_ACCOUNT_FILE", "").strip()
GOOGLE_SERVICE_ACCOUNT_JSON = os.environ.get("GOOGLE_SERVICE_ACCOUNT_JSON", "").strip()

# Render users often paste full service-account JSON into GOOGLE_SERVICE_ACCOUNT_FILE.
if (not GOOGLE_SERVICE_ACCOUNT_JSON) and GOOGLE_SERVICE_ACCOUNT_FILE.startswith("{"):
	GOOGLE_SERVICE_ACCOUNT_JSON = GOOGLE_SERVICE_ACCOUNT_FILE
	GOOGLE_SERVICE_ACCOUNT_FILE = ""

# Render runs on Linux and cannot write Mac local paths like /Users/...
if CSV_PATH.startswith("/Users/"):
	CSV_PATH = "otp_wps.csv"
if AUDIT_LOG_FILE.startswith("/Users/"):
	AUDIT_LOG_FILE = ".runtime/otp_web_access.log"

SESSION_COOKIE_NAME = "otp_web_session"
SESSION_SIGNING_KEY = os.environ.get("OTP_WEB_SESSION_SIGNING_KEY", WEB_API_KEY or "change-this-session-key")

_SESSIONS_LOCK = threading.Lock()
_SESSIONS: Dict[str, Dict[str, Any]] = {}
_SHEET_LOCK = threading.Lock()
_LAST_SHEET_SYNC_TS = 0
_LAST_SHEET_SYNC_OK = False
_LAST_SHEET_SYNC_MSG = "not started"


def _now_ts() -> int:
	return int(time.time())


def _write_audit_line(payload: Dict[str, Any]) -> None:
	try:
		os.makedirs(os.path.dirname(os.path.abspath(AUDIT_LOG_FILE)), exist_ok=True)
		with open(AUDIT_LOG_FILE, "a", encoding="utf-8") as f:
			f.write(json.dumps(payload, ensure_ascii=False) + "\n")
	except Exception:
		# Never break request flow because of logging path/config issues.
		fallback = ".runtime/otp_web_access.log"
		os.makedirs(os.path.dirname(os.path.abspath(fallback)), exist_ok=True)
		with open(fallback, "a", encoding="utf-8") as f:
			f.write(json.dumps(payload, ensure_ascii=False) + "\n")


def _sign_token(raw_token: str) -> str:
	sig = hmac.new(SESSION_SIGNING_KEY.encode("utf-8"), raw_token.encode("utf-8"), hashlib.sha256).hexdigest()
	return f"{raw_token}.{sig}"


def _unsign_token(signed_token: str) -> Optional[str]:
	token = (signed_token or "").strip()
	if "." not in token:
		return None
	raw, given = token.rsplit(".", 1)
	expect = hmac.new(SESSION_SIGNING_KEY.encode("utf-8"), raw.encode("utf-8"), hashlib.sha256).hexdigest()
	if not hmac.compare_digest(given, expect):
		return None
	return raw


def _cleanup_sessions(now_ts: int) -> None:
	expired = [k for k, v in _SESSIONS.items() if int(v.get("expires_at", 0)) <= now_ts]
	for k in expired:
		_SESSIONS.pop(k, None)


def _create_session(client_ip: str, username: str) -> str:
	raw = secrets.token_urlsafe(32)
	now = _now_ts()
	with _SESSIONS_LOCK:
		_cleanup_sessions(now)
		_SESSIONS[raw] = {
			"username": username,
			"client_ip": client_ip if WEB_SESSION_BIND_IP else "",
			"created_at": now,
			"last_seen": now,
			"expires_at": now + WEB_SESSION_TTL_SECONDS,
		}
	return _sign_token(raw)


def _get_session(signed: str, client_ip: str) -> Optional[Dict[str, Any]]:
	raw = _unsign_token(signed)
	if not raw:
		return None
	now = _now_ts()
	with _SESSIONS_LOCK:
		_cleanup_sessions(now)
		session = _SESSIONS.get(raw)
		if not session:
			return None
		if WEB_SESSION_BIND_IP and session.get("client_ip") and session.get("client_ip") != client_ip:
			return None
		session["last_seen"] = now
		session["expires_at"] = now + WEB_SESSION_TTL_SECONDS
		return dict(session)


def _delete_session(signed: str) -> None:
	raw = _unsign_token(signed)
	if not raw:
		return
	with _SESSIONS_LOCK:
		_SESSIONS.pop(raw, None)


def _now_vn() -> datetime:
	"""Return current time in Vietnam timezone (UTC+7, no DST)."""
	try:
		import zoneinfo
		return datetime.now(zoneinfo.ZoneInfo(WEB_TIMEZONE))
	except Exception:
		# Fallback: UTC+7 offset requires no system timezone data
		vn_tz = timezone(timedelta(hours=7))
		return datetime.now(vn_tz)


def _is_time_window_allowed() -> bool:
	if WEB_ALLOWED_TIME_WINDOW is None:
		return True
	now = _now_vn()
	now_m = now.hour * 60 + now.minute
	start, end = WEB_ALLOWED_TIME_WINDOW
	if start <= end:
		return start <= now_m <= end
	return now_m >= start or now_m <= end


def _maybe_refresh_csv_from_sheet() -> None:
	global _LAST_SHEET_SYNC_TS, _LAST_SHEET_SYNC_OK, _LAST_SHEET_SYNC_MSG
	if not GOOGLE_SHEET_ID:
		_LAST_SHEET_SYNC_OK = False
		_LAST_SHEET_SYNC_MSG = "missing GOOGLE_SHEET_ID"
		return
	now = _now_ts()
	if now - int(_LAST_SHEET_SYNC_TS) < WEB_SHEET_REFRESH_SECONDS:
		return
	with _SHEET_LOCK:
		now = _now_ts()
		if now - int(_LAST_SHEET_SYNC_TS) < WEB_SHEET_REFRESH_SECONDS:
			return
		ok, msg = force_restore_csv_from_google_sheet(
			CSV_PATH,
			GOOGLE_SHEET_ID,
			GOOGLE_SHEET_NAME,
			GOOGLE_SERVICE_ACCOUNT_JSON,
			GOOGLE_SERVICE_ACCOUNT_FILE,
		)
		_LAST_SHEET_SYNC_TS = now
		_LAST_SHEET_SYNC_OK = bool(ok)
		_LAST_SHEET_SYNC_MSG = msg
		_write_audit_line(
			{
				"ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
				"type": "sheet_refresh",
				"ok": bool(ok),
				"msg": msg,
			}
		)


def _suggest_account_names(query: str, csv_path: str, limit: int = 8) -> list[str]:
	query = (query or "").strip().lower()
	if not query:
		return []

	_, rows = load_csv_rows(csv_path)
	if not rows:
		return []

	tokens = query.split()
	seen: Set[str] = set()
	scored: list[tuple[tuple[int, int], str]] = []

	for row in rows:
		account_name = (row.get("Account") or "").strip()
		if not account_name or account_name in seen:
			continue
		name_lower = account_name.lower()
		if not all(token in name_lower for token in tokens):
			continue
		seen.add(account_name)
		prefix_rank = 0 if name_lower.startswith(query) else 1
		scored.append(((prefix_rank, len(account_name)), account_name))

	scored.sort(key=lambda item: item[0])
	return [name for _, name in scored[:max(limit, 1)]]


def _find_secret_by_account(account_name: str, csv_path: str) -> Tuple[Optional[str], str]:
	name = (account_name or "").strip()
	if not name:
		return None, "empty account"
	_, rows = load_csv_rows(csv_path)
	if not rows:
		return None, "no csv rows"

	name_lower = name.lower()
	for row in rows:
		acc = (row.get("Account") or "").strip()
		if acc.lower() == name_lower:
			secret = (row.get("Secret") or "").strip()
			if secret:
				return secret, ""
			return None, "empty secret"
	return None, "account not found"


def _html_page() -> str:
	return """<!doctype html>
<html lang=\"vi\"><head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\" />
  <title>Nefitly OTP</title>
  <style>
	:root {
	  --bg-1:#07122b;
	  --bg-2:#0f2047;
	  --bg-3:#15356e;
	  --panel:#0c1b3ac9;
	  --panel-strong:#10244f;
	  --line:rgba(148, 163, 184, .18);
	  --text:#eef4ff;
	  --muted:#aac0e8;
	  --soft:#d9ecff;
	  --accent:#35d0ff;
	  --accent-2:#4fffb0;
	  --shadow:0 32px 80px rgba(2, 7, 23, .52);
	}
	* { box-sizing: border-box; }
	body {
	  margin: 0;
	  min-height: 100vh;
	  color: var(--text);
	  font-family: 'Segoe UI', 'SF Pro Display', -apple-system, sans-serif;
	  background:
	    radial-gradient(900px 480px at 0% 0%, rgba(53,208,255,.22), transparent 60%),
	    radial-gradient(760px 540px at 100% 100%, rgba(79,255,176,.12), transparent 55%),
	    linear-gradient(145deg, var(--bg-1), var(--bg-2) 45%, var(--bg-3));
	  padding: 28px;
	}
	.shell {
	  max-width: 1160px;
	  margin: 0 auto;
	}
	.hero {
	  display: grid;
	  grid-template-columns: 1.4fr .9fr;
	  gap: 18px;
	  margin-bottom: 18px;
	}
	.hero-card,
	.side-card,
	.main-card {
	  background: linear-gradient(180deg, rgba(14,28,60,.92), rgba(11,24,54,.88));
	  border: 1px solid var(--line);
	  border-radius: 24px;
	  box-shadow: var(--shadow);
	  backdrop-filter: blur(10px);
	}
	.hero-card {
	  padding: 28px;
	  min-height: 220px;
	  position: relative;
	  overflow: hidden;
	}
	.hero-card:before {
	  content: '';
	  position: absolute;
	  width: 320px;
	  height: 320px;
	  border-radius: 50%;
	  background: radial-gradient(circle, rgba(53,208,255,.18), transparent 60%);
	  top: -120px;
	  right: -80px;
	}
	.badge {
	  display: inline-flex;
	  align-items: center;
	  gap: 8px;
	  padding: 8px 14px;
	  border: 1px solid rgba(79,255,176,.28);
	  border-radius: 999px;
	  color: #d7ffef;
	  background: rgba(79,255,176,.08);
	  font-size: 13px;
	  letter-spacing: .08em;
	  text-transform: uppercase;
	}
	.hero-title {
	  margin: 18px 0 10px;
	  font-size: 54px;
	  line-height: 1;
	  letter-spacing: -.04em;
	}
	.hero-text {
	  max-width: 680px;
	  color: var(--muted);
	  font-size: 18px;
	  line-height: 1.6;
	}
	.kpi-grid {
	  display: grid;
	  gap: 14px;
	  padding: 18px;
	}
	.kpi {
	  background: rgba(9, 20, 47, .84);
	  border: 1px solid var(--line);
	  border-radius: 20px;
	  padding: 18px;
	}
	.kpi-label {
	  color: var(--muted);
	  font-size: 12px;
	  text-transform: uppercase;
	  letter-spacing: .08em;
	}
	.kpi-value {
	  margin-top: 10px;
	  font-size: 22px;
	  font-weight: 700;
	}
	.main-card { padding: 24px; }
	.login-grid { display: grid; grid-template-columns: 1fr 1fr auto; gap: 12px; }
	.toolbar { display: grid; gap: 14px; }
	.workspace {
	  display: grid;
	  grid-template-columns: 1.5fr .8fr;
	  gap: 14px;
	}
	.result-col,
	.live-col {
	  border: 1px solid var(--line);
	  border-radius: 18px;
	  background: rgba(9, 20, 47, .55);
	  padding: 14px;
	}
	.search-wrap { position: relative; }
	.query-row { display: grid; grid-template-columns: 1fr auto auto; gap: 12px; align-items: start; }
	.input-shell {
	  position: relative;
	  border-radius: 18px;
	  background: linear-gradient(180deg, rgba(255,255,255,.06), rgba(255,255,255,.02));
	  border: 1px solid rgba(148,163,184,.22);
	  padding: 6px;
	}
	.input-shell:focus-within {
	  border-color: rgba(53,208,255,.55);
	  box-shadow: 0 0 0 4px rgba(53,208,255,.12);
	}
	input {
	  width: 100%;
	  border: 0;
	  outline: 0;
	  border-radius: 14px;
	  padding: 18px 18px;
	  background: var(--soft);
	  color: #0f172a;
	  font-size: 26px;
	  font-weight: 600;
	}
	input::placeholder { color: #64748b; font-weight: 500; }
	button {
	  border: 0;
	  border-radius: 18px;
	  cursor: pointer;
	  padding: 18px 22px;
	  font-size: 20px;
	  font-weight: 800;
	  letter-spacing: -.02em;
	  transition: transform .12s ease, filter .12s ease, box-shadow .12s ease;
	}
	button:hover { transform: translateY(-1px); filter: brightness(1.03); }
	button:active { transform: translateY(0); }
	.primary {
	  color: #082032;
	  background: linear-gradient(135deg, var(--accent), var(--accent-2));
	  box-shadow: 0 18px 30px rgba(53,208,255,.18);
	}
	.ghost {
	  color: #dce9ff;
	  background: rgba(255,255,255,.08);
	  border: 1px solid rgba(148,163,184,.16);
	}
	.hide { display: none; }
	.status-bar {
	  display: flex;
	  align-items: center;
	  justify-content: space-between;
	  gap: 12px;
	  flex-wrap: wrap;
	  padding: 14px 16px;
	  border: 1px solid var(--line);
	  border-radius: 18px;
	  background: rgba(13,27,58,.72);
	}
	.status-main { font-size: 18px; color: #dbeafe; }
	.status-tag {
	  padding: 8px 12px;
	  border-radius: 999px;
	  background: rgba(53,208,255,.14);
	  border: 1px solid rgba(53,208,255,.26);
	  color: #c9f7ff;
	  font-size: 13px;
	}
	.suggest-menu {
	  position: absolute;
	  top: calc(100% + 10px);
	  left: 0;
	  right: 0;
	  display: grid;
	  gap: 8px;
	  padding: 10px;
	  border-radius: 18px;
	  background: rgba(10, 20, 45, .96);
	  border: 1px solid rgba(148,163,184,.18);
	  box-shadow: 0 22px 44px rgba(2, 7, 23, .45);
	  z-index: 25;
	}
	.suggest-item {
	  display: grid;
	  grid-template-columns: 1fr auto;
	  gap: 4px 12px;
	  text-align: left;
	  border-radius: 14px;
	  padding: 14px 16px;
	  background: rgba(255,255,255,.04);
	  color: #f8fbff;
	  border: 1px solid transparent;
	}
	.suggest-item:hover,
	.suggest-item.active {
	  background: linear-gradient(135deg, rgba(53,208,255,.18), rgba(79,255,176,.14));
	  border-color: rgba(79,255,176,.22);
	}
	.suggest-title { font-size: 18px; font-weight: 700; }
	.suggest-meta { font-size: 12px; color: #bcd1f2; text-transform: uppercase; letter-spacing: .08em; }
	.suggest-main { display: grid; gap: 4px; }
	.suggest-live {
	  align-self: center;
	  justify-self: end;
	  min-width: 104px;
	  text-align: right;
	}
	.suggest-otp {
	  font-size: 24px;
	  letter-spacing: .08em;
	  font-weight: 800;
	  color: #f1f8ff;
	}
	.suggest-sec {
	  margin-top: 2px;
	  font-size: 12px;
	  color: #a9c4ee;
	}
	.panel-head {
	  display: flex;
	  align-items: center;
	  justify-content: space-between;
	  gap: 12px;
	  margin-bottom: 12px;
	}
	.panel-title { font-size: 16px; color: #dce8ff; text-transform: uppercase; letter-spacing: .1em; }
	.live-dot {
	  width: 10px;
	  height: 10px;
	  border-radius: 50%;
	  background: #4fffb0;
	  box-shadow: 0 0 0 8px rgba(79,255,176,.12);
	}
	pre {
	  margin: 0;
	  min-height: 320px;
	  border-radius: 20px;
	  border: 1px solid var(--line);
	  background: linear-gradient(180deg, rgba(8,18,44,.9), rgba(8,18,44,.82));
	  color: #f4f8ff;
	  padding: 22px;
	  white-space: pre-wrap;
	  font-size: 30px;
	  line-height: 1.42;
	  box-shadow: inset 0 1px 0 rgba(255,255,255,.03);
	}
	.live-title {
	  font-size: 14px;
	  letter-spacing: .1em;
	  text-transform: uppercase;
	  color: #cfe2ff;
	}
	.live-account {
	  margin-top: 8px;
	  font-size: 16px;
	  color: #eaf1ff;
	  min-height: 24px;
	}
	.otp-card {
	  margin-top: 12px;
	  border-radius: 18px;
	  border: 1px solid var(--line);
	  background: linear-gradient(180deg, rgba(8,18,44,.95), rgba(8,18,44,.8));
	  padding: 16px;
	}
	.otp-code {
	  font-size: 52px;
	  letter-spacing: .12em;
	  font-weight: 800;
	  color: #f8fdff;
	}
	.otp-sub {
	  margin-top: 8px;
	  color: var(--muted);
	  font-size: 14px;
	}
	.ring-wrap {
	  margin-top: 16px;
	  display: flex;
	  align-items: center;
	  gap: 14px;
	}
	.ring {
	  --pct: 0;
	  width: 74px;
	  height: 74px;
	  border-radius: 50%;
	  background: conic-gradient(var(--accent) calc(var(--pct) * 1%), rgba(148,163,184,.2) 0);
	  display: grid;
	  place-items: center;
	}
	.ring::after {
	  content: '';
	  width: 56px;
	  height: 56px;
	  border-radius: 50%;
	  background: #0c1c3f;
	  border: 1px solid rgba(148,163,184,.22);
	}
	.ring-sec {
	  margin-left: -58px;
	  width: 56px;
	  text-align: center;
	  font-size: 18px;
	  font-weight: 700;
	  z-index: 2;
	}
	.copy-btn {
	  margin-top: 14px;
	  width: 100%;
	}
	.mini-help {
	  display: flex;
	  gap: 10px;
	  flex-wrap: wrap;
	  color: var(--muted);
	  font-size: 13px;
	}
	.mini-chip {
	  padding: 8px 12px;
	  border-radius: 999px;
	  border: 1px solid var(--line);
	  background: rgba(255,255,255,.03);
	}
	@media (max-width: 960px) {
	  .hero { grid-template-columns: 1fr; }
	}
	@media (max-width: 760px) {
	  body { padding: 16px; }
	  .hero-title { font-size: 40px; }
	  .login-grid, .query-row, .workspace { grid-template-columns: 1fr; }
	  pre { font-size: 23px; min-height: 280px; }
	  input, button { font-size: 20px; }
	  .otp-code { font-size: 40px; }
	}
  </style>
</head><body>
  <main class=\"shell\">
	<section class=\"hero\">
	  <div class=\"hero-card\">
		<div class=\"badge\">Live OTP Console</div>
		<h1 class=\"hero-title\">OTP lookup that feels instant.</h1>
		<div class=\"hero-text\">Go tung ky tu, nhin goi y hien ngay ben duoi. Chon nhanh bang chuot hoac phim len/xuong, Enter de lay OTP.</div>
	  </div>
	  <div class=\"side-card\">
		<div class=\"kpi-grid\">
		  <div class=\"kpi\"><div class=\"kpi-label\">Mode</div><div class=\"kpi-value\">Realtime suggest</div></div>
		  <div class=\"kpi\"><div class=\"kpi-label\">Access</div><div class=\"kpi-value\">Employee session</div></div>
		  <div class=\"kpi\"><div class=\"kpi-label\">Source</div><div class=\"kpi-value\">Google Sheet sync</div></div>
		</div>
	  </div>
	</section>

	<section class=\"main-card\">
	  <form id=\"loginBox\" class=\"login-grid\" method=\"post\" action=\"/login\">
		<div class=\"input-shell\"><input id=\"username\" name=\"username\" placeholder=\"Username\" /></div>
		<div class=\"input-shell\"><input id=\"password\" name=\"password\" type=\"password\" placeholder=\"Password\" /></div>
		<button id=\"btnLogin\" class=\"primary\" type=\"submit\">Dang nhap</button>
	  </form>

	  <div id=\"appBox\" class=\"toolbar hide\">
		<div class=\"query-row\">
		  <div class=\"search-wrap\">
			<div class=\"input-shell\"><input id=\"query\" placeholder=\"Nhap keyword OTP de goi y tu dong...\" autocomplete=\"off\" /></div>
			<div id=\"suggestions\" class=\"suggest-menu hide\"></div>
		  </div>
		  <button id=\"btnLookup\" class=\"primary\">Lay OTP</button>
		  <button id=\"btnLogout\" class=\"ghost\">Dang xuat</button>
		</div>
		<div class=\"mini-help\">
		  <div class=\"mini-chip\">Arrow up/down: chon goi y</div>
		  <div class=\"mini-chip\">Enter: chon goi y hoac tim ngay</div>
		  <div class=\"mini-chip\">Click vao goi y de lay OTP</div>
		</div>
	  </div>

	  <div class=\"status-bar\">
		<div id=\"status\" class=\"status-main\">Dang kiem tra phien...</div>
		<div class=\"status-tag\"><span class=\"live-dot\"></span> live session</div>
	  </div>

	  <div class=\"workspace\">
		<div class=\"result-col\">
		  <div class=\"panel-head\">
			<div class=\"panel-title\">Result stream</div>
			<div class=\"panel-title\">OTP output</div>
		  </div>
		  <pre id=\"out\">San sang.</pre>
		</div>
		<div class=\"live-col\">
		  <div class=\"live-title\">Live OTP</div>
		  <div id=\"liveAccount\" class=\"live-account\">Chua chon account</div>
		  <div class=\"otp-card\">
			<div id=\"liveCode\" class=\"otp-code\">------</div>
			<div id=\"liveMeta\" class=\"otp-sub\">Chon goi y ben trai de xem OTP realtime</div>
			<div class=\"ring-wrap\">
			  <div id=\"liveRing\" class=\"ring\" style=\"--pct:0\"></div>
			  <div id=\"liveSec\" class=\"ring-sec\">0s</div>
			</div>
			<button id=\"btnCopyLive\" class=\"primary copy-btn\">Copy OTP</button>
		  </div>
		</div>
	  </div>
	</section>
  </main>

  <script>
	const loginBox = document.getElementById('loginBox');
	const appBox = document.getElementById('appBox');
	const status = document.getElementById('status');
	const out = document.getElementById('out');
	const loginForm = document.getElementById('loginBox');
	const queryInput = document.getElementById('query');
	const suggestBox = document.getElementById('suggestions');
	const btnLookup = document.getElementById('btnLookup');
	const liveAccount = document.getElementById('liveAccount');
	const liveCode = document.getElementById('liveCode');
	const liveMeta = document.getElementById('liveMeta');
	const liveRing = document.getElementById('liveRing');
	const liveSec = document.getElementById('liveSec');
	const btnCopyLive = document.getElementById('btnCopyLive');
	const pageParams = new URLSearchParams(window.location.search);
	let suggestTimer = null;
	let suggestOtpTimer = null;
	let currentSuggestions = [];
	let activeSuggestionIndex = -1;
	let liveAccountName = '';
	let liveTimer = null;

	async function readJsonSafe(res) {
	  const raw = await res.text();
	  try {
		return JSON.parse(raw || '{}');
	  } catch (e) {
		return { ok:false, error: 'invalid server response', raw };
	  }
	}

	function setOutput(text) {
	  out.textContent = text;
	}

	if (pageParams.get('login_error') === '1') {
	  status.textContent = 'Dang nhap that bai. Kiem tra lai tai khoan/mat khau.';
	  setOutput('Dang nhap that bai: invalid credentials');
	  if (window.history && window.history.replaceState) {
		window.history.replaceState({}, '', '/');
	  }
	}

	function setLiveStateEmpty(msg) {
	  liveAccountName = '';
	  liveAccount.textContent = 'Chua chon account';
	  liveCode.textContent = '------';
	  liveMeta.textContent = msg || 'Chon goi y ben trai de xem OTP realtime';
	  liveRing.style.setProperty('--pct', 0);
	  liveSec.textContent = '0s';
	}

	function parseAccountFromText(text) {
	  const lines = String(text || '').split('\n');
	  for (const ln of lines) {
		const s = ln.trim();
		if (s.startsWith('Account:')) {
		  return s.slice('Account:'.length).trim();
		}
	  }
	  return '';
	}

	function updateLiveVisual(code, remaining, period) {
	  const safeCode = String(code || '------');
	  const rem = Math.max(0, Number(remaining || 0));
	  const per = Math.max(1, Number(period || 30));
	  const pct = Math.max(0, Math.min(100, (rem / per) * 100));
	  liveCode.textContent = safeCode;
	  liveSec.textContent = rem + 's';
	  liveRing.style.setProperty('--pct', pct.toFixed(1));
	  liveMeta.textContent = 'Tu dong lam moi moi giay';
	}

	async function refreshLiveOtp() {
	  if (!liveAccountName) return;
	  try {
		const res = await fetch('/api/otp-live?account=' + encodeURIComponent(liveAccountName), { credentials:'same-origin' });
		if (res.status === 401) {
		  if (liveTimer) clearInterval(liveTimer);
		  liveTimer = null;
		  setLiveStateEmpty('Het phien. Vui long dang nhap lai.');
		  await checkSession();
		  return;
		}
		const d = await res.json();
		if (!d.ok) {
		  liveMeta.textContent = d.error || 'Khong lay duoc OTP live';
		  return;
		}
		liveAccount.textContent = d.account || liveAccountName;
		updateLiveVisual(d.code, d.remaining, d.period || 30);
	  } catch (e) {
		liveMeta.textContent = 'Loi ket noi live OTP';
	  }
	}

	function startLiveOtp(accountName) {
	  const acc = String(accountName || '').trim();
	  if (!acc) return;
	  liveAccountName = acc;
	  liveAccount.textContent = acc;
	  liveMeta.textContent = 'Dang dong bo OTP live...';
	  refreshLiveOtp();
	  if (liveTimer) clearInterval(liveTimer);
	  liveTimer = setInterval(refreshLiveOtp, 1000);
	}

	function showSuggestions() {
	  suggestBox.classList.remove('hide');
	}

	function hideSuggestions() {
	  suggestBox.classList.add('hide');
	  suggestBox.innerHTML = '';
	  currentSuggestions = [];
	  activeSuggestionIndex = -1;
	  if (suggestOtpTimer) clearInterval(suggestOtpTimer);
	  suggestOtpTimer = null;
	}

	function activateSuggestion(index) {
	  activeSuggestionIndex = index;
	  suggestBox.querySelectorAll('.suggest-item').forEach((node, idx) => {
		node.classList.toggle('active', idx === index);
	  });
	  if (index >= 0 && currentSuggestions[index]) {
		startLiveOtp(currentSuggestions[index]);
	  }
	}

	async function refreshSuggestionOtps() {
	  if (!currentSuggestions.length || suggestBox.classList.contains('hide')) return;
	  try {
		const params = new URLSearchParams();
		for (const name of currentSuggestions) params.append('account', name);
		const res = await fetch('/api/otp-live-batch?' + params.toString(), { credentials:'same-origin' });
		if (res.status === 401) {
		  hideSuggestions();
		  await checkSession();
		  return;
		}
		const d = await res.json();
		if (!d.ok || !Array.isArray(d.items)) return;
		d.items.forEach((item, idx) => {
		  const otpNode = suggestBox.querySelector('.suggest-otp[data-index="' + idx + '"]');
		  const secNode = suggestBox.querySelector('.suggest-sec[data-index="' + idx + '"]');
		  if (!otpNode || !secNode) return;
		  if (item && item.ok) {
			otpNode.textContent = String(item.code || '------');
			secNode.textContent = String(Math.max(0, Number(item.remaining || 0))) + 's';
		  } else {
			otpNode.textContent = '------';
			secNode.textContent = '--';
		  }
		});
	  } catch (e) {
		// Keep UI responsive if batch live fetch fails.
	  }
	}

	async function checkSession() {
	  try {
		const res = await fetch('/api/session', { credentials:'same-origin' });
		const d = await readJsonSafe(res);
		if (d.ok && d.authenticated) {
		  loginBox.classList.add('hide');
		  appBox.classList.remove('hide');
		  status.textContent = (d.username ? ('Xin chao ' + d.username + '. ') : '') + (d.sessionText || 'Da dang nhap');
		} else {
		  loginBox.classList.remove('hide');
		  appBox.classList.add('hide');
		  hideSuggestions();
		  if (liveTimer) clearInterval(liveTimer);
		  liveTimer = null;
		  setLiveStateEmpty('Dang xac thuc phien...');
		  status.textContent = d.error || 'Chua dang nhap.';
		}
	  } catch (e) {
		status.textContent = 'Loi ket noi server';
	  }
	}

	async function logout() {
	  await fetch('/api/logout', { method:'POST', credentials:'same-origin' });
	  hideSuggestions();
	  if (liveTimer) clearInterval(liveTimer);
	  liveTimer = null;
	  setLiveStateEmpty('Da dang xuat');
	  setOutput('Da dang xuat.');
	  await checkSession();
	}

	async function lookup(forceQuery) {
	  const query = (forceQuery || queryInput.value).trim();
	  if (!query) {
		setOutput('Nhap query truoc.');
		return;
	  }
	  queryInput.value = query;
	  hideSuggestions();
	  setOutput('Dang xu ly...');
	  btnLookup.disabled = true;
	  try {
		const res = await fetch('/api/getotp', {
		  method:'POST',
		  headers:{'Content-Type':'application/json'},
		  credentials:'same-origin',
		  body: JSON.stringify({ query })
		});
		const d = await res.json();
		setOutput(d.text || d.error || '(trong)');
		const parsedAccount = parseAccountFromText(d.text || '');
		if (parsedAccount) startLiveOtp(parsedAccount);
		else if (res.ok) startLiveOtp(query);
		if (d.sessionText) status.textContent = d.sessionText;
		if (res.status === 401) await checkSession();
	  } finally {
		btnLookup.disabled = false;
	  }
	}

	function renderSuggestions(items) {
	  currentSuggestions = items || [];
	  activeSuggestionIndex = -1;
	  if (!currentSuggestions.length) {
		hideSuggestions();
		return;
	  }
	  suggestBox.innerHTML = currentSuggestions.map((item, index) => (
		`<button type=\"button\" class=\"suggest-item\" data-index=\"${index}\" data-name=\"${item.replace(/\"/g, '&quot;')}\">`
		+ `<span class=\"suggest-main\"><span class=\"suggest-title\">${item}</span><span class=\"suggest-meta\">click de lookup ngay</span></span>`
		+ `<span class=\"suggest-live\"><span class=\"suggest-otp\" data-index=\"${index}\">------</span><span class=\"suggest-sec\" data-index=\"${index}\">--</span></span>`
		+ `</button>`
	  )).join('');
	  suggestBox.querySelectorAll('.suggest-item').forEach((node) => {
		node.addEventListener('click', () => {
		  const name = node.getAttribute('data-name') || '';
		  startLiveOtp(name);
		  lookup(name);
		});
	  });
	  showSuggestions();
	  activateSuggestion(0);
	  refreshSuggestionOtps();
	  if (suggestOtpTimer) clearInterval(suggestOtpTimer);
	  suggestOtpTimer = setInterval(refreshSuggestionOtps, 1000);
	}

	async function fetchSuggestions() {
	  const q = queryInput.value.trim();
	  if (!q) {
		hideSuggestions();
		return;
	  }
	  suggestBox.innerHTML = '<div class=\"suggest-item\"><span class=\"suggest-title\">Dang tim goi y...</span><span class=\"suggest-meta\">realtime</span></div>';
	  showSuggestions();
	  try {
		const res = await fetch('/api/suggest?q=' + encodeURIComponent(q), { credentials:'same-origin' });
		if (res.status === 401) {
		  hideSuggestions();
		  await checkSession();
		  return;
		}
		const data = await res.json();
		renderSuggestions(data.items || []);
	  } catch (e) {
		hideSuggestions();
	  }
	}

	queryInput.addEventListener('input', () => {
	  if (suggestTimer) clearTimeout(suggestTimer);
	  suggestTimer = setTimeout(fetchSuggestions, 90);
	});

	queryInput.addEventListener('keydown', (e) => {
	  if (!currentSuggestions.length) {
		if (e.key === 'Enter') {
		  e.preventDefault();
		  lookup();
		}
		return;
	  }
	  if (e.key === 'ArrowDown') {
		e.preventDefault();
		activateSuggestion((activeSuggestionIndex + 1) % currentSuggestions.length);
	  } else if (e.key === 'ArrowUp') {
		e.preventDefault();
		activateSuggestion(activeSuggestionIndex <= 0 ? currentSuggestions.length - 1 : activeSuggestionIndex - 1);
	  } else if (e.key === 'Enter') {
		e.preventDefault();
		if (activeSuggestionIndex >= 0 && currentSuggestions[activeSuggestionIndex]) {
		  startLiveOtp(currentSuggestions[activeSuggestionIndex]);
		  lookup(currentSuggestions[activeSuggestionIndex]);
		} else {
		  lookup();
		}
	  } else if (e.key === 'Escape') {
		hideSuggestions();
	  }
	});

	document.addEventListener('click', (e) => {
	  if (!suggestBox.contains(e.target) && e.target !== queryInput) {
		hideSuggestions();
	  }
	});

	loginForm.addEventListener('submit', () => {
	  setOutput('Dang dang nhap...');
	});
	document.getElementById('btnLookup').addEventListener('click', () => lookup());
	document.getElementById('btnLogout').addEventListener('click', logout);
	btnCopyLive.addEventListener('click', async () => {
	  const val = (liveCode.textContent || '').trim();
	  if (!val || val === '------') return;
	  try {
		await navigator.clipboard.writeText(val);
		liveMeta.textContent = 'Da copy OTP vao clipboard';
	  } catch (e) {
		liveMeta.textContent = 'Khong copy duoc. Thu lai';
	  }
	});
	setLiveStateEmpty('Chon goi y ben trai de xem OTP realtime');
	checkSession();
  </script>
</body></html>"""


class OTPWebHandler(BaseHTTPRequestHandler):
	server_version = "OTPWeb/3.0"

	def _client_ip(self) -> str:
		if WEB_TRUST_PROXY:
			xff = self.headers.get("X-Forwarded-For", "")
			if xff:
				return xff.split(",", 1)[0].strip()
		return self.client_address[0] if self.client_address else ""

	def _cookie_value(self, key: str) -> str:
		raw = self.headers.get("Cookie", "")
		for part in raw.split(";"):
			item = part.strip()
			if "=" not in item:
				continue
			k, v = item.split("=", 1)
			if k.strip() == key:
				return v.strip()
		return ""

	def _set_cookie(self, key: str, value: str, max_age: int) -> None:
		self.send_header("Set-Cookie", f"{key}={value}; Max-Age={max_age}; Path=/; HttpOnly; SameSite=Lax")

	def _clear_cookie(self, key: str) -> None:
		self.send_header("Set-Cookie", f"{key}=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax")

	def _session_text(self, session: Dict[str, Any]) -> str:
		now = _now_ts()
		remain = max(int(session.get("expires_at", now)) - now, 0)
		user = str(session.get("username", ""))
		if user:
			return f"Tai khoan: {user} | phien con {remain}s"
		return f"Phien con {remain}s"

	def _is_ip_allowed(self, client_ip: str) -> bool:
		if not WEB_ALLOWED_IPS:
			return True
		return client_ip in WEB_ALLOWED_IPS

	def _read_json_body(self) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
		n = int(self.headers.get("Content-Length", "0") or "0")
		raw = self.rfile.read(n) if n > 0 else b"{}"
		try:
			return json.loads(raw.decode("utf-8")), None
		except Exception:
			return None, "invalid json"

	def _login_ok(self, username: str, password: str, api_key: str) -> Tuple[bool, str]:
		login_user = username
		if WEB_USERS:
			expected = WEB_USERS.get(username)
			ok = bool(expected and hmac.compare_digest(password, expected))
			if (not ok) and WEB_API_KEY and password:
				ok = hmac.compare_digest(password, WEB_API_KEY)
				if ok and not login_user:
					login_user = "api-key-user"
			return ok, login_user
		provided_key = api_key or password
		ok = WEB_REQUIRE_KEY and bool(WEB_API_KEY and provided_key and hmac.compare_digest(provided_key, WEB_API_KEY))
		if ok and not login_user:
			login_user = "api-key-user"
		return ok, login_user

	def _send_json(self, code: int, payload: Dict[str, Any]) -> None:
		data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
		self.send_response(code)
		self.send_header("Content-Type", "application/json; charset=utf-8")
		self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
		self.send_header("Pragma", "no-cache")
		self.send_header("Content-Length", str(len(data)))
		self.end_headers()
		self.wfile.write(data)

	def _send_html(self, html: str) -> None:
		data = html.encode("utf-8")
		self.send_response(200)
		self.send_header("Content-Type", "text/html; charset=utf-8")
		self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
		self.send_header("Pragma", "no-cache")
		self.send_header("Content-Length", str(len(data)))
		self.end_headers()
		self.wfile.write(data)

	def _current_session(self) -> Optional[Dict[str, Any]]:
		signed = self._cookie_value(SESSION_COOKIE_NAME)
		if not signed:
			return None
		return _get_session(signed, self._client_ip())

	def do_GET(self) -> None:
		parsed = urlparse(self.path)
		if parsed.path in {"/", "/index.html"}:
			self._send_html(_html_page())
			return
		if parsed.path == "/favicon.ico":
			self.send_response(204)
			self.send_header("Content-Length", "0")
			self.end_headers()
			return
		if parsed.path == "/health":
			self._send_json(200, {"ok": True, "service": "otp-web", "ts": _now_ts()})
			return
		if parsed.path == "/api/session":
			ip = self._client_ip()
			if not self._is_ip_allowed(ip):
				self._send_json(403, {"ok": False, "authenticated": False, "error": "ip not allowed"})
				return
			session = self._current_session()
			if not session:
				self._send_json(200, {"ok": True, "authenticated": False})
				return
			# Inform frontend about time window but never block authentication.
			time_ok = _is_time_window_allowed()
			self._send_json(
				200,
				{
					"ok": True,
					"authenticated": True,
					"username": session.get("username", ""),
					"sessionText": self._session_text(session),
					"timeWindowOk": time_ok,
				},
			)
			return
		if parsed.path == "/api/suggest":
			ip = self._client_ip()
			if not self._is_ip_allowed(ip):
				self._send_json(403, {"ok": False, "items": [], "error": "ip not allowed"})
				return
			session = self._current_session()
			if WEB_REQUIRE_KEY and not session:
				self._send_json(401, {"ok": False, "items": [], "error": "unauthorized"})
				return
			params = parse_qs(parsed.query or "")
			query = (params.get("q") or [""])[0]
			_maybe_refresh_csv_from_sheet()
			items = _suggest_account_names(query, CSV_PATH, 8)
			self._send_json(200, {"ok": True, "items": items})
			return
		if parsed.path == "/api/otp-live":
			ip = self._client_ip()
			if not self._is_ip_allowed(ip):
				self._send_json(403, {"ok": False, "error": "ip not allowed"})
				return
			session = self._current_session()
			if WEB_REQUIRE_KEY and not session:
				self._send_json(401, {"ok": False, "error": "unauthorized"})
				return
			params = parse_qs(parsed.query or "")
			account = (params.get("account") or [""])[0].strip()
			if not account:
				self._send_json(400, {"ok": False, "error": "missing account"})
				return
			_maybe_refresh_csv_from_sheet()
			secret, err = _find_secret_by_account(account, CSV_PATH)
			if not secret:
				self._send_json(404, {"ok": False, "error": err or "account not found"})
				return
			code, remaining = generate_totp_code(secret)
			if not code:
				self._send_json(422, {"ok": False, "error": "invalid secret"})
				return
			self._send_json(
				200,
				{
					"ok": True,
					"account": account,
					"code": code,
					"remaining": int(remaining or 0),
					"period": 30,
					"sessionText": self._session_text(session or {}),
				},
			)
			return
		if parsed.path == "/api/otp-live-batch":
			ip = self._client_ip()
			if not self._is_ip_allowed(ip):
				self._send_json(403, {"ok": False, "items": [], "error": "ip not allowed"})
				return
			session = self._current_session()
			if WEB_REQUIRE_KEY and not session:
				self._send_json(401, {"ok": False, "items": [], "error": "unauthorized"})
				return
			params = parse_qs(parsed.query or "")
			accounts = [a.strip() for a in (params.get("account") or []) if a.strip()]
			if not accounts:
				self._send_json(200, {"ok": True, "items": []})
				return
			accounts = accounts[:8]
			_maybe_refresh_csv_from_sheet()
			items = []
			for account in accounts:
				secret, err = _find_secret_by_account(account, CSV_PATH)
				if not secret:
					items.append({"ok": False, "account": account, "error": err or "account not found"})
					continue
				code, remaining = generate_totp_code(secret)
				if not code:
					items.append({"ok": False, "account": account, "error": "invalid secret"})
					continue
				items.append({
					"ok": True,
					"account": account,
					"code": code,
					"remaining": int(remaining or 0),
					"period": 30,
				})
			self._send_json(200, {"ok": True, "items": items, "sessionText": self._session_text(session or {})})
			return
		self._send_json(404, {"ok": False, "error": "not found"})

	def do_HEAD(self) -> None:
		parsed = urlparse(self.path)
		if parsed.path in {"/", "/index.html", "/health", "/favicon.ico"}:
			self.send_response(200)
			self.send_header("Content-Length", "0")
			self.end_headers()
			return
		self.send_response(404)
		self.send_header("Content-Length", "0")
		self.end_headers()

	def do_POST(self) -> None:
		parsed = urlparse(self.path)
		ip = self._client_ip()

		if not self._is_ip_allowed(ip):
			self._send_json(403, {"ok": False, "error": "ip not allowed"})
			return

		# Time-window restriction applies only to OTP lookups, not to login/logout.
		_time_restricted_paths = {"/api/getotp"}
		if parsed.path in _time_restricted_paths and not _is_time_window_allowed():
			self._send_json(403, {"ok": False, "error": "outside allowed time"})
			return

		if parsed.path == "/login":

			n = int(self.headers.get("Content-Length", "0") or "0")
			raw = self.rfile.read(n) if n > 0 else b""
			form = parse_qs(raw.decode("utf-8", errors="ignore"))
			username = (form.get("username") or [""])[0].strip()
			password = (form.get("password") or [""])[0].strip()
			ok, login_user = self._login_ok(username, password, "")
			if not ok:
				_write_audit_line({"ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "type": "login", "client": ip, "username": username, "ok": False})
				self.send_response(303)
				self.send_header("Location", "/?login_error=1")
				self.send_header("Content-Length", "0")
				self.end_headers()
				return
			cookie_val = _create_session(ip, login_user)
			self.send_response(303)
			self._set_cookie(SESSION_COOKIE_NAME, cookie_val, WEB_SESSION_TTL_SECONDS)
			self.send_header("Location", "/")
			self.send_header("Content-Length", "0")
			self.end_headers()
			_write_audit_line({"ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "type": "login", "client": ip, "username": login_user, "ok": True})
			return

		if parsed.path == "/api/login":
			payload, err = self._read_json_body()
			if err:
				self._send_json(400, {"ok": False, "error": err})
				return
			username = str((payload or {}).get("username", "")).strip()
			password = str((payload or {}).get("password", "")).strip()
			api_key = str((payload or {}).get("apiKey", "")).strip()
			login_ok, login_user = self._login_ok(username, password, api_key)

			if not login_ok:
				self._send_json(401, {"ok": False, "error": "invalid credentials"})
				_write_audit_line({"ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "type": "login", "client": ip, "username": username, "ok": False})
				return

			cookie_val = _create_session(ip, login_user)
			self.send_response(200)
			self._set_cookie(SESSION_COOKIE_NAME, cookie_val, WEB_SESSION_TTL_SECONDS)
			body = json.dumps({"ok": True}, ensure_ascii=False).encode("utf-8")
			self.send_header("Content-Type", "application/json; charset=utf-8")
			self.send_header("Content-Length", str(len(body)))
			self.end_headers()
			self.wfile.write(body)
			_write_audit_line({"ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "type": "login", "client": ip, "username": login_user, "ok": True})
			return

		if parsed.path == "/api/logout":
			signed = self._cookie_value(SESSION_COOKIE_NAME)
			session = self._current_session()
			if signed:
				_delete_session(signed)
			self.send_response(200)
			self._clear_cookie(SESSION_COOKIE_NAME)
			body = json.dumps({"ok": True}, ensure_ascii=False).encode("utf-8")
			self.send_header("Content-Type", "application/json; charset=utf-8")
			self.send_header("Content-Length", str(len(body)))
			self.end_headers()
			self.wfile.write(body)
			_write_audit_line({"ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "type": "logout", "client": ip, "username": (session or {}).get("username", ""), "ok": True})
			return

		if parsed.path != "/api/getotp":
			self._send_json(404, {"ok": False, "error": "not found"})
			return

		session = self._current_session()
		if WEB_REQUIRE_KEY and not session:
			self._send_json(401, {"ok": False, "error": "unauthorized"})
			return

		payload, err = self._read_json_body()
		if err:
			self._send_json(400, {"ok": False, "error": err})
			return

		query = str((payload or {}).get("query", "")).strip()
		if not query:
			self._send_json(400, {"ok": False, "error": "empty query"})
			return

		_maybe_refresh_csv_from_sheet()
		text, ok = process_getotp_query(query, CSV_PATH)
		if (not ok) and ("Chưa có dữ liệu OTP" in text):
			text = (
				text
				+ "\n\n[Sheet sync]\n"
				+ f"ok={_LAST_SHEET_SYNC_OK} | msg={_LAST_SHEET_SYNC_MSG}\n"
				+ f"sheet_id={GOOGLE_SHEET_ID}\n"
				+ f"sheet_name={GOOGLE_SHEET_NAME}"
			)
		self._send_json(200, {"ok": bool(ok), "text": text, "sessionText": self._session_text(session or {})})
		_write_audit_line({"ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "type": "lookup", "client": ip, "username": (session or {}).get("username", ""), "query": query, "ok": bool(ok)})


def main() -> int:
	if WEB_REQUIRE_KEY and not WEB_USERS and not WEB_API_KEY:
		print("Missing credentials: set OTP_WEB_USERS or OTP_WEB_API_KEY")
		return 1

	if not os.path.exists(CSV_PATH):
		print(f"CSV file not found yet: {CSV_PATH}")

	_maybe_refresh_csv_from_sheet()
	print(f"Initial sheet sync: ok={_LAST_SHEET_SYNC_OK} msg={_LAST_SHEET_SYNC_MSG}")

	server = ThreadingHTTPServer((WEB_HOST, WEB_PORT), OTPWebHandler)
	print(f"OTP Web server running at http://{WEB_HOST}:{WEB_PORT}")
	print(f"CSV source: {CSV_PATH}")
	print(f"Session TTL: {WEB_SESSION_TTL_SECONDS}s")
	print(f"Sheet refresh interval: {WEB_SHEET_REFRESH_SECONDS}s")
	if WEB_USERS:
		print(f"Web users loaded: {len(WEB_USERS)}")
	print(f"Session bind IP: {WEB_SESSION_BIND_IP}")
	if WEB_ALLOWED_IPS:
		print(f"Allowed IPs: {','.join(sorted(WEB_ALLOWED_IPS))}")
	if WEB_ALLOWED_TIME_WINDOW:
		print(f"Allowed time window: {os.environ.get('OTP_WEB_ALLOWED_TIME_WINDOW', '')}")
	print(f"Time zone for window: {WEB_TIMEZONE}")
	server.serve_forever()
	return 0


if __name__ == "__main__":
	raise SystemExit(main())
