#!/usr/bin/env python3

import hashlib
import hmac
import html
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


def _html_page(authenticated: bool = False, session_text: str = "Dang kiem tra phien...", login_error: bool = False) -> str:
	status_text = session_text if authenticated else ("Dang nhap that bai. Kiem tra lai tai khoan/mat khau." if login_error else "")
	is_auth_js = "true" if authenticated else "false"
	err_vis = "" if login_error else ' style="display:none"'
	login_vis = ' style="display:none"' if authenticated else ""
	app_vis = "" if authenticated else ' style="display:none"'
	html_text = """<!doctype html>
<html lang=\"vi\"><head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\" />
  <title>Nefitly OTP</title>
  <style>
	:root {
	  --bg:#f2f2f7;
	  --white:#ffffff;
	  --line:#e5e5ea;
	  --text:#1c1c1e;
	  --sub:#8e8e93;
	  --accent:#007aff;
	  --otp:#b71c1c;
	}
	* { box-sizing: border-box; margin: 0; padding: 0; }
	body {
	  background: var(--bg);
	  color: var(--text);
	  font-family: -apple-system, 'SF Pro Text', 'Segoe UI', sans-serif;
	  min-height: 100vh;
	}

	/* ---- LOGIN PAGE ---- */
	.login-page {
	  display: flex;
	  flex-direction: column;
	  align-items: center;
	  justify-content: center;
	  min-height: 100vh;
	  padding: 24px;
	}
	.login-card {
	  width: 100%;
	  max-width: 360px;
	  background: var(--white);
	  border-radius: 18px;
	  padding: 32px 28px;
	  box-shadow: 0 4px 24px rgba(0,0,0,.09);
	}
	.login-title {
	  font-size: 22px;
	  font-weight: 700;
	  margin-bottom: 6px;
	}
	.login-sub {
	  font-size: 14px;
	  color: var(--sub);
	  margin-bottom: 28px;
	}
	.login-field {
	  width: 100%;
	  height: 48px;
	  border: 1px solid var(--line);
	  border-radius: 12px;
	  padding: 0 14px;
	  font-size: 16px;
	  background: var(--bg);
	  color: var(--text);
	  outline: none;
	  margin-bottom: 14px;
	}
	.login-field:focus { border-color: var(--accent); }
	.login-btn {
	  width: 100%;
	  height: 48px;
	  border: none;
	  border-radius: 12px;
	  background: var(--accent);
	  color: #fff;
	  font-size: 17px;
	  font-weight: 600;
	  cursor: pointer;
	  margin-top: 4px;
	}
	.err-msg {
	  color: #d32f2f;
	  font-size: 13px;
	  margin-bottom: 12px;
	}

	/* ---- APP PAGE ---- */
	.app-page { display: flex; flex-direction: column; height: 100vh; }
	.topbar {
	  background: var(--white);
	  border-bottom: 1px solid var(--line);
	  padding: 14px 16px 10px;
	  position: sticky;
	  top: 0;
	  z-index: 20;
	}
	.topbar-row1 {
	  display: flex;
	  align-items: center;
	  justify-content: space-between;
	  margin-bottom: 12px;
	}
	.app-title {
	  font-size: 22px;
	  font-weight: 700;
	}
	.logout-btn {
	  height: 34px;
	  padding: 0 16px;
	  border: 1px solid var(--line);
	  border-radius: 999px;
	  background: transparent;
	  color: var(--sub);
	  font-size: 14px;
	  cursor: pointer;
	}
	.search-bar {
	  width: 100%;
	  height: 42px;
	  background: var(--bg);
	  border: none;
	  border-radius: 12px;
	  padding: 0 14px 0 38px;
	  font-size: 16px;
	  color: var(--text);
	  outline: none;
	}
	.search-wrap {
	  position: relative;
	}
	.search-icon {
	  position: absolute;
	  left: 11px;
	  top: 50%;
	  transform: translateY(-50%);
	  width: 18px;
	  height: 18px;
	  color: var(--sub);
	  pointer-events: none;
	}
	.otp-list {
	  flex: 1;
	  overflow-y: auto;
	  padding: 8px 0 40px;
	}
	.otp-row {
	  background: var(--white);
	  display: flex;
	  align-items: center;
	  justify-content: space-between;
	  padding: 18px 20px;
	  border-bottom: 1px solid var(--line);
	  cursor: pointer;
	  transition: background .1s;
	}
	.otp-row:first-child { border-top: 1px solid var(--line); }
	.otp-row:hover { background: #f9f9f9; }
	.otp-row:active { background: #f0f0f5; }
	.otp-name {
	  font-size: 15px;
	  color: var(--sub);
	  margin-bottom: 4px;
	}
	.otp-code-big {
	  font-size: 36px;
	  font-weight: 400;
	  color: var(--otp);
	  letter-spacing: .04em;
	}
	.otp-right {
	  display: flex;
	  align-items: center;
	  gap: 10px;
	}
	.otp-timer {
	  position: relative;
	  width: 32px;
	  height: 32px;
	  flex-shrink: 0;
	}
	.otp-timer svg {
	  transform: rotate(-90deg);
	}
	.otp-timer-text {
	  position: absolute;
	  inset: 0;
	  display: flex;
	  align-items: center;
	  justify-content: center;
	  font-size: 10px;
	  font-weight: 700;
	  color: var(--otp);
	}
	.otp-copy-icon {
	  color: var(--sub);
	  opacity: .5;
	}
	.empty-msg {
	  text-align: center;
	  color: var(--sub);
	  font-size: 15px;
	  padding: 40px 20px;
	}
	.status-chip {
	  font-size: 12px;
	  color: var(--sub);
	  text-align: center;
	  padding: 8px;
	}
	.spinner {
	  display: inline-block;
	  width: 18px;
	  height: 18px;
	  border: 2px solid var(--line);
	  border-top-color: var(--accent);
	  border-radius: 50%;
	  animation: spin .7s linear infinite;
	  vertical-align: middle;
	  margin-right: 6px;
	}
	@keyframes spin { to { transform: rotate(360deg); } }
	/* copy flash */
	.otp-row.copied .otp-code-big { color: #2e7d32; }
  </style>
</head><body>

  <!-- LOGIN PAGE -->
  <div id=\"loginPage\" class=\"login-page\"__LOGIN_VIS__>
	<div class=\"login-card\">
	  <div class=\"login-title\">Nefitly OTP</div>
	  <div class=\"login-sub\">Dang nhap de xem ma xac thuc</div>
	  <div id=\"errMsg\" class=\"err-msg\"__ERR_VIS__>Sai tai khoan hoac mat khau.</div>
	  <form method=\"post\" action=\"/login\">
		<input class=\"login-field\" name=\"username\" type=\"text\" placeholder=\"Ten tai khoan\" autocomplete=\"username\" required />
		<input class=\"login-field\" name=\"password\" type=\"password\" placeholder=\"Mat khau\" autocomplete=\"current-password\" required />
		<button class=\"login-btn\" type=\"submit\">Dang nhap</button>
	  </form>
	</div>
  </div>

  <!-- APP PAGE -->
  <div id=\"appPage\" class=\"app-page\"__APP_VIS__>
	<div class=\"topbar\">
	  <div class=\"topbar-row1\">
		<div class=\"app-title\">Authenticator</div>
		<button class=\"logout-btn\" id=\"btnLogout\">Dang xuat</button>
	  </div>
	  <div class=\"search-wrap\">
		<svg class=\"search-icon\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\"><circle cx=\"11\" cy=\"11\" r=\"8\"/><line x1=\"21\" y1=\"21\" x2=\"16.65\" y2=\"16.65\"/></svg>
		<input id=\"searchInput\" class=\"search-bar\" type=\"text\" placeholder=\"Tim kiem...\" autocomplete=\"off\" />
	  </div>
	</div>
	<div id=\"otpList\" class=\"otp-list\">
	  <div class=\"empty-msg\"><span class=\"spinner\"></span> Dang tai danh sach...</div>
	</div>
	<div id=\"statusBar\" class=\"status-chip\">__STATUS_TEXT__</div>
  </div>

  <script>
	const IS_AUTH = __IS_AUTH__;
	const loginPage = document.getElementById('loginPage');
	const appPage = document.getElementById('appPage');
	const searchInput = document.getElementById('searchInput');
	const otpList = document.getElementById('otpList');
	const statusBar = document.getElementById('statusBar');

	// ---- OTP list state ----
	let allAccounts = [];     // all account names from server
	let otpData = {};         // account -> { code, remaining, period }
	let tickInterval = null;
	let refreshInterval = null;
	let filterText = '';

	// ---- Utility ----
	function fmtCode(code) {
	  const s = String(code || '------').replace(/\\s/g, '');
	  if (s.length === 6) return s.slice(0,3) + ' ' + s.slice(3);
	  return s;
	}

	function timerSvg(remaining, period) {
	  const r = 13;
	  const circ = 2 * Math.PI * r;
	  const rem = Math.max(0, Number(remaining || 0));
	  const per = Math.max(1, Number(period || 30));
	  const pct = rem / per;
	  const dash = circ * pct;
	  const clr = rem <= 5 ? '#ff3b30' : '#b71c1c';
	  return '<svg width="32" height="32" viewBox="0 0 32 32">'
		+ '<circle cx="16" cy="16" r="' + r + '" fill="none" stroke="#e5e5ea" stroke-width="3"/>'
		+ '<circle cx="16" cy="16" r="' + r + '" fill="none" stroke="' + clr + '" stroke-width="3"'
		+ ' stroke-dasharray="' + dash.toFixed(1) + ' ' + circ.toFixed(1) + '"'
		+ ' stroke-linecap="round"/>'
		+ '</svg>'
		+ '<div class="otp-timer-text" style="color:' + clr + '">' + rem + '</div>';
	}

	function copyIcon() {
	  return '<svg class="otp-copy-icon" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>';
	}

	// ---- Render ----
	function renderList() {
	  const q = filterText.toLowerCase().trim();
	  const visible = q
		? allAccounts.filter(a => a.toLowerCase().includes(q))
		: allAccounts;

	  if (!visible.length) {
		otpList.innerHTML = '<div class="empty-msg">' + (allAccounts.length ? 'Khong tim thay ket qua.' : 'Chua co tai khoan nao.') + '</div>';
		return;
	  }

	otpList.innerHTML = visible.map(name => {
		const d = otpData[name] || {};
		const code = fmtCode(d.code);
		const rem = d.remaining !== undefined ? d.remaining : 30;
		const per = d.period || 30;
		const isActive = name === selectedAccount;
		return '<div class="otp-row' + (isActive ? ' active' : '') + '" data-name="' + name.replace(/"/g,'&quot;') + '">' 
			+ '<div><div class="otp-name">' + name + '</div>'
			+ (isActive ? ('<div class="otp-code-big">' + code + '</div>') : '')
			+ '</div>'
			+ (isActive ? ('<div class="otp-right">' + '<div class="otp-timer">' + timerSvg(rem, per) + '</div>' + copyIcon() + '</div>') : '')
			+ '</div>';
	}).join('');

	otpList.querySelectorAll('.otp-row').forEach(row => {
		row.addEventListener('click', () => selectAccount(row));
	});
	}


	let selectedAccount = null;
	async function selectAccount(row) {
		const name = row.getAttribute('data-name') || '';
		if (!name) return;
		selectedAccount = name;
		renderList();
		// Gửi Telegram khi nhấp vào
		const d = otpData[name] || {};
		const code = String(d.code || '').replace(/\s/g, '');
		if (code) {
			try {
				await navigator.clipboard.writeText(code);
			} catch(e) {}
			row.classList.add('copied');
			setTimeout(() => row.classList.remove('copied'), 1500);
			// Gọi API gửi Telegram
			fetch('/api/notify-telegram', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				credentials: 'same-origin',
				body: JSON.stringify({ account: name, code: code })
			});
		}
	}

	// ---- Data loading ----
	async function loadAccounts() {
	  try {
		const res = await fetch('/api/accounts', { credentials: 'same-origin' });
		if (res.status === 401) { showLogin(); return; }
		const d = await res.json();
		if (d.ok) {
		  allAccounts = d.items || [];
		  renderList();
		  batchRefresh();
		}
	  } catch (e) {
		otpList.innerHTML = '<div class="empty-msg">Loi ket noi.</div>';
	  }
	}

	async function batchRefresh() {
	  if (!allAccounts.length) return;
	  // Chia toàn bộ account thành nhiều batch 50, gọi song song
	  const batchSize = 50;
	  const batches = [];
	  for (let i = 0; i < allAccounts.length; i += batchSize) {
		batches.push(allAccounts.slice(i, i + batchSize));
	  }
	  try {
		const results = await Promise.all(batches.map(async (chunk) => {
		  const params = new URLSearchParams();
		  for (const a of chunk) params.append('account', a);
		  const res = await fetch('/api/otp-live-batch?' + params.toString(), { credentials: 'same-origin' });
		  if (res.status === 401) { showLogin(); return null; }
		  const d = await res.json();
		  if (d.ok && Array.isArray(d.items)) {
			return d.items.map((item, i) => ({ name: chunk[i], ...item }));
		  }
		  return [];
		}));
		// Ghép kết quả lại
		results.flat().forEach((item) => {
		  if (item && item.ok) {
			otpData[item.name] = { code: item.code, remaining: item.remaining, period: item.period || 30 };
		  }
		});
		renderList();
	  } catch(e) {}
	}

	// tick countdown every second
	function tick() {
	  let needRefresh = false;
	  for (const name of allAccounts) {
		const d = otpData[name];
		if (!d) continue;
		d.remaining = Math.max(0, (d.remaining || 0) - 1);
		if (d.remaining === 0) needRefresh = true;
	  }
	  // update timer SVGs in-place to avoid full re-render
	  const q = filterText.toLowerCase().trim();
	  otpList.querySelectorAll('.otp-row').forEach(row => {
		const name = row.getAttribute('data-name') || '';
		if (q && !name.toLowerCase().includes(q)) return;
		const d = otpData[name];
		if (!d) return;
		const timerEl = row.querySelector('.otp-timer');
		if (timerEl) timerEl.innerHTML = timerSvg(d.remaining, d.period);
	  });
	  if (needRefresh) batchRefresh();
	}

	// ---- Session check ----
	async function checkSession() {
	  if (!IS_AUTH) return;
	  try {
		const res = await fetch('/api/session', { credentials: 'same-origin' });
		const d = await res.json();
		if (!d.ok || !d.authenticated) { showLogin(); return; }
		if (d.sessionText) statusBar.textContent = d.sessionText;
	  } catch(e) {}
	}

	function showLogin() {
	  appPage.style.display = 'none';
	  loginPage.style.display = '';
	  clearInterval(tickInterval);
	  clearInterval(refreshInterval);
	}

	// ---- Search ----
	searchInput.addEventListener('input', () => {
	  filterText = searchInput.value;
	  renderList();
	});

	// ---- Logout ----
	document.getElementById('btnLogout').addEventListener('click', async () => {
	  await fetch('/api/logout', { method: 'POST', credentials: 'same-origin' });
	  showLogin();
	});

	// ---- Boot ----
	if (IS_AUTH) {
	  loadAccounts();
	  tickInterval = setInterval(tick, 1000);
	  refreshInterval = setInterval(batchRefresh, 25000);
	  setInterval(checkSession, 60000);
	}
  </script>
</body></html>"""
	return (
		html_text
		.replace("__LOGIN_VIS__", login_vis)
		.replace("__APP_VIS__", app_vis)
		.replace("__ERR_VIS__", err_vis)
		.replace("__IS_AUTH__", is_auth_js)
		.replace("__STATUS_TEXT__", html.escape(status_text, quote=False))
	)


class OTPWebHandler(BaseHTTPRequestHandler):

	def do_POST(self) -> None:
		parsed = urlparse(self.path)
		ip = self._client_ip()
		if parsed.path == "/api/notify-telegram":
			session = self._current_session()
			if not session:
				self._send_json(401, {"ok": False, "error": "unauthorized"})
				return
			n = int(self.headers.get("Content-Length", "0") or "0")
			raw = self.rfile.read(n) if n > 0 else b"{}"
			try:
				data = json.loads(raw.decode("utf-8"))
			except Exception:
				self._send_json(400, {"ok": False, "error": "invalid json"})
				return
			account = str(data.get("account", "")).strip()
			code = str(data.get("code", "")).strip()
			user = session.get("username", "")
			now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
			msg = f"[OTP WEB]\nNguoi dung: {user}\nTai khoan: {account}\nMa OTP: {code}\nThoi gian: {now}"
			try:
				telegram_send(msg)
			except Exception as e:
				self._send_json(500, {"ok": False, "error": str(e)})
				return
			self._send_json(200, {"ok": True})
			return
		# ...existing code...

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
			params = parse_qs(parsed.query or "")
			login_error = ((params.get("login_error") or [""])[0] == "1")
			session = self._current_session()
			session_text = self._session_text(session or {}) if session else "Dang kiem tra phien..."
			self._send_html(_html_page(authenticated=bool(session), session_text=session_text, login_error=login_error))
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
		if parsed.path == "/api/accounts":
			ip = self._client_ip()
			if not self._is_ip_allowed(ip):
				self._send_json(403, {"ok": False, "items": [], "error": "ip not allowed"})
				return
			session = self._current_session()
			if WEB_REQUIRE_KEY and not session:
				self._send_json(401, {"ok": False, "items": [], "error": "unauthorized"})
				return
			_maybe_refresh_csv_from_sheet()
			_, rows = load_csv_rows(CSV_PATH)
			seen: Set[str] = set()
			names: list[str] = []
			for row in (rows or []):
				acc = (row.get("Account") or "").strip()
				if acc and acc not in seen:
					seen.add(acc)
					names.append(acc)
			self._send_json(200, {"ok": True, "items": names, "total": len(names)})
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
			accounts = accounts[:50]
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
