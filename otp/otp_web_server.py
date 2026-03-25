#!/usr/bin/env python3

import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional, Set, Tuple
from urllib.parse import parse_qs, urlparse

from telegram_otp_listener import force_restore_csv_from_google_sheet, load_csv_rows, process_getotp_query


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
			"client_ip": client_ip,
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
		if session.get("client_ip") and session.get("client_ip") != client_ip:
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


def _is_time_window_allowed() -> bool:
	if WEB_ALLOWED_TIME_WINDOW is None:
		return True
	now = datetime.now()
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


def _html_page() -> str:
	return """<!doctype html>
<html lang=\"vi\"><head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\" />
  <title>Nefitly OTP</title>
  <style>
	:root {
	  --bg-a:#0d1a39;
	  --bg-b:#11214b;
	  --bg-c:#1a2f63;
	  --card:#0f1f47cc;
	  --line:#8ea4d133;
	  --text:#e9f1ff;
	  --muted:#b4c4e8;
	  --primary:#2dd4bf;
	  --primary-2:#38bdf8;
	}
	* { box-sizing:border-box; }
	body {
	  font-family: 'Segoe UI', 'SF Pro Text', -apple-system, sans-serif;
	  background: radial-gradient(1200px 700px at 10% 5%, #1c3270 0%, transparent 50%),
	              radial-gradient(1000px 600px at 90% 90%, #0a2556 0%, transparent 55%),
	              linear-gradient(145deg, var(--bg-a), var(--bg-b) 45%, var(--bg-c));
	  color: var(--text);
	  margin: 0;
	  min-height: 100vh;
	  padding: 22px;
	}
	.card {
	  max-width: 980px;
	  margin: 0 auto;
	  background: var(--card);
	  border: 1px solid var(--line);
	  border-radius: 20px;
	  overflow: hidden;
	  box-shadow: 0 24px 70px rgba(1, 8, 30, .45);
	}
	.head {
	  padding: 24px;
	  background: linear-gradient(120deg, rgba(45,212,191,.22), rgba(56,189,248,.12));
	  border-bottom: 1px solid var(--line);
	}
	.head h2 { margin: 0; font-size: 36px; letter-spacing: .2px; }
	.sub { margin-top: 8px; color: var(--muted); font-size: 14px; }
	.body { padding: 20px; display: grid; gap: 12px; }
	.row { display: grid; grid-template-columns: 1fr 1fr auto; gap: 10px; }
	.query-row { display: grid; grid-template-columns: 1fr auto auto; gap: 10px; }
	input, button {
	  border-radius: 14px;
	  padding: 12px 14px;
	  font-size: 19px;
	}
	input {
	  border: 1px solid #89a6db55;
	  background: #f4f8ff;
	  color: #0f172a;
	}
	button {
	  border: none;
	  cursor: pointer;
	  color: #03111f;
	  background: linear-gradient(120deg, var(--primary), var(--primary-2));
	  font-weight: 700;
	}
	button:hover { transform: translateY(-1px); filter: brightness(1.04); }
	.ghost {
	  background: #dbeafe;
	  color: #1e293b;
	}
	.hide { display: none; }
	.hint {
	  color: #dbeafe;
	  font-size: 30px;
	}
	.suggest {
	  margin-top: -2px;
	  display: grid;
	  gap: 8px;
	}
	.suggest button {
	  text-align: left;
	  font-size: 17px;
	  border-radius: 12px;
	  background: #dbeafe;
	  color: #0f172a;
	}
	pre {
	  background: #0a1738cc;
	  border: 1px solid var(--line);
	  color: #eff6ff;
	  border-radius: 14px;
	  padding: 16px;
	  min-height: 300px;
	  white-space: pre-wrap;
	  font-size: 30px;
	  line-height: 1.35;
	}
	@media (max-width: 760px) {
	  .row, .query-row { grid-template-columns: 1fr; }
	  .head h2 { font-size: 30px; }
	  .hint { font-size: 24px; }
	  pre { font-size: 24px; min-height: 260px; }
	}
  </style>
</head><body>
  <main class=\"card\">
	<section class=\"head\"><h2>OTP Web Lookup</h2><div class=\"sub\">Tra cuu OTP nhanh, go den dau goi y den do</div></section>
	<section class=\"body\">
	  <div id=\"loginBox\" class=\"row\">
		<input id=\"username\" placeholder=\"Username\" />
		<input id=\"password\" type=\"password\" placeholder=\"Password\" />
		<button id=\"btnLogin\">Dang nhap</button>
	  </div>

	  <div id=\"appBox\" class=\"hide\">
		<div class=\"query-row\">
		  <input id=\"query\" placeholder=\"Nhap keyword OTP\" />
		  <button id=\"btnLookup\">Lay OTP</button>
		  <button id=\"btnLogout\" class=\"ghost\">Dang xuat</button>
		</div>
		<div id=\"suggestions\" class=\"suggest\"></div>
	  </div>

	  <div id=\"status\" class=\"hint\">Dang kiem tra phien...</div>
	  <pre id=\"out\">San sang.</pre>
	</section>
  </main>

  <script>
	const loginBox = document.getElementById('loginBox');
	const appBox = document.getElementById('appBox');
	const status = document.getElementById('status');
	const out = document.getElementById('out');
	const queryInput = document.getElementById('query');
	const suggestBox = document.getElementById('suggestions');
	let suggestTimer = null;

	async function checkSession() {
	  try {
		const res = await fetch('/api/session', {credentials:'same-origin'});
		const d = await res.json();
		if (d.ok && d.authenticated) {
		  loginBox.classList.add('hide');
		  appBox.classList.remove('hide');
		  status.textContent = (d.username ? ('Xin chao ' + d.username + '. ') : '') + (d.sessionText || 'Da dang nhap');
		} else {
		  loginBox.classList.remove('hide');
		  appBox.classList.add('hide');
		  status.textContent = d.error || 'Chua dang nhap.';
		}
	  } catch (e) {
		status.textContent = 'Loi ket noi server';
	  }
	}

	async function login() {
	  const username = document.getElementById('username').value.trim();
	  const password = document.getElementById('password').value.trim();
	  out.textContent = 'Dang dang nhap...';
	  const res = await fetch('/api/login', {
		method:'POST',
		headers:{'Content-Type':'application/json'},
		credentials:'same-origin',
		body: JSON.stringify({username, password})
	  });
	  const d = await res.json();
	  out.textContent = d.ok ? 'Dang nhap thanh cong.' : (d.error || 'Dang nhap that bai');
	  await checkSession();
	}

	async function logout() {
	  await fetch('/api/logout', {method:'POST', credentials:'same-origin'});
	  out.textContent = 'Da dang xuat.';
	  await checkSession();
	}

	async function lookup() {
	  const query = queryInput.value.trim();
	  if (!query) {
		out.textContent = 'Nhap query truoc.';
		return;
	  }
	  suggestBox.innerHTML = '';
	  out.textContent = 'Dang xu ly...';
	  const res = await fetch('/api/getotp', {
		method:'POST',
		headers:{'Content-Type':'application/json'},
		credentials:'same-origin',
		body: JSON.stringify({query})
	  });
	  const d = await res.json();
	  out.textContent = d.text || d.error || '(trong)';
	  if (d.sessionText) status.textContent = d.sessionText;
	  if (res.status === 401) await checkSession();
	}

	function renderSuggestions(items) {
	  if (!items || !items.length) {
		suggestBox.innerHTML = '';
		return;
	  }
	  suggestBox.innerHTML = items.map((item) => `<button type=\"button\" data-name=\"${item.replace(/\"/g, '&quot;')}\">${item}</button>`).join('');
	  suggestBox.querySelectorAll('button').forEach((btn) => {
		btn.addEventListener('click', () => {
		  queryInput.value = btn.getAttribute('data-name') || '';
		  suggestBox.innerHTML = '';
		  lookup();
		});
	  });
	}

	async function fetchSuggestions() {
	  const q = queryInput.value.trim();
	  if (!q) {
		suggestBox.innerHTML = '';
		return;
	  }
	  try {
		const res = await fetch('/api/suggest?q=' + encodeURIComponent(q), {credentials:'same-origin'});
		if (res.status === 401) {
		  suggestBox.innerHTML = '';
		  await checkSession();
		  return;
		}
		const data = await res.json();
		renderSuggestions(data.items || []);
	  } catch (e) {
		suggestBox.innerHTML = '';
	  }
	}

	document.getElementById('btnLogin').addEventListener('click', login);
	document.getElementById('btnLookup').addEventListener('click', lookup);
	document.getElementById('btnLogout').addEventListener('click', logout);
	queryInput.addEventListener('keydown', (e)=>{ if (e.key==='Enter') lookup(); });
	queryInput.addEventListener('input', () => {
	  if (suggestTimer) clearTimeout(suggestTimer);
	  suggestTimer = setTimeout(fetchSuggestions, 120);
	});
	document.getElementById('password').addEventListener('keydown', (e)=>{ if (e.key==='Enter') login(); });
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

	def _send_json(self, code: int, payload: Dict[str, Any]) -> None:
		data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
		self.send_response(code)
		self.send_header("Content-Type", "application/json; charset=utf-8")
		self.send_header("Content-Length", str(len(data)))
		self.end_headers()
		self.wfile.write(data)

	def _send_html(self, html: str) -> None:
		data = html.encode("utf-8")
		self.send_response(200)
		self.send_header("Content-Type", "text/html; charset=utf-8")
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
		if parsed.path == "/health":
			self._send_json(200, {"ok": True, "service": "otp-web", "ts": _now_ts()})
			return
		if parsed.path == "/api/session":
			ip = self._client_ip()
			if not self._is_ip_allowed(ip):
				self._send_json(403, {"ok": False, "authenticated": False, "error": "ip not allowed"})
				return
			if not _is_time_window_allowed():
				self._send_json(403, {"ok": False, "authenticated": False, "error": "outside allowed time"})
				return
			session = self._current_session()
			if not session:
				self._send_json(200, {"ok": True, "authenticated": False})
				return
			self._send_json(
				200,
				{
					"ok": True,
					"authenticated": True,
					"username": session.get("username", ""),
					"sessionText": self._session_text(session),
				},
			)
			return
		if parsed.path == "/api/suggest":
			ip = self._client_ip()
			if not self._is_ip_allowed(ip):
				self._send_json(403, {"ok": False, "items": [], "error": "ip not allowed"})
				return
			if not _is_time_window_allowed():
				self._send_json(403, {"ok": False, "items": [], "error": "outside allowed time"})
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
		self._send_json(404, {"ok": False, "error": "not found"})

	def do_POST(self) -> None:
		parsed = urlparse(self.path)
		ip = self._client_ip()

		if not self._is_ip_allowed(ip):
			self._send_json(403, {"ok": False, "error": "ip not allowed"})
			return
		if not _is_time_window_allowed():
			self._send_json(403, {"ok": False, "error": "outside allowed time"})
			return

		if parsed.path == "/api/login":
			payload, err = self._read_json_body()
			if err:
				self._send_json(400, {"ok": False, "error": err})
				return
			username = str((payload or {}).get("username", "")).strip()
			password = str((payload or {}).get("password", "")).strip()
			api_key = str((payload or {}).get("apiKey", "")).strip()

			login_ok = False
			login_user = username

			if WEB_USERS:
				expected = WEB_USERS.get(username)
				login_ok = bool(expected and hmac.compare_digest(password, expected))
			else:
				login_ok = WEB_REQUIRE_KEY and bool(WEB_API_KEY and api_key and hmac.compare_digest(api_key, WEB_API_KEY))
				if login_ok and not login_user:
					login_user = "api-key-user"

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
	if WEB_ALLOWED_IPS:
		print(f"Allowed IPs: {','.join(sorted(WEB_ALLOWED_IPS))}")
	if WEB_ALLOWED_TIME_WINDOW:
		print(f"Allowed time window: {os.environ.get('OTP_WEB_ALLOWED_TIME_WINDOW', '')}")
	server.serve_forever()
	return 0


if __name__ == "__main__":
	raise SystemExit(main())
