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
from urllib.parse import urlparse

from telegram_otp_listener import force_restore_csv_from_google_sheet, process_getotp_query


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
GOOGLE_SHEET_NAME = os.environ.get("GOOGLE_SHEET_NAME", "OTP").strip() or "OTP"
GOOGLE_SERVICE_ACCOUNT_FILE = os.environ.get("GOOGLE_SERVICE_ACCOUNT_FILE", "").strip()
GOOGLE_SERVICE_ACCOUNT_JSON = os.environ.get("GOOGLE_SERVICE_ACCOUNT_JSON", "").strip()

SESSION_COOKIE_NAME = "otp_web_session"
SESSION_SIGNING_KEY = os.environ.get("OTP_WEB_SESSION_SIGNING_KEY", WEB_API_KEY or "change-this-session-key")

_SESSIONS_LOCK = threading.Lock()
_SESSIONS: Dict[str, Dict[str, Any]] = {}
_SHEET_LOCK = threading.Lock()
_LAST_SHEET_SYNC_TS = 0


def _now_ts() -> int:
	return int(time.time())


def _write_audit_line(payload: Dict[str, Any]) -> None:
	os.makedirs(os.path.dirname(os.path.abspath(AUDIT_LOG_FILE)), exist_ok=True)
	with open(AUDIT_LOG_FILE, "a", encoding="utf-8") as f:
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
	global _LAST_SHEET_SYNC_TS
	if not GOOGLE_SHEET_ID:
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
		_write_audit_line(
			{
				"ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
				"type": "sheet_refresh",
				"ok": bool(ok),
				"msg": msg,
			}
		)


def _html_page() -> str:
	return """<!doctype html>
<html lang=\"vi\"><head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\" />
  <title>Nefitly OTP Web</title>
  <style>
	body { font-family: ui-sans-serif, -apple-system, Segoe UI, sans-serif; background:#f3f7f5; margin:0; padding:24px; }
	.card { max-width: 860px; margin: 0 auto; background:#fff; border:1px solid #d7e5df; border-radius:14px; overflow:hidden; }
	.head { padding:18px; background:linear-gradient(135deg,#0f766e,#0d9488); color:#fff; }
	.body { padding:16px; display:grid; gap:10px; }
	.row { display:grid; grid-template-columns:1fr 1fr auto; gap:8px; }
	input,button { border:1px solid #c6d9d1; border-radius:10px; padding:10px 12px; font-size:14px; }
	button { background:#0f766e; color:#fff; border-color:transparent; cursor:pointer; }
	.ghost { background:#fff; color:#1d2a24; border-color:#c6d9d1; }
	.hide { display:none; }
	.hint { color:#51645c; font-size:13px; }
	pre { background:#fbfdfc; border:1px solid #dce9e3; border-radius:10px; padding:12px; min-height:180px; white-space:pre-wrap; }
	@media (max-width:760px){ .row { grid-template-columns:1fr; } }
  </style>
</head><body>
  <main class=\"card\">
	<section class=\"head\"><h2 style=\"margin:0\">OTP Web Lookup</h2></section>
	<section class=\"body\">
	  <div id=\"loginBox\" class=\"row\">
		<input id=\"username\" placeholder=\"Username\" />
		<input id=\"password\" type=\"password\" placeholder=\"Password\" />
		<button id=\"btnLogin\">Dang nhap</button>
	  </div>

	  <div id=\"appBox\" class=\"hide\">
		<div class=\"row\">
		  <input id=\"query\" placeholder=\"Nhap keyword OTP\" />
		  <button id=\"btnLookup\">Lay OTP</button>
		  <button id=\"btnLogout\" class=\"ghost\">Dang xuat</button>
		</div>
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

	async function checkSession() {
	  try {
		const res = await fetch('/api/session', {credentials:'same-origin'});
		const d = await res.json();
		if (d.ok && d.authenticated) {
		  loginBox.classList.add('hide');
		  appBox.classList.remove('hide');
		  status.textContent = (d.username ? ('Xin chao ' + d.username + '. ') : '') + (d.sessionText || 'Da dang nhap');
		} else {

			return """<!DOCTYPE html>
		<html lang="vi"><head>
		  <meta charset="utf-8"/>
		  <meta name="viewport" content="width=device-width,initial-scale=1"/>
		  <title>Nefitly • OTP Lookup</title>
		  <style>
		    * { margin:0; padding:0; box-sizing:border-box; }
		    body { font-family:-apple-system,'Segoe UI','Helvetica Neue',sans-serif; background:linear-gradient(135deg,#667eea 0%,#764ba2 100%); min-height:100vh; display:flex; align-items:center; justify-content:center; padding:16px; }
		    .container { width:100%; max-width:480px; }
		    .card { background:#fff; border-radius:20px; box-shadow:0 20px 60px rgba(0,0,0,0.3); overflow:hidden; animation:slideIn 0.4s ease-out; }
		    @keyframes slideIn { from { opacity:0; transform:translateY(20px); } to { opacity:1; transform:translateY(0); } }
		    .header { background:linear-gradient(135deg,#667eea,#764ba2); padding:40px 24px; text-align:center; color:#fff; }
		    .header h1 { font-size:28px; font-weight:600; letter-spacing:-0.5px; }
		    .header .subtitle { font-size:13px; opacity:0.9; margin-top:6px; }
		    .body { padding:32px 24px; }
		    .form-group { margin-bottom:16px; }
		    input { width:100%; padding:12px 16px; border:1.5px solid #e0e0e0; border-radius:12px; font-size:15px; transition:all 0.3s; background:#f9f9f9; }
		    input:focus { outline:none; border-color:#667eea; background:#fff; box-shadow:0 0 0 3px rgba(102,126,234,0.1); }
		    .row { display:grid; grid-template-columns:1fr auto auto; gap:8px; margin-bottom:16px; }
		    button { padding:12px 24px; border:none; border-radius:12px; font-size:14px; font-weight:500; cursor:pointer; transition:all 0.3s; }
		    .btn-primary { background:linear-gradient(135deg,#667eea,#764ba2); color:#fff; width:100%; }
		    .btn-primary:hover { transform:translateY(-2px); box-shadow:0 10px 20px rgba(102,126,234,0.3); }
		    .btn-primary:active { transform:translateY(0); }
		    .btn-secondary { background:#f0f0f0; color:#333; }
		    .btn-secondary:hover { background:#e0e0e0; }
		    .status { font-size:13px; color:#666; margin:16px 0; padding:12px 16px; background:#f5f5f5; border-radius:8px; border-left:3px solid #667eea; }
		    .output { font-family:'Courier New',monospace; font-size:13px; line-height:1.6; color:#222; background:#f9f9f9; border:1px solid #e0e0e0; border-radius:12px; padding:16px; min-height:200px; white-space:pre-wrap; word-break:break-word; max-height:400px; overflow-y:auto; }
		    .hide { display:none; }
		    .loading { animation:pulse 1.5s infinite; }
		    @keyframes pulse { 0%,100% { opacity:1; } 50% { opacity:0.6; } }
		    .success { color:#10b981; }
		    .error { color:#ef4444; }
		    @media (max-width:480px) { .header { padding:32px 20px; } .body { padding:24px 20px; } .row { grid-template-columns:1fr; } }
		  </style>
		</head><body>
		  <div class="container">
		    <div class="card">
		      <div class="header">
		        <h1>🔐 Nefitly OTP</h1>
		        <p class="subtitle">Tra cứu mã xác thực nhanh chóng</p>
		      </div>
		      <div class="body">
		        <div id="loginBox">
		          <div class="form-group">
		            <input id="username" placeholder="👤 Tên đăng nhập" autocomplete="username"/>
		          </div>
		          <div class="form-group">
		            <input id="password" type="password" placeholder="🔑 Mật khẩu" autocomplete="current-password"/>
		          </div>
		          <button id="btnLogin" class="btn-primary">Đăng nhập</button>
		        </div>
		        <div id="appBox" class="hide">
		          <div class="row">
		            <input id="query" placeholder="🔍 Nhập từ khóa OTP..."/>
		            <button id="btnLookup" class="btn-primary">Lấy</button>
		            <button id="btnLogout" class="btn-secondary">Thoát</button>
		          </div>
		        </div>
		        <div id="status" class="status">⏳ Kiểm tra phiên...</div>
		        <div id="out" class="output">Sẵn sàng.</div>
		      </div>
		    </div>
		  </div>
		  <script>
		    const loginBox=document.getElementById('loginBox'),appBox=document.getElementById('appBox'),status=document.getElementById('status'),out=document.getElementById('out');
		    async function checkSession(){try{const res=await fetch('/api/session',{credentials:'same-origin'}),d=await res.json();if(d.ok&&d.authenticated){loginBox.classList.add('hide'),appBox.classList.remove('hide'),status.classList.remove('error'),status.innerHTML='✅ '+(d.username?'Xin chào '+d.username:'Đã đăng nhập')+' <br/><small>Phiên: '+d.sessionText+'</small>'}else{loginBox.classList.remove('hide'),appBox.classList.add('hide'),status.classList.add('error'),status.textContent='❌ '+d.error||'Chưa đăng nhập'}}catch(e){status.classList.add('error'),status.textContent='❌ Lỗi kết nối'}}
		    async function login(){const u=document.getElementById('username').value.trim(),p=document.getElementById('password').value.trim();out.classList.add('loading'),out.textContent='⏳ Đang đăng nhập...';const res=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},credentials:'same-origin',body:JSON.stringify({username:u,password:p})}),d=await res.json();if(out.classList.remove('loading'),d.ok){out.classList.add('success'),out.textContent='✅ Đăng nhập thành công!'}else out.classList.add('error'),out.textContent='❌ '+(d.error||'Đăng nhập thất bại');await checkSession()}
		    async function logout(){out.textContent='⏳ Đang đăng xuất...';await fetch('/api/logout',{method:'POST',credentials:'same-origin'}),out.textContent='✅ Đã đăng xuất.',await checkSession()}
		    async function lookup(){const q=document.getElementById('query').value.trim();if(!q){out.textContent='⚠️ Nhập từ khóa trước',out.classList.add('error');return}out.classList.remove('success','error'),out.textContent='⏳ Tìm kiếm...';const res=await fetch('/api/getotp',{method:'POST',headers:{'Content-Type':'application/json'},credentials:'same-origin',body:JSON.stringify({query:q})}),d=await res.json();res.status===401?(out.classList.add('error'),out.textContent='❌ Hết phiên. Vui lòng đăng nhập lại'):d.ok?(out.classList.add('success'),out.textContent='✅ '+d.text):(out.classList.add('error'),out.textContent='❌ '+(d.text||d.error||'Không tìm thấy')),d.sessionText&&(status.textContent='✅ '+d.sessionText)}
		    document.getElementById('btnLogin').addEventListener('click',login),document.getElementById('btnLookup').addEventListener('click',lookup),document.getElementById('btnLogout').addEventListener('click',logout),document.getElementById('query').addEventListener('keydown',(e)=>{e.key==='Enter'&&lookup()}),document.getElementById('password').addEventListener('keydown',(e)=>{e.key==='Enter'&&login()}),checkSession();
		  </script>
		</body></html>"""
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
		self._send_json(200, {"ok": bool(ok), "text": text, "sessionText": self._session_text(session or {})})
		_write_audit_line({"ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "type": "lookup", "client": ip, "username": (session or {}).get("username", ""), "query": query, "ok": bool(ok)})


def main() -> int:
	if WEB_REQUIRE_KEY and not WEB_USERS and not WEB_API_KEY:
		print("Missing credentials: set OTP_WEB_USERS or OTP_WEB_API_KEY")
		return 1

	if not os.path.exists(CSV_PATH):
		print(f"CSV file not found yet: {CSV_PATH}")

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
