#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT_DIR"

if [[ -f "$ROOT_DIR/.env.local" ]]; then
  set -a
  # shellcheck disable=SC1091
  . "$ROOT_DIR/.env.local"
  set +a
fi

export OTP_WEB_HOST="${OTP_WEB_HOST:-0.0.0.0}"
export OTP_WEB_PORT="${OTP_WEB_PORT:-${PORT:-8787}}"
export OTP_WEB_REQUIRE_KEY="${OTP_WEB_REQUIRE_KEY:-1}"
export OTP_WEB_WPS_FILE="${OTP_WEB_WPS_FILE:-$ROOT_DIR/otp_wps.csv}"
export OTP_WEB_AUDIT_LOG="${OTP_WEB_AUDIT_LOG:-$ROOT_DIR/.runtime/otp_web_access.log}"
export OTP_WEB_SESSION_TTL_SECONDS="${OTP_WEB_SESSION_TTL_SECONDS:-1800}"
export OTP_WEB_ALLOWED_IPS="${OTP_WEB_ALLOWED_IPS:-}"
export OTP_WEB_ALLOWED_TIME_WINDOW="${OTP_WEB_ALLOWED_TIME_WINDOW:-}"
export OTP_WEB_TRUST_PROXY="${OTP_WEB_TRUST_PROXY:-0}"
export OTP_WEB_SESSION_SIGNING_KEY="${OTP_WEB_SESSION_SIGNING_KEY:-${OTP_WEB_API_KEY:-}}"
export OTP_WEB_SHEET_REFRESH_SECONDS="${OTP_WEB_SHEET_REFRESH_SECONDS:-15}"

PYTHON_BIN="$(command -v python3)"
"$PYTHON_BIN" -u otp_web_server.py "$@"
