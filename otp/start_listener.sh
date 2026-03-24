#!/usr/bin/env bash
set -euo pipefail

DATA_DIR="${DATA_DIR:-/var/data}"
SLEEP_SECONDS="${SLEEP_SECONDS:-1}"

mkdir -p "$DATA_DIR"

# Seed persistent files on first boot only.
if [[ ! -f "$DATA_DIR/otp_wps.csv" && -f "otp_wps.csv" ]]; then
  cp otp_wps.csv "$DATA_DIR/otp_wps.csv"
fi
if [[ ! -f "$DATA_DIR/telegram_permissions.json" && -f "telegram_permissions.json" ]]; then
  cp telegram_permissions.json "$DATA_DIR/telegram_permissions.json"
fi
if [[ ! -f "$DATA_DIR/telegram_offset.txt" && -f "telegram_offset.txt" ]]; then
  cp telegram_offset.txt "$DATA_DIR/telegram_offset.txt"
fi

# Heal and merge permission seed into persistent storage before booting the listener.
python3 - <<'PY'
import json
import os

data_dir = os.environ.get("DATA_DIR", "/var/data")
data_file = os.path.join(data_dir, "telegram_permissions.json")
app_file = os.path.join(os.getcwd(), "telegram_permissions.json")

def load_perm(path):
  if not os.path.exists(path):
    return {"get": {}, "delete": {}}
  try:
    with open(path, "r", encoding="utf-8") as f:
      raw = json.load(f)
  except Exception:
    return {"get": {}, "delete": {}}
  if not isinstance(raw, dict):
    return {"get": {}, "delete": {}}
  return {
    "get": raw.get("get", {}) if isinstance(raw.get("get", {}), dict) else {},
    "delete": raw.get("delete", {}) if isinstance(raw.get("delete", {}), dict) else {},
  }

def merge(base, extra):
  out = {
    "get": dict(base.get("get", {})),
    "delete": dict(base.get("delete", {})),
  }
  for action in ("get", "delete"):
    for key, value in extra.get(action, {}).items():
      key = str(key).strip()
      value = str(value).strip()
      if key and value and key not in out[action]:
        out[action][key] = value
  return out

os.makedirs(data_dir, exist_ok=True)
merged = merge(load_perm(data_file), load_perm(app_file))
tmp = data_file + ".bootstrap.tmp"
with open(tmp, "w", encoding="utf-8") as f:
  json.dump(merged, f, ensure_ascii=False, indent=2, sort_keys=True)
os.replace(tmp, data_file)
print(f"Permission bootstrap: get={len(merged['get'])}, delete={len(merged['delete'])}")
PY

# Keep a lightweight HTTP server alive for Render Web Service health checks.
HEALTH_PORT="${PORT:-10000}"
python3 -u -c '
import os
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

port = int(os.environ.get("PORT", "10000"))
ThreadingHTTPServer(("0.0.0.0", port), SimpleHTTPRequestHandler).serve_forever()
' >/dev/null 2>&1 &
echo "Health check OK on port ${HEALTH_PORT}"

exec python3 -u telegram_otp_listener.py \
  --sleep-seconds "$SLEEP_SECONDS" \
  --wps-file "$DATA_DIR/otp_wps.csv" \
  --offset-file "$DATA_DIR/telegram_offset.txt" \
  --permission-file "$DATA_DIR/telegram_permissions.json" \
  --pending-file "$DATA_DIR/telegram_qr_pending.json" \
  --processed-updates-file "$DATA_DIR/telegram_processed_updates.json" \
  --processed-messages-file "$DATA_DIR/telegram_processed_messages.json" \
  --processed-commands-file "$DATA_DIR/telegram_processed_commands.json" \
  --singleton-lock-file "$DATA_DIR/telegram_listener.lock" \
  --sheet-pull-interval-seconds "${TELEGRAM_SHEET_PULL_INTERVAL_SECONDS:-120}" \
  --sent-dedupe-file "$DATA_DIR/telegram_sent_dedupe.json"
