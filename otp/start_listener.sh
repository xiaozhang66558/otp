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

# Start tiny health-check HTTP server so Render free Web Service is happy
python3 -c "
import http.server, threading, os
port = int(os.environ.get('PORT', 10000))
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.end_headers(); self.wfile.write(b'OK')
    def log_message(self, *a): pass
threading.Thread(target=http.server.HTTPServer(('', port), H).serve_forever, daemon=True).start()
print(f'Health check OK on port {port}', flush=True)
" &

exec python3 -u telegram_otp_listener.py \
  --sleep-seconds "$SLEEP_SECONDS" \
  --wps-file "$DATA_DIR/otp_wps.csv" \
  --offset-file "$DATA_DIR/telegram_offset.txt" \
  --permission-file "$DATA_DIR/telegram_permissions.json"
