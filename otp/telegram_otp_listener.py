#!/usr/bin/env python3
"""
Telegram OTP Listener
- Listen commands from Telegram group
- Add OTP records directly from group messages to otp_wps.csv
- Skip duplicates and report details back to group

Command format in group:
  /addotp account|issuer|secret
  /addotp
  account1|issuer1|secret1
  account2||secret2

Optional:
  /helpotp
    /delotp keyword
"""

import argparse
import base64
import concurrent.futures
import csv
import errno
import hmac
import hashlib
import json
import os
import random
import shutil
import ssl
import struct
import string
import threading
import time
import tempfile
import traceback
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple


OUTBOUND_DEDUPE_FILE = ""
OUTBOUND_DEDUPE_TTL_SECONDS = 10

# Module-level lock serialises concurrent CSV read-modify-write from QR worker threads.
_csv_rw_lock = threading.Lock()
_qr_jobs_lock = threading.Lock()
_qr_jobs_inflight = 0


def begin_qr_job() -> int:
    global _qr_jobs_inflight
    with _qr_jobs_lock:
        _qr_jobs_inflight += 1
        return _qr_jobs_inflight


def finish_qr_job() -> int:
    global _qr_jobs_inflight
    with _qr_jobs_lock:
        _qr_jobs_inflight = max(_qr_jobs_inflight - 1, 0)
        return _qr_jobs_inflight


def configure_outbound_dedupe(file_path: str, ttl_seconds: int = 10) -> None:
    global OUTBOUND_DEDUPE_FILE, OUTBOUND_DEDUPE_TTL_SECONDS
    OUTBOUND_DEDUPE_FILE = (file_path or "").strip()
    OUTBOUND_DEDUPE_TTL_SECONDS = max(int(ttl_seconds), 1)


def should_send_outbound(dedupe_key: str) -> bool:
    if not OUTBOUND_DEDUPE_FILE:
        return True
    now_ts = int(time.time())
    if is_recent_command_duplicate(OUTBOUND_DEDUPE_FILE, dedupe_key, now_ts, OUTBOUND_DEDUPE_TTL_SECONDS):
        print(f"[SKIP] Outbound duplicate blocked: {dedupe_key[:120]}", flush=True)
        return False
    mark_command_seen(OUTBOUND_DEDUPE_FILE, dedupe_key, now_ts)
    return True


def load_otp_modules():
    try:
        import cv2
    except Exception:
        print("❌ Thiếu cv2. Cài: pip install opencv-python")
        raise SystemExit(1)

    try:
        from pyzbar.pyzbar import decode
    except Exception:
        print("❌ Thiếu pyzbar. Cài: pip install pyzbar")
        raise SystemExit(1)

    try:
        import otp_pb2
    except Exception:
        print("❌ Thiếu otp_pb2.py")
        raise SystemExit(1)

    return cv2, decode, otp_pb2


def b64decode_urlsafe_padded(data_str: str) -> bytes:
    pad_len = (-len(data_str)) % 4
    data_str += "=" * pad_len
    return base64.urlsafe_b64decode(data_str)


def b32decode_no_padding(secret_b32: str) -> Optional[bytes]:
    secret_clean = (secret_b32 or "").strip().replace(" ", "").replace("-", "").upper()
    if not secret_clean:
        return None
    try:
        pad_len = (-len(secret_clean)) % 8
        return base64.b32decode(secret_clean + ("=" * pad_len), casefold=True)
    except Exception:
        return None


def generate_totp_code(secret_b32: str, digits: int = 6, period: int = 30) -> Tuple[Optional[str], Optional[int]]:
    secret_clean = (secret_b32 or "").strip().replace(" ", "").replace("-", "").upper()
    if not secret_clean:
        return None, None

    try:
        # Telegram/Google Authenticator secrets are commonly stored without '=' padding.
        pad_len = (-len(secret_clean)) % 8
        secret_padded = secret_clean + ("=" * pad_len)
        key = base64.b32decode(secret_padded, casefold=True)
    except Exception:
        return None, None

    now_ts = int(time.time())
    counter = now_ts // period
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    truncated = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    otp_int = truncated % (10**digits)
    code = str(otp_int).zfill(digits)
    remaining = period - (now_ts % period)
    return code, remaining


def stable_key(name: str, issuer: str, secret_b32: str) -> str:
    raw = f"{name.strip().lower()}|{issuer.strip().lower()}|{secret_b32.strip()}"
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()


def build_account_cell(account: str, issuer: str) -> str:
    account = (account or "").strip()
    issuer = (issuer or "").strip()
    if not issuer:
        return account
    if not account:
        return issuer
    return f"{issuer} {account}"


def load_existing_keys(csv_path: str) -> Set[str]:
    if not os.path.exists(csv_path):
        return set()

    keys: Set[str] = set()
    with open(csv_path, "r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            key = (row.get("Key") or "").strip()
            if key:
                keys.add(key)
    return keys


def load_existing_account_names(csv_path: str) -> Set[str]:
    if not os.path.exists(csv_path):
        return set()

    names: Set[str] = set()
    with open(csv_path, "r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            account = (row.get("Account") or "").strip().lower()
            if account:
                names.add(account)
    return names


def load_csv_rows(csv_path: str) -> Tuple[List[str], List[Dict[str, str]]]:
    if not os.path.exists(csv_path):
        return [], []

    with open(csv_path, "r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames or []
        rows = list(reader)
    return fieldnames, rows


def save_csv_rows(csv_path: str, fieldnames: List[str], rows: List[Dict[str, str]]) -> None:
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def _load_google_service_account_info(
    service_account_json: str,
    service_account_file: str,
) -> Tuple[Optional[Dict], str]:
    raw = (service_account_json or "").strip()
    if raw:
        try:
            info = json.loads(raw)
            if isinstance(info.get("private_key"), str):
                info["private_key"] = info["private_key"].replace("\\n", "\n")
            return info, ""
        except Exception as e:
            return None, f"GOOGLE_SERVICE_ACCOUNT_JSON không hợp lệ: {e}"

    file_path = (service_account_file or "").strip()
    if not file_path:
        return None, "Thiếu service account (GOOGLE_SERVICE_ACCOUNT_JSON hoặc GOOGLE_SERVICE_ACCOUNT_FILE)"
    if not os.path.exists(file_path):
        return None, f"Không tìm thấy file service account: {file_path}"

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            info = json.load(f)
        return info, ""
    except Exception as e:
        return None, f"Không đọc được service account file: {e}"


def sync_csv_to_google_sheet(
    csv_path: str,
    spreadsheet_id: str,
    sheet_name: str,
    service_account_json: str,
    service_account_file: str,
) -> Tuple[bool, str]:
    if not os.path.exists(csv_path):
        return False, f"Không tìm thấy file CSV: {csv_path}"

    if not (spreadsheet_id or "").strip():
        return False, "Thiếu GOOGLE_SHEET_ID"

    account_info, err = _load_google_service_account_info(service_account_json, service_account_file)
    if not account_info:
        return False, err

    try:
        from google.oauth2.service_account import Credentials
        from googleapiclient.discovery import build
    except Exception as e:
        return False, f"Thiếu thư viện Google API: {e}"

    try:
        with open(csv_path, "r", newline="", encoding="utf-8") as f:
            reader = csv.reader(f)
            values = [row for row in reader]
    except Exception as e:
        return False, f"Không đọc được CSV để đồng bộ: {e}"

    try:
        creds = Credentials.from_service_account_info(
            account_info,
            scopes=["https://www.googleapis.com/auth/spreadsheets"],
        )
        service = build("sheets", "v4", credentials=creds, cache_discovery=False)

        # Ensure sheet exists before writing.
        meta = service.spreadsheets().get(spreadsheetId=spreadsheet_id).execute()
        current_titles = {
            (s.get("properties") or {}).get("title", "")
            for s in (meta.get("sheets") or [])
        }
        if sheet_name not in current_titles:
            service.spreadsheets().batchUpdate(
                spreadsheetId=spreadsheet_id,
                body={"requests": [{"addSheet": {"properties": {"title": sheet_name}}}]},
            ).execute()

        service.spreadsheets().values().clear(
            spreadsheetId=spreadsheet_id,
            range=f"{sheet_name}!A:Z",
            body={},
        ).execute()

        if values:
            service.spreadsheets().values().update(
                spreadsheetId=spreadsheet_id,
                range=f"{sheet_name}!A1",
                valueInputOption="RAW",
                body={"values": values},
            ).execute()

        return True, f"Đã đồng bộ {max(len(values) - 1, 0)} dòng"
    except Exception as e:
        return False, f"Lỗi đồng bộ Google Sheets: {e}"


def maybe_sync_google_sheet(
    csv_path: str,
    spreadsheet_id: str,
    sheet_name: str,
    service_account_json: str,
    service_account_file: str,
) -> Tuple[bool, str]:
    if not (spreadsheet_id or "").strip():
        return True, "Bỏ qua đồng bộ (chưa cấu hình GOOGLE_SHEET_ID)"
    return sync_csv_to_google_sheet(
        csv_path,
        spreadsheet_id,
        sheet_name,
        service_account_json,
        service_account_file,
    )


def load_sheet_rows(
    spreadsheet_id: str,
    sheet_name: str,
    service_account_json: str,
    service_account_file: str,
) -> Tuple[bool, List[List[str]], str]:
    if not (spreadsheet_id or "").strip():
        return False, [], "Thiếu GOOGLE_SHEET_ID"

    account_info, err = _load_google_service_account_info(service_account_json, service_account_file)
    if not account_info:
        return False, [], err

    try:
        from google.oauth2.service_account import Credentials
        from googleapiclient.discovery import build
    except Exception as e:
        return False, [], f"Thiếu thư viện Google API: {e}"

    try:
        creds = Credentials.from_service_account_info(
            account_info,
            scopes=["https://www.googleapis.com/auth/spreadsheets.readonly"],
        )
        service = build("sheets", "v4", credentials=creds, cache_discovery=False)
        resp = service.spreadsheets().values().get(
            spreadsheetId=spreadsheet_id,
            range=f"{sheet_name}!A:Z",
        ).execute()
        values = resp.get("values") or []
        return True, values, ""
    except Exception as e:
        return False, [], f"Lỗi đọc Google Sheets: {e}"


def restore_csv_from_google_sheet_if_newer(
    csv_path: str,
    spreadsheet_id: str,
    sheet_name: str,
    service_account_json: str,
    service_account_file: str,
) -> Tuple[bool, str]:
    if not (spreadsheet_id or "").strip():
        return True, "Bỏ qua restore (chưa cấu hình GOOGLE_SHEET_ID)"

    ok, values, err = load_sheet_rows(
        spreadsheet_id,
        sheet_name,
        service_account_json,
        service_account_file,
    )
    if not ok:
        return False, err
    if not values:
        return True, "Google Sheet đang trống"

    sheet_header = [str(col).strip() for col in values[0]]
    if not sheet_header:
        return False, "Google Sheet không có header hợp lệ"

    local_fieldnames, local_rows = load_csv_rows(csv_path)
    sheet_rows_count = max(len(values) - 1, 0)
    local_rows_count = len(local_rows)

    # If cloud already has more rows than local, restore local from cloud.
    if sheet_rows_count <= local_rows_count:
        return True, f"Không cần restore (local={local_rows_count}, sheet={sheet_rows_count})"

    normalized_width = len(sheet_header)
    rebuilt_rows: List[Dict[str, str]] = []
    for raw_row in values[1:]:
        padded = list(raw_row) + [""] * (normalized_width - len(raw_row))
        rebuilt_rows.append({sheet_header[idx]: str(padded[idx]) for idx in range(normalized_width)})

    os.makedirs(os.path.dirname(csv_path) or ".", exist_ok=True)
    save_csv_rows(csv_path, sheet_header, rebuilt_rows)
    return True, f"Đã restore {len(rebuilt_rows)} dòng từ Google Sheet"


def force_restore_csv_from_google_sheet(
    csv_path: str,
    spreadsheet_id: str,
    sheet_name: str,
    service_account_json: str,
    service_account_file: str,
) -> Tuple[bool, str]:
    if not (spreadsheet_id or "").strip():
        return True, "Bỏ qua restore (chưa cấu hình GOOGLE_SHEET_ID)"

    ok, values, err = load_sheet_rows(
        spreadsheet_id,
        sheet_name,
        service_account_json,
        service_account_file,
    )
    if not ok:
        return False, err
    if not values:
        local_header, _ = load_csv_rows(csv_path)
        if not local_header:
            local_header = ["Account", "Secret", "FirstSeen", "Key"]
        os.makedirs(os.path.dirname(csv_path) or ".", exist_ok=True)
        save_csv_rows(csv_path, local_header, [])
        return True, "Google Sheet đang trống (đã xoá dữ liệu local)"

    header = [str(col).strip() for col in values[0]]
    if not header:
        return False, "Google Sheet không có header hợp lệ"

    width = len(header)
    rebuilt_rows: List[Dict[str, str]] = []
    for raw_row in values[1:]:
        padded = list(raw_row) + [""] * (width - len(raw_row))
        rebuilt_rows.append({header[idx]: str(padded[idx]) for idx in range(width)})

    os.makedirs(os.path.dirname(csv_path) or ".", exist_ok=True)
    save_csv_rows(csv_path, header, rebuilt_rows)
    return True, f"Đã nạp {len(rebuilt_rows)} dòng từ Google Sheet"


def atomic_write_json(file_path: str, data: Any) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(file_path)), exist_ok=True)
    tmp_path = f"{file_path}.tmp.{os.getpid()}.{int(time.time() * 1000)}"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2, sort_keys=True)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp_path, file_path)


def normalize_permission_data(data: Any) -> Dict[str, Dict[str, str]]:
    if not isinstance(data, dict):
        return {"get": {}, "delete": {}}
    return {
        "get": data.get("get", {}) if isinstance(data.get("get", {}), dict) else {},
        "delete": data.get("delete", {}) if isinstance(data.get("delete", {}), dict) else {},
    }


def merge_permission_data(base_data: Dict[str, Dict[str, str]], extra_data: Dict[str, Dict[str, str]]) -> Dict[str, Dict[str, str]]:
    merged = {
        "get": dict(base_data.get("get", {})),
        "delete": dict(base_data.get("delete", {})),
    }
    for action in ("get", "delete"):
        for key, value in extra_data.get(action, {}).items():
            key_str = str(key).strip()
            value_str = str(value).strip()
            if key_str and value_str and key_str not in merged[action]:
                merged[action][key_str] = value_str
    return merged


def load_permissions(permission_file: str) -> Dict[str, Dict[str, Dict[str, str]]]:
    default_data = {"get": {}, "delete": {}}
    app_dir = os.path.dirname(os.path.abspath(__file__))
    candidates: List[Tuple[str, bool]] = [
        (permission_file, True),
        (permission_file + ".bak", True),
    ]

    local_file = os.path.basename(permission_file)
    for extra_path in [
        os.path.join(app_dir, local_file),
        os.path.join(app_dir, local_file + ".bak"),
        local_file,
        local_file + ".bak",
    ]:
        if extra_path not in {path for path, _ in candidates}:
            candidates.append((extra_path, False))

    recovered = default_data
    recovered_from: List[str] = []
    for candidate_path, should_heal in candidates:
        if not os.path.exists(candidate_path):
            continue
        try:
            with open(candidate_path, "r", encoding="utf-8") as f:
                raw_data = json.load(f)
        except Exception:
            continue

        normalized = normalize_permission_data(raw_data)
        if not normalized.get("get") and not normalized.get("delete"):
            continue

        recovered = merge_permission_data(recovered, normalized)
        recovered_from.append(candidate_path)

        if should_heal and candidate_path != permission_file:
            print(f"[WARN] Khôi phục quyền OTP từ {candidate_path}", flush=True)

    if recovered_from and not os.path.exists(permission_file):
        save_permissions(permission_file, recovered)
    elif recovered_from and permission_file not in recovered_from:
        save_permissions(permission_file, recovered)

    return recovered


def save_permissions(permission_file: str, data: Dict[str, Dict[str, Dict[str, str]]]) -> None:
    backup_file = permission_file + ".bak"
    lock_path = permission_file + ".lock"
    os.makedirs(os.path.dirname(os.path.abspath(permission_file)), exist_ok=True)

    lock_handle = open(lock_path, "a")
    try:
        try:
            import fcntl

            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
        except Exception:
            pass

        if os.path.exists(permission_file):
            try:
                shutil.copyfile(permission_file, backup_file)
            except Exception:
                pass
        atomic_write_json(permission_file, data)
    finally:
        try:
            import fcntl

            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)
        except Exception:
            pass
        lock_handle.close()


def load_pending_qr_renames(pending_file: str) -> Dict[str, Dict[str, Any]]:
    if not os.path.exists(pending_file):
        return {}

    try:
        with open(pending_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save_pending_qr_renames(pending_file: str, data: Dict[str, Dict[str, Any]]) -> None:
    atomic_write_json(pending_file, data)


def load_processed_update_ids(processed_file: str) -> List[int]:
    if not os.path.exists(processed_file):
        return []
    try:
        with open(processed_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return []
        values = data.get("ids")
        if not isinstance(values, list):
            return []
        out: List[int] = []
        for item in values:
            try:
                out.append(int(item))
            except Exception:
                continue
        return out
    except Exception:
        return []


def save_processed_update_ids(processed_file: str, ids: List[int]) -> None:
    atomic_write_json(processed_file, {"ids": ids})


def is_update_already_processed(processed_file: str, update_id: int) -> bool:
    ids = load_processed_update_ids(processed_file)
    return int(update_id) in set(ids)


def mark_update_processed(processed_file: str, update_id: int, keep_last: int = 5000) -> None:
    ids = load_processed_update_ids(processed_file)
    ids.append(int(update_id))
    # Keep only newest IDs to bound file size.
    if len(ids) > keep_last:
        ids = ids[-keep_last:]
    save_processed_update_ids(processed_file, ids)


def check_and_mark_update_processed(processed_file: str, update_id: int, keep_last: int = 5000) -> bool:
    """
    Atomically checks if update_id was already processed.
    Returns True if already processed (should SKIP).
    Returns False if new (has been marked, should PROCESS).
    Uses fcntl.flock to prevent two simultaneous bot instances from both
    processing the same update (the main cause of duplicate messages).
    """
    try:
        import fcntl
        lock_path = processed_file + ".lock"
        os.makedirs(os.path.dirname(os.path.abspath(processed_file)), exist_ok=True)
        with open(lock_path, "a") as lf:
            fcntl.flock(lf.fileno(), fcntl.LOCK_EX)
            try:
                ids = load_processed_update_ids(processed_file)
                if int(update_id) in set(ids):
                    return True  # Already processed — skip
                ids.append(int(update_id))
                if len(ids) > keep_last:
                    ids = ids[-keep_last:]
                save_processed_update_ids(processed_file, ids)
                return False  # Newly marked — process
            finally:
                fcntl.flock(lf.fileno(), fcntl.LOCK_UN)
    except Exception as e:
        print(f"[WARN] flock không khả dụng: {e} — dùng check thường", flush=True)
        if is_update_already_processed(processed_file, update_id):
            return True
        mark_update_processed(processed_file, update_id, keep_last)
        return False


def acquire_singleton_lock(lock_file: str, retry_seconds: float = 2.0):
    """
    Ensure only one polling loop is active for a bot token.
    Uses a blocking non-busy loop so overlap instances wait instead of double-polling.
    """
    lock_path = (lock_file or "").strip()
    if not lock_path:
        return None

    try:
        import fcntl
    except Exception:
        print("[WARN] Không hỗ trợ fcntl, bỏ qua singleton lock", flush=True)
        return None

    os.makedirs(os.path.dirname(os.path.abspath(lock_path)), exist_ok=True)
    lf = open(lock_path, "a+")

    while True:
        try:
            fcntl.flock(lf.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            try:
                lf.seek(0)
                lf.truncate(0)
                lf.write(str(os.getpid()))
                lf.flush()
                os.fsync(lf.fileno())
            except Exception:
                pass
            print(f"🔒 Singleton lock acquired: {lock_path} (pid={os.getpid()})", flush=True)
            return lf
        except OSError as e:
            if e.errno in (errno.EACCES, errno.EAGAIN):
                print(f"⏳ Đang chờ lock listener: {lock_path}", flush=True)
                time.sleep(max(float(retry_seconds), 0.5))
                continue
            raise


def load_recent_message_keys(processed_file: str) -> Dict[str, int]:
    if not os.path.exists(processed_file):
        return {}
    try:
        with open(processed_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return {}
        out: Dict[str, int] = {}
        for k, v in data.items():
            try:
                out[str(k)] = int(v)
            except Exception:
                continue
        return out
    except Exception:
        return {}


def save_recent_message_keys(processed_file: str, keys: Dict[str, int]) -> None:
    atomic_write_json(processed_file, keys)


def is_recent_message_duplicate(processed_file: str, message_key: str, now_ts: int, ttl_seconds: int = 180) -> bool:
    keys = load_recent_message_keys(processed_file)
    last_ts = keys.get(message_key)
    if last_ts is None:
        return False
    return (now_ts - int(last_ts)) <= ttl_seconds


def mark_message_seen(processed_file: str, message_key: str, now_ts: int, keep_last: int = 5000) -> None:
    keys = load_recent_message_keys(processed_file)
    keys[message_key] = int(now_ts)

    # Cleanup old entries to keep this file bounded.
    entries = sorted(keys.items(), key=lambda kv: kv[1])
    if len(entries) > keep_last:
        entries = entries[-keep_last:]
    trimmed = {k: v for k, v in entries}
    save_recent_message_keys(processed_file, trimmed)


def is_recent_command_duplicate(processed_file: str, command_key: str, now_ts: int, ttl_seconds: int = 8) -> bool:
    keys = load_recent_message_keys(processed_file)
    last_ts = keys.get(command_key)
    if last_ts is None:
        return False
    return (now_ts - int(last_ts)) <= ttl_seconds


def mark_command_seen(processed_file: str, command_key: str, now_ts: int, keep_last: int = 5000) -> None:
    keys = load_recent_message_keys(processed_file)
    keys[command_key] = int(now_ts)
    entries = sorted(keys.items(), key=lambda kv: kv[1])
    if len(entries) > keep_last:
        entries = entries[-keep_last:]
    save_recent_message_keys(processed_file, {k: v for k, v in entries})


def check_and_mark_recent_command_key(
    processed_file: str,
    command_key: str,
    now_ts: int,
    ttl_seconds: int = 8,
    keep_last: int = 5000,
) -> bool:
    """
    Atomically checks whether a recent command key is still in cooldown.
    Returns True if key is still recent and should be skipped.
    Returns False if key was newly marked and caller may proceed.
    """
    try:
        import fcntl

        lock_path = processed_file + ".lock"
        os.makedirs(os.path.dirname(os.path.abspath(processed_file)), exist_ok=True)
        with open(lock_path, "a") as lf:
            fcntl.flock(lf.fileno(), fcntl.LOCK_EX)
            try:
                keys = load_recent_message_keys(processed_file)
                last_ts = keys.get(command_key)
                if last_ts is not None and (int(now_ts) - int(last_ts)) <= ttl_seconds:
                    return True

                keys[command_key] = int(now_ts)
                entries = sorted(keys.items(), key=lambda kv: kv[1])
                if len(entries) > keep_last:
                    entries = entries[-keep_last:]
                save_recent_message_keys(processed_file, {k: v for k, v in entries})
                return False
            finally:
                fcntl.flock(lf.fileno(), fcntl.LOCK_UN)
    except Exception as e:
        print(f"[WARN] recent-command flock lỗi: {e} — dùng check thường", flush=True)
        if is_recent_command_duplicate(processed_file, command_key, now_ts, ttl_seconds=ttl_seconds):
            return True
        mark_command_seen(processed_file, command_key, now_ts, keep_last)
        return False


def clear_recent_command_key(processed_file: str, command_key: str) -> None:
    keys = load_recent_message_keys(processed_file)
    if command_key not in keys:
        return
    del keys[command_key]
    save_recent_message_keys(processed_file, keys)


def _get_pending_pick_id(item: Dict[str, Any]) -> str:
    pick_id = str((item or {}).get("pick_index", "")).strip()
    if pick_id:
        return pick_id
    return str((item or {}).get("index", "")).strip()


def _get_next_pending_pick_id(pending: Dict[str, Any], chat_id: str) -> int:
    max_pick_id = 0
    prefix = f"{chat_id}:"
    for bucket_key, bucket in pending.items():
        if not str(bucket_key).startswith(prefix) or not isinstance(bucket, dict):
            continue
        items = bucket.get("items")
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            pick_id = _get_pending_pick_id(item)
            if pick_id.isdigit():
                max_pick_id = max(max_pick_id, int(pick_id))
    return max_pick_id + 1


def remember_qr_duplicate_names(
    pending_file: str,
    chat_id: str,
    user_id: str,
    duplicate_names: List[Dict[str, str]],
) -> int:
    pending = load_pending_qr_renames(pending_file)
    bucket_key = f"{chat_id}:{user_id}"
    items: List[Dict[str, str]] = []
    existing_bucket = pending.get(bucket_key)
    next_pick_id = _get_next_pending_pick_id(pending, chat_id)

    if isinstance(existing_bucket, dict):
        existing_items = existing_bucket.get("items")
        if isinstance(existing_items, list):
            for item in existing_items:
                if not isinstance(item, dict):
                    continue
                copied = dict(item)
                pick_id = _get_pending_pick_id(copied)
                if pick_id.isdigit():
                    copied["pick_index"] = pick_id
                else:
                    copied["pick_index"] = str(next_pick_id)
                    next_pick_id += 1
                items.append(copied)

    for rec in duplicate_names:
        idx = str(rec.get("index", "")).strip()
        account_cell = str(rec.get("account_cell", "")).strip()
        secret = str(rec.get("secret", "")).strip()
        if not (idx and account_cell and secret):
            continue
        items.append(
            {
                "index": idx,
                "pick_index": str(next_pick_id),
                "account_cell": account_cell,
                "secret": secret,
            }
        )
        next_pick_id += 1

    pending[bucket_key] = {
        "updated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "items": items,
        "awaiting_index": "",
    }
    save_pending_qr_renames(pending_file, pending)
    return len(items)


def set_pending_qr_awaiting_index(
    pending_file: str,
    chat_id: str,
    user_id: str,
    idx_raw: str,
) -> Tuple[bool, str]:
    pending = load_pending_qr_renames(pending_file)
    bucket_key = f"{chat_id}:{user_id}"
    bucket = pending.get(bucket_key) or {}
    items = bucket.get("items") if isinstance(bucket, dict) else None
    if not isinstance(items, list) or not items:
        return False, "Không có OTP trùng tên đang chờ đổi"

    picked_name = ""
    matched = False
    for item in items:
        if _get_pending_pick_id(item or {}) == idx_raw:
            picked_name = str((item or {}).get("account_cell", "")).strip()
            matched = True
            break

    if not matched:
        # Fallback: allow selecting duplicate item prepared by another admin in same chat.
        prefix = f"{chat_id}:"
        source_bucket = None
        source_items: List[Dict[str, str]] = []
        for candidate_bucket_key, candidate_bucket in pending.items():
            if not str(candidate_bucket_key).startswith(prefix) or not isinstance(candidate_bucket, dict):
                continue
            candidate_items = candidate_bucket.get("items")
            if not isinstance(candidate_items, list) or not candidate_items:
                continue
            for item in candidate_items:
                if _get_pending_pick_id(item or {}) == idx_raw:
                    source_bucket = candidate_bucket
                    source_items = [i for i in candidate_items if isinstance(i, dict)]
                    picked_name = str((item or {}).get("account_cell", "")).strip()
                    matched = True
                    break
            if matched:
                break

        if matched and source_bucket is not None:
            bucket = {
                "updated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "items": source_items,
                "awaiting_index": idx_raw,
            }
            pending[bucket_key] = bucket
            save_pending_qr_renames(pending_file, pending)
            return True, picked_name

    if not matched:
        return False, f"Không tìm thấy mã thứ {idx_raw}"

    bucket["awaiting_index"] = idx_raw
    bucket["updated_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    pending[bucket_key] = bucket
    save_pending_qr_renames(pending_file, pending)
    return True, picked_name


def clear_pending_qr_awaiting_index(
    pending_file: str,
    chat_id: str,
    user_id: str,
) -> None:
    pending = load_pending_qr_renames(pending_file)
    bucket_key = f"{chat_id}:{user_id}"
    bucket = pending.get(bucket_key)
    if not isinstance(bucket, dict):
        return
    bucket["awaiting_index"] = ""
    bucket["updated_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    pending[bucket_key] = bucket
    save_pending_qr_renames(pending_file, pending)


def get_pending_qr_awaiting_item(
    pending_file: str,
    chat_id: str,
    user_id: str,
) -> Optional[Dict[str, str]]:
    pending = load_pending_qr_renames(pending_file)
    bucket_key = f"{chat_id}:{user_id}"
    bucket = pending.get(bucket_key)
    if not isinstance(bucket, dict):
        return None

    awaiting_index = str(bucket.get("awaiting_index", "")).strip()
    if not awaiting_index:
        return None

    items = bucket.get("items")
    if not isinstance(items, list):
        return None

    for item in items:
        idx = _get_pending_pick_id(item or {})
        if idx == awaiting_index:
            return {
                "index": idx,
                "account_cell": str((item or {}).get("account_cell", "")).strip(),
            }
    return None


def get_pending_qr_duplicates_for_user_or_chat(
    pending_file: str,
    chat_id: str,
    user_id: str,
) -> List[Dict[str, str]]:
    pending = load_pending_qr_renames(pending_file)
    preferred_key = f"{chat_id}:{user_id}"
    prefix = f"{chat_id}:"
    all_items: List[Dict[str, str]] = []

    preferred_bucket = pending.get(preferred_key)
    if isinstance(preferred_bucket, dict):
        preferred_items = preferred_bucket.get("items")
        if isinstance(preferred_items, list):
            all_items.extend(item for item in preferred_items if isinstance(item, dict))

    for bucket_key, bucket in pending.items():
        if str(bucket_key) == preferred_key:
            continue
        if not str(bucket_key).startswith(prefix) or not isinstance(bucket, dict):
            continue
        items = bucket.get("items")
        if isinstance(items, list):
            all_items.extend(item for item in items if isinstance(item, dict))

    all_items.sort(
        key=lambda item: int(_get_pending_pick_id(item)) if _get_pending_pick_id(item).isdigit() else 10**9
    )
    return all_items


def build_pending_qr_duplicate_message(duplicate_names: List[Dict[str, str]]) -> str:
    if not duplicate_names:
        return "📭 Không có OTP trùng tên đang chờ đổi"

    lines: List[str] = []
    lines.append("🛠 Danh sách OTP trùng tên đang chờ đổi")
    lines.append(f"- Tổng: {len(duplicate_names)}")
    lines.append("- Bấm nút để chọn OTP cần đổi tên")
    lines.append("- Sau đó gửi trực tiếp tên mới vào nhóm")
    lines.append("")
    lines.append("Danh sách:")
    for rec in duplicate_names[:30]:
        idx = _get_pending_pick_id(rec)
        account_cell = str(rec.get("account_cell", "")).strip()
        if not idx:
            continue
        lines.append(f"- Mã thứ {idx}: {account_cell or '(không có tên)'}")
    return "\n".join(lines)


def process_rename_qr_duplicate(
    text: str,
    csv_path: str,
    pending_file: str,
    chat_id: str,
    user_id: str,
) -> Tuple[str, bool]:
    payload = text[len("/renqr") :].strip()
    if not payload:
        return "❌ Dùng: /renqr stt|ten_moi", False

    if "|" in payload:
        idx_raw, new_name = [p.strip() for p in payload.split("|", 1)]
    else:
        parts = payload.split(maxsplit=1)
        if len(parts) < 2:
            return "❌ Dùng: /renqr stt|ten_moi", False
        idx_raw, new_name = parts[0].strip(), parts[1].strip()

    if not idx_raw.isdigit() or not new_name:
        return "❌ Dùng: /renqr stt|ten_moi", False

    pending = load_pending_qr_renames(pending_file)
    bucket_key = f"{chat_id}:{user_id}"
    bucket = pending.get(bucket_key) or {}
    items = bucket.get("items") if isinstance(bucket, dict) else None
    if not isinstance(items, list) or not items:
        return "❌ Không có OTP trùng tên đang chờ đổi. Gửi QR lại rồi thử /renqr", False

    target = None
    source_bucket_key = bucket_key
    remain: List[Dict[str, str]] = []
    for item in items:
        item_idx = _get_pending_pick_id(item or {})
        if item_idx == idx_raw and target is None:
            target = item
        else:
            remain.append(item)

    if not target:
        # Fallback: cho phép admin khác trong cùng chat tiếp tục xử lý danh sách trùng tên.
        prefix = f"{chat_id}:"
        for candidate_bucket_key, candidate_bucket in pending.items():
            if not str(candidate_bucket_key).startswith(prefix) or not isinstance(candidate_bucket, dict):
                continue
            candidate_items = candidate_bucket.get("items")
            if not isinstance(candidate_items, list) or not candidate_items:
                continue

            candidate_target = None
            candidate_remain: List[Dict[str, str]] = []
            for item in candidate_items:
                item_idx = _get_pending_pick_id(item or {})
                if item_idx == idx_raw and candidate_target is None:
                    candidate_target = item
                else:
                    candidate_remain.append(item)

            if candidate_target is not None:
                target = candidate_target
                remain = candidate_remain
                source_bucket_key = str(candidate_bucket_key)
                break

    if not target:
        return f"❌ Không tìm thấy mã thứ {idx_raw} trong danh sách trùng tên đang chờ đổi", False

    new_name_lower = new_name.lower()
    existing_names = load_existing_account_names(csv_path)
    if new_name_lower in existing_names:
        return f"❌ Tên mới đã tồn tại: {new_name}", False

    secret = str(target.get("secret", "")).strip()
    new_key = stable_key(new_name, "", secret)
    existing_keys = load_existing_keys(csv_path)
    if new_key in existing_keys:
        return "❌ Secret này đã tồn tại với tên khác, không thể thêm trùng", False

    append_rows(
        csv_path,
        [
            {
                "account": new_name,
                "issuer": "",
                "secret": secret,
                "key": new_key,
            }
        ],
    )

    if remain:
        pending[source_bucket_key] = {
            "updated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "items": remain,
            "awaiting_index": "",
        }
    else:
        pending.pop(source_bucket_key, None)
    save_pending_qr_renames(pending_file, pending)

    lines = [
        "✅ Đã lưu OTP trùng tên sau khi đổi",
        f"- Mã thứ: {idx_raw}",
        f"- Tên cũ: {target.get('account_cell', '')}",
        f"- Tên mới: {new_name}",
        f"- Còn chờ đổi: {len(remain)}",
    ]
    if remain:
        lines.append("Tiếp tục dùng: /renqr stt|ten_moi")
    return "\n".join(lines), True


def parse_qr_records(text: str) -> Tuple[List[Dict[str, str]], List[str]]:
    lines = [line.rstrip() for line in text.splitlines()]
    if not lines:
        return [], ["Không có nội dung lệnh"]

    first = lines[0].strip()
    if not first.startswith("/qr"):
        return [], ["Không phải lệnh /qr"]

    body_lines: List[str] = []
    first_payload = first[len("/qr") :].strip()
    if first_payload:
        body_lines.append(first_payload)
    body_lines.extend(line.strip() for line in lines[1:] if line.strip())

    if not body_lines:
        return [], ["Thiếu dữ liệu. Dùng: /qr account secret"]

    records: List[Dict[str, str]] = []
    errors: List[str] = []
    for idx, raw in enumerate(body_lines, 1):
        parts = raw.split()
        if len(parts) < 2:
            errors.append(f"Dòng {idx} sai định dạng: {raw}")
            continue
        secret = parts[-1].strip()
        account = " ".join(parts[:-1]).strip()
        if not account or not secret:
            errors.append(f"Dòng {idx} thiếu account/secret")
            continue

        secret_bytes = b32decode_no_padding(secret)
        if not secret_bytes:
            errors.append(f"Dòng {idx} secret không hợp lệ: {account}")
            continue

        records.append(
            {
                "account": account,
                "secret": secret.replace("=", "").replace(" ", "").upper(),
            }
        )

    return records, errors


def build_qr_migration_uri(records: List[Dict[str, str]]) -> str:
    import otp_pb2

    payload = otp_pb2.MigrationPayload()
    payload.version = 1
    payload.batch_size = len(records)
    payload.batch_index = 0
    payload.batch_id = random.randint(100000, 999999)

    for rec in records:
        otp = payload.otp_parameters.add()
        otp.secret = b32decode_no_padding(rec.get("secret", "")) or b""
        otp.name = rec.get("account", "")
        otp.issuer = ""
        otp.algorithm = otp_pb2.MigrationPayload.SHA1
        otp.digits = otp_pb2.MigrationPayload.SIX
        otp.type = otp_pb2.MigrationPayload.TOTP

    raw = payload.SerializeToString()
    encoded = base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")
    return f"otpauth-migration://offline?data={encoded}"


def create_qr_png_from_text(content: str) -> str:
    try:
        import qrcode
    except Exception:
        raise RuntimeError("Thiếu thư viện qrcode. Cài: pip install qrcode[pil]")

    qr = qrcode.QRCode(version=None, box_size=10, border=2)
    qr.add_data(content)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")

    tmp_file = tempfile.NamedTemporaryFile(prefix="otp_migration_", suffix=".png", delete=False)
    tmp_path = tmp_file.name
    tmp_file.close()
    img.save(tmp_path)
    return tmp_path


def process_qr_command(text: str) -> Tuple[str, bool, Optional[str]]:
    records, errors = parse_qr_records(text)
    if errors and not records:
        return "❌ Lỗi lệnh /qr:\n- " + "\n- ".join(errors), False, None

    if not records:
        return "❌ Không có bản ghi hợp lệ để tạo QR", False, None

    try:
        uri = build_qr_migration_uri(records)
        qr_path = create_qr_png_from_text(uri)
    except Exception as e:
        return f"❌ Không tạo được QR: {e}", False, None

    lines: List[str] = []
    lines.append("✅ Đã tạo QR migration")
    lines.append(f"📦 Số OTP trong QR: {len(records)}")
    if errors:
        lines.append(f"⚠️ Bỏ qua dòng lỗi: {len(errors)}")
    lines.append("Mở Google Authenticator để quét QR này.")
    return "\n".join(lines), True, qr_path


def normalize_permission_target(raw_target: str) -> Tuple[str, str]:
    target = (raw_target or "").strip()
    if not target:
        return "", ""
    if target.startswith("@"):
        username = target[1:].strip().lower()
        return (f"username:{username}", f"@{username}") if username else ("", "")
    if target.isdigit():
        return f"id:{target}", target
    return "", ""


def make_user_targets(user: Dict) -> List[str]:
    targets: List[str] = []
    user_id = str(user.get("id", "")).strip()
    username = str(user.get("username", "")).strip().lower()
    if user_id:
        targets.append(f"id:{user_id}")
    if username:
        targets.append(f"username:{username}")
    return targets


def user_has_permission(permission_data: Dict[str, Dict[str, str]], action: str, user: Dict) -> bool:
    allowed = permission_data.get(action, {})
    return any(target in allowed for target in make_user_targets(user))


def describe_user(user: Dict) -> str:
    username = str(user.get("username", "")).strip()
    user_id = str(user.get("id", "")).strip()
    if username:
        return f"@{username} ({user_id})" if user_id else f"@{username}"
    first_name = str(user.get("first_name", "")).strip()
    if first_name and user_id:
        return f"{first_name} ({user_id})"
    return user_id or "unknown"


def append_rows(csv_path: str, rows: List[Dict[str, str]]) -> None:
    file_exists = os.path.exists(csv_path)
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(csv_path, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(["Account", "Secret", "FirstSeen", "Key"])

        for row in rows:
            writer.writerow(
                [
                    build_account_cell(row.get("account", ""), row.get("issuer", "")),
                    row.get("secret", ""),
                    now_str,
                    row.get("key", ""),
                ]
            )


def parse_addotp_records(text: str) -> Tuple[List[Dict[str, str]], List[str]]:
    """Parse /addotp command payload into records."""
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        return [], ["Không có nội dung lệnh"]

    first = lines[0]
    command_payload = ""
    if first.startswith("/addotp"):
        command_payload = first[len("/addotp") :].strip()
        lines = lines[1:]
    else:
        return [], ["Không phải lệnh /addotp"]

    record_lines: List[str] = []
    if command_payload:
        record_lines.append(command_payload)
    record_lines.extend(lines)

    if not record_lines:
        return [], ["Thiếu dữ liệu OTP. Dùng: /addotp account secret"]

    records: List[Dict[str, str]] = []
    errors: List[str] = []

    for idx, raw_line in enumerate(record_lines, 1):
        if "|" in raw_line:
            parts = [p.strip() for p in raw_line.split("|")]
            if len(parts) == 2:
                account, secret = parts
                issuer = ""
            elif len(parts) == 3:
                account, issuer, secret = parts
            else:
                errors.append(f"Dòng {idx} sai định dạng: {raw_line}")
                continue
        else:
            parts = raw_line.split()
            if len(parts) == 2:
                account, secret = parts
                issuer = ""
            else:
                errors.append(f"Dòng {idx} sai định dạng: {raw_line}")
                continue

        if not account:
            errors.append(f"Dòng {idx} thiếu account")
            continue
        if not secret:
            errors.append(f"Dòng {idx} thiếu secret")
            continue

        secret_clean = secret.replace("=", "").replace(" ", "").upper()
        key = stable_key(account, issuer, secret_clean)
        records.append(
            {
                "index": str(idx),
                "account": account,
                "issuer": issuer,
                "secret": secret_clean,
                "key": key,
            }
        )

    return records, errors


def parse_otpauth_uri(qr_data: str) -> Optional[Dict[str, str]]:
    uri = (qr_data or "").strip()
    if not uri.lower().startswith("otpauth://"):
        return None

    parsed = urllib.parse.urlparse(uri)
    otp_type = (parsed.netloc or "").strip().lower()
    if otp_type not in {"totp", "hotp"}:
        return None

    label = urllib.parse.unquote((parsed.path or "").lstrip("/")).strip()
    qs = urllib.parse.parse_qs(parsed.query or "", keep_blank_values=False)

    secret = (qs.get("secret", [""])[0] or "").strip().replace(" ", "").replace("-", "").upper()
    if not secret:
        return None

    issuer_q = (qs.get("issuer", [""])[0] or "").strip()
    issuer_from_label = ""
    account = label
    if ":" in label:
        issuer_from_label, account = [p.strip() for p in label.split(":", 1)]
    issuer = issuer_q or issuer_from_label
    account = account.strip() or label or "OTP"

    key = stable_key(account, issuer, secret)
    return {
        "account": account,
        "issuer": issuer,
        "secret": secret,
        "key": key,
    }


def extract_otps_from_qr_image(image_path: str) -> List[Dict[str, str]]:
    cv2, decode, otp_pb2 = load_otp_modules()

    img = cv2.imread(image_path)
    if img is None:
        return []

    qr_texts: List[str] = []
    seen_qr_texts: Set[str] = set()

    def _collect_qr_text(raw_text: str) -> None:
        text_norm = (raw_text or "").strip()
        if not text_norm:
            return
        if text_norm in seen_qr_texts:
            return
        seen_qr_texts.add(text_norm)
        qr_texts.append(text_norm)

    # First pass with pyzbar on several image variants.
    variants = [img]
    try:
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        variants.append(gray)
        variants.append(cv2.GaussianBlur(gray, (3, 3), 0))
        variants.append(cv2.adaptiveThreshold(gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 31, 2))
        h, w = gray.shape[:2]
        if h > 0 and w > 0:
            variants.append(cv2.resize(gray, (w * 2, h * 2), interpolation=cv2.INTER_CUBIC))
    except Exception:
        pass

    for variant in variants:
        try:
            decoded_objs = decode(variant)
        except Exception:
            decoded_objs = []
        for obj in decoded_objs:
            try:
                _collect_qr_text(obj.data.decode("utf-8", errors="replace"))
            except Exception:
                continue

    # Second pass with OpenCV detector as fallback.
    try:
        detector = cv2.QRCodeDetector()
        ok_multi, decoded_multi, _, _ = detector.detectAndDecodeMulti(img)
        if ok_multi and decoded_multi:
            for item in decoded_multi:
                _collect_qr_text(item)
        else:
            decoded_single, _, _ = detector.detectAndDecode(img)
            _collect_qr_text(decoded_single)
    except Exception:
        pass

    if not qr_texts:
        return []

    otp_list: List[Dict[str, str]] = []
    seen: Set[str] = set()

    for qr_data in qr_texts:
        if "otpauth-migration://" not in qr_data or "data=" not in qr_data:
            parsed_plain = parse_otpauth_uri(qr_data)
            if parsed_plain and parsed_plain["key"] not in seen:
                seen.add(parsed_plain["key"])
                otp_list.append(parsed_plain)
            continue

        try:
            data = qr_data.split("data=", 1)[1]
            data = urllib.parse.unquote(data)
            raw = b64decode_urlsafe_padded(data)

            payload = otp_pb2.MigrationPayload()
            payload.ParseFromString(raw)

            for otp in payload.otp_parameters:
                secret_b32 = base64.b32encode(otp.secret).decode("utf-8").replace("=", "")
                account = otp.name or ""
                issuer = otp.issuer or ""
                key = stable_key(account, issuer, secret_b32)
                if key in seen:
                    continue
                seen.add(key)
                otp_list.append(
                    {
                        "account": account,
                        "issuer": issuer,
                        "secret": secret_b32,
                        "key": key,
                    }
                )
        except Exception:
            continue

    return otp_list


def _urlopen_with_ssl_fallback(req: urllib.request.Request, timeout: int = 30) -> str:
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except Exception as e:
        if "CERTIFICATE_VERIFY_FAILED" in str(e):
            insecure_ctx = ssl._create_unverified_context()
            with urllib.request.urlopen(req, timeout=timeout, context=insecure_ctx) as resp:
                return resp.read().decode("utf-8", errors="replace")
        raise


class TelegramAPIError(Exception):
    def __init__(self, method: str, status_code: int, description: str):
        self.method = method
        self.status_code = int(status_code)
        self.description = (description or "").strip()
        super().__init__(f"Telegram API {method} failed ({self.status_code}): {self.description}")


def telegram_api(bot_token: str, method: str, payload: Dict[str, str]) -> Dict:
    url = f"https://api.telegram.org/bot{bot_token}/{method}"
    data = urllib.parse.urlencode(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        raw = _urlopen_with_ssl_fallback(req, timeout=40)
        parsed = json.loads(raw)
        if not parsed.get("ok", False):
            desc = str(parsed.get("description", "Telegram API error"))
            code = int(parsed.get("error_code", 400))
            raise TelegramAPIError(method, code, desc)
        return parsed
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read().decode("utf-8", errors="replace")
        except Exception:
            body = ""

        desc = body.strip() or str(e)
        try:
            parsed = json.loads(body)
            desc = str(parsed.get("description", desc))
        except Exception:
            pass
        raise TelegramAPIError(method, int(getattr(e, "code", 0) or 0), desc)


def delete_webhook(bot_token: str, drop_pending_updates: bool = False) -> Tuple[bool, str]:
    try:
        resp = telegram_api(
            bot_token,
            "deleteWebhook",
            {"drop_pending_updates": "true" if drop_pending_updates else "false"},
        )
        return True, str(resp.get("description", "OK"))
    except Exception as e:
        return False, str(e)


def get_chat_administrators(bot_token: str, chat_id: str) -> List[Dict]:
    resp = telegram_api(bot_token, "getChatAdministrators", {"chat_id": chat_id})
    if not resp.get("ok"):
        return []
    return resp.get("result", [])


def is_chat_admin(bot_token: str, chat_id: str, user_id: str) -> bool:
    for item in get_chat_administrators(bot_token, chat_id):
        admin_user = item.get("user") or {}
        if str(admin_user.get("id", "")) == str(user_id):
            return True
    return False


def get_chat_member(bot_token: str, chat_id: str, user_id: str) -> Optional[Dict]:
    resp = telegram_api(bot_token, "getChatMember", {"chat_id": chat_id, "user_id": user_id})
    if not resp.get("ok"):
        return None
    return resp.get("result") or None


def telegram_get_file_path(bot_token: str, file_id: str) -> Optional[str]:
    resp = telegram_api(bot_token, "getFile", {"file_id": file_id})
    if not resp.get("ok"):
        return None
    result = resp.get("result") or {}
    return result.get("file_path")


def download_telegram_file(bot_token: str, file_path: str, save_path: str) -> bool:
    url = f"https://api.telegram.org/file/bot{bot_token}/{file_path}"
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=40) as resp:
            data = resp.read()
    except Exception as e:
        if "CERTIFICATE_VERIFY_FAILED" not in str(e):
            return False
        insecure_ctx = ssl._create_unverified_context()
        with urllib.request.urlopen(req, timeout=40, context=insecure_ctx) as resp:
            data = resp.read()

    with open(save_path, "wb") as f:
        f.write(data)
    return os.path.getsize(save_path) > 0


def send_message(
    bot_token: str,
    chat_id: str,
    text: str,
    reply_markup: Optional[Dict] = None,
) -> bool:
    # Outbound dedupe removed: upstream layers (atomic update-level + message-level +
    # command-level) already prevent duplicate processing.  Content-based outbound
    # dedupe was causing legitimate responses from different users to be silently dropped.
    payload = {"chat_id": chat_id, "text": text}
    if reply_markup:
        payload["reply_markup"] = json.dumps(reply_markup, ensure_ascii=False)
    try:
        resp = telegram_api(bot_token, "sendMessage", payload)
        return bool(resp.get("ok"))
    except Exception as e:
        print(f"[WARN] sendMessage lỗi: {e}", flush=True)
        return False


def edit_message_text(
    bot_token: str,
    chat_id: str,
    message_id: str,
    text: str,
    reply_markup: Optional[Dict] = None,
) -> bool:
    payload = {
        "chat_id": chat_id,
        "message_id": message_id,
        "text": text,
    }
    if reply_markup:
        payload["reply_markup"] = json.dumps(reply_markup, ensure_ascii=False)
    try:
        resp = telegram_api(bot_token, "editMessageText", payload)
        return bool(resp.get("ok"))
    except Exception as e:
        print(f"[WARN] editMessageText lỗi: {e}", flush=True)
        return False


def answer_callback_query(
    bot_token: str,
    callback_query_id: str,
    text: str = "",
    show_alert: bool = False,
) -> bool:
    payload = {"callback_query_id": callback_query_id}
    if text:
        payload["text"] = text
    if show_alert:
        payload["show_alert"] = "true"
    try:
        resp = telegram_api(bot_token, "answerCallbackQuery", payload)
        return bool(resp.get("ok"))
    except Exception as e:
        print(f"[WARN] answerCallbackQuery lỗi: {e}", flush=True)
        return False


def send_document(bot_token: str, chat_id: str, file_path: str, caption: str) -> bool:
    if not os.path.exists(file_path):
        return False
    filename = os.path.basename(file_path) or "otp_wps.csv"

    url = f"https://api.telegram.org/bot{bot_token}/sendDocument"
    boundary = "----otplistener" + "".join(random.choice(string.ascii_letters) for _ in range(16))

    with open(file_path, "rb") as f:
        file_data = f.read()

    parts: List[bytes] = []

    def add_text_part(name: str, value: str) -> None:
        parts.append(f"--{boundary}\r\n".encode("utf-8"))
        parts.append(f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode("utf-8"))
        parts.append(value.encode("utf-8"))
        parts.append(b"\r\n")

    add_text_part("chat_id", chat_id)
    add_text_part("caption", caption)

    parts.append(f"--{boundary}\r\n".encode("utf-8"))
    parts.append(
        f'Content-Disposition: form-data; name="document"; filename="{filename}"\r\n'.encode("utf-8")
    )
    parts.append(b"Content-Type: text/csv\r\n\r\n")
    parts.append(file_data)
    parts.append(b"\r\n")
    parts.append(f"--{boundary}--\r\n".encode("utf-8"))

    body = b"".join(parts)
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", f"multipart/form-data; boundary={boundary}")

    try:
        raw = _urlopen_with_ssl_fallback(req, timeout=40)
        parsed = json.loads(raw)
        return bool(parsed.get("ok"))
    except Exception:
        return False


def get_updates(bot_token: str, offset: int, timeout_seconds: int) -> List[Dict]:
    payload = {
        "timeout": str(timeout_seconds),
        "offset": str(offset),
        "allowed_updates": json.dumps(["message", "callback_query"]),
    }
    resp = telegram_api(bot_token, "getUpdates", payload)
    if not resp.get("ok"):
        return []
    return resp.get("result", [])


def load_offset(offset_file: str) -> int:
    if not os.path.exists(offset_file):
        return 0
    try:
        with open(offset_file, "r", encoding="utf-8") as f:
            return int(f.read().strip() or "0")
    except Exception:
        return 0


def save_offset(offset_file: str, offset: int) -> None:
    with open(offset_file, "w", encoding="utf-8") as f:
        f.write(str(offset))


def build_help() -> str:
    return (
        "📘 Nhóm admin:\n"
        "- /help: gửi các lệnh\n"
        "- /addotp account secret: thêm bằng secret\n"
        "- /addotp rồi xuống dòng nhiều record: account secret\n"
        "- /c ten_cu ten_moi: đổi tên account\n"
        "- /delotp keyword: xoá otp\n"
        "- /qr account secret: tạo QR từ OTP\n"
        "- /qr nhiều dòng account secret: tạo 1 QR chứa nhiều OTP\n"
        "- /bd @username_or_userid: liên kết tài khoản lấy otp\n"
        "- bdls: hiện danh sách liên kết lấy otp (tên + id)\n"
        "- /delacc @username_or_userid: xoá tài khoản lấy otp\n"
        "- ls hoặc /ls: gửi file OTP mới nhất\n"
        "- Gửi ảnh QR migration: tự đọc OTP và thêm vào file\n\n"
        "- /renqr stt|ten_moi: lưu OTP đang trùng tên sau khi đổi tên\n\n"
        "- /cf: hiện lại danh sách OTP trùng tên đang chờ đổi (kèm nút chọn)\n\n"
        "📘 Nhóm nhân viên:\n"
        "- /myid\n"
        "- /getotp keyword\n"
        "- Hoặc gửi thẳng tên OTP"
    )


def process_addotp(text: str, csv_path: str) -> Tuple[str, bool]:
    records, errors = parse_addotp_records(text)
    if errors and not records:
        return "❌ Lỗi lệnh:\n- " + "\n- ".join(errors), False

    existing_keys = load_existing_keys(csv_path)
    existing_names = load_existing_account_names(csv_path)
    new_rows: List[Dict[str, str]] = []
    duplicates: List[Dict[str, str]] = []
    duplicate_names: List[Dict[str, str]] = []

    for rec in records:
        account_cell = build_account_cell(rec.get("account", ""), rec.get("issuer", "")).strip()
        account_key = account_cell.lower()
        if rec["key"] in existing_keys:
            duplicates.append(rec)
            continue
        if account_key in existing_names:
            rec["account_cell"] = account_cell
            duplicate_names.append(rec)
        else:
            new_rows.append(rec)
            existing_keys.add(rec["key"])
            if account_key:
                existing_names.add(account_key)

    if new_rows:
        append_rows(csv_path, new_rows)

    lines: List[str] = []
    lines.append("📡 Kết quả thêm OTP từ Telegram")
    lines.append(f"✅ Thêm mới: {len(new_rows)}")
    lines.append(f"♻️ Trùng: {len(duplicates)}")
    lines.append(f"🚫 Trùng tên: {len(duplicate_names)}")

    if errors:
        lines.append(f"⚠️ Dòng lỗi định dạng: {len(errors)}")

    if new_rows:
        lines.append("")
        lines.append("✅ OTP đã thêm:")
        for rec in new_rows[:20]:
            name = rec.get("account", "")
            issuer = rec.get("issuer", "")
            idx = rec.get("index", "?")
            lines.append(f"- Dòng {idx}: {name}" + (f" ({issuer})" if issuer else ""))

    if duplicates:
        lines.append("")
        lines.append("♻️ OTP đã tồn tại:")
        for rec in duplicates[:20]:
            name = rec.get("account", "")
            issuer = rec.get("issuer", "")
            idx = rec.get("index", "?")
            lines.append(f"- Dòng {idx}: {name}" + (f" ({issuer})" if issuer else ""))

    if duplicate_names:
        lines.append("")
        lines.append("🚫 Tên OTP đã tồn tại, vui lòng đổi tên rồi thêm lại:")
        for rec in duplicate_names[:20]:
            idx = rec.get("index", "?")
            account_cell = rec.get("account_cell", "")
            lines.append(f"- Dòng {idx}: {account_cell}")

    if errors:
        lines.append("")
        lines.append("⚠️ Dòng lỗi:")
        for err in errors[:20]:
            lines.append(f"- {err}")

    return "\n".join(lines), True


def process_delotp(text: str, csv_path: str) -> Tuple[str, bool]:
    query = text[len("/delotp") :].strip()
    if not query:
        return "❌ Thiếu từ khoá xoá. Dùng: /delotp keyword", False

    fieldnames, rows = load_csv_rows(csv_path)
    if not fieldnames:
        return "❌ Không tìm thấy file OTP để xoá", False

    query_lower = query.lower()
    kept_rows: List[Dict[str, str]] = []
    deleted_rows: List[Dict[str, str]] = []

    for row in rows:
        account = (row.get("Account") or "").strip()
        secret = (row.get("Secret") or "").strip()
        key = (row.get("Key") or "").strip()

        matched = (
            query_lower in account.lower()
            or query_lower == secret.lower()
            or query_lower == key.lower()
        )

        if matched:
            deleted_rows.append(row)
        else:
            kept_rows.append(row)

    if not deleted_rows:
        return f"❌ Không tìm thấy OTP nào khớp: {query}", False

    save_csv_rows(csv_path, fieldnames, kept_rows)

    lines: List[str] = []
    lines.append("🗑️ Kết quả xoá OTP từ Telegram")
    lines.append(f"🔎 Từ khoá: {query}")
    lines.append(f"✅ Đã xoá: {len(deleted_rows)}")
    lines.append(f"📦 Còn lại: {len(kept_rows)}")
    lines.append("")
    lines.append("🗑️ OTP đã xoá:")
    for row in deleted_rows[:20]:
        lines.append(f"- {(row.get('Account') or '').strip()}")

    if len(deleted_rows) > 20:
        lines.append(f"- ... và thêm {len(deleted_rows) - 20} dòng")

    return "\n".join(lines), True


def process_change_account_name(text: str, csv_path: str) -> Tuple[str, bool]:
    payload = text[len("/c") :].strip()
    if not payload:
        return "❌ Dùng: /c ten_cu ten_moi", False

    if "|" in payload:
        old_name, new_name = [p.strip() for p in payload.split("|", 1)]
    else:
        parts = payload.split(maxsplit=1)
        if len(parts) < 2:
            return "❌ Dùng: /c ten_cu ten_moi", False
        old_name, new_name = parts[0].strip(), parts[1].strip()

    if not old_name or not new_name:
        return "❌ Dùng: /c ten_cu ten_moi", False
    if old_name.lower() == new_name.lower():
        return "❌ Tên mới phải khác tên cũ", False

    fieldnames, rows = load_csv_rows(csv_path)
    if not fieldnames:
        return "❌ Không tìm thấy file OTP để đổi tên", False

    new_name_lower = new_name.lower()
    if any((row.get("Account") or "").strip().lower() == new_name_lower for row in rows):
        return f"❌ Tên mới đã tồn tại: {new_name}", False

    changed = 0
    old_name_lower = old_name.lower()
    for row in rows:
        account_name = (row.get("Account") or "").strip()
        if account_name.lower() == old_name_lower:
            row["Account"] = new_name
            secret = (row.get("Secret") or "").strip()
            row["Key"] = stable_key(new_name, "", secret)
            changed += 1

    if not changed:
        return f"❌ Không tìm thấy account: {old_name}", False

    save_csv_rows(csv_path, fieldnames, rows)
    return f"✅ Đã đổi tên {changed} dòng:\n{old_name} -> {new_name}", True


def process_getotp_query(query: str, csv_path: str) -> Tuple[str, bool]:
    query = (query or "").strip()
    if not query:
        return "❌ Thiếu từ khoá tìm OTP. Dùng: /getotp keyword hoặc gửi thẳng tên OTP", False

    _, rows = load_csv_rows(csv_path)
    if not rows:
        return "❌ Chưa có dữ liệu OTP", False

    query_lower = query.lower()
    # Multi-token search: split query by whitespace, require ALL tokens present in account name.
    # E.g. "91 a" matches "91club abc", "91club abcd" because both "91" and "a" are substrings.
    tokens = query_lower.split()
    matched_rows = [
        row for row in rows
        if all(token in (row.get("Account") or "").lower() for token in tokens)
    ]

    if not matched_rows:
        return f"❌ Không tìm thấy OTP nào khớp: {query}", False

    exact_rows = [row for row in matched_rows if (row.get("Account") or "").strip().lower() == query_lower]
    if exact_rows:
        matched_rows = exact_rows

    unique_account_names: List[str] = []
    seen_accounts: Set[str] = set()
    for row in matched_rows:
        account_name = (row.get("Account") or "").strip()
        if account_name and account_name not in seen_accounts:
            seen_accounts.add(account_name)
            unique_account_names.append(account_name)

    if len(unique_account_names) == 1:
        matched_rows = [matched_rows[-1]]

    if len(matched_rows) > 1:
        lines: List[str] = []
        lines.append("📋 Danh sách OTP khớp")
        lines.append(f"🔎 Từ khoá: {query}")
        lines.append(f"✅ Tìm thấy: {len(unique_account_names)} tên")
        lines.append("")
        for account_name in unique_account_names[:30]:
            lines.append(f"- {account_name}")
        if len(unique_account_names) > 30:
            lines.append(f"- ... và thêm {len(unique_account_names) - 30} tên")
        lines.append("")
        lines.append("Gửi lại đúng tên OTP để lấy mã 6 số.")
        return "\n".join(lines).strip(), True

    lines: List[str] = []
    lines.append("🔐 Kết quả lấy OTP")
    lines.append(f"🔎 Từ khoá: {query}")
    lines.append(f"✅ Tìm thấy: {len(matched_rows)}")
    lines.append("")

    for row in matched_rows[:20]:
        code, remaining = generate_totp_code((row.get("Secret") or "").strip())
        lines.append(f"Account: {(row.get('Account') or '').strip()}")
        if code:
            lines.append(f"Code: {code}")
            lines.append(f"Hết hạn sau: {remaining}s")
        else:
            lines.append("Code: ❌ Secret không hợp lệ")
        lines.append("")

    if len(matched_rows) > 20:
        lines.append(f"... và thêm {len(matched_rows) - 20} kết quả")

    return "\n".join(lines).strip(), True


def process_getotp(text: str, csv_path: str) -> Tuple[str, bool]:
    query = text[len("/getotp") :].strip()
    return process_getotp_query(query, csv_path)


def extract_code_from_getotp_result(message_text: str) -> str:
    prefix = "Code:"
    for line in (message_text or "").splitlines():
        line_strip = line.strip()
        if line_strip.startswith(prefix):
            return line_strip[len(prefix) :].strip()
    return ""


def build_getotp_buttons(message_text: str) -> Optional[Dict]:
    code = extract_code_from_getotp_result(message_text)
    if not (code and code.isdigit()):
        return None

    keyboard = [[{"text": "🔄 Làm mới", "callback_data": "refreshotp"}]]
    if code and code.isdigit():
        keyboard.append([{"text": f"📋 Copy {code}", "copy_text": {"text": code}}])
    return {"inline_keyboard": keyboard}


def extract_account_choices_from_list_result(message_text: str) -> List[str]:
    choices: List[str] = []
    for line in (message_text or "").splitlines():
        line_strip = line.strip()
        if not line_strip.startswith("- "):
            continue
        account_name = line_strip[2:].strip()
        if not account_name or account_name.startswith("..."):
            continue
        choices.append(account_name)
    return choices


def build_getotp_list_buttons(message_text: str) -> Optional[Dict]:
    choices = extract_account_choices_from_list_result(message_text)
    if not choices:
        return None

    keyboard: List[List[Dict[str, str]]] = []
    for idx, account_name in enumerate(choices[:30]):
        display_text = account_name if len(account_name) <= 60 else (account_name[:57] + "...")
        keyboard.append([{"text": display_text, "callback_data": f"pickotp:{idx}"}])
    return {"inline_keyboard": keyboard}


def build_getotp_reply_markup(message_text: str) -> Optional[Dict]:
    if (message_text or "").startswith("📋 Danh sách OTP khớp"):
        return build_getotp_list_buttons(message_text)
    return build_getotp_buttons(message_text)


def build_qr_duplicate_buttons(duplicate_names: List[Dict[str, str]]) -> Optional[Dict]:
    if not duplicate_names:
        return None

    keyboard: List[List[Dict[str, str]]] = []
    for rec in duplicate_names[:20]:
        idx = _get_pending_pick_id(rec)
        account_cell = str(rec.get("account_cell", "")).strip()
        if not idx:
            continue
        label = f"✏️ Đổi tên mã {idx}"
        if account_cell:
            short_name = account_cell if len(account_cell) <= 24 else (account_cell[:21] + "...")
            label = f"✏️ #{idx} {short_name}"
        keyboard.append([{"text": label, "callback_data": f"renqrpick:{idx}"}])

    if not keyboard:
        return None

    keyboard.append([{"text": "❎ Huỷ chờ đổi tên", "callback_data": "renqrcancel"}])
    return {"inline_keyboard": keyboard}


def extract_refresh_history_lines(message_text: str) -> List[str]:
    lines = (message_text or "").splitlines()
    header = "🕒 Lịch sử làm mới"
    start_idx = -1
    for idx, line in enumerate(lines):
        if line.strip().startswith(header):
            start_idx = idx + 1
            break

    if start_idx < 0:
        return []

    history: List[str] = []
    for line in lines[start_idx:]:
        line_strip = line.strip()
        if not line_strip:
            continue
        if line_strip.startswith("-"):
            history.append(line_strip)
    return history


def build_refresh_actor_name(user: Dict) -> str:
    first_name = str(user.get("first_name", "")).strip()
    last_name = str(user.get("last_name", "")).strip()
    full_name = f"{first_name} {last_name}".strip()
    if full_name:
        return full_name
    username = str(user.get("username", "")).strip()
    if username:
        return username
    user_id = str(user.get("id", "")).strip()
    return user_id or "unknown"


def attach_refresh_history(base_message_text: str, history_lines: List[str]) -> str:
    text = (base_message_text or "").strip()
    if not history_lines:
        return text
    lines = [text, "", "🕒 Lịch sử làm mới"]
    lines.extend(history_lines)
    return "\n".join(lines)


def extract_query_from_getotp_result(message_text: str) -> str:
    prefix = "🔎 Từ khoá:"
    for line in (message_text or "").splitlines():
        line_strip = line.strip()
        if line_strip.startswith(prefix):
            return line_strip[len(prefix) :].strip()
    return ""


def process_grant_command(text: str, permission_file: str) -> Tuple[str, bool]:
    parts = text.split(maxsplit=2)
    if len(parts) < 3:
        return "❌ Dùng: /grantotp get|delete|both @username|user_id", False

    action = parts[1].strip().lower()
    target_key, target_label = normalize_permission_target(parts[2])
    if action not in {"get", "delete", "both"}:
        return "❌ Quyền hợp lệ: get, delete, both", False
    if not target_key:
        return "❌ Target phải là @username hoặc user_id", False

    permission_data = load_permissions(permission_file)
    actions = ["get", "delete"] if action == "both" else [action]
    for action_name in actions:
        permission_data.setdefault(action_name, {})[target_key] = target_label
    save_permissions(permission_file, permission_data)

    return f"✅ Đã cấp quyền {', '.join(actions)} cho {target_label}", True


def process_revoke_command(text: str, permission_file: str) -> Tuple[str, bool]:
    parts = text.split(maxsplit=2)
    if len(parts) < 3:
        return "❌ Dùng: /revokeotp get|delete|both @username|user_id", False

    action = parts[1].strip().lower()
    target_key, target_label = normalize_permission_target(parts[2])
    if action not in {"get", "delete", "both"}:
        return "❌ Quyền hợp lệ: get, delete, both", False
    if not target_key:
        return "❌ Target phải là @username hoặc user_id", False

    permission_data = load_permissions(permission_file)
    actions = ["get", "delete"] if action == "both" else [action]
    removed = 0
    for action_name in actions:
        bucket = permission_data.setdefault(action_name, {})
        if target_key in bucket:
            removed += 1
            del bucket[target_key]
    save_permissions(permission_file, permission_data)

    if not removed:
        return f"❌ {target_label} chưa có quyền để thu hồi", False
    return f"✅ Đã thu hồi quyền {', '.join(actions)} của {target_label}", True


def build_bdls_message(bot_token: str, chat_id: str, permission_file: str) -> str:
    permission_data = load_permissions(permission_file)
    get_bucket = permission_data.get("get", {})
    if not get_bucket:
        return "📭 Chưa có tài khoản nào liên kết quyền lấy OTP"

    lines: List[str] = []
    lines.append("📋 Danh sách liên kết lấy OTP")
    lines.append(f"✅ Tổng: {len(get_bucket)}")
    lines.append("")

    idx = 1
    for target_key, target_label in sorted(get_bucket.items()):
        username = ""
        user_id = ""

        if target_key.startswith("username:"):
            username = "@" + target_key[len("username:") :]
        elif target_key.startswith("id:"):
            user_id = target_key[len("id:") :]

        label = str(target_label).strip()
        if label.startswith("@"):
            username = label
        elif label.isdigit():
            user_id = label

        if user_id:
            member = get_chat_member(bot_token, chat_id, user_id)
            member_user = (member or {}).get("user") or {}
            first_name = str(member_user.get("first_name", "")).strip()
            last_name = str(member_user.get("last_name", "")).strip()
            full_name = f"{first_name} {last_name}".strip()
            if full_name:
                username = full_name
            elif member_user.get("username"):
                username = "@" + str(member_user.get("username", "")).strip()

        if not username:
            username = "(chưa có)"
        if not user_id:
            user_id = "(chưa có)"

        lines.append(f"{idx}. Tên: {username} | ID: {user_id}")
        idx += 1

    return "\n".join(lines)


def build_myid_message(user: Dict, permission_file: str) -> str:
    permission_data = load_permissions(permission_file)
    can_get = user_has_permission(permission_data, "get", user)
    can_delete = user_has_permission(permission_data, "delete", user)
    username = str(user.get("username", "")).strip()
    user_id = str(user.get("id", "")).strip()
    lines = ["👤 Thông tin tài khoản"]
    if username:
        lines.append(f"Username: @{username}")
    lines.append(f"User ID: {user_id}")
    lines.append(f"Quyền lấy OTP: {'Có' if can_get else 'Không'}")
    lines.append(f"Quyền xoá OTP: {'Có' if can_delete else 'Không'}")
    return "\n".join(lines)


def build_access_request_buttons(user_id: str) -> Dict:
    return {
        "inline_keyboard": [
            [
                {"text": "✅ Chấp thuận", "callback_data": f"reqok:{user_id}"},
                {"text": "❌ Từ chối", "callback_data": f"reqno:{user_id}"},
            ]
        ]
    }


def extract_username_from_access_request_text(text: str) -> str:
    for raw_line in str(text or "").splitlines():
        line = raw_line.strip()
        if not line.lower().startswith("username:"):
            continue
        value = line.split(":", 1)[1].strip() if ":" in line else ""
        if value.startswith("@"):
            value = value[1:]
        value = value.strip().lower()
        if value and value != "(không có)":
            return value
    return ""


def grant_get_permission_for_user(permission_file: str, user_id: str, username: str = "") -> None:
    permission_data = load_permissions(permission_file)
    key = f"id:{user_id}"
    permission_data.setdefault("get", {})[key] = user_id
    username = str(username or "").strip().lower().lstrip("@")
    if username:
        permission_data.setdefault("get", {})[f"username:{username}"] = f"@{username}"
    save_permissions(permission_file, permission_data)


def process_qr_photo(bot_token: str, msg: Dict, csv_path: str) -> Tuple[str, bool, List[Dict[str, str]]]:
    photos = msg.get("photo") or []
    if not photos:
        return "❌ Không có ảnh QR", False, []

    file_id = photos[-1].get("file_id")
    if not file_id:
        return "❌ Không lấy được file_id ảnh", False, []

    file_path = telegram_get_file_path(bot_token, file_id)
    if not file_path:
        return "❌ Không lấy được file_path từ Telegram", False, []

    tmp_name = f"tmp_qr_{int(time.time())}_{random.randint(1000,9999)}.jpg"
    tmp_path = os.path.join(os.getcwd(), tmp_name)

    try:
        print(f"[QR_PHOTO] Bắt đầu tải ảnh: {tmp_path}")
        if not download_telegram_file(bot_token, file_path, tmp_path):
            print("[QR_PHOTO] Tải ảnh thất bại")
            return "❌ Tải ảnh từ Telegram thất bại", False, []

        print(f"[QR_PHOTO] Tải xong, kích thước: {os.path.getsize(tmp_path)} bytes")
        print("[QR_PHOTO] Bắt đầu giải mã OTP từ ảnh")
        otp_rows = extract_otps_from_qr_image(tmp_path)
        print(f"[QR_PHOTO] Giải mã xong, tìm thấy {len(otp_rows)} OTP")
        if not otp_rows:
            return "❌ Ảnh không có QR OTP hợp lệ (hỗ trợ otpauth-migration và otpauth://totp)", False, []

        # Phase 2 — serialised under lock so concurrent QR workers never produce
        # duplicate CSV rows when multiple images are processed simultaneously.
        with _csv_rw_lock:
            existing_keys = load_existing_keys(csv_path)
            existing_names = load_existing_account_names(csv_path)
            new_rows: List[Dict[str, str]] = []
            duplicates: List[Dict[str, str]] = []
            duplicate_names: List[Dict[str, str]] = []

            for idx, rec in enumerate(otp_rows, 1):
                rec["index"] = str(idx)
                account_cell = build_account_cell(rec.get("account", ""), rec.get("issuer", "")).strip()
                account_key = account_cell.lower()
                if rec["key"] in existing_keys:
                    duplicates.append(rec)
                elif account_key in existing_names:
                    rec["account_cell"] = account_cell
                    duplicate_names.append(rec)
                else:
                    new_rows.append(rec)
                    existing_keys.add(rec["key"])
                    if account_key:
                        existing_names.add(account_key)

            if new_rows:
                append_rows(csv_path, new_rows)

        lines: List[str] = []
        lines.append("📷 Kết quả đọc QR OTP từ nhóm")
        lines.append(f"📥 Tổng quét: {len(otp_rows)}")
        lines.append(f"✅ Thêm mới: {len(new_rows)}")
        lines.append(f"♻️ Trùng: {len(duplicates)}")
        lines.append(f"🚫 Trùng tên: {len(duplicate_names)}")

        if duplicates:
            lines.append("")
            lines.append("♻️ OTP đã tồn tại:")
            for rec in duplicates[:20]:
                name = rec.get("account", "")
                issuer = rec.get("issuer", "")
                idx = rec.get("index", "?")
                lines.append(f"- Mã thứ {idx}: {name}" + (f" ({issuer})" if issuer else ""))

        if duplicate_names:
            lines.append("")
            lines.append("🚫 Tên OTP đã tồn tại, vui lòng đổi tên rồi thêm lại:")
            for rec in duplicate_names[:20]:
                idx = rec.get("index", "?")
                lines.append(f"- Mã thứ {idx}: {rec.get('account_cell', '')}")

        print(f"[QR_PHOTO] Hoàn thành, sắp gửi Telegram")
        return "\n".join(lines), True, duplicate_names
    except Exception as e:
        print(f"[QR_PHOTO] LỖI: {e}")
        import traceback
        traceback.print_exc()
        return f"❌ Lỗi xử lý QR: {e}", False, []
    finally:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass


def _qr_photo_worker(
    bot_token: str,
    msg: Dict,
    wps_file: str,
    pending_file: str,
    message_chat_id: str,
    user_id_str: str,
    google_sheet_id: str,
    google_sheet_name: str,
    google_service_account_json: str,
    google_service_account_file: str,
) -> None:
    """Background thread: process one QR photo message and send result back.

    The heavy work (download + OpenCV decode) runs concurrently with other
    workers. The CSV write phase is already serialised inside process_qr_photo
    via _csv_rw_lock, so results are always consistent even when dozens of
    images arrive at once.
    """
    try:
        print(f"[QR_WORKER] Bắt đầu xử lý ảnh QR cho {message_chat_id}", flush=True)
        report_text, ok, duplicate_names = process_qr_photo(bot_token, msg, wps_file)

        if ok and duplicate_names:
            pending_count = remember_qr_duplicate_names(
                pending_file,
                message_chat_id,
                user_id_str,
                duplicate_names,
            )
            if pending_count:
                tips: List[str] = [
                    "",
                    "🛠 OTP trùng tên đang chờ đổi rồi lưu trực tiếp:",
                    "- Bấm nút bên dưới để chọn OTP cần đổi tên",
                    "- Hoặc dùng: /renqr stt|ten_moi",
                    f"- Đang chờ: {pending_count} OTP",
                ]
                report_text = report_text + "\n" + "\n".join(tips)

        print(f"[QR_WORKER] Gửi kết quả về {message_chat_id}: ok={ok}", flush=True)
        duplicate_buttons = build_qr_duplicate_buttons(duplicate_names) if (ok and duplicate_names) else None
        remaining_jobs = finish_qr_job()
        should_flush_qr_batch = ok and remaining_jobs == 0

        if ok and google_sheet_id:
            if should_flush_qr_batch:
                sync_ok, sync_msg = maybe_sync_google_sheet(
                    wps_file,
                    google_sheet_id,
                    google_sheet_name,
                    google_service_account_json,
                    google_service_account_file,
                )
                report_text = f"{report_text}\n\n☁️ Google Sheets: {'✅ ' if sync_ok else '❌ '}{sync_msg}"
            else:
                report_text = (
                    f"{report_text}\n\n"
                    f"⏳ Còn {remaining_jobs} ảnh QR đang xếp hàng, sẽ đồng bộ Google Sheets sau khi xử lý xong đợt này"
                )

        send_message(bot_token, message_chat_id, report_text, duplicate_buttons)
        if should_flush_qr_batch:
            caption = f"Cập nhật OTP từ QR lúc {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            send_document(bot_token, message_chat_id, wps_file, caption)
    except Exception as e:
        print(f"[QR_WORKER] LỖI ngoài dự kiến: {e}", flush=True)
        traceback.print_exc()
        try:
            send_message(bot_token, message_chat_id, f"❌ Lỗi xử lý QR: {e}")
        except Exception:
            pass
        finish_qr_job()


def parse_args():
    parser = argparse.ArgumentParser(description="Listen OTP commands from Telegram groups")
    data_dir = os.environ.get("DATA_DIR", "")
    default_permission_file = os.path.join(data_dir, "telegram_permissions.json") if data_dir else "telegram_permissions.json"
    parser.add_argument("--bot-token", default=os.environ.get("TELEGRAM_BOT_TOKEN", ""))
    parser.add_argument("--chat-id", default=os.environ.get("TELEGRAM_CHAT_ID", ""))
    parser.add_argument("--employee-chat-id", default=os.environ.get("EMPLOYEE_TELEGRAM_CHAT_ID", "-1003820328844"))
    parser.add_argument("--wps-file", default="otp_wps.csv")
    parser.add_argument("--offset-file", default="telegram_offset.txt")
    parser.add_argument("--permission-file", default=os.environ.get("TELEGRAM_PERMISSION_FILE", default_permission_file))
    parser.add_argument("--pending-file", default=os.environ.get("TELEGRAM_QR_PENDING_FILE", "telegram_qr_pending.json"))
    parser.add_argument("--processed-updates-file", default=os.environ.get("TELEGRAM_PROCESSED_UPDATES_FILE", "telegram_processed_updates.json"))
    parser.add_argument("--processed-messages-file", default=os.environ.get("TELEGRAM_PROCESSED_MESSAGES_FILE", "telegram_processed_messages.json"))
    parser.add_argument("--processed-commands-file", default=os.environ.get("TELEGRAM_PROCESSED_COMMANDS_FILE", "telegram_processed_commands.json"))
    parser.add_argument("--sent-dedupe-file", default=os.environ.get("TELEGRAM_SENT_DEDUPE_FILE", "telegram_sent_dedupe.json"))
    parser.add_argument("--singleton-lock-file", default=os.environ.get("TELEGRAM_SINGLETON_LOCK_FILE", ""))
    parser.add_argument("--poll-timeout", type=int, default=30)
    parser.add_argument("--sleep-seconds", type=float, default=1.0)
    parser.add_argument("--sheet-pull-interval-seconds", type=float, default=float(os.environ.get("TELEGRAM_SHEET_PULL_INTERVAL_SECONDS", "120")))
    parser.add_argument("--google-sheet-id", default=os.environ.get("GOOGLE_SHEET_ID", ""))
    parser.add_argument("--google-sheet-name", default=os.environ.get("GOOGLE_SHEET_NAME", "OTP"))
    parser.add_argument("--google-service-account-file", default=os.environ.get("GOOGLE_SERVICE_ACCOUNT_FILE", ""))
    parser.add_argument("--google-service-account-json", default=os.environ.get("GOOGLE_SERVICE_ACCOUNT_JSON", ""))
    parser.add_argument("--once", action="store_true", help="Run one poll cycle then exit")
    return parser.parse_args()


def send_photo(bot_token: str, chat_id: str, file_path: str, caption: str = "") -> bool:
    if not os.path.exists(file_path):
        return False
    filename = os.path.basename(file_path) or "otp_qr.png"

    url = f"https://api.telegram.org/bot{bot_token}/sendPhoto"
    boundary = "----otpphoto" + "".join(random.choice(string.ascii_letters) for _ in range(16))

    with open(file_path, "rb") as f:
        file_data = f.read()

    parts: List[bytes] = []

    def add_text_part(name: str, value: str) -> None:
        parts.append(f"--{boundary}\r\n".encode("utf-8"))
        parts.append(f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode("utf-8"))
        parts.append(value.encode("utf-8"))
        parts.append(b"\r\n")

    add_text_part("chat_id", chat_id)
    if caption:
        add_text_part("caption", caption)

    parts.append(f"--{boundary}\r\n".encode("utf-8"))
    parts.append(f'Content-Disposition: form-data; name="photo"; filename="{filename}"\r\n'.encode("utf-8"))
    parts.append(b"Content-Type: image/png\r\n\r\n")
    parts.append(file_data)
    parts.append(b"\r\n")
    parts.append(f"--{boundary}--\r\n".encode("utf-8"))

    req = urllib.request.Request(url, data=b"".join(parts), method="POST")
    req.add_header("Content-Type", f"multipart/form-data; boundary={boundary}")

    try:
        raw = _urlopen_with_ssl_fallback(req, timeout=40)
        parsed = json.loads(raw)
        return bool(parsed.get("ok"))
    except Exception:
        return False


def main() -> int:
    args = parse_args()

    configure_outbound_dedupe(args.sent_dedupe_file, ttl_seconds=10)

    # Hold process-wide lock to avoid two concurrent pollers causing duplicates.
    _singleton_lock_handle = acquire_singleton_lock(args.singleton_lock_file)

    # Thread pool for QR photo processing — max 4 concurrent heavy tasks so the
    # main poll loop is never blocked downloading/decoding images.  CSV writes in
    # each worker are already serialised by _csv_rw_lock.
    _photo_pool = concurrent.futures.ThreadPoolExecutor(
        max_workers=6, thread_name_prefix="qr_worker"
    )

    if not args.bot_token or not args.chat_id or not args.employee_chat_id:
        print("❌ Thiếu TELEGRAM_BOT_TOKEN hoặc chat id của admin/nhân viên")
        return 1

    restore_ok, restore_msg = restore_csv_from_google_sheet_if_newer(
        args.wps_file,
        args.google_sheet_id,
        args.google_sheet_name,
        args.google_service_account_json,
        args.google_service_account_file,
    )
    print(f"☁️ Restore Google Sheet: {'OK' if restore_ok else 'FAIL'} | {restore_msg}")

    offset = load_offset(args.offset_file)
    conflict_409_count = 0
    last_sheet_pull_ts = 0.0
    sheet_pull_interval = max(float(args.sheet_pull_interval_seconds), 10.0)
    print("🤖 Telegram listener đang chạy...")
    print(f"📄 File WPS: {args.wps_file}")
    print(f"📌 Chat admin: {args.chat_id}")
    print(f"📌 Chat nhân viên: {args.employee_chat_id}")
    if args.google_sheet_id:
        print(f"☁️ Google Sheet: {args.google_sheet_id} | tab={args.google_sheet_name}")
    else:
        print("☁️ Google Sheet: chưa cấu hình (bỏ qua đồng bộ)")
    permission_snapshot = load_permissions(args.permission_file)
    print(
        f"🔐 Quyền OTP đã nạp: get={len(permission_snapshot.get('get', {}))}, delete={len(permission_snapshot.get('delete', {}))} | file={args.permission_file}",
        flush=True,
    )

    while True:
        now_ts = time.time()
        if args.google_sheet_id and now_ts - last_sheet_pull_ts >= sheet_pull_interval:
            pull_ok, pull_msg = restore_csv_from_google_sheet_if_newer(
                args.wps_file,
                args.google_sheet_id,
                args.google_sheet_name,
                args.google_service_account_json,
                args.google_service_account_file,
            )
            print(f"☁️ Pull Google Sheet: {'OK' if pull_ok else 'FAIL'} | {pull_msg}", flush=True)
            last_sheet_pull_ts = now_ts

        try:
            updates = get_updates(args.bot_token, offset, args.poll_timeout)
            conflict_409_count = 0
        except Exception as e:
            if isinstance(e, TelegramAPIError) and e.status_code == 409:
                conflict_409_count += 1
                desc_lower = e.description.lower()
                print(f"⚠️ Lỗi getUpdates 409: {e.description}", flush=True)

                if "webhook" in desc_lower:
                    ok_del, msg_del = delete_webhook(args.bot_token, drop_pending_updates=False)
                    print(f"🧹 deleteWebhook: {'OK' if ok_del else 'FAIL'} | {msg_del}", flush=True)

                backoff = min(30.0, max(args.sleep_seconds, 1.0) * (2 ** min(conflict_409_count, 4)))
                print(f"⏳ Chờ {backoff:.1f}s rồi thử lại getUpdates", flush=True)
                time.sleep(backoff)
            else:
                print(f"⚠️ Lỗi getUpdates: {e}", flush=True)
                time.sleep(max(args.sleep_seconds, 1.0))
            if args.once:
                return 1
            continue

        if not updates:
            print(f"[POLL] Không có updates (offset={offset})", flush=True)
            if args.once:
                return 0
            continue

        print(f"[POLL] Nhận {len(updates)} updates", flush=True)
        for upd in updates:
            update_id = upd.get("update_id", 0)
            offset = max(offset, update_id + 1)

            # Atomic check+mark via flock — prevents two concurrent bot instances
            # (during Render deploy overlap) from both processing the same update.
            if check_and_mark_update_processed(args.processed_updates_file, int(update_id)):
                print(f"[SKIP] Update đã xử lý trước đó: {update_id}", flush=True)
                save_offset(args.offset_file, offset)
                continue

            save_offset(args.offset_file, offset)

            callback_query = upd.get("callback_query") or {}
            if callback_query:
                callback_id = str(callback_query.get("id", ""))
                callback_data = str(callback_query.get("data", "")).strip()
                callback_user = callback_query.get("from") or {}
                callback_message = callback_query.get("message") or {}
                callback_chat = callback_message.get("chat") or {}
                callback_chat_id = str(callback_chat.get("id", ""))
                callback_message_id = str(callback_message.get("message_id", ""))
                callback_text = str(callback_message.get("text", ""))

                print(
                    f"[CALLBACK] ID={update_id}, chat_id={callback_chat_id}, data={callback_data}",
                    flush=True,
                )

                if callback_data == "refreshotp":
                    is_employee_callback = callback_chat_id == str(args.employee_chat_id)
                    if not is_employee_callback:
                        answer_callback_query(args.bot_token, callback_id, "Nút này chỉ dùng ở nhóm nhân viên")
                        continue

                    permission_data = load_permissions(args.permission_file)
                    if not user_has_permission(permission_data, "get", callback_user):
                        answer_callback_query(args.bot_token, callback_id, "Bạn chưa có quyền lấy OTP")
                        continue

                    query = extract_query_from_getotp_result(callback_text)
                    if not query:
                        answer_callback_query(args.bot_token, callback_id, "Không đọc được từ khoá để làm mới")
                        continue

                    if args.google_sheet_id:
                        restore_ok, restore_msg = force_restore_csv_from_google_sheet(
                            args.wps_file,
                            args.google_sheet_id,
                            args.google_sheet_name,
                            args.google_service_account_json,
                            args.google_service_account_file,
                        )
                        print(f"☁️ Pre-getotp(refresh) restore: {'OK' if restore_ok else 'FAIL'} | {restore_msg}", flush=True)
                        if not restore_ok:
                            answer_callback_query(args.bot_token, callback_id, "Lỗi đọc Google Sheet, thử lại sau")
                            continue

                    refreshed_text, ok = process_getotp(f"/getotp {query}", args.wps_file)
                    if ok:
                        history_lines = extract_refresh_history_lines(callback_text)
                        actor_name = build_refresh_actor_name(callback_user)
                        now_label = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        history_lines.append(f"- {actor_name} làm mới lúc {now_label}")
                        history_lines = history_lines[-10:]
                        refreshed_with_history = attach_refresh_history(refreshed_text, history_lines)

                        edit_message_text(
                            args.bot_token,
                            callback_chat_id,
                            callback_message_id,
                            refreshed_with_history,
                            build_getotp_reply_markup(refreshed_with_history),
                        )
                        answer_callback_query(args.bot_token, callback_id, "Đã làm mới OTP")
                    else:
                        answer_callback_query(args.bot_token, callback_id, refreshed_text)
                    continue

                if callback_data.startswith("pickotp:"):
                    is_employee_callback = callback_chat_id == str(args.employee_chat_id)
                    if not is_employee_callback:
                        answer_callback_query(args.bot_token, callback_id, "Nút này chỉ dùng ở nhóm nhân viên")
                        continue

                    permission_data = load_permissions(args.permission_file)
                    if not user_has_permission(permission_data, "get", callback_user):
                        answer_callback_query(args.bot_token, callback_id, "Bạn chưa có quyền lấy OTP")
                        continue

                    idx_str = callback_data.split(":", 1)[1].strip()
                    if not idx_str.isdigit():
                        answer_callback_query(args.bot_token, callback_id, "Lựa chọn không hợp lệ")
                        continue

                    choices = extract_account_choices_from_list_result(callback_text)
                    pick_idx = int(idx_str)
                    if pick_idx < 0 or pick_idx >= len(choices):
                        answer_callback_query(args.bot_token, callback_id, "Danh sách đã cũ, hãy tìm lại")
                        continue

                    chosen_account = choices[pick_idx]

                    if args.google_sheet_id:
                        restore_ok, restore_msg = force_restore_csv_from_google_sheet(
                            args.wps_file,
                            args.google_sheet_id,
                            args.google_sheet_name,
                            args.google_service_account_json,
                            args.google_service_account_file,
                        )
                        print(f"☁️ Pre-getotp(pick) restore: {'OK' if restore_ok else 'FAIL'} | {restore_msg}", flush=True)
                        if not restore_ok:
                            answer_callback_query(args.bot_token, callback_id, "Lỗi đọc Google Sheet, thử lại sau")
                            continue

                    selected_text, ok = process_getotp_query(chosen_account, args.wps_file)
                    if ok:
                        edit_message_text(
                            args.bot_token,
                            callback_chat_id,
                            callback_message_id,
                            selected_text,
                            build_getotp_reply_markup(selected_text),
                        )
                        answer_callback_query(args.bot_token, callback_id, "Đã chọn OTP")
                    else:
                        answer_callback_query(args.bot_token, callback_id, selected_text)
                    continue

                if callback_data.startswith("reqok:") or callback_data.startswith("reqno:"):
                    is_admin_callback = callback_chat_id == str(args.chat_id)
                    if not is_admin_callback:
                        answer_callback_query(args.bot_token, callback_id, "Nút này chỉ dùng ở nhóm admin")
                        continue

                    if not is_chat_admin(args.bot_token, args.chat_id, str(callback_user.get("id", ""))):
                        answer_callback_query(args.bot_token, callback_id, "Chỉ admin mới được duyệt")
                        continue

                    action, user_id = callback_data.split(":", 1)
                    user_id = user_id.strip()
                    if not user_id.isdigit():
                        answer_callback_query(args.bot_token, callback_id, "User ID không hợp lệ")
                        continue

                    clear_recent_command_key(args.processed_commands_file, f"permreq:{user_id}")
                    notify_key = f"permresult:{action}:{user_id}"
                    should_notify_employee_group = not check_and_mark_recent_command_key(
                        args.processed_commands_file,
                        notify_key,
                        int(time.time()),
                        ttl_seconds=300,
                    )

                    if action == "reqok":
                        request_username = extract_username_from_access_request_text(callback_text)
                        grant_get_permission_for_user(args.permission_file, user_id, request_username)
                        verify_permission = load_permissions(args.permission_file)
                        verify_get = verify_permission.get("get", {})
                        if f"id:{user_id}" not in verify_get:
                            answer_callback_query(args.bot_token, callback_id, "Lưu quyền thất bại, thử lại")
                            send_message(
                                args.bot_token,
                                callback_chat_id,
                                f"❌ Không lưu được quyền cho user_id {user_id}. Kiểm tra file quyền và thử lại.",
                            )
                            continue
                        result_text = f"✅ Đã chấp thuận quyền lấy OTP cho user_id {user_id}"
                        edit_message_text(
                            args.bot_token,
                            callback_chat_id,
                            callback_message_id,
                            callback_text + "\n\n" + result_text,
                        )
                        sent_group = True
                        if should_notify_employee_group:
                            sent_group = send_message(
                                args.bot_token,
                                str(args.employee_chat_id),
                                "✅ Kết quả duyệt quyền OTP\n"
                                f"- User ID: {user_id}\n"
                                "- Trạng thái: Đã chấp thuận\n"
                                "Bạn có thể dùng /getotp ngay.",
                            )
                        # Try DM as well; may fail if user has not started bot.
                        send_message(
                            args.bot_token,
                            user_id,
                            "✅ Yêu cầu quyền OTP của bạn đã được chấp thuận.",
                        )
                        if not sent_group:
                            send_message(args.bot_token, callback_chat_id, "⚠️ Không gửi được thông báo sang nhóm nhân viên")
                        answer_callback_query(args.bot_token, callback_id, "Đã chấp thuận")
                    else:
                        result_text = f"❌ Đã từ chối yêu cầu quyền của user_id {user_id}"
                        edit_message_text(
                            args.bot_token,
                            callback_chat_id,
                            callback_message_id,
                            callback_text + "\n\n" + result_text,
                        )
                        sent_group = True
                        if should_notify_employee_group:
                            sent_group = send_message(
                                args.bot_token,
                                str(args.employee_chat_id),
                                "❌ Kết quả duyệt quyền OTP\n"
                                f"- User ID: {user_id}\n"
                                "- Trạng thái: Từ chối\n"
                                "Liên hệ admin nếu cần mở quyền.",
                            )
                        send_message(
                            args.bot_token,
                            user_id,
                            "❌ Yêu cầu quyền OTP của bạn đã bị từ chối.",
                        )
                        if not sent_group:
                            send_message(args.bot_token, callback_chat_id, "⚠️ Không gửi được thông báo sang nhóm nhân viên")
                        answer_callback_query(args.bot_token, callback_id, "Đã từ chối")
                    continue

                if callback_data.startswith("renqrpick:"):
                    is_admin_callback = callback_chat_id == str(args.chat_id)
                    if not is_admin_callback:
                        answer_callback_query(args.bot_token, callback_id, "Nút này chỉ dùng ở nhóm admin")
                        continue

                    idx_str = callback_data.split(":", 1)[1].strip()
                    if not idx_str.isdigit():
                        answer_callback_query(args.bot_token, callback_id, "Mã OTP không hợp lệ")
                        continue

                    ok_pick, picked_name = set_pending_qr_awaiting_index(
                        args.pending_file,
                        callback_chat_id,
                        str(callback_user.get("id", "")),
                        idx_str,
                    )
                    if not ok_pick:
                        answer_callback_query(args.bot_token, callback_id, picked_name)
                        continue

                    answer_callback_query(args.bot_token, callback_id, f"Đã chọn mã {idx_str}")
                    prompt = [
                        "📝 Vui lòng nhập tên mới cho OTP trùng:",
                        f"- Mã thứ: {idx_str}",
                    ]
                    if picked_name:
                        prompt.append(f"- Tên hiện tại: {picked_name}")
                    prompt.append("")
                    prompt.append("Gửi trực tiếp tên mới vào nhóm (không cần lệnh).")
                    prompt.append("Ví dụ: ATPay test")
                    send_message(args.bot_token, callback_chat_id, "\n".join(prompt))
                    continue

                if callback_data == "renqrcancel":
                    is_admin_callback = callback_chat_id == str(args.chat_id)
                    if not is_admin_callback:
                        answer_callback_query(args.bot_token, callback_id, "Nút này chỉ dùng ở nhóm admin")
                        continue
                    clear_pending_qr_awaiting_index(
                        args.pending_file,
                        callback_chat_id,
                        str(callback_user.get("id", "")),
                    )
                    answer_callback_query(args.bot_token, callback_id, "Đã huỷ chờ đổi tên")
                    continue

                answer_callback_query(args.bot_token, callback_id)
                continue

            msg = upd.get("message") or {}
            chat = msg.get("chat") or {}
            user = msg.get("from") or {}
            text = (msg.get("text") or "").strip()
            message_chat_id = str(chat.get("id", ""))
            message_id = str(msg.get("message_id", "")).strip()
            is_admin_chat = message_chat_id == str(args.chat_id)
            is_employee_chat = message_chat_id == str(args.employee_chat_id)

            if message_chat_id and message_id:
                message_key = f"{message_chat_id}:{message_id}"
                now_ts = int(time.time())
                if check_and_mark_recent_command_key(
                    args.processed_messages_file,
                    message_key,
                    now_ts,
                    ttl_seconds=3600,
                ):
                    print(f"[SKIP] Tin nhắn trùng gần đây: {message_key}", flush=True)
                    continue

            print(
                f"[UPDATE] ID={update_id}, chat_id={message_chat_id}, admin_chat={is_admin_chat}, employee_chat={is_employee_chat}, has_text={bool(text)}, has_photo={bool(msg.get('photo'))}",
                flush=True,
            )

            if not is_admin_chat and not is_employee_chat:
                print(f"[SKIP] Chat ID không match, bỏ qua", flush=True)
                continue

            # Nhóm admin: xử lý ảnh QR trước tiên
            if is_admin_chat and msg.get("photo"):
                queued_jobs = begin_qr_job()
                print(
                    f"[MAIN] Ảnh QR nhận từ {message_chat_id}, submit vào worker pool (không chặn poll) | queue={queued_jobs}",
                    flush=True,
                )
                _photo_pool.submit(
                    _qr_photo_worker,
                    args.bot_token,
                    msg,
                    args.wps_file,
                    args.pending_file,
                    message_chat_id,
                    str(user.get("id", "")),
                    args.google_sheet_id,
                    args.google_sheet_name,
                    args.google_service_account_json,
                    args.google_service_account_file,
                )
                continue

            if is_admin_chat and text.startswith("/renqr"):
                if args.google_sheet_id:
                    restore_ok, restore_msg = force_restore_csv_from_google_sheet(
                        args.wps_file,
                        args.google_sheet_id,
                        args.google_sheet_name,
                        args.google_service_account_json,
                        args.google_service_account_file,
                    )
                    print(f"☁️ Pre-write restore: {'OK' if restore_ok else 'FAIL'} | {restore_msg}", flush=True)
                report_text, ok = process_rename_qr_duplicate(
                    text,
                    args.wps_file,
                    args.pending_file,
                    message_chat_id,
                    str(user.get("id", "")),
                )
                if ok:
                    sync_ok, sync_msg = maybe_sync_google_sheet(
                        args.wps_file,
                        args.google_sheet_id,
                        args.google_sheet_name,
                        args.google_service_account_json,
                        args.google_service_account_file,
                    )
                    report_text = f"{report_text}\n\n☁️ Google Sheets: {'✅ ' if sync_ok else '❌ '}{sync_msg}"
                send_message(args.bot_token, message_chat_id, report_text)
                if ok:
                    caption = f"Đổi tên OTP trùng từ QR lúc {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                    send_document(args.bot_token, message_chat_id, args.wps_file, caption)
                    remain_duplicates = get_pending_qr_duplicates_for_user_or_chat(
                        args.pending_file,
                        message_chat_id,
                        str(user.get("id", "")),
                    )
                    if remain_duplicates:
                        send_message(
                            args.bot_token,
                            message_chat_id,
                            build_pending_qr_duplicate_message(remain_duplicates),
                            build_qr_duplicate_buttons(remain_duplicates),
                        )
                continue

            # Kiểm tra tin nhắn text
            if not text:
                continue

            # Keep command dedupe marker only for diagnostics; do not block execution.
            # Blocking here made normal repeated queries look like bot was not responding.
            cmd_key = f"{message_chat_id}:{str(user.get('id', '')).strip()}:{text[:200]}"
            mark_command_seen(args.processed_commands_file, cmd_key, int(time.time()))

            print(f"[MAIN] Nhận tin nhắn text từ {message_chat_id}: {text[:40]}...")

            if is_admin_chat and not text.startswith("/"):
                waiting_item = get_pending_qr_awaiting_item(
                    args.pending_file,
                    message_chat_id,
                    str(user.get("id", "")),
                )
                if waiting_item:
                    rename_cmd = f"/renqr {waiting_item.get('index', '')}|{text}"
                    if args.google_sheet_id:
                        restore_ok, restore_msg = force_restore_csv_from_google_sheet(
                            args.wps_file,
                            args.google_sheet_id,
                            args.google_sheet_name,
                            args.google_service_account_json,
                            args.google_service_account_file,
                        )
                        print(f"☁️ Pre-write restore: {'OK' if restore_ok else 'FAIL'} | {restore_msg}", flush=True)

                    report_text, ok = process_rename_qr_duplicate(
                        rename_cmd,
                        args.wps_file,
                        args.pending_file,
                        message_chat_id,
                        str(user.get("id", "")),
                    )
                    if ok:
                        sync_ok, sync_msg = maybe_sync_google_sheet(
                            args.wps_file,
                            args.google_sheet_id,
                            args.google_sheet_name,
                            args.google_service_account_json,
                            args.google_service_account_file,
                        )
                        report_text = f"{report_text}\n\n☁️ Google Sheets: {'✅ ' if sync_ok else '❌ '}{sync_msg}"
                    send_message(args.bot_token, message_chat_id, report_text)
                    if ok:
                        caption = f"Đổi tên OTP trùng từ QR lúc {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                        send_document(args.bot_token, message_chat_id, args.wps_file, caption)
                        remain_duplicates = get_pending_qr_duplicates_for_user_or_chat(
                            args.pending_file,
                            message_chat_id,
                            str(user.get("id", "")),
                        )
                        if remain_duplicates:
                            send_message(
                                args.bot_token,
                                message_chat_id,
                                build_pending_qr_duplicate_message(remain_duplicates),
                                build_qr_duplicate_buttons(remain_duplicates),
                            )
                    continue

            if text.startswith("/helpotp") or text.startswith("/help"):
                send_message(args.bot_token, message_chat_id, build_help())
                continue

            if is_admin_chat and text.strip().lower() in {"/cf", "cf"}:
                duplicate_items = get_pending_qr_duplicates_for_user_or_chat(
                    args.pending_file,
                    message_chat_id,
                    str(user.get("id", "")),
                )
                send_message(
                    args.bot_token,
                    message_chat_id,
                    build_pending_qr_duplicate_message(duplicate_items),
                    build_qr_duplicate_buttons(duplicate_items),
                )
                continue

            if text.startswith("/myid"):
                myid_key = f"myid:{message_chat_id}:{message_id}"
                if check_and_mark_recent_command_key(
                    args.processed_commands_file,
                    myid_key,
                    int(time.time()),
                    ttl_seconds=86400,
                ):
                    print(f"[SKIP] /myid đã xử lý: {myid_key}", flush=True)
                    continue

                send_message(args.bot_token, message_chat_id, build_myid_message(user, args.permission_file))

                if is_employee_chat:
                    permission_data = load_permissions(args.permission_file)
                    if not user_has_permission(permission_data, "get", user):
                        user_id = str(user.get("id", "")).strip()
                        username = str(user.get("username", "")).strip()
                        full_name = build_refresh_actor_name(user)
                        if user_id:
                            req_key = f"permreq:{user_id}"
                            now_req_ts = int(time.time())
                            should_notify_admin = not check_and_mark_recent_command_key(
                                args.processed_commands_file,
                                req_key,
                                now_req_ts,
                                ttl_seconds=90,
                            )

                            if should_notify_admin:
                                req_lines: List[str] = []
                                req_lines.append("📥 Yêu cầu cấp quyền lấy OTP")
                                req_lines.append(f"Tên: {full_name}")
                                req_lines.append(f"Username: @{username}" if username else "Username: (không có)")
                                req_lines.append(f"User ID: {user_id}")
                                req_lines.append(f"Nhóm nhân viên: {args.employee_chat_id}")
                                req_lines.append("")
                                req_lines.append("Admin bấm nút để duyệt nhanh:")
                                send_message(
                                    args.bot_token,
                                    str(args.chat_id),
                                    "\n".join(req_lines),
                                    build_access_request_buttons(user_id),
                                )
                continue

            if is_admin_chat and (text.startswith("/grantotp") or text.startswith("/bd")):
                if not is_chat_admin(args.bot_token, args.chat_id, str(user.get("id", ""))):
                    send_message(args.bot_token, message_chat_id, "❌ Chỉ admin nhóm admin mới được cấp quyền")
                    continue
                grant_text = text
                if text.startswith("/bd"):
                    target = text[len("/bd") :].strip()
                    grant_text = f"/grantotp get {target}"
                report_text, _ = process_grant_command(grant_text, args.permission_file)
                send_message(args.bot_token, message_chat_id, report_text)
                continue

            if is_admin_chat and (text.startswith("/revokeotp") or text.startswith("/delacc")):
                if not is_chat_admin(args.bot_token, args.chat_id, str(user.get("id", ""))):
                    send_message(args.bot_token, message_chat_id, "❌ Chỉ admin nhóm admin mới được thu hồi quyền")
                    continue
                revoke_text = text
                if text.startswith("/delacc"):
                    target = text[len("/delacc") :].strip()
                    revoke_text = f"/revokeotp get {target}"
                report_text, _ = process_revoke_command(revoke_text, args.permission_file)
                send_message(args.bot_token, message_chat_id, report_text)
                continue

            if is_admin_chat and text.strip().lower() in {"ls", "/ls"}:
                if args.google_sheet_id:
                    restore_ok, restore_msg = force_restore_csv_from_google_sheet(
                        args.wps_file,
                        args.google_sheet_id,
                        args.google_sheet_name,
                        args.google_service_account_json,
                        args.google_service_account_file,
                    )
                    print(f"☁️ Pre-read restore: {'OK' if restore_ok else 'FAIL'} | {restore_msg}", flush=True)
                    if not restore_ok:
                        send_message(args.bot_token, message_chat_id, f"❌ Lỗi đọc Google Sheet trước khi gửi ls: {restore_msg}")
                        continue
                caption = f"📄 File OTP mới nhất lúc {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                ok = send_document(args.bot_token, message_chat_id, args.wps_file, caption)
                if not ok:
                    send_message(args.bot_token, message_chat_id, f"❌ Không gửi được file {args.wps_file}")
                continue

            if is_admin_chat and text.startswith("/qr"):
                report_text, ok, qr_path = process_qr_command(text)
                if ok and qr_path:
                    send_message(args.bot_token, message_chat_id, report_text)
                    sent = send_photo(
                        args.bot_token,
                        message_chat_id,
                        qr_path,
                        f"QR migration chứa OTP ({datetime.now().strftime('%Y-%m-%d %H:%M:%S')})",
                    )
                    if not sent:
                        send_message(args.bot_token, message_chat_id, "❌ Không gửi được ảnh QR")
                else:
                    send_message(args.bot_token, message_chat_id, report_text)
                if qr_path and os.path.exists(qr_path):
                    try:
                        os.remove(qr_path)
                    except Exception:
                        pass
                continue

            if is_admin_chat and text.strip().lower() in {"bdls", "/bdls"}:
                send_message(args.bot_token, message_chat_id, build_bdls_message(args.bot_token, args.employee_chat_id, args.permission_file))
                continue

            if is_employee_chat and text.startswith("/getotp"):
                permission_data = load_permissions(args.permission_file)
                if not user_has_permission(permission_data, "get", user):
                    send_message(args.bot_token, message_chat_id, "❌ Bạn chưa được cấp quyền lấy OTP. Gửi /myid rồi nhờ admin cấp quyền.")
                    continue
                if args.google_sheet_id:
                    restore_ok, restore_msg = force_restore_csv_from_google_sheet(
                        args.wps_file,
                        args.google_sheet_id,
                        args.google_sheet_name,
                        args.google_service_account_json,
                        args.google_service_account_file,
                    )
                    print(f"☁️ Pre-getotp(command) restore: {'OK' if restore_ok else 'FAIL'} | {restore_msg}", flush=True)
                    if not restore_ok:
                        send_message(args.bot_token, message_chat_id, f"❌ Lỗi đọc Google Sheet trước khi lấy OTP: {restore_msg}")
                        continue
                report_text, ok = process_getotp(text, args.wps_file)
                reply_markup = build_getotp_reply_markup(report_text) if ok else None
                if ok:
                    send_message(args.bot_token, message_chat_id, report_text, reply_markup)
                else:
                    send_message(args.bot_token, message_chat_id, report_text)
                continue

            if is_employee_chat and not text.startswith("/"):
                permission_data = load_permissions(args.permission_file)
                if not user_has_permission(permission_data, "get", user):
                    send_message(args.bot_token, message_chat_id, "❌ Bạn chưa được cấp quyền lấy OTP. Gửi /myid rồi nhờ admin cấp quyền.")
                    continue
                if args.google_sheet_id:
                    restore_ok, restore_msg = force_restore_csv_from_google_sheet(
                        args.wps_file,
                        args.google_sheet_id,
                        args.google_sheet_name,
                        args.google_service_account_json,
                        args.google_service_account_file,
                    )
                    print(f"☁️ Pre-getotp(text) restore: {'OK' if restore_ok else 'FAIL'} | {restore_msg}", flush=True)
                    if not restore_ok:
                        send_message(args.bot_token, message_chat_id, f"❌ Lỗi đọc Google Sheet trước khi lấy OTP: {restore_msg}")
                        continue
                report_text, ok = process_getotp_query(text, args.wps_file)
                reply_markup = build_getotp_reply_markup(report_text) if ok else None
                if ok:
                    send_message(args.bot_token, message_chat_id, report_text, reply_markup)
                else:
                    send_message(args.bot_token, message_chat_id, report_text)
                continue

            if is_admin_chat and text.startswith("/addotp"):
                if args.google_sheet_id:
                    restore_ok, restore_msg = force_restore_csv_from_google_sheet(
                        args.wps_file,
                        args.google_sheet_id,
                        args.google_sheet_name,
                        args.google_service_account_json,
                        args.google_service_account_file,
                    )
                    print(f"☁️ Pre-write restore: {'OK' if restore_ok else 'FAIL'} | {restore_msg}", flush=True)
                    if not restore_ok:
                        send_message(args.bot_token, message_chat_id, f"❌ Lỗi đọc Google Sheet trước khi add: {restore_msg}")
                        continue
                report_text, ok = process_addotp(text, args.wps_file)
                print(f"🧾 /addotp parsed result: ok={ok}", flush=True)
                if ok:
                    sync_ok, sync_msg = maybe_sync_google_sheet(
                        args.wps_file,
                        args.google_sheet_id,
                        args.google_sheet_name,
                        args.google_service_account_json,
                        args.google_service_account_file,
                    )
                    print(f"☁️ /addotp sync result: {'OK' if sync_ok else 'FAIL'} | {sync_msg}", flush=True)
                    report_text = f"{report_text}\n\n☁️ Google Sheets: {'✅ ' if sync_ok else '❌ '}{sync_msg}"
                sent_ok = send_message(args.bot_token, message_chat_id, report_text)
                print(f"📨 /addotp send report: {'OK' if sent_ok else 'FAIL'}", flush=True)
                if not sent_ok:
                    send_message(
                        args.bot_token,
                        message_chat_id,
                        "❌ Không gửi được báo cáo /addotp (Telegram API lỗi tạm thời).",
                    )
                if ok:
                    caption = f"Cập nhật OTP lúc {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                    doc_ok = send_document(args.bot_token, message_chat_id, args.wps_file, caption)
                    print(f"📎 /addotp send document: {'OK' if doc_ok else 'FAIL'}", flush=True)
                    if not doc_ok:
                        send_message(args.bot_token, message_chat_id, "⚠️ Đã cập nhật nhưng gửi file CSV thất bại.")
                continue

            if is_admin_chat and text.startswith("/c"):
                if args.google_sheet_id:
                    restore_ok, restore_msg = force_restore_csv_from_google_sheet(
                        args.wps_file,
                        args.google_sheet_id,
                        args.google_sheet_name,
                        args.google_service_account_json,
                        args.google_service_account_file,
                    )
                    print(f"☁️ Pre-write restore: {'OK' if restore_ok else 'FAIL'} | {restore_msg}", flush=True)
                report_text, ok = process_change_account_name(text, args.wps_file)
                if ok:
                    sync_ok, sync_msg = maybe_sync_google_sheet(
                        args.wps_file,
                        args.google_sheet_id,
                        args.google_sheet_name,
                        args.google_service_account_json,
                        args.google_service_account_file,
                    )
                    report_text = f"{report_text}\n\n☁️ Google Sheets: {'✅ ' if sync_ok else '❌ '}{sync_msg}"
                send_message(args.bot_token, message_chat_id, report_text)
                if ok:
                    caption = f"Đổi tên OTP lúc {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                    send_document(args.bot_token, message_chat_id, args.wps_file, caption)
                continue

            if is_admin_chat and text.startswith("/delotp"):
                permission_data = load_permissions(args.permission_file)
                is_admin_user = is_chat_admin(args.bot_token, args.chat_id, str(user.get("id", "")))
                if not is_admin_user and not user_has_permission(permission_data, "delete", user):
                    send_message(args.bot_token, message_chat_id, "❌ Bạn chưa được cấp quyền xoá OTP")
                    continue
                if args.google_sheet_id:
                    restore_ok, restore_msg = force_restore_csv_from_google_sheet(
                        args.wps_file,
                        args.google_sheet_id,
                        args.google_sheet_name,
                        args.google_service_account_json,
                        args.google_service_account_file,
                    )
                    print(f"☁️ Pre-write restore: {'OK' if restore_ok else 'FAIL'} | {restore_msg}", flush=True)
                report_text, ok = process_delotp(text, args.wps_file)
                if ok:
                    sync_ok, sync_msg = maybe_sync_google_sheet(
                        args.wps_file,
                        args.google_sheet_id,
                        args.google_sheet_name,
                        args.google_service_account_json,
                        args.google_service_account_file,
                    )
                    report_text = f"{report_text}\n\n☁️ Google Sheets: {'✅ ' if sync_ok else '❌ '}{sync_msg}"
                send_message(args.bot_token, message_chat_id, report_text)
                if ok:
                    caption = f"Đã xoá OTP lúc {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                    send_document(args.bot_token, message_chat_id, args.wps_file, caption)

        save_offset(args.offset_file, offset)

        if args.once:
            return 0

        time.sleep(args.sleep_seconds)


if __name__ == "__main__":
    while True:
        try:
            raise SystemExit(main())
        except SystemExit:
            raise
        except Exception as e:
            print(f"💥 Listener crash ngoài dự kiến: {e}", flush=True)
            traceback.print_exc()
            # Keep process alive on Render by auto-restarting main loop.
            time.sleep(2.0)
