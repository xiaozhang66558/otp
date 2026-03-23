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
import csv
import hmac
import hashlib
import json
import os
import random
import ssl
import struct
import string
import time
import tempfile
import urllib.parse
import urllib.request
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple


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
        return True, "Google Sheet đang trống"

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


def load_permissions(permission_file: str) -> Dict[str, Dict[str, Dict[str, str]]]:
    if not os.path.exists(permission_file):
        return {"get": {}, "delete": {}}

    try:
        with open(permission_file, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return {"get": {}, "delete": {}}

    return {
        "get": data.get("get", {}) if isinstance(data.get("get", {}), dict) else {},
        "delete": data.get("delete", {}) if isinstance(data.get("delete", {}), dict) else {},
    }


def save_permissions(permission_file: str, data: Dict[str, Dict[str, Dict[str, str]]]) -> None:
    with open(permission_file, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2, sort_keys=True)


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
    with open(pending_file, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2, sort_keys=True)


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
    with open(processed_file, "w", encoding="utf-8") as f:
        json.dump({"ids": ids}, f, ensure_ascii=False, indent=2)


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


def remember_qr_duplicate_names(
    pending_file: str,
    chat_id: str,
    user_id: str,
    duplicate_names: List[Dict[str, str]],
) -> int:
    pending = load_pending_qr_renames(pending_file)
    bucket_key = f"{chat_id}:{user_id}"
    items: List[Dict[str, str]] = []

    for rec in duplicate_names:
        idx = str(rec.get("index", "")).strip()
        account_cell = str(rec.get("account_cell", "")).strip()
        secret = str(rec.get("secret", "")).strip()
        if not (idx and account_cell and secret):
            continue
        items.append(
            {
                "index": idx,
                "account_cell": account_cell,
                "secret": secret,
            }
        )

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
        if str((item or {}).get("index", "")).strip() == idx_raw:
            picked_name = str((item or {}).get("account_cell", "")).strip()
            matched = True
            break

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
        idx = str((item or {}).get("index", "")).strip()
        if idx == awaiting_index:
            return {
                "index": idx,
                "account_cell": str((item or {}).get("account_cell", "")).strip(),
            }
    return None


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
    remain: List[Dict[str, str]] = []
    for item in items:
        item_idx = str((item or {}).get("index", "")).strip()
        if item_idx == idx_raw and target is None:
            target = item
        else:
            remain.append(item)

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
        pending[bucket_key] = {
            "updated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "items": remain,
            "awaiting_index": "",
        }
    else:
        pending.pop(bucket_key, None)
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


def extract_otps_from_qr_image(image_path: str) -> List[Dict[str, str]]:
    cv2, decode, otp_pb2 = load_otp_modules()

    img = cv2.imread(image_path)
    if img is None:
        return []

    decoded_objs = decode(img)
    if not decoded_objs:
        return []

    otp_list: List[Dict[str, str]] = []
    seen: Set[str] = set()

    for obj in decoded_objs:
        qr_data = obj.data.decode("utf-8", errors="replace")
        if "otpauth-migration://" not in qr_data or "data=" not in qr_data:
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


def telegram_api(bot_token: str, method: str, payload: Dict[str, str]) -> Dict:
    url = f"https://api.telegram.org/bot{bot_token}/{method}"
    data = urllib.parse.urlencode(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    raw = _urlopen_with_ssl_fallback(req, timeout=40)
    return json.loads(raw)


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
    payload = {"chat_id": chat_id, "text": text}
    if reply_markup:
        payload["reply_markup"] = json.dumps(reply_markup, ensure_ascii=False)
    resp = telegram_api(bot_token, "sendMessage", payload)
    return bool(resp.get("ok"))


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
    resp = telegram_api(bot_token, "editMessageText", payload)
    return bool(resp.get("ok"))


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
    resp = telegram_api(bot_token, "answerCallbackQuery", payload)
    return bool(resp.get("ok"))


def send_document(bot_token: str, chat_id: str, file_path: str, caption: str) -> bool:
    if not os.path.exists(file_path):
        return False

    url = f"https://api.telegram.org/bot{bot_token}/sendDocument"
    boundary = "----otplistener" + "".join(random.choice(string.ascii_letters) for _ in range(16))

    with open(file_path, "rb") as f:
        file_data = f.read()

    filename = os.path.basename(file_path)
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
    matched_rows = [row for row in rows if query_lower in (row.get("Account") or "").lower()]

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
        idx = str(rec.get("index", "")).strip()
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
            return "❌ Ảnh không có QR OTP hợp lệ", False, []

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


def parse_args():
    parser = argparse.ArgumentParser(description="Listen OTP commands from Telegram groups")
    parser.add_argument("--bot-token", default=os.environ.get("TELEGRAM_BOT_TOKEN", ""))
    parser.add_argument("--chat-id", default=os.environ.get("TELEGRAM_CHAT_ID", ""))
    parser.add_argument("--employee-chat-id", default=os.environ.get("EMPLOYEE_TELEGRAM_CHAT_ID", "-1003820328844"))
    parser.add_argument("--wps-file", default="otp_wps.csv")
    parser.add_argument("--offset-file", default="telegram_offset.txt")
    parser.add_argument("--permission-file", default="telegram_permissions.json")
    parser.add_argument("--pending-file", default=os.environ.get("TELEGRAM_QR_PENDING_FILE", "telegram_qr_pending.json"))
    parser.add_argument("--processed-updates-file", default=os.environ.get("TELEGRAM_PROCESSED_UPDATES_FILE", "telegram_processed_updates.json"))
    parser.add_argument("--poll-timeout", type=int, default=30)
    parser.add_argument("--sleep-seconds", type=float, default=1.0)
    parser.add_argument("--google-sheet-id", default=os.environ.get("GOOGLE_SHEET_ID", ""))
    parser.add_argument("--google-sheet-name", default=os.environ.get("GOOGLE_SHEET_NAME", "OTP"))
    parser.add_argument("--google-service-account-file", default=os.environ.get("GOOGLE_SERVICE_ACCOUNT_FILE", ""))
    parser.add_argument("--google-service-account-json", default=os.environ.get("GOOGLE_SERVICE_ACCOUNT_JSON", ""))
    parser.add_argument("--once", action="store_true", help="Run one poll cycle then exit")
    return parser.parse_args()


def send_photo(bot_token: str, chat_id: str, file_path: str, caption: str = "") -> bool:
    if not os.path.exists(file_path):
        return False

    url = f"https://api.telegram.org/bot{bot_token}/sendPhoto"
    boundary = "----otpphoto" + "".join(random.choice(string.ascii_letters) for _ in range(16))

    with open(file_path, "rb") as f:
        file_data = f.read()

    filename = os.path.basename(file_path)
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
    last_sheet_pull_ts = 0.0
    sheet_pull_interval = 20.0
    print("🤖 Telegram listener đang chạy...")
    print(f"📄 File WPS: {args.wps_file}")
    print(f"📌 Chat admin: {args.chat_id}")
    print(f"📌 Chat nhân viên: {args.employee_chat_id}")
    if args.google_sheet_id:
        print(f"☁️ Google Sheet: {args.google_sheet_id} | tab={args.google_sheet_name}")
    else:
        print("☁️ Google Sheet: chưa cấu hình (bỏ qua đồng bộ)")

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
        except Exception as e:
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

            if is_update_already_processed(args.processed_updates_file, int(update_id)):
                print(f"[SKIP] Update đã xử lý trước đó: {update_id}", flush=True)
                save_offset(args.offset_file, offset)
                continue

            # Mark+saving offset early prevents duplicate replies when service restarts/redeploys.
            mark_update_processed(args.processed_updates_file, int(update_id))
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
            is_admin_chat = message_chat_id == str(args.chat_id)
            is_employee_chat = message_chat_id == str(args.employee_chat_id)

            print(
                f"[UPDATE] ID={update_id}, chat_id={message_chat_id}, admin_chat={is_admin_chat}, employee_chat={is_employee_chat}, has_text={bool(text)}, has_photo={bool(msg.get('photo'))}",
                flush=True,
            )
            
            # Debug: In toàn bộ message structure nếu có tin nhắn
            if msg:
                print(f"[DEBUG] Full message: {json.dumps(msg, indent=2, default=str)}", flush=True)

            if not is_admin_chat and not is_employee_chat:
                print(f"[SKIP] Chat ID không match, bỏ qua", flush=True)
                continue

            # Nhóm admin: xử lý ảnh QR trước tiên
            if is_admin_chat and msg.get("photo"):
                print(f"[MAIN] Nhận tin nhắn ảnh từ {message_chat_id}")
                if args.google_sheet_id:
                    restore_ok, restore_msg = force_restore_csv_from_google_sheet(
                        args.wps_file,
                        args.google_sheet_id,
                        args.google_sheet_name,
                        args.google_service_account_json,
                        args.google_service_account_file,
                    )
                    print(f"☁️ Pre-write restore: {'OK' if restore_ok else 'FAIL'} | {restore_msg}", flush=True)
                report_text, ok, duplicate_names = process_qr_photo(args.bot_token, msg, args.wps_file)
                if ok and duplicate_names:
                    pending_count = remember_qr_duplicate_names(
                        args.pending_file,
                        message_chat_id,
                        str(user.get("id", "")),
                        duplicate_names,
                    )
                    if pending_count:
                        tips: List[str] = []
                        tips.append("")
                        tips.append("🛠 OTP trùng tên đang chờ đổi rồi lưu trực tiếp:")
                        tips.append("- Bấm nút bên dưới để chọn OTP cần đổi tên")
                        tips.append("- Hoặc dùng: /renqr stt|ten_moi")
                        tips.append(f"- Đang chờ: {pending_count} OTP")
                        report_text = report_text + "\n" + "\n".join(tips)
                if ok:
                    sync_ok, sync_msg = maybe_sync_google_sheet(
                        args.wps_file,
                        args.google_sheet_id,
                        args.google_sheet_name,
                        args.google_service_account_json,
                        args.google_service_account_file,
                    )
                    report_text = f"{report_text}\n\n☁️ Google Sheets: {'✅ ' if sync_ok else '❌ '}{sync_msg}"
                print(f"[MAIN] Sắp gửi Telegram: {report_text[:50]}...")
                duplicate_buttons = build_qr_duplicate_buttons(duplicate_names) if (ok and duplicate_names) else None
                send_message(args.bot_token, message_chat_id, report_text, duplicate_buttons)
                if ok:
                    caption = f"Cập nhật OTP từ QR lúc {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                    send_document(args.bot_token, message_chat_id, args.wps_file, caption)
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
                continue

            # Kiểm tra tin nhắn text
            if not text:
                continue

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
                    continue

            if text.startswith("/helpotp") or text.startswith("/help"):
                send_message(args.bot_token, message_chat_id, build_help())
                continue

            if text.startswith("/myid"):
                send_message(args.bot_token, message_chat_id, build_myid_message(user, args.permission_file))
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
                report_text, ok = process_addotp(text, args.wps_file)
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
                    caption = f"Cập nhật OTP lúc {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                    send_document(args.bot_token, message_chat_id, args.wps_file, caption)
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
    raise SystemExit(main())
