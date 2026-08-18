import os
from pathlib import Path

from cryptography.fernet import Fernet

BASE_DIR = Path(__file__).resolve().parent
KEY_FILE = BASE_DIR / ".encryption.key"


def _load_or_create_key():
    if KEY_FILE.exists():
        key = KEY_FILE.read_bytes().strip()
        if key:
            return key

    key = Fernet.generate_key()
    KEY_FILE.write_bytes(key + b"\n")
    return key


_KEY = _load_or_create_key()
_FERNET = Fernet(_KEY)

SENSITIVE_FIELDS = ("national_id", "phone_number", "bank_account_number", "monthly_income")


def encrypt_value(value, field_name=None):
    if value is None:
        return None

    if isinstance(value, bool):
        value = str(value)
    elif isinstance(value, (int, float)):
        value = str(value)
    elif not isinstance(value, str):
        value = str(value)

    if value == "":
        return None

    return _FERNET.encrypt(value.encode("utf-8")).decode("utf-8")


def decrypt_value(value, field_name=None):
    if value is None:
        return None

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return value

    if not isinstance(value, str):
        return value

    try:
        decrypted = _FERNET.decrypt(value.encode("utf-8")).decode("utf-8")
    except Exception:
        return value

    if field_name == "monthly_income":
        try:
            return int(float(decrypted))
        except (TypeError, ValueError):
            return decrypted

    return decrypted


def encrypt_fields(payload):
    if not payload:
        return payload

    encrypted = dict(payload)
    for field in SENSITIVE_FIELDS:
        if field in encrypted:
            encrypted[field] = encrypt_value(encrypted[field], field_name=field)
    return encrypted


def decrypt_row(row):
    if not row:
        return row

    decrypted = dict(row)
    for field in SENSITIVE_FIELDS:
        if field in decrypted:
            decrypted[field] = decrypt_value(decrypted[field], field_name=field)
    return decrypted
