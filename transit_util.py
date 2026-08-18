import os
import requests
from pathlib import Path

ENV_PATH = Path(__file__).resolve().parent / ".vault.env"


def _load_env_file():
    if not ENV_PATH.exists():
        return {}

    values = {}
    for line in ENV_PATH.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and ((value[0] == value[-1] == '"') or (value[0] == value[-1] == "'")):
            value = value[1:-1]
        values[key] = value
    return values


for key, value in _load_env_file().items():
    if key not in os.environ:
        os.environ[key] = value


VAULT_ADDR = os.getenv("VAULT_ADDR")
VAULT_ROLE_ID = os.getenv("VAULT_ROLE_ID")
VAULT_SECRET_ID = os.getenv("VAULT_SECRET_ID")
VAULT_SKIP_VERIFY = os.getenv("VAULT_SKIP_VERIFY")
TRANSIT_PATH = os.getenv("TRANSIT_PATH", "transit")
TRANSIT_KEY_NAME = os.getenv("TRANSIT_KEY_NAME", "vault-db-key")

SENSITIVE_FIELDS = ("national_id", "phone_number", "bank_account_number", "monthly_income")


class TransitError(Exception):
    pass


def _get_vault_token():
    if not VAULT_ROLE_ID or not VAULT_SECRET_ID:
        raise TransitError("VAULT_ROLE_ID / VAULT_SECRET_ID must be configured")

    url = f"{VAULT_ADDR.rstrip('/')}/v1/auth/approle/login"
    response = requests.post(
        url,
        json={"role_id": VAULT_ROLE_ID, "secret_id": VAULT_SECRET_ID},
        verify=not str(VAULT_SKIP_VERIFY).lower() in {"1", "true", "yes"},
        timeout=5,
    )
    if response.status_code != 200:
        raise TransitError(f"Vault login failed: {response.status_code} {response.text}")

    return response.json()["auth"]["client_token"]


def _call_transit(action, payload_value):
    token = _get_vault_token()
    url = f"{VAULT_ADDR.rstrip('/')}/v1/{TRANSIT_PATH}/encrypt/{TRANSIT_KEY_NAME}"
    if action == "decrypt":
        url = f"{VAULT_ADDR.rstrip('/')}/v1/{TRANSIT_PATH}/decrypt/{TRANSIT_KEY_NAME}"

    payload = {"plaintext": payload_value}
    if action == "decrypt":
        payload = {"ciphertext": payload_value}

    response = requests.post(
        url,
        headers={"X-Vault-Token": token},
        json=payload,
        verify=not str(VAULT_SKIP_VERIFY).lower() in {"1", "true", "yes"},
        timeout=5,
    )
    if response.status_code != 200:
        raise TransitError(f"Vault transit {action} failed: {response.status_code} {response.text}")

    data = response.json().get("data", {})
    if action == "encrypt":
        return data["ciphertext"]
    return data["plaintext"]


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

    import base64

    plaintext = base64.b64encode(value.encode("utf-8")).decode("utf-8")
    return _call_transit("encrypt", plaintext)


def decrypt_value(value, field_name=None):
    if value is None:
        return None

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return value

    if not isinstance(value, str):
        return value

    import base64

    try:
        plaintext_b64 = _call_transit("decrypt", value)
    except Exception:
        return value

    try:
        decoded = base64.b64decode(plaintext_b64.encode("utf-8")).decode("utf-8")
    except Exception:
        return plaintext_b64

    if field_name == "monthly_income":
        try:
            return int(float(decoded))
        except (TypeError, ValueError):
            return decoded

    return decoded


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
