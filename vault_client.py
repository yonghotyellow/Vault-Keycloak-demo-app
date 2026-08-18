import os
from pathlib import Path

import requests

ENV_PATH = Path(__file__).resolve().parent / ".vault.env"


def _load_env_file():
    if not ENV_PATH.exists():
        return

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
        if key not in os.environ:
            os.environ[key] = value


_load_env_file()

VAULT_ADDR = os.getenv("VAULT_ADDR")
VAULT_ROLE_ID = os.getenv("VAULT_ROLE_ID")
VAULT_SECRET_ID = os.getenv("VAULT_SECRET_ID")
STATIC_ROLE_PATH = os.getenv("STATIC_ROLE_PATH")
VAULT_SKIP_VERIFY = os.getenv("VAULT_SKIP_VERIFY")

class VaultCredentialError(Exception):
    pass


def _approle_login():
    """
    Step 1: exchange ROLE_ID + SECRET_ID for a short-lived Vault token.
    Vault rejects this call outright if the request doesn't originate from
    the CIDR bound on the AppRole (10.0.91.0/24) — that check happens
    entirely on the Vault server side.
    """
    if not VAULT_ROLE_ID or not VAULT_SECRET_ID:
        raise VaultCredentialError(
            "VAULT_ROLE_ID / VAULT_SECRET_ID not set. Export both before starting the app."
        )

    url = f"{VAULT_ADDR.rstrip('/')}/v1/auth/approle/login"
    resp = requests.post(
        url,
        json={"role_id": VAULT_ROLE_ID, "secret_id": VAULT_SECRET_ID},
        verify=not VAULT_SKIP_VERIFY,
        timeout=5,
    )
    if resp.status_code != 200:
        raise VaultCredentialError(
            f"AppRole login failed ({resp.status_code}): {resp.text}"
        )

    return resp.json()["auth"]["client_token"]


def get_db_credentials():
    """
    Step 2: use the token from AppRole login to read the current static
    credential for the DB role. Called fresh on every new DB connection —
    see db.py.
    """
    vault_token = _approle_login()

    url = f"{VAULT_ADDR.rstrip('/')}/v1/{STATIC_ROLE_PATH}"
    resp = requests.get(
        url,
        headers={"X-Vault-Token": vault_token},
        verify=not VAULT_SKIP_VERIFY,
        timeout=5,
    )
    if resp.status_code != 200:
        raise VaultCredentialError(
            f"Vault returned {resp.status_code} reading {STATIC_ROLE_PATH}: {resp.text}"
        )

    data = resp.json().get("data", {})
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        raise VaultCredentialError(f"Unexpected Vault response shape: {data}")

    return username, password
