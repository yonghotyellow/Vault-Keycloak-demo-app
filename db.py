import os
from pathlib import Path

import psycopg2
import psycopg2.extras
from vault_client import get_db_credentials
from encryption_util import decrypt_row as decrypt_fernet_row, encrypt_fields as encrypt_fernet_fields
from transit_util import decrypt_row as decrypt_transit_row, encrypt_fields as encrypt_transit_fields

ENV_PATH = Path(__file__).resolve().parent / ".env"
ENCRYPT_ENV_PATH = Path(__file__).resolve().parent / ".encrypt.env"


def _load_env_file(path):
    if not path.exists():
        return {}

    values = {}
    for line in path.read_text().splitlines():
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


def _load_settings():
    for key, value in _load_env_file(ENV_PATH).items():
        if key not in os.environ:
            os.environ[key] = value

    for key, value in _load_env_file(ENCRYPT_ENV_PATH).items():
        if key not in os.environ:
            os.environ[key] = value


_load_settings()

CUSTOMER_TABLE = os.getenv("CUSTOMER_TABLE")
ENCRYPT_MODE = os.getenv("ENCRYPT_MODE", "None").strip().lower()

if not CUSTOMER_TABLE:
    if ENCRYPT_MODE == "fernet":
        CUSTOMER_TABLE = "encrypt_customer_profile"
    elif ENCRYPT_MODE == "transit":
        CUSTOMER_TABLE = "transit_customer_profile"
    else:
        CUSTOMER_TABLE = "customer_profile"


DB_HOST = os.getenv("DB_HOST")
DB_PORT = os.getenv("DB_PORT")
DB_NAME = os.getenv("DB_NAME")
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_CONNECTION_METHOD = "vault"


def _get_plain_db_credentials():
    if not DB_USER or not DB_PASSWORD:
        raise ValueError(
            "DB_USER and DB_PASSWORD must be set for plain DB connection mode"
        )
    return DB_USER, DB_PASSWORD


def get_connection():
    """
    Support two demo connection paths:
      - plain: read DB_USER / DB_PASSWORD from .env
      - vault: fetch DB credentials from Vault for each connection
    """
    if DB_CONNECTION_METHOD in ("plain", "env", "static"):
        username, password = _get_plain_db_credentials()
    elif DB_CONNECTION_METHOD == "vault":
        username, password = get_db_credentials()
    else:
        raise ValueError(
            f"Unknown DB_CONNECTION_METHOD '{DB_CONNECTION_METHOD}'. "
            "Use 'plain' or 'vault'."
        )

    return psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        dbname=DB_NAME,
        user=username,
        password=password,
        connect_timeout=5,
    )


def get_db_password():
    if DB_CONNECTION_METHOD in ("plain", "env", "static"):
        if not DB_PASSWORD:
            raise ValueError("DB_PASSWORD is not configured for plain DB connection mode")
        return DB_PASSWORD

    if DB_CONNECTION_METHOD == "vault":
        _, password = get_db_credentials()
        return password

    raise ValueError(
        f"Unknown DB_CONNECTION_METHOD '{DB_CONNECTION_METHOD}'. Use 'plain' or 'vault'."
    )


def _normalize_row(row):
    if ENCRYPT_MODE == "fernet":
        return decrypt_fernet_row(row)
    if ENCRYPT_MODE == "transit":
        return decrypt_transit_row(row)
    return row


def list_customers():
    conn = get_connection()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                f"SELECT * FROM {CUSTOMER_TABLE} ORDER BY created_at DESC, id DESC"
            )
            rows = cur.fetchall()
            return [_normalize_row(row) for row in rows]
    finally:
        conn.close()


def list_customers_for_user(username):
    conn = get_connection()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                f"SELECT * FROM {CUSTOMER_TABLE} WHERE processed_by = %s ORDER BY created_at DESC, id DESC",
                (username,),
            )
            rows = cur.fetchall()
            return [_normalize_row(row) for row in rows]
    finally:
        conn.close()


def get_customer(customer_id):
    conn = get_connection()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                f"SELECT * FROM {CUSTOMER_TABLE} WHERE id = %s", (customer_id,)
            )
            row = cur.fetchone()
            return _normalize_row(row)
    finally:
        conn.close()


def create_customer(data, processed_by):
    conn = get_connection()
    try:
        payload = data.copy()
        if ENCRYPT_MODE == "fernet":
            payload = encrypt_fernet_fields(data)
        elif ENCRYPT_MODE == "transit":
            payload = encrypt_transit_fields(data)
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                f"""
                INSERT INTO {CUSTOMER_TABLE}
                    (full_name, national_id, phone_number, email,
                     bank_account_number, monthly_income, application_status, processed_by)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING *;
                """,
                (
                    payload.get("full_name"),
                    payload.get("national_id"),
                    payload.get("phone_number"),
                    payload.get("email"),
                    payload.get("bank_account_number"),
                    payload.get("monthly_income") or None,
                    payload.get("application_status") or "Pending",
                    processed_by,
                ),
            )
            row = cur.fetchone()
        conn.commit()
        return _normalize_row(row)
    finally:
        conn.close()


def update_customer(customer_id, data, processed_by):
    conn = get_connection()
    try:
        payload = data.copy()
        if ENCRYPT_MODE == "fernet":
            payload = encrypt_fernet_fields(data)
        elif ENCRYPT_MODE == "transit":
            payload = encrypt_transit_fields(data)
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                f"""
                UPDATE {CUSTOMER_TABLE}
                SET full_name = %s,
                    national_id = %s,
                    phone_number = %s,
                    email = %s,
                    bank_account_number = %s,
                    monthly_income = %s,
                    application_status = %s,
                    processed_by = %s
                WHERE id = %s
                RETURNING *;
                """,
                (
                    payload.get("full_name"),
                    payload.get("national_id"),
                    payload.get("phone_number"),
                    payload.get("email"),
                    payload.get("bank_account_number"),
                    payload.get("monthly_income") or None,
                    payload.get("application_status") or "Pending",
                    processed_by,
                    customer_id,
                ),
            )
            row = cur.fetchone()
        conn.commit()
        return _normalize_row(row)
    finally:
        conn.close()


def whoami():
    """Returns the DB username currently in use — handy to show on the UI
    that it never changes even as passwords rotate underneath."""
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT current_user;")
            return cur.fetchone()[0]
    finally:
        conn.close()
