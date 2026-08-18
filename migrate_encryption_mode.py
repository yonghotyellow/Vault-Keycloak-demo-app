import os
from db import get_connection
from encryption_util import encrypt_fields as encrypt_fernet_fields
from transit_util import encrypt_fields as encrypt_transit_fields


def _encrypt_payload(data, target_table):
    if "transit" in target_table:
        return encrypt_transit_fields(data)
    return encrypt_fernet_fields(data)


def copy_data(source_table, target_table, encrypt_target=False):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                f"SELECT id, full_name, national_id, phone_number, email, bank_account_number, monthly_income, application_status, processed_by, created_at FROM {source_table} ORDER BY id"
            )
            rows = cur.fetchall()
            for row in rows:
                row_id, full_name, national_id, phone_number, email, bank_account_number, monthly_income, application_status, processed_by, created_at = row
                data = {
                    "full_name": full_name,
                    "national_id": national_id,
                    "phone_number": phone_number,
                    "email": email,
                    "bank_account_number": bank_account_number,
                    "monthly_income": monthly_income,
                    "application_status": application_status,
                }
                payload = _encrypt_payload(data, target_table) if encrypt_target else data
                cur.execute(
                    f"""
                    INSERT INTO {target_table}
                    (id, full_name, national_id, phone_number, email, bank_account_number, monthly_income, application_status, processed_by, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (id) DO NOTHING
                    """,
                    (
                        row_id,
                        payload.get("full_name"),
                        payload.get("national_id"),
                        payload.get("phone_number"),
                        email,
                        payload.get("bank_account_number"),
                        payload.get("monthly_income"),
                        payload.get("application_status"),
                        processed_by,
                        created_at,
                    ),
                )
            conn.commit()
            print(f"Copied {len(rows)} rows from {source_table} to {target_table}")
    finally:
        conn.close()


if __name__ == "__main__":
    os.environ.setdefault("ENCRYPT_MODE", "None")
    copy_data("customer_profile", "encrypt_customer_profile", encrypt_target=True)
    copy_data("customer_profile", "transit_customer_profile", encrypt_target=True)
