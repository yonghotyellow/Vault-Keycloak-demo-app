import json
import math
import os
import secrets
import sqlite3
import time
from collections.abc import Mapping
from pathlib import Path

import requests


class KeycloakTokenStoreError(RuntimeError):
    pass


def _token_store_path():
    configured_path = os.getenv("KEYCLOAK_TOKEN_STORE")
    if configured_path:
        return Path(configured_path).expanduser()
    return Path(__file__).resolve().parent / ".keycloak_tokens.sqlite3"


def _connect_token_store():
    path = _token_store_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        pass
    else:
        os.close(descriptor)

    connection = sqlite3.connect(path, timeout=5)
    connection.execute(
        "CREATE TABLE IF NOT EXISTS keycloak_tokens "
        "(session_id TEXT PRIMARY KEY, token_json TEXT NOT NULL)"
    )
    return connection


def save_keycloak_token(token):
    if not isinstance(token, Mapping):
        raise KeycloakTokenStoreError("Cannot store an invalid Keycloak token")

    session_id = secrets.token_urlsafe(32)
    try:
        connection = _connect_token_store()
        try:
            connection.execute(
                "INSERT INTO keycloak_tokens (session_id, token_json) VALUES (?, ?)",
                (session_id, json.dumps(dict(token), separators=(",", ":"))),
            )
            connection.commit()
        finally:
            connection.close()
    except (OSError, sqlite3.Error, TypeError, ValueError) as exc:
        raise KeycloakTokenStoreError("Unable to save the Keycloak token") from exc
    return session_id


def load_keycloak_token(session_id):
    try:
        connection = _connect_token_store()
        try:
            row = connection.execute(
                "SELECT token_json FROM keycloak_tokens WHERE session_id = ?",
                (session_id,),
            ).fetchone()
        finally:
            connection.close()
        token = json.loads(row[0]) if row else None
        if token is not None and not isinstance(token, Mapping):
            raise ValueError("Stored Keycloak token is invalid")
        return token
    except (OSError, sqlite3.Error, TypeError, ValueError) as exc:
        raise KeycloakTokenStoreError("Unable to load the Keycloak token") from exc


def delete_keycloak_token(session_id):
    if not session_id:
        return
    try:
        connection = _connect_token_store()
        try:
            connection.execute(
                "DELETE FROM keycloak_tokens WHERE session_id = ?", (session_id,)
            )
            connection.commit()
        finally:
            connection.close()
    except (OSError, sqlite3.Error) as exc:
        raise KeycloakTokenStoreError("Unable to delete the Keycloak token") from exc


def refresh_stored_keycloak_session(
    session_id,
    token_endpoint,
    client_id,
    client_secret,
    verify=True,
):
    connection = None
    try:
        connection = _connect_token_store()
        connection.execute("PRAGMA busy_timeout = 10000")
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute(
            "SELECT token_json FROM keycloak_tokens WHERE session_id = ?",
            (session_id,),
        ).fetchone()
        if row is None:
            connection.commit()
            return False

        token_state = {"token": json.loads(row[0])}
        if not refresh_keycloak_session(
            token_state,
            token_endpoint,
            client_id,
            client_secret,
            verify=verify,
        ) or keycloak_session_expired(token_state):
            connection.execute(
                "DELETE FROM keycloak_tokens WHERE session_id = ?", (session_id,)
            )
            connection.commit()
            return False

        connection.execute(
            "UPDATE keycloak_tokens SET token_json = ? WHERE session_id = ?",
            (json.dumps(token_state["token"], separators=(",", ":")), session_id),
        )
        connection.commit()
        return True
    except requests.RequestException:
        if connection is not None:
            connection.rollback()
        raise
    except (OSError, sqlite3.Error, TypeError, ValueError) as exc:
        if connection is not None:
            connection.rollback()
        raise KeycloakTokenStoreError(
            "Unable to refresh the stored Keycloak session"
        ) from exc
    finally:
        if connection is not None:
            connection.close()


def clear_keycloak_session(session_data):
    delete_keycloak_token(session_data.get("keycloak_session_id"))
    session_data.clear()


def token_expiry(token, now=None):
    if not isinstance(token, Mapping):
        return None

    try:
        expires_at = token.get("expires_at")
        if expires_at is not None:
            expiry = float(expires_at)
        else:
            expires_in = token.get("expires_in")
            if expires_in is None:
                return None
            expiry = (time.time() if now is None else now) + float(expires_in)
    except (TypeError, ValueError):
        return None

    return expiry if math.isfinite(expiry) else None


def keycloak_session_expired(session_data, now=None):
    is_keycloak_session = any(
        session_data.get(key) is not None
        for key in ("token", "id_token", "keycloak_expires_at")
    )
    if not is_keycloak_session:
        return False

    stored_expiry = session_data.get("keycloak_expires_at")
    if stored_expiry is None:
        stored_expiry = token_expiry(session_data.get("token"))

    try:
        expires_at = float(stored_expiry)
    except (TypeError, ValueError):
        return True

    current_time = time.time() if now is None else now
    return not math.isfinite(expires_at) or expires_at <= current_time


def refresh_keycloak_session(
    session_data,
    token_endpoint,
    client_id,
    client_secret,
    verify=True,
):
    token = session_data.get("token")
    if not isinstance(token, Mapping):
        return False

    refresh_token = token.get("refresh_token")
    if not refresh_token:
        return False

    response = requests.post(
        token_endpoint,
        data={"grant_type": "refresh_token", "refresh_token": refresh_token},
        auth=(client_id, client_secret),
        verify=verify,
        timeout=5,
    )

    try:
        refreshed_token = response.json()
    except ValueError as exc:
        raise ValueError("Keycloak returned an invalid token response") from exc

    if not isinstance(refreshed_token, Mapping):
        raise ValueError("Keycloak returned an invalid token response")

    if response.status_code >= 400:
        if refreshed_token.get("error") == "invalid_grant":
            return False
        response.raise_for_status()

    if not refreshed_token.get("access_token"):
        raise ValueError("Keycloak token response did not contain an access token")

    updated_token = dict(token)
    updated_token.pop("expires_at", None)
    updated_token.update(refreshed_token)
    expires_at = token_expiry(updated_token)
    if expires_at is None:
        raise ValueError("Keycloak token response did not contain a valid expiry")

    updated_token["expires_at"] = expires_at
    session_data["token"] = updated_token
    session_data["keycloak_expires_at"] = expires_at
    return True
