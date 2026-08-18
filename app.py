from functools import wraps
import os
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, abort
from pathlib import Path
from authlib.integrations.flask_client import OAuth
import requests
import urllib3
from urllib.parse import urlencode

import db

app = Flask(__name__)
app.secret_key = "dev-secret-change-me"


ENV_PATH = Path(__file__).resolve().parent / ".env"


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

# Local fallback credentials (kept for demo/testing)
APP_USER = "hieutq"
APP_PASS = "1"

# Keycloak / OIDC configuration
KEYCLOAK_BASE = os.getenv("KEYCLOAK_BASE")
KEYCLOAK_REALM = os.getenv("KEYCLOAK_REALM")
KEYCLOAK_CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID")
KEYCLOAK_CLIENT_SECRET = os.getenv("KEYCLOAK_CLIENT_SECRET")
KEYCLOAK_SKIP_VERIFY = os.getenv("KEYCLOAK_SKIP_VERIFY", "false").lower() in ("1", "true", "yes")
oauth = OAuth(app)
if KEYCLOAK_CLIENT_ID and KEYCLOAK_CLIENT_SECRET:
    # If skipping TLS verification, fetch metadata manually with verify=False
    if KEYCLOAK_SKIP_VERIFY:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        metadata_url = f"{KEYCLOAK_BASE.rstrip('/')}/realms/{KEYCLOAK_REALM}/.well-known/openid-configuration"
        resp = requests.get(metadata_url, verify=False, timeout=5)
        resp.raise_for_status()
        server_metadata = resp.json()
        # Prefer standard OIDC keys, but fall back to common alternatives
        authorize_url = server_metadata.get("authorization_endpoint") or server_metadata.get("authorize_url")
        token_url = server_metadata.get("token_endpoint") or server_metadata.get("access_token_url")
        userinfo_endpoint = server_metadata.get("userinfo_endpoint")
        jwks_uri = server_metadata.get("jwks_uri")
        # Register with explicit endpoints to avoid missing authorize_url errors
        oauth.register(
            name="keycloak",
            client_id=KEYCLOAK_CLIENT_ID,
            client_secret=KEYCLOAK_CLIENT_SECRET,
            authorize_url=authorize_url,
            access_token_url=token_url,
            userinfo_endpoint=userinfo_endpoint,
            jwks_uri=jwks_uri,
            client_kwargs={"scope": "openid profile email","verify": False},
            server_metadata=server_metadata,
        )
    else:
        oauth.register(
            name="keycloak",
            client_id=KEYCLOAK_CLIENT_ID,
            client_secret=KEYCLOAK_CLIENT_SECRET,
            server_metadata_url=f"{KEYCLOAK_BASE.rstrip('/')}/realms/{KEYCLOAK_REALM}/.well-known/openid-configuration",
            client_kwargs={"scope": "openid profile email"},
        )


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def requires_group(*allowed_groups):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            groups = session.get("groups", []) or []
            if any(g in groups for g in allowed_groups):
                return view(*args, **kwargs)
            abort(403)
        return wrapped
    return decorator


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if username == APP_USER and password == APP_PASS:
            session["logged_in"] = True
            session["user"] = username
            # grant local fallback user full create/view rights for testing
            session["groups"] = ["create_view_all"]
            return redirect(url_for("dashboard"))
        return render_template("login.html", error="Sai tài khoản hoặc mật khẩu")
    if session.get("logged_in"):
        return redirect(url_for("dashboard"))
    return render_template("login.html", error=None)


@app.route("/login/keycloak")
def login_keycloak():
    if not KEYCLOAK_CLIENT_ID or not KEYCLOAK_CLIENT_SECRET:
        return "Keycloak not configured", 500
    redirect_uri = url_for("auth_callback", _external=True)
    return oauth.keycloak.authorize_redirect(redirect_uri)


@app.route("/auth/callback")
def auth_callback():
    token = oauth.keycloak.authorize_access_token()
    # store raw token for debugging
    try:
        session["token"] = token
    except Exception:
        # session may reject non-serializable items; fallback to storing id_token
        session["token"] = {k: v for k, v in (token.items() if isinstance(token, dict) else [])}

    # Try to get userinfo and id_token claims; groups may appear in either
    userinfo = {}
    id_claims = {}
    try:
        userinfo = oauth.keycloak.userinfo(token=token) or {}
    except Exception:
        userinfo = {}

    username = userinfo.get("preferred_username") or userinfo.get("email") or "keycloak-user"
    groups = userinfo.get("groups") or []
    # Persist session
    session["logged_in"] = True
    session["user"] = username
    session["groups"] = groups
    session["id_token_claims"] = id_claims

    # Print token and claims server-side to help debugging
    # print("[DEBUG] Keycloak token:", token)
    print("[DEBUG] userinfo:", userinfo)
    # print("[DEBUG] id_token claims:", id_claims)

    return redirect(url_for("dashboard"))


@app.route("/logout")
def logout():
    id_token = session.get("id_token")
    session.clear()

    if KEYCLOAK_CLIENT_ID and KEYCLOAK_CLIENT_SECRET:
        end_session_url = server_metadata.get("end_session_endpoint")
        if end_session_url:
            params = {
                "post_logout_redirect_uri": url_for("login", _external=True),
                "client_id": KEYCLOAK_CLIENT_ID,
            }
            if id_token:
                params["id_token_hint"] = id_token
            return redirect(f"{end_session_url}?{urlencode(params)}")

    return redirect(url_for("login"))


@app.route("/")
@login_required
def dashboard():
    groups = session.get("groups", []) or []
    # Suggested group names (must be created in Keycloak):
    # - view_all: can only view all customers
    # - create_own: can create customers and view only their own
    # - create_view_all: can create and view all customers
    if "create_own" in groups and "view_all" not in groups and "create_view_all" not in groups:
        customers = db.list_customers_for_user(session.get("user"))
    else:
        customers = db.list_customers()
    db_user = None
    db_password = None
    db_error = None
    try:
        db_user = db.whoami()
        db_password = db.get_db_password()
    except Exception as exc:
        db_error = str(exc)
    return render_template(
        "dashboard.html",
        customers=customers,
        current_user=session.get("user"),
        db_user=db_user,
        db_password=db_password,
        db_error=db_error,
        keycloak_token=session.get("token"),
        id_token_claims=session.get("id_token_claims"),
        groups=session.get("groups", []) or [],
    )


@app.route("/api/customers", methods=["POST"])
@login_required
def api_create_customer():
    data = request.get_json(force=True)
    groups = session.get("groups", []) or []
    # Only users in create_own or create_view_all may create customers
    if not ("create_own" in groups or "create_view_all" in groups):
        return jsonify({"ok": False, "error": "Forbidden"}), 403
    row = db.create_customer(data, processed_by=session.get("user"))
    return jsonify({"ok": True, "customer": row})


@app.route("/api/customers/<int:customer_id>", methods=["GET"])
@login_required
def api_get_customer(customer_id):
    row = db.get_customer(customer_id)
    if not row:
        return jsonify({"ok": False, "error": "Not found"}), 404
    groups = session.get("groups", []) or []
    if "create_own" in groups and "view_all" not in groups and "create_view_all" not in groups:
        if row.get("processed_by") != session.get("user"):
            return jsonify({"ok": False, "error": "Forbidden"}), 403
    return jsonify({"ok": True, "customer": row})


@app.route("/api/customers/<int:customer_id>", methods=["PUT"])
@login_required
def api_update_customer(customer_id):
    data = request.get_json(force=True)
    row = db.get_customer(customer_id)
    if not row:
        return jsonify({"ok": False, "error": "Not found"}), 404
    groups = session.get("groups", []) or []
    # Allow update if user can create and either:
    # - has `create_view_all` (can update any), or
    # - has `create_own` and is the `processed_by` owner.
    if "create_view_all" in groups:
        pass
    elif "create_own" in groups:
        if row.get("processed_by") != session.get("user"):
            return jsonify({"ok": False, "error": "Forbidden"}), 403
    else:
        return jsonify({"ok": False, "error": "Forbidden"}), 403

    row = db.update_customer(customer_id, data, processed_by=session.get("user"))
    return jsonify({"ok": True, "customer": row})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8002, debug=True)
