from functools import wraps
import os
from pathlib import Path
from urllib.parse import urlencode

from authlib.integrations.flask_client import OAuth
from flask import Flask, abort, redirect, render_template, request, session, url_for
import requests
import urllib3
from keycloak_session import (
    KeycloakTokenStoreError,
    clear_keycloak_session,
    load_keycloak_token,
    refresh_stored_keycloak_session,
    save_keycloak_token,
    token_expiry,
)

app = Flask(__name__)
app.secret_key = os.getenv("APP2_SECRET_KEY", "dev-secret-change-me-app2")
app.config["SESSION_COOKIE_NAME"] = "vault_db_app2_session"

ENV_PATH = Path(__file__).resolve().parent / ".env"


def _load_env_file():
    if not ENV_PATH.exists():
        return

    for line in ENV_PATH.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        os.environ.setdefault(key, value)


_load_env_file()


@app.before_request
def clear_expired_keycloak_session():
    if request.endpoint == "logout":
        return

    session_id = session.get("keycloak_session_id")
    if not session.get("logged_in"):
        return

    if not session_id:
        if any(session.get(key) is not None for key in ("token", "id_token")):
            clear_keycloak_session(session)
        return

    if not all(
        (KEYCLOAK_BASE, KEYCLOAK_REALM, KEYCLOAK_CLIENT_ID, KEYCLOAK_CLIENT_SECRET)
    ):
        clear_keycloak_session(session)
        return

    token_endpoint = (
        f"{KEYCLOAK_BASE.rstrip('/')}/realms/{KEYCLOAK_REALM}/"
        "protocol/openid-connect/token"
    )
    try:
        valid = refresh_stored_keycloak_session(
            session_id,
            token_endpoint,
            KEYCLOAK_CLIENT_ID,
            KEYCLOAK_CLIENT_SECRET,
            verify=not KEYCLOAK_SKIP_VERIFY,
        )
        if not valid:
            clear_keycloak_session(session)
    except (requests.RequestException, ValueError, KeycloakTokenStoreError):
        app.logger.exception("Unable to validate the Keycloak session")
        return "Unable to validate the Keycloak session. Please try again.", 503


# Local fallback credentials. Replace these before exposing this app.
APP_USER = "hieutq"
APP_PASS = "1"

COURSES = [
    {"code": "RH124", "title": "Red Hat System Administration I"},
    {"code": "RH134", "title": "Red Hat System Administration II"},
    {"code": "RH199", "title": "RHCSA Rapid Track Course"},
    {"code": "RH294", "title": "Red Hat Enterprise Linux Automation with Ansible"},
    {"code": "RH342", "title": "Red Hat Enterprise Linux Diagnostics and Troubleshooting"},
    {"code": "RH358", "title": "Red Hat Services Management and Automation"},
    {"code": "RH415", "title": "Red Hat Security: Linux in Physical, Virtual, and Cloud"},
    {"code": "DO180", "title": "Red Hat OpenShift Administration I"},
    {"code": "DO188", "title": "Introduction to Containers with Podman"},
    {"code": "DO280", "title": "Red Hat OpenShift Administration II"},
    {"code": "RH436", "title": "Red Hat Enterprise Linux High Availability Clustering"},
    {"code": "DO380", "title": "Red Hat OpenShift Administration III"},
]

KEYCLOAK_BASE = os.getenv("KEYCLOAK_BASE")
KEYCLOAK_REALM = os.getenv("KEYCLOAK_REALM")
KEYCLOAK_CLIENT_ID = os.getenv("APP2_KEYCLOAK_CLIENT_ID", "demo-app2")
KEYCLOAK_CLIENT_SECRET = os.getenv("APP2_KEYCLOAK_CLIENT_SECRET")
KEYCLOAK_SKIP_VERIFY = os.getenv("KEYCLOAK_SKIP_VERIFY", "false").lower() in (
    "1", "true", "yes"
)

oauth = OAuth(app)
server_metadata = {}
if all((KEYCLOAK_BASE, KEYCLOAK_REALM, KEYCLOAK_CLIENT_ID, KEYCLOAK_CLIENT_SECRET)):
    metadata_url = (
        f"{KEYCLOAK_BASE.rstrip('/')}/realms/{KEYCLOAK_REALM}/"
        ".well-known/openid-configuration"
    )
    if KEYCLOAK_SKIP_VERIFY:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        response = requests.get(metadata_url, verify=False, timeout=5)
        response.raise_for_status()
        server_metadata = response.json()
        oauth.register(
            name="keycloak",
            client_id=KEYCLOAK_CLIENT_ID,
            client_secret=KEYCLOAK_CLIENT_SECRET,
            authorize_url=server_metadata.get("authorization_endpoint"),
            access_token_url=server_metadata.get("token_endpoint"),
            userinfo_endpoint=server_metadata.get("userinfo_endpoint"),
            jwks_uri=server_metadata.get("jwks_uri"),
            server_metadata=server_metadata,
            client_kwargs={"scope": "openid profile email", "verify": False},
        )
    else:
        oauth.register(
            name="keycloak",
            client_id=KEYCLOAK_CLIENT_ID,
            client_secret=KEYCLOAK_CLIENT_SECRET,
            server_metadata_url=metadata_url,
            client_kwargs={"scope": "openid profile email"},
        )


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if username == APP_USER and password == APP_PASS:
            clear_keycloak_session(session)
            session["logged_in"] = True
            session["user"] = username
            return redirect(url_for("dashboard"))
        return render_template(
            "app2_login.html",
            error="Sai tài khoản hoặc mật khẩu",
            portal_title="Amigo Training Portal",
            keycloak_enabled=bool(KEYCLOAK_CLIENT_ID and KEYCLOAK_CLIENT_SECRET),
        )
    if session.get("logged_in"):
        return redirect(url_for("dashboard"))
    return render_template(
        "app2_login.html",
        error=None,
        portal_title="Amigo Training Portal",
        keycloak_enabled=bool(KEYCLOAK_CLIENT_ID and KEYCLOAK_CLIENT_SECRET),
    )


@app.route("/login/keycloak")
def login_keycloak():
    if not oauth.keycloak:
        abort(500, description="Keycloak is not configured")
    redirect_uri = url_for("auth_callback", _external=True)
    return oauth.keycloak.authorize_redirect(redirect_uri)


@app.route("/auth/callback")
def auth_callback():
    token = dict(oauth.keycloak.authorize_access_token())
    clear_keycloak_session(session)
    expires_at = token_expiry(token)
    if expires_at is not None:
        token["expires_at"] = expires_at
    try:
        userinfo = oauth.keycloak.userinfo(token=token) or {}
    except Exception:
        userinfo = {}

    keycloak_session_id = save_keycloak_token(token)
    session["keycloak_session_id"] = keycloak_session_id
    session["logged_in"] = True
    session["user"] = (
        userinfo.get("preferred_username")
        or userinfo.get("email")
        or userinfo.get("sub")
        or "keycloak-user"
    )
    return redirect(url_for("dashboard"))


@app.route("/logout")
def logout():
    stored_token = load_keycloak_token(session.get("keycloak_session_id"))
    id_token = stored_token.get("id_token") if stored_token else None
    clear_keycloak_session(session)
    end_session_url = server_metadata.get("end_session_endpoint")
    if not end_session_url and KEYCLOAK_BASE and KEYCLOAK_REALM:
        end_session_url = (
            f"{KEYCLOAK_BASE.rstrip('/')}/realms/{KEYCLOAK_REALM}/"
            "protocol/openid-connect/logout"
        )
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
    return render_template(
        "app2_dashboard.html",
        portal_title="Amigo Training Portal",
        current_user=session.get("user"),
        courses=COURSES,
    )

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8003, debug=False)