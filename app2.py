from functools import wraps
from datetime import date, datetime, timezone
import json
import os
from pathlib import Path
import threading
from urllib.parse import urlencode

from authlib.integrations.flask_client import OAuth
from flask import Flask, abort, jsonify, redirect, render_template, request, session, url_for
import requests
import urllib3

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

TASKS_FILE = Path(os.getenv(
    "APP2_TASKS_FILE",
    str(Path(__file__).resolve().parent / "instance" / "app2-tasks.json"),
)).resolve()
TASKS_LOCK = threading.Lock()

# Local fallback credentials. Replace these before exposing this app.
APP_USER = "hieutq"
APP_PASS = "1"

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
            session.clear()
            session["logged_in"] = True
            session["user"] = username
            return redirect(url_for("dashboard"))
        return render_template(
            "app2_login.html",
            error="Sai tài khoản hoặc mật khẩu",
            portal_title="Daymark Workboard",
            keycloak_enabled=bool(KEYCLOAK_CLIENT_ID and KEYCLOAK_CLIENT_SECRET),
        )
    if session.get("logged_in"):
        return redirect(url_for("dashboard"))
    return render_template(
        "app2_login.html",
        error=None,
        portal_title="Daymark Workboard",
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
    token = oauth.keycloak.authorize_access_token()
    try:
        userinfo = oauth.keycloak.userinfo(token=token) or {}
    except Exception:
        userinfo = {}

    session.clear()
    session["logged_in"] = True
    session["user"] = (
        userinfo.get("preferred_username")
        or userinfo.get("email")
        or userinfo.get("sub")
        or "keycloak-user"
    )
    session["id_token"] = token.get("id_token") if isinstance(token, dict) else None
    return redirect(url_for("dashboard"))


@app.route("/logout")
def logout():
    id_token = session.get("id_token")
    session.clear()
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
    return render_template(
        "app2_dashboard.html",
        tasks=_get_user_tasks(session.get("user")),
        current_user=session.get("user"),
        portal_title="Daymark Workboard",
    )


def _read_task_store():
    if not TASKS_FILE.exists():
        return {}
    store = json.loads(TASKS_FILE.read_text(encoding="utf-8"))
    if not isinstance(store, dict):
        raise ValueError("Task store must contain a JSON object")
    return store


def _write_task_store(store):
    TASKS_FILE.parent.mkdir(parents=True, exist_ok=True)
    temporary_file = TASKS_FILE.with_suffix(TASKS_FILE.suffix + ".tmp")
    temporary_file.write_text(json.dumps(store, indent=2), encoding="utf-8")
    os.chmod(temporary_file, 0o600)
    temporary_file.replace(TASKS_FILE)


def _get_user_tasks(username):
    with TASKS_LOCK:
        tasks = _read_task_store().get(username, [])
    return sorted(tasks, key=lambda task: (task.get("completed", False), task.get("due_date") or "9999-12-31", -task["id"]))


def _parse_task_fields(data, existing=None):
    if not isinstance(data, dict):
        return None, "Task data must be a JSON object"
    fields = dict(existing) if existing is not None else {
        "notes": "",
        "due_date": "",
        "priority": "medium",
        "completed": False,
    }
    if "title" in data:
        title = str(data.get("title", "")).strip()
        if not title or len(title) > 160:
            return None, "Title is required and must be at most 160 characters"
        fields["title"] = title
    if "notes" in data:
        notes = str(data.get("notes", "")).strip()
        if len(notes) > 1000:
            return None, "Notes must be at most 1000 characters"
        fields["notes"] = notes
    if "due_date" in data:
        due_date = str(data.get("due_date", "")).strip()
        if due_date:
            try:
                date.fromisoformat(due_date)
            except ValueError:
                return None, "Due date must use YYYY-MM-DD format"
        fields["due_date"] = due_date
    if "priority" in data:
        priority = data.get("priority")
        if priority not in ("low", "medium", "high"):
            return None, "Priority must be low, medium, or high"
        fields["priority"] = priority
    if "completed" in data:
        if not isinstance(data["completed"], bool):
            return None, "Completed must be true or false"
        fields["completed"] = data["completed"]
    return fields, None


@app.route("/api/tasks", methods=["POST"])
@login_required
def api_create_task():
    data = request.get_json(silent=True) or {}
    fields, error = _parse_task_fields(data)
    if error or "title" not in fields:
        return jsonify({"ok": False, "error": error or "Title is required"}), 400

    username = session.get("user")
    with TASKS_LOCK:
        store = _read_task_store()
        tasks = store.setdefault(username, [])
        task = {
            **fields,
            "id": max((item["id"] for item in tasks), default=0) + 1,
            "completed": False,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        tasks.append(task)
        _write_task_store(store)
    return jsonify({"ok": True, "task": task}), 201


@app.route("/api/tasks/<int:task_id>", methods=["PATCH", "DELETE"])
@login_required
def api_task(task_id):
    username = session.get("user")
    with TASKS_LOCK:
        store = _read_task_store()
        tasks = store.get(username, [])
        task = next((item for item in tasks if item["id"] == task_id), None)
        if task is None:
            return jsonify({"ok": False, "error": "Not found"}), 404

        if request.method == "DELETE":
            tasks.remove(task)
            _write_task_store(store)
            return jsonify({"ok": True})

        data = request.get_json(silent=True) or {}
        fields, error = _parse_task_fields(data, task)
        if error:
            return jsonify({"ok": False, "error": error}), 400
        task.update(fields)
        _write_task_store(store)
    return jsonify({"ok": True, "task": task})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8003, debug=False)