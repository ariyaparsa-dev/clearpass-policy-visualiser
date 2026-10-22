"""
Environments page: add, rename, edit and remove ClearPass environments.

Only a signed-in Administrator can use it. The Administrator role comes from
the RADIUS login of the environment currently selected in the navbar.
"""

import logging
import secrets
from urllib.parse import urlparse

from flask import (
    Blueprint,
    abort,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_login import current_user

import cp_env
import cp_environments
from auth import login_manager
from cp_setup import validate_setup_connectivity

logger = logging.getLogger(__name__)

env_admin_bp = Blueprint("env_admin", __name__, url_prefix="/environments")

# form field -> key in the environment file
FIELD_TO_KEY = {
    "api_url": "CLEARPASS_API_URL",
    "client_id": "CLEARPASS_CLIENT_ID",
    "client_secret": "CLEARPASS_CLIENT_SECRET",
    "verify_ssl": "CLEARPASS_VERIFY_SSL",
    "radius_server": "RADIUS_SERVER",
    "radius_port": "RADIUS_AUTH_PORT",
    "radius_secret": "RADIUS_SECRET",
    "nas_identifier": "RADIUS_NAS_IDENTIFIER",
    "sql_host": "CP_SQL_HOST",
    "sql_port": "CP_SQL_PORT",
    "sql_database": "CP_SQL_DATABASE",
    "sql_username": "CP_SQL_USERNAME",
    "sql_password": "CP_SQL_PASSWORD",
}

SECRET_FIELDS = {"client_secret", "radius_secret", "sql_password"}

LABELS = {
    "api_url": "ClearPass API URL",
    "client_id": "ClearPass Client ID",
    "client_secret": "ClearPass Client Secret",
    "verify_ssl": "SSL verification setting",
    "radius_server": "RADIUS Server",
    "radius_port": "RADIUS Port",
    "radius_secret": "RADIUS Shared Secret",
    "nas_identifier": "NAS Identifier",
    "sql_host": "PostgreSQL Host",
    "sql_port": "PostgreSQL Port",
    "sql_database": "PostgreSQL Database",
    "sql_username": "PostgreSQL Username",
    "sql_password": "PostgreSQL Password",
}

DEFAULTS = {
    "verify_ssl": "false",
    "radius_port": "1812",
    "nas_identifier": "clearpass-policy-visualiser",
    "sql_port": "5432",
    "sql_database": "tipsdb",
    "sql_username": "appexternal",
}


# -------------------------------------------------------------------
# Access control and CSRF
# -------------------------------------------------------------------


def _csrf_token():
    token = session.get("_csrf")

    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf"] = token

    return token


@env_admin_bp.app_context_processor
def _inject_csrf():
    return {"csrf_token": _csrf_token}


@env_admin_bp.before_request
def _require_admin():
    if not current_user.is_authenticated:
        return login_manager.unauthorized()

    if getattr(current_user, "role", None) != "Admin":
        abort(403)

    if request.method == "POST":
        expected = session.get("_csrf", "")
        sent = request.form.get("csrf_token", "")

        if not expected or not secrets.compare_digest(sent, expected):
            abort(400)

    return None


@env_admin_bp.after_request
def _no_store(response):
    response.headers["Cache-Control"] = "no-store"
    return response


# -------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------


def _status(env_id):
    state = cp_env.peek_state(env_id)

    if state is None:
        return "Not loaded"

    if state.load_status == "loading":
        return "Loading"

    if state.initialised:
        return "Ready"

    if state.load_status == "error":
        return "Error"

    return "Not loaded"


def _is_loading(env_id):
    state = cp_env.peek_state(env_id)
    return bool(state and state.load_status == "loading")


def _api_host(env_id):
    try:
        settings = cp_environments.environment_settings(env_id)
    except cp_environments.UnknownEnvironment:
        return ""

    return cp_environments._host(settings.get("CLEARPASS_API_URL"))


def _valid_port(value):
    return value.isdigit() and 1 <= int(value) <= 65535


def _parse_form(existing):
    """
    Read and validate the environment form.

    Returns (display_values, env_values, errors, connection_changed).
    Blank secrets keep the existing value when editing.
    """
    posted = request.form

    display = {
        "name": posted.get("name", "").strip(),
        "production": posted.get("production") == "on",
    }
    values = {}
    errors = []

    for field, key in FIELD_TO_KEY.items():
        label = LABELS[field]

        if field in SECRET_FIELDS:
            entered = posted.get(field, "")
            confirm = posted.get(f"{field}_confirm", "")

            if entered:
                if entered != confirm:
                    errors.append(f"{label} entries do not match.")
                values[key] = entered
            elif existing and existing.get(key):
                values[key] = existing[key]
            else:
                errors.append(f"{label} is required.")
                values[key] = ""
        else:
            entered = posted.get(field, "").strip()
            display[field] = entered
            values[key] = entered

            if not entered:
                errors.append(f"{label} is required.")

    for key, value in values.items():
        if any(char in value for char in "\r\n\x00"):
            errors.append("Values cannot contain line breaks.")
            break

    api_url = values["CLEARPASS_API_URL"]
    parsed = urlparse(api_url)

    if api_url and (parsed.scheme not in {"http", "https"} or not parsed.hostname):
        errors.append(
            "ClearPass API URL must start with https:// and include a host."
        )

    for field in ("radius_port", "sql_port"):
        value = values[FIELD_TO_KEY[field]]
        if value and not _valid_port(value):
            errors.append(f"{LABELS[field]} must be a number from 1 to 65535.")

    if values["CLEARPASS_VERIFY_SSL"] not in {"true", "false"}:
        errors.append("Invalid ClearPass SSL verification setting.")

    for field in ("radius_server", "sql_host"):
        if " " in values[FIELD_TO_KEY[field]]:
            errors.append(f"{LABELS[field]} cannot contain spaces.")

    if existing is None:
        changed = True
    else:
        changed = any(
            values.get(key, "") != existing.get(key, "")
            for key in FIELD_TO_KEY.values()
        )

    return display, values, errors, changed


def _validation_config(values):
    return {
        "clearpass_api_url": values["CLEARPASS_API_URL"],
        "clearpass_client_id": values["CLEARPASS_CLIENT_ID"],
        "clearpass_client_secret": values["CLEARPASS_CLIENT_SECRET"],
        "clearpass_verify_ssl": values["CLEARPASS_VERIFY_SSL"],
        "sql_host": values["CP_SQL_HOST"],
        "sql_port": values["CP_SQL_PORT"],
        "sql_database": values["CP_SQL_DATABASE"],
        "sql_username": values["CP_SQL_USERNAME"],
        "sql_password": values["CP_SQL_PASSWORD"],
    }


def check_insight(values):
    """
    Check that Insight is reachable for Service Hit Counts.

    Returns a warning message, or None when the check passes. This never
    blocks saving, because Hit Counts fall back to n/a when Insight is
    unavailable.
    """
    try:
        import psycopg

        with psycopg.connect(
            host=values["CP_SQL_HOST"],
            port=5433,
            dbname="insightdb",
            user=values["CP_SQL_USERNAME"],
            password=values["CP_SQL_PASSWORD"],
            sslmode=values.get("CP_SQL_SSLMODE", "prefer"),
            connect_timeout=3,
        ) as connection:
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1 FROM public.auth LIMIT 1")
                cursor.fetchall()
    except Exception as exc:
        return (
            "ClearPass Insight could not be queried "
            f"({type(exc).__name__}). Service Hit Counts will show n/a for "
            "this environment until the database is reachable on port 5433."
        )

    return None


def _after_save_warnings(env_id, values):
    for message in cp_environments.host_warnings(env_id, values):
        flash(message, "warning")

    insight_problem = check_insight(values)

    if insight_problem:
        flash(insight_problem, "warning")


def _form_defaults():
    form = {"name": "", "production": False}
    form.update(DEFAULTS)
    return form


def _render_form(mode, form, errors=None, env_id=None, status=200):
    return (
        render_template(
            "environment_form.html",
            mode=mode,
            env_id=env_id,
            is_default=env_id == cp_env.DEFAULT_ENV_ID,
            form=form,
            errors=errors or [],
            labels=LABELS,
        ),
        status,
    )


def _ordered_values(name, production, merged):
    ordered = {
        "ENV_NAME": name,
        "ENV_PRODUCTION": "true" if production else "false",
    }

    for key, value in merged.items():
        if key not in ordered:
            ordered[key] = value

    return ordered


def _existing_or_404(env_id):
    if env_id != cp_env.DEFAULT_ENV_ID and not cp_environments.is_valid_id(env_id):
        abort(404)

    if not cp_environments.is_known(env_id):
        abort(404)

    return cp_environments.get_environment(env_id)


# -------------------------------------------------------------------
# Routes
# -------------------------------------------------------------------


@env_admin_bp.route("/")
def index():
    rows = []

    for environment in cp_environments.list_environments():
        rows.append(
            dict(
                environment,
                host=_api_host(environment["id"]),
                status=_status(environment["id"]),
                is_default=environment["id"] == cp_env.DEFAULT_ENV_ID,
                is_active=environment["id"] == cp_env.current_env_id(),
            )
        )

    return render_template(
        "environments.html",
        environments=rows,
        can_add=len(rows) < cp_environments.MAX_ENVIRONMENTS,
        maximum=cp_environments.MAX_ENVIRONMENTS,
    )


@env_admin_bp.route("/new", methods=["GET", "POST"])
def new():
    if len(cp_environments.list_environments()) >= cp_environments.MAX_ENVIRONMENTS:
        flash(
            f"A maximum of {cp_environments.MAX_ENVIRONMENTS} environments "
            "is supported. Remove one before adding another.",
            "danger",
        )
        return redirect(url_for("env_admin.index"))

    if request.method == "GET":
        return _render_form("new", _form_defaults())

    form, values, errors, _ = _parse_form(None)

    name_error = cp_environments.validate_name(form["name"])
    if name_error:
        errors.insert(0, name_error)

    if errors:
        return _render_form("new", form, errors, status=400)

    validation = validate_setup_connectivity(_validation_config(values))

    if not validation["success"]:
        return _render_form("new", form, validation["errors"], status=400)

    values["CP_SQL_SSLMODE"] = "prefer"

    env_id = cp_environments.make_environment_id(form["name"])
    merged = _ordered_values(form["name"], form["production"], values)

    cp_environments.write_environment(env_id, merged)

    logger.info(
        "Environment '%s' added by %s.", form["name"], current_user.username
    )

    flash(
        f"Environment '{form['name']}' added. Choose it from the "
        "Environment menu and sign in with its ClearPass RADIUS account. "
        "It loads the first time you open it.",
        "success",
    )
    _after_save_warnings(env_id, merged)

    return redirect(url_for("env_admin.index"))


@env_admin_bp.route("/<env_id>/edit", methods=["GET", "POST"])
def edit(env_id):
    environment = _existing_or_404(env_id)
    is_default = env_id == cp_env.DEFAULT_ENV_ID

    if is_default:
        if request.method == "GET":
            return _render_form(
                "edit",
                {
                    "name": environment["name"],
                    "production": environment["production"],
                },
                env_id=env_id,
            )

        form = {
            "name": request.form.get("name", "").strip(),
            "production": request.form.get("production") == "on",
        }

        name_error = cp_environments.validate_name(
            form["name"], exclude_id=env_id
        )

        if name_error:
            return _render_form(
                "edit", form, [name_error], env_id=env_id, status=400
            )

        cp_environments.set_default_metadata(form["name"], form["production"])

        logger.info(
            "Default environment renamed to '%s' by %s.",
            form["name"],
            current_user.username,
        )
        flash("Environment updated.", "success")
        return redirect(url_for("env_admin.index"))

    existing = dict(cp_environments.environment_settings(env_id))

    if request.method == "GET":
        form = {
            "name": environment["name"],
            "production": environment["production"],
        }
        for field, key in FIELD_TO_KEY.items():
            if field not in SECRET_FIELDS:
                form[field] = existing.get(key, DEFAULTS.get(field, ""))

        return _render_form("edit", form, env_id=env_id)

    form, values, errors, changed = _parse_form(existing)

    name_error = cp_environments.validate_name(form["name"], exclude_id=env_id)
    if name_error:
        errors.insert(0, name_error)

    if changed and _is_loading(env_id):
        errors.append(
            "This environment is loading. Wait for it to finish before "
            "changing its connection settings."
        )

    if errors:
        return _render_form("edit", form, errors, env_id=env_id, status=400)

    if changed:
        validation = validate_setup_connectivity(_validation_config(values))

        if not validation["success"]:
            return _render_form(
                "edit", form, validation["errors"], env_id=env_id, status=400
            )

    merged = dict(existing)
    merged.update(values)
    merged.setdefault("CP_SQL_SSLMODE", "prefer")
    merged = _ordered_values(form["name"], form["production"], merged)

    cp_environments.write_environment(env_id, merged)

    if changed:
        # Cached data came from the old settings, so start again.
        cp_env.drop_state(env_id)

    logger.info(
        "Environment '%s' updated by %s.", form["name"], current_user.username
    )
    flash("Environment updated.", "success")

    if changed:
        _after_save_warnings(env_id, merged)

    return redirect(url_for("env_admin.index"))


@env_admin_bp.route("/<env_id>/delete", methods=["POST"])
def delete(env_id):
    environment = _existing_or_404(env_id)

    if env_id == cp_env.DEFAULT_ENV_ID:
        flash(
            "The default environment is set up through Initial Setup and "
            "cannot be removed here.",
            "danger",
        )
        return redirect(url_for("env_admin.index"))

    if env_id == cp_env.current_env_id():
        flash(
            "You are using this environment. Switch to another one first.",
            "danger",
        )
        return redirect(url_for("env_admin.index"))

    if _is_loading(env_id):
        flash(
            "This environment is loading. Try again when it has finished.",
            "danger",
        )
        return redirect(url_for("env_admin.index"))

    cp_environments.delete_environment(env_id)
    cp_env.drop_state(env_id)

    logger.info(
        "Environment '%s' removed by %s.",
        environment["name"],
        current_user.username,
    )
    flash(f"Environment '{environment['name']}' removed.", "success")

    return redirect(url_for("env_admin.index"))
