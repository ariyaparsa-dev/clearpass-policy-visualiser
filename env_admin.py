"""
Environments page: add, rename, edit and remove ClearPass environments.

Only a signed-in Administrator can use it. The Administrator role comes from
the RADIUS login of the environment currently selected in the navbar.

Adding an environment follows the same flow as Initial Setup: connection
validation, an optional read-only review of the ClearPass objects the
Visualiser needs, and optional assisted provisioning of those objects.

The initial environment (the one created by Initial Setup) can also be
edited here. Its settings live in the application's own configuration file,
so changing them is handled by cp_default_env and followed by a reload.
"""

import logging
import secrets
import socket
from urllib.parse import urlparse

from flask import (
    Blueprint,
    abort,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_login import current_user
from pyclearpass import ClearPassAPILogin

import cp_default_env
import cp_env
import cp_environments
from auth import login_manager
from cp_netdiag import probe_radius
from cp_provision import (
    plan_visualiser_configuration,
    provision_visualiser_configuration,
)
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

PROVISION_DEFAULTS = {
    "provision_admin_user_id": "vis-admin",
    "provision_helpdesk_user_id": "vis-helpdesk",
}

RADIUS_KEYS = (
    "RADIUS_SERVER",
    "RADIUS_AUTH_PORT",
    "RADIUS_SECRET",
    "RADIUS_NAS_IDENTIFIER",
)


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

    if api_url and (
        parsed.scheme not in {"http", "https"} or not parsed.hostname
    ):
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


def _same_host(first, second):
    return bool(first) and bool(second) and (
        str(first).strip().lower() == str(second).strip().lower()
    )


def _preview_host_warnings(values):
    """
    Warn when a host looks copied from the default environment.

    This is the mistake of leaving the RADIUS or PostgreSQL host on the
    first environment's server while pointing the REST API at a new one.
    """
    try:
        api_host = cp_environments._host(values["CLEARPASS_API_URL"])
        default_host = cp_environments._host(
            cp_environments.environment_settings(
                cp_env.DEFAULT_ENV_ID
            ).get("CLEARPASS_API_URL")
        )
    except Exception:
        return []

    warnings = []

    if not api_host or _same_host(api_host, default_host):
        return warnings

    for label, key in (
        ("RADIUS Server", "RADIUS_SERVER"),
        ("PostgreSQL Host", "CP_SQL_HOST"),
    ):
        host = values.get(key, "")

        if _same_host(host, default_host):
            warnings.append(
                f"{label} ({host}) is the default environment's server, but "
                f"the REST API points at {api_host}. Check this is intended."
            )

    return warnings


def _sql_host_mismatch(values):
    """
    Amber warning when the PostgreSQL host is not the ClearPass API host.

    On a single ClearPass server they are normally the same machine. A
    different host is allowed, so this never blocks saving.
    """
    try:
        api_host = cp_environments._host(values.get("CLEARPASS_API_URL"))
        sql_host = str(values.get("CP_SQL_HOST") or "").strip()

        if not api_host or not sql_host or _same_host(api_host, sql_host):
            return None

        # A host copied from the default environment already has its own,
        # more specific warning.
        default_host = cp_environments._host(
            cp_environments.environment_settings(
                cp_env.DEFAULT_ENV_ID
            ).get("CLEARPASS_API_URL")
        )

        if _same_host(sql_host, default_host):
            return None

        # A name and an IP address can be the same machine.
        try:
            if socket.gethostbyname(api_host) == socket.gethostbyname(sql_host):
                return None
        except Exception:
            pass

    except Exception:
        return None

    return {
        "success": False,
        "warning": True,
        "message": (
            f"The PostgreSQL host ({sql_host}) differs from the ClearPass "
            f"API host ({api_host}). On a single ClearPass server they are "
            "normally the same. Check this is intended."
        ),
    }


def _radius_host_checks(values):
    """
    Non-blocking checks of the RADIUS server field.

    RADIUS uses UDP, so it cannot be tested by connecting. Instead one
    Access-Request is sent for a throw-away user, and any signed answer
    proves the server is reachable, accepts this host and shares the secret.
    Every problem is a warning, because the checklist items here never block
    saving.
    """
    checks = {}

    result = probe_radius(
        values.get("RADIUS_SERVER"),
        values.get("RADIUS_AUTH_PORT"),
        values.get("RADIUS_SECRET"),
        values.get("RADIUS_NAS_IDENTIFIER"),
    )

    # Missing or invalid fields are already reported by the form itself.
    if result["state"] == "ok":
        checks["radius"] = {"success": True, "message": result["message"]}
    elif result["state"] != "bad_input":
        checks["radius"] = {
            "success": False,
            "warning": True,
            "message": result["message"],
        }

    if result["state"] in ("dns", "bad_input"):
        return checks

    radius_host = str(values.get("RADIUS_SERVER") or "").strip()
    api_host = cp_environments._host(values.get("CLEARPASS_API_URL"))

    if api_host and not _same_host(api_host, radius_host):
        try:
            same_machine = (
                socket.gethostbyname(api_host) == socket.gethostbyname(radius_host)
            )
        except Exception:
            same_machine = False

        if not same_machine:
            checks["radius_mismatch"] = {
                "success": False,
                "warning": True,
                "message": (
                    f"The RADIUS server ({radius_host}) differs from the "
                    f"ClearPass API host ({api_host}). On a single ClearPass "
                    "server they are normally the same. Check this is "
                    "intended."
                ),
            }

    return checks


def _default_radius_problem(values, existing):
    """
    A message when the default environment's RADIUS settings were changed
    and the test request to the new server did not get a signed answer.

    Users sign in to an environment through its own RADIUS server, so a
    wrong setting here can stop everyone signing in to it. That is checked
    only for the default environment, because the others can be fixed from
    the default.
    """
    if all(values.get(key, "") == existing.get(key, "") for key in RADIUS_KEYS):
        return None

    radius = _radius_host_checks(values).get("radius")
    confirmed = bool(radius and radius["success"])

    # Never logs the secret; it only records whether the gate applied.
    logger.info(
        "RADIUS settings of the initial environment were changed. The test "
        "request %s.",
        "was answered with the shared secret"
        if confirmed
        else "did not confirm the shared secret",
    )

    if radius and not confirmed:
        return (
            radius["message"]
            + " Saving these RADIUS settings could stop anyone signing in "
            "to this environment."
        )

    return None


def _connection_warnings(values):
    """Non-blocking checks that are useful even when validation failed."""
    warnings = {}

    sql_warning = _sql_host_mismatch(values)

    if sql_warning:
        warnings["sql_host_mismatch"] = sql_warning

    warnings.update(_radius_host_checks(values))

    return warnings


def _extra_checks(values):
    """Additional non-blocking checks shown with the validation results."""
    extra = {}

    problem = check_insight(values)

    if problem is None:
        extra["insight"] = {
            "success": True,
            "message": "ClearPass Insight reachable for Service Hit Counts.",
        }
    else:
        extra["insight"] = {
            "success": False,
            "warning": True,
            "message": problem,
        }

    for index, message in enumerate(_preview_host_warnings(values)):
        extra[f"host_{index}"] = {
            "success": False,
            "warning": True,
            "message": message,
        }

    extra.update(_connection_warnings(values))

    return extra


def _after_save_warnings(env_id, values):
    # The default environment is the one the others are compared with.
    if env_id != cp_env.DEFAULT_ENV_ID:
        for message in cp_environments.host_warnings(env_id, values):
            flash(message, "warning")

    mismatch = _sql_host_mismatch(values)

    if mismatch:
        flash(mismatch["message"], "warning")

    for check in _radius_host_checks(values).values():
        if check.get("warning"):
            flash(check["message"], "warning")

    insight_problem = check_insight(values)

    if insight_problem:
        flash(insight_problem, "warning")


# -------------------------------------------------------------------
# Assisted provisioning
# -------------------------------------------------------------------

def _provisioning_form():
    posted = request.form

    return {
        "assisted_provisioning": posted.get("assisted_provisioning") == "on",
        "provision_admin_user_id": posted.get(
            "provision_admin_user_id", PROVISION_DEFAULTS["provision_admin_user_id"]
        ).strip(),
        "provision_helpdesk_user_id": posted.get(
            "provision_helpdesk_user_id",
            PROVISION_DEFAULTS["provision_helpdesk_user_id"],
        ).strip(),
    }


def _provisioning_id_errors(prov):
    admin_id = prov["provision_admin_user_id"]
    helpdesk_id = prov["provision_helpdesk_user_id"]
    errors = []

    if not admin_id:
        errors.append("Visualiser Administrator username is required.")

    if not helpdesk_id:
        errors.append("Visualiser Helpdesk username is required.")

    if admin_id and admin_id == helpdesk_id:
        errors.append("Administrator and Helpdesk usernames must be different.")

    if any(
        char in value
        for value in (admin_id, helpdesk_id)
        for char in "\r\n\x00"
    ):
        errors.append("Usernames cannot contain line breaks.")

    return errors


def _provisioning_login(values):
    """A temporary API login for the new ClearPass; it is never stored."""
    return ClearPassAPILogin(
        server=values["CLEARPASS_API_URL"],
        granttype="client_credentials",
        clientid=values["CLEARPASS_CLIENT_ID"],
        clientsecret=values["CLEARPASS_CLIENT_SECRET"],
        verify_ssl=values["CLEARPASS_VERIFY_SSL"] == "true",
    )


def _run_plan(values, prov):
    """Read-only inspection of the new ClearPass (GET requests only)."""
    return plan_visualiser_configuration(
        login=_provisioning_login(values),
        admin_user_id=prov["provision_admin_user_id"],
        helpdesk_user_id=prov["provision_helpdesk_user_id"],
        nas_identifier=values["RADIUS_NAS_IDENTIFIER"],
    )


def _password_errors(plan, prov):
    """Passwords are needed only for local users that would be created."""
    posted = request.form

    would_create = {
        item.get("name")
        for item in plan.get("items", [])
        if item.get("object_type") == "local_user"
        and item.get("status") == "would_create"
    }

    errors = []

    for label, user_id, field in (
        ("Administrator", prov["provision_admin_user_id"],
         "provision_admin_password"),
        ("Helpdesk", prov["provision_helpdesk_user_id"],
         "provision_helpdesk_password"),
    ):
        if user_id not in would_create:
            continue

        password = posted.get(field, "")
        confirm = posted.get(f"{field}_confirm", "")

        if not password:
            errors.append(
                f"{label} password is required because the ClearPass local "
                f"user {user_id} will be created."
            )
        elif password != confirm:
            errors.append(f"{label} password entries do not match.")

    return errors


# -------------------------------------------------------------------
# Rendering
# -------------------------------------------------------------------

def _form_defaults():
    form = {"name": "", "production": False, "assisted_provisioning": False}
    form.update(DEFAULTS)
    form.update(PROVISION_DEFAULTS)

    return form


def _render_form(
    mode,
    form,
    errors=None,
    env_id=None,
    status=200,
    validation=None,
    plan=None,
    result=None,
):
    return (
        render_template(
            "environment_form.html",
            mode=mode,
            env_id=env_id,
            is_default=env_id == cp_env.DEFAULT_ENV_ID,
            form=form,
            errors=errors or [],
            labels=LABELS,
            validation=validation,
            provisioning_plan=plan,
            provisioning_result=result,
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


@env_admin_bp.route("/status")
def status():
    """
    The load status of every environment, as JSON.

    The Environments page polls this while an environment is loading, so a
    status of Loading changes to Ready without reloading the page.
    """
    return jsonify(
        {
            environment["id"]: _status(environment["id"])
            for environment in cp_environments.list_environments()
        }
    )


@env_admin_bp.route("/provisioning-preview", methods=["POST"])
def provisioning_preview():
    """
    Read-only review of a new ClearPass, returned as JSON.

    Validates the connection, runs the non-blocking Insight and host checks,
    then inspects which Visualiser objects exist. Nothing is changed in
    ClearPass and nothing is saved.
    """
    prov = _provisioning_form()
    _, values, errors, _ = _parse_form(None)

    if not prov["assisted_provisioning"]:
        errors.append(
            "Enable assisted provisioning before previewing ClearPass changes."
        )

    errors.extend(_provisioning_id_errors(prov))

    if errors:
        return jsonify({"success": False, "errors": errors}), 400

    validation = validate_setup_connectivity(_validation_config(values))

    if not validation["success"]:
        return (
            jsonify(
                {
                    "success": False,
                    "errors": validation["errors"],
                    "validation": {
                        **validation["results"],
                        **_connection_warnings(values),
                    },
                }
            ),
            400,
        )

    results = dict(validation["results"])
    results.update(_extra_checks(values))

    try:
        plan = _run_plan(values, prov)
    except Exception:
        logger.exception("Unable to build the ClearPass provisioning plan.")

        return (
            jsonify(
                {
                    "success": False,
                    "errors": [
                        "Unable to inspect the existing ClearPass "
                        "configuration."
                    ],
                    "validation": results,
                }
            ),
            500,
        )

    preview_errors = []

    if plan.get("error"):
        preview_errors.append(plan["error"])

    preview_errors.extend(_password_errors(plan, prov))

    ok = plan["success"] and not preview_errors

    return (
        jsonify(
            {
                "success": ok,
                "errors": preview_errors,
                "validation": results,
                "provisioning_plan": plan,
            }
        ),
        200 if ok else 400,
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
    prov = _provisioning_form()
    form.update(prov)

    name_error = cp_environments.validate_name(form["name"])

    if name_error:
        errors.insert(0, name_error)

    if prov["assisted_provisioning"]:
        errors.extend(_provisioning_id_errors(prov))

    if errors:
        return _render_form("new", form, errors, status=400)

    validation = validate_setup_connectivity(_validation_config(values))

    if not validation["success"]:
        return _render_form(
            "new",
            form,
            validation["errors"],
            status=400,
            validation={
                **validation["results"],
                **_connection_warnings(values),
            },
        )

    plan = None
    result = None

    if prov["assisted_provisioning"]:
        try:
            plan = _run_plan(values, prov)
        except Exception:
            logger.exception("Unable to build the ClearPass provisioning plan.")

            return _render_form(
                "new",
                form,
                ["Unable to inspect the existing ClearPass configuration."],
                status=500,
                validation=validation["results"],
            )

        if not plan["success"]:
            return _render_form(
                "new",
                form,
                [
                    plan.get("error")
                    or "ClearPass provisioning conflicts were found."
                ],
                status=400,
                validation=validation["results"],
                plan=plan,
            )

        password_errors = _password_errors(plan, prov)

        if password_errors:
            return _render_form(
                "new",
                form,
                password_errors,
                status=400,
                validation=validation["results"],
                plan=plan,
            )

        try:
            result = provision_visualiser_configuration(
                login=_provisioning_login(values),
                admin_user_id=prov["provision_admin_user_id"],
                admin_password=request.form.get("provision_admin_password", ""),
                helpdesk_user_id=prov["provision_helpdesk_user_id"],
                helpdesk_password=request.form.get(
                    "provision_helpdesk_password", ""
                ),
                nas_identifier=values["RADIUS_NAS_IDENTIFIER"],
            )
        except Exception:
            logger.exception("ClearPass assisted provisioning failed.")

            return _render_form(
                "new",
                form,
                ["ClearPass assisted provisioning failed."],
                status=500,
                validation=validation["results"],
                plan=plan,
            )

        if not result["success"]:
            created = [i for i in result["items"] if i.get("created")]

            message = (
                result.get("error") or "ClearPass provisioning did not complete."
            )

            if created:
                message += (
                    " Objects created before the failure were not removed. "
                    "They are listed below."
                )

            return _render_form(
                "new",
                form,
                [message],
                status=500,
                validation=validation["results"],
                plan=plan,
                result=result,
            )

        logger.info(
            "ClearPass provisioning completed for new environment '%s' "
            "by %s.",
            form["name"],
            current_user.username,
        )

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

    if result:
        created_count = sum(1 for i in result["items"] if i.get("created"))
        existing_count = len(result["items"]) - created_count

        flash(
            f"ClearPass provisioning completed: {created_count} created, "
            f"{existing_count} already existed and were left unchanged.",
            "success",
        )

    _after_save_warnings(env_id, merged)

    return redirect(url_for("env_admin.index"))


@env_admin_bp.route("/<env_id>/edit", methods=["GET", "POST"])
def edit(env_id):
    # Imported here because cp_env_web imports this module.
    from cp_env_web import reload_environment

    environment = _existing_or_404(env_id)
    is_default = env_id == cp_env.DEFAULT_ENV_ID

    if is_default:
        # The default environment's settings are the application's own.
        existing = cp_default_env.current_settings(FIELD_TO_KEY.values())
    else:
        existing = dict(cp_environments.environment_settings(env_id))

    if request.method == "GET":
        form = {
            "name": environment["name"],
            "production": environment["production"],
        }

        for field, key in FIELD_TO_KEY.items():
            if field not in SECRET_FIELDS:
                form[field] = existing.get(key) or DEFAULTS.get(field, "")

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

        if is_default and not request.form.get("confirm_radius"):
            problem = _default_radius_problem(values, existing)

            if problem:
                form["radius_blocked"] = True

                return _render_form(
                    "edit", form, [problem], env_id=env_id, status=400
                )

    if is_default:
        merged = dict(existing)
        merged.update(values)

        changes = {
            key: value
            for key, value in values.items()
            if value != existing.get(key, "")
        }

        if changes:
            try:
                cp_default_env.save_default_settings(changes)
            except cp_default_env.SettingsNotSaved as exc:
                return _render_form(
                    "edit", form, [str(exc)], env_id=env_id, status=400
                )
            except OSError:
                logger.exception("The default environment settings were not saved.")

                return _render_form(
                    "edit",
                    form,
                    [
                        "The configuration file could not be written. "
                        "Nothing was changed."
                    ],
                    env_id=env_id,
                    status=500,
                )

        if (
            form["name"] != environment["name"]
            or form["production"] != environment["production"]
        ):
            cp_environments.set_default_metadata(form["name"], form["production"])

        if changed:
            # Everything cached came from the old settings.
            reload_environment(env_id)

        logger.info(
            "Default environment '%s' updated by %s.",
            form["name"],
            current_user.username,
        )

        flash(
            "Environment updated. It is reloading with the new settings."
            if changed
            else "Environment updated.",
            "success",
        )

    else:
        merged = dict(existing)
        merged.update(values)
        merged.setdefault("CP_SQL_SSLMODE", "prefer")
        merged = _ordered_values(form["name"], form["production"], merged)

        cp_environments.write_environment(env_id, merged)

        if changed:
            # Cached data came from the old settings, so start again.
            cp_env.drop_state(env_id)

        logger.info(
            "Environment '%s' updated by %s.",
            form["name"],
            current_user.username,
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
            "The initial environment is created by Initial Setup and "
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
