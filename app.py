import logging
import os
import secrets
import time
from datetime import timedelta
from urllib.parse import urlparse

import requests
from cp_env_web import init_environment_support 
from dotenv import load_dotenv
from flask import (
    Flask,
    abort,
    jsonify,
    redirect,
    render_template,
    render_template_string,
    request,
    session,
    url_for,
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import current_user, login_required
from pyclearpass import ClearPassAPILogin
from contextlib import contextmanager

from auth import login_manager
from auth.routes import auth_bp
from cp_provision import (
    plan_visualiser_configuration,
    provision_visualiser_configuration,
)
from cp_setup import (
    is_setup_complete,
    save_setup_configuration,
    validate_setup_connectivity,
)

from cp_paths import (
    get_flask_secret_file,
    get_visualiser_env_file,
)

from cp_unused_objects import get_unused_object_summary

from cp_object_graph import (
    build_enforcement_policy_graph,
    build_role_mapping_graph,
)

from cp_impact_analysis import (
    analyse_enforcement_policy,
    analyse_enforcement_profile,
    analyse_role,
    analyse_role_mapping_policy,
)

from cp_impact_lookup import (
    build_impact_analysis_lookup_cache,
)

from cp_role_references import (
    build_role_reference_cache,
)

import cp_cache
import cp_env

load_dotenv(
    get_visualiser_env_file(),
    override=True,
)


from cp_endpoint import (
    format_mac_with_hyphens,
    get_endpoint_profile_value,
    get_matching_repository_objects,
    preload_endpoint_data,
)

from cp_enforcement import (
    ENFORCEMENT_POLICY_CACHE,
    ENFORCEMENT_POLICY_LOOKUP_CACHE,
    PROFILE_CACHE,
    build_profile_reference_cache,
    get_enforcement_details,
    get_enforcement_profile,
)

from cp_graph import build_service_graph
from cp_health import check_clearpass
from cp_role_mapping import (
    ROLE_CACHE,
    ROLE_MAPPING_CACHE,
    build_role_cache,
    build_role_mapping_reference_cache,
    get_role_mapping_details,
)
from cp_services import (
    get_all_services_with_hit_counts,
    get_service,
)
from version import VERSION


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(env_tag)s%(message)s",
    datefmt="%d-%m-%Y %H:%M:%S",
)

logger = logging.getLogger(__name__)

radius_server = os.getenv("RADIUS_SERVER")

if radius_server:
    logger.info(
        "RADIUS_SERVER=%s",
        radius_server,
    )


app = Flask(__name__)

FLASK_SECRET_FILE = get_flask_secret_file()


def get_flask_secret_key():
    """Return the configured or persistent generated Flask secret."""

    env_secret = os.getenv("FLASK_SECRET_KEY")

    if env_secret:
        return env_secret

    if os.path.exists(FLASK_SECRET_FILE):

        if os.name == "posix":
            os.chmod(
                FLASK_SECRET_FILE,
                0o600,
            )

        with open(
            FLASK_SECRET_FILE,
            "r",
            encoding="utf-8",
        ) as secret_file:
            existing_secret = secret_file.read().strip()

        if existing_secret:
            return existing_secret

    new_secret = secrets.token_hex(32)

    with open(
        FLASK_SECRET_FILE,
        "w",
        encoding="utf-8",
    ) as secret_file:
        secret_file.write(new_secret)

    if os.name == "posix":
        os.chmod(
            FLASK_SECRET_FILE,
            0o600,
        )

    logger.info(
        "Generated new Flask session secret."
    )

    return new_secret


app.config["SECRET_KEY"] = get_flask_secret_key()
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = (
    os.getenv(
        "SESSION_COOKIE_SECURE",
        "false",
    ).lower()
    == "true"
)
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=8)

login_manager.init_app(app)
app.register_blueprint(auth_bp)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[],
    storage_uri="memory://",
)

limiter.limit("10 per minute")(
    app.view_functions["auth.login"]
)


# -------------------------------------------------
# ClearPass unreachable
#
# Pages such as Visualise and Impact Analysis fetch live
# ClearPass data. When ClearPass cannot be reached, show a
# short page and log one line instead of a 500 error and a
# full traceback.
# -------------------------------------------------

_UNREACHABLE_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>ClearPass unreachable - ClearPass Policy Visualiser</title>
<style>
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
background:#0f172a;color:#e2e8f0;font-family:Arial,Helvetica,sans-serif}
.panel{width:min(480px,92%);padding:32px;background:#1e293b;border:1px solid #475569;
border-radius:12px;text-align:center}
.icon{width:48px;height:48px;margin:0 auto 18px;border-radius:50%;display:flex;
align-items:center;justify-content:center;background:#450a0a;border:1px solid #991b1b;
color:#ef4444;font-size:26px;font-weight:700}
h2{margin:0 0 10px;font-size:22px}
p{margin:0;color:#cbd5e1;font-size:14px;line-height:1.6}
a{display:inline-block;margin-top:22px;padding:10px 20px;border-radius:6px;
background:#01A982;color:#001b14;font-weight:700;text-decoration:none}
</style>
</head>
<body>
<div class="panel">
<div class="icon">!</div>
<h2>ClearPass is unreachable</h2>
<p>{{ host }} could not be reached, so this page could not be loaded.
The dashboard still shows the data loaded earlier.</p>
<a href="{{ url_for('home') }}">Back to dashboard</a>
</div>
</body>
</html>
"""


@app.errorhandler(requests.exceptions.ConnectionError)
@app.errorhandler(requests.exceptions.Timeout)
def clearpass_unreachable(exc):
    """
    A page that needs live ClearPass data was opened while ClearPass
    could not be reached.
    """
    host = (
        urlparse(cp_env.getenv("CLEARPASS_API_URL", "") or "").hostname
        or "The ClearPass server"
    )

    logger.error(
        "ClearPass unreachable while opening %s %s (%s: %s).",
        request.method,
        request.path,
        host,
        type(exc).__name__,
    )

    if request.path.startswith("/api/"):
        return jsonify({"error": f"{host} is unreachable."}), 503

    return render_template_string(_UNREACHABLE_PAGE, host=host), 503


@app.context_processor
def inject_auth_context():
    return {
        "logged_in_user": (
            current_user
            if current_user.is_authenticated
            else None
        ),
        "logged_in_role": (
            getattr(current_user, "role", None)
            if current_user.is_authenticated
            else None
        ),
    }


@app.before_request
def log_request():
    logger.info(
        "%s %s",
        request.method,
        request.path,
    )


@app.before_request
def require_initial_setup():
    if is_setup_complete():
        # Once configured, Initial Setup can no longer be submitted.
        if (
            request.endpoint == "setup_provisioning_preview"
            or (request.endpoint == "setup" and request.method == "POST")
        ):
            abort(403)
        return None

    allowed_endpoints = {
        "setup",
        "setup_provisioning_preview",
        "setup_complete",
        "start_visualiser",
        "static",
    }

    if request.endpoint in allowed_endpoints:
        return None

    return redirect(url_for("setup"))


def build_provisioning_login(config):
    """Build a temporary pyclearpass login for setup planning/provisioning."""

    return ClearPassAPILogin(
        server=config["clearpass_api_url"],
        granttype="client_credentials",
        clientid=config["clearpass_client_id"],
        clientsecret=config["clearpass_client_secret"],
        verify_ssl=(
            config["clearpass_verify_ssl"]
            == "true"
        ),
    )


def render_setup(
    *,
    errors=None,
    form=None,
    validation=None,
    provisioning_plan=None,
    provisioning_result=None,
):
    """Render Initial Setup using one consistent template context."""

    return render_template(
        "setup.html",
        version=VERSION,
        errors=errors,
        form=form,
        validation=validation,
        provisioning_plan=provisioning_plan,
        provisioning_result=provisioning_result,
    )


@app.route(
    "/setup/provisioning-preview",
    methods=["POST"],
)
def setup_provisioning_preview():
    """Return a read-only ClearPass provisioning preview as JSON."""

    clearpass_verify_ssl = (
        request.form.get("clearpass_verify_ssl", "false")
        .strip()
        .lower()
    )

    config = {
        "clearpass_api_url": request.form.get(
            "clearpass_api_url", ""
        ).strip(),
        "clearpass_client_id": request.form.get(
            "clearpass_client_id", ""
        ).strip(),
        "clearpass_client_secret": request.form.get(
            "clearpass_client_secret", ""
        ),
        "clearpass_verify_ssl": clearpass_verify_ssl,
        "radius_server": request.form.get(
            "radius_server", ""
        ).strip(),
        "radius_port": request.form.get(
            "radius_port", "1812"
        ).strip(),
        "radius_secret": request.form.get(
            "radius_secret", ""
        ),
        "nas_identifier": request.form.get(
            "nas_identifier", "clearpass-policy-visualiser"
        ).strip(),
        "sql_host": request.form.get(
            "sql_host", ""
        ).strip(),
        "sql_port": request.form.get(
            "sql_port", "5432"
        ).strip(),
        "sql_database": request.form.get(
            "sql_database", "tipsdb"
        ).strip(),
        "sql_username": request.form.get(
            "sql_username", "appexternal"
        ).strip(),
        "sql_password": request.form.get(
            "sql_password", ""
        ),
    }

    admin_user_id = request.form.get(
        "provision_admin_user_id", "vis-admin"
    ).strip()

    helpdesk_user_id = request.form.get(
        "provision_helpdesk_user_id", "vis-helpdesk"
    ).strip()

    errors = []

    if request.form.get("assisted_provisioning", "") != "on":
        errors.append(
            "Enable assisted provisioning before previewing "
            "ClearPass changes."
        )

    if not config["clearpass_api_url"]:
        errors.append(
            "ClearPass API URL is required."
        )

    if not config["clearpass_client_id"]:
        errors.append(
            "ClearPass Client ID is required."
        )

    if not config["clearpass_client_secret"]:
        errors.append(
            "ClearPass Client Secret is required."
        )
    elif (
        config["clearpass_client_secret"]
        != request.form.get(
            "clearpass_client_secret_confirm",
            ""
        )
    ):
        errors.append(
            "ClearPass Client Secret entries do not match."
        )

    if clearpass_verify_ssl not in {
        "true",
        "false",
    }:
        errors.append(
            "Invalid ClearPass SSL verification setting."
        )

    if not config["radius_server"]:
        errors.append(
            "RADIUS Server is required."
        )

    if not config["radius_secret"]:
        errors.append(
            "RADIUS Shared Secret is required."
        )
    elif (
        config["radius_secret"]
        != request.form.get(
            "radius_secret_confirm",
            ""
        )
    ):
        errors.append(
            "RADIUS Shared Secret entries do not match."
        )

    if not config["nas_identifier"]:
        errors.append(
            "NAS Identifier is required for ClearPass provisioning."
        )

    if not admin_user_id:
        errors.append(
            "Visualiser Administrator username is required."
        )

    if not helpdesk_user_id:
        errors.append(
            "Visualiser Helpdesk username is required."
        )

    if (
        admin_user_id
        and admin_user_id == helpdesk_user_id
    ):
        errors.append(
            "Administrator and Helpdesk usernames must be different."
        )

    if not config["sql_host"]:
        errors.append(
            "PostgreSQL Host is required."
        )

    if not config["sql_password"]:
        errors.append(
            "PostgreSQL Password is required."
        )
    elif (
        config["sql_password"]
        != request.form.get(
            "sql_password_confirm",
            ""
        )
    ):
        errors.append(
            "PostgreSQL Password entries do not match."
        )

    if errors:

        return jsonify(
            {
                "success": False,
                "errors": errors,
            }
        ), 400

    validation = validate_setup_connectivity(
        config
    )

    if not validation["success"]:

        return jsonify(
            {
                "success": False,
                "errors": validation["errors"],
                "validation": validation["results"],
            }
        ), 400

    try:

        provisioning_login = build_provisioning_login(
            config
        )

        plan = plan_visualiser_configuration(
            login=provisioning_login,
            admin_user_id=admin_user_id,
            helpdesk_user_id=helpdesk_user_id,
            nas_identifier=config["nas_identifier"],
        )

    except Exception:

        logger.exception(
            "Unable to build ClearPass AJAX provisioning plan."
        )

        return jsonify(
            {
                "success": False,
                "errors": [
                    "Unable to inspect the existing "
                    "ClearPass configuration."
                ],
                "validation": validation["results"],
            }
        ), 500

    preview_errors = []

    if plan.get("error"):

        preview_errors.append(
            plan["error"]
        )

    plan_items = plan.get(
        "items",
        []
    )

    plan_by_name = {
        item.get("name"): item
        for item in plan_items
    }

    admin_user_plan = plan_by_name.get(
        admin_user_id,
        {}
    )

    helpdesk_user_plan = plan_by_name.get(
        helpdesk_user_id,
        {}
    )

    admin_password = request.form.get(
        "provision_admin_password",
        ""
    )

    admin_password_confirm = request.form.get(
        "provision_admin_password_confirm",
        ""
    )

    helpdesk_password = request.form.get(
        "provision_helpdesk_password",
        ""
    )

    helpdesk_password_confirm = request.form.get(
        "provision_helpdesk_password_confirm",
        ""
    )

    # -------------------------------------------------
    # Validate passwords only for missing Local Users
    # -------------------------------------------------

    if (
        admin_user_plan.get("status")
        == "would_create"
    ):

        if not admin_password:

            preview_errors.append(
                "Administrator password is required "
                "because the ClearPass local user "
                f"{admin_user_id} will be created."
            )

        elif not admin_password_confirm:

            preview_errors.append(
                "Confirm Administrator Password is "
                "required because the ClearPass local "
                f"user {admin_user_id} will be created."
            )

        elif (
            admin_password
            != admin_password_confirm
        ):

            preview_errors.append(
                "Administrator password entries "
                "do not match."
            )

    if (
        helpdesk_user_plan.get("status")
        == "would_create"
    ):

        if not helpdesk_password:

            preview_errors.append(
                "Helpdesk password is required "
                "because the ClearPass local user "
                f"{helpdesk_user_id} will be created."
            )

        elif not helpdesk_password_confirm:

            preview_errors.append(
                "Confirm Helpdesk Password is required "
                "because the ClearPass local user "
                f"{helpdesk_user_id} will be created."
            )

        elif (
            helpdesk_password
            != helpdesk_password_confirm
        ):

            preview_errors.append(
                "Helpdesk password entries "
                "do not match."
            )

    preview_success = (
        plan["success"]
        and not preview_errors
    )

    status_code = (
        200
        if preview_success
        else 400
    )

    return jsonify(
        {
            "success": preview_success,
            "errors": preview_errors,
            "validation": validation[
                "results"
            ],
            "provisioning_plan": plan,
        }
    ), status_code

@app.route(
    "/setup",
    methods=["GET", "POST"],
)
def setup():
    if (
        request.method == "GET"
        and is_setup_complete()
    ):
        return redirect(
            url_for("home")
        )

    if request.method == "POST":

        setup_action = (
            request.form.get(
                "setup_action",
                "save",
            )
            .strip()
            .lower()
        )

        assisted_provisioning = (
            request.form.get(
                "assisted_provisioning",
                "",
            )
            == "on"
        )

        provision_admin_user_id = (
            request.form.get(
                "provision_admin_user_id",
                "vis-admin",
            ).strip()
        )

        provision_helpdesk_user_id = (
            request.form.get(
                "provision_helpdesk_user_id",
                "vis-helpdesk",
            ).strip()
        )

        provision_admin_password = request.form.get(
            "provision_admin_password",
            "",
        )
        provision_admin_password_confirm = request.form.get(
            "provision_admin_password_confirm",
            "",
        )
        provision_helpdesk_password = request.form.get(
            "provision_helpdesk_password",
            "",
        )
        provision_helpdesk_password_confirm = request.form.get(
            "provision_helpdesk_password_confirm",
            "",
        )

        clearpass_verify_ssl = (
            request.form.get(
                "clearpass_verify_ssl",
                "false",
            )
            .strip()
            .lower()
        )

        config = {
            # ClearPass REST API
            "clearpass_api_url": request.form.get(
                "clearpass_api_url",
                "",
            ).strip(),
            "clearpass_client_id": request.form.get(
                "clearpass_client_id",
                "",
            ).strip(),
            "clearpass_client_secret": request.form.get(
                "clearpass_client_secret",
                "",
            ),
            "clearpass_verify_ssl": clearpass_verify_ssl,
            # RADIUS Authentication
            "radius_server": request.form.get(
                "radius_server",
                "",
            ).strip(),
            "radius_port": request.form.get(
                "radius_port",
                "1812",
            ).strip(),
            "radius_secret": request.form.get(
                "radius_secret",
                "",
            ),
            "nas_identifier": request.form.get(
                "nas_identifier",
                "clearpass-policy-visualiser",
            ).strip(),

            # PostgreSQL Endpoint Profiling
            "sql_host": request.form.get(
                "sql_host",
                "",
            ).strip(),
            "sql_port": request.form.get(
                "sql_port",
                "5432",
            ).strip(),
            "sql_database": request.form.get(
                "sql_database",
                "tipsdb",
            ).strip(),
            "sql_username": request.form.get(
                "sql_username",
                "appexternal",
            ).strip(),
            "sql_password": request.form.get(
                "sql_password",
                "",
            ),
        }

        form_data = dict(config)
        form_data.update(
            {
                "assisted_provisioning": assisted_provisioning,
                "provision_admin_user_id": provision_admin_user_id,
                "provision_helpdesk_user_id": provision_helpdesk_user_id,
            }
        )

        clearpass_client_secret_confirm = request.form.get(
            "clearpass_client_secret_confirm",
            "",
        )
        radius_secret_confirm = request.form.get(
            "radius_secret_confirm",
            "",
        )
        sql_password_confirm = request.form.get(
            "sql_password_confirm",
            "",
        )

        errors = []

        # -------------------------------------------------
        # ClearPass REST API validation
        # -------------------------------------------------

        if not config["clearpass_api_url"]:
            errors.append(
                "ClearPass API URL is required."
            )

        if not config["clearpass_client_id"]:
            errors.append(
                "ClearPass Client ID is required."
            )

        if not config["clearpass_client_secret"]:
            errors.append(
                "ClearPass Client Secret is required."
            )
        elif not clearpass_client_secret_confirm:
            errors.append(
                "Confirm ClearPass Client Secret is required."
            )
        elif (
            config["clearpass_client_secret"]
            != clearpass_client_secret_confirm
        ):
            errors.append(
                "ClearPass Client Secret entries do not match."
            )

        if clearpass_verify_ssl not in {
            "true",
            "false",
        }:
            errors.append(
                "Invalid ClearPass SSL verification setting."
            )

        # -------------------------------------------------
        # RADIUS validation
        # -------------------------------------------------

        if not config["radius_server"]:
            errors.append(
                "RADIUS Server is required."
            )

        if not config["radius_secret"]:
            errors.append(
                "RADIUS Shared Secret is required."
            )
        elif not radius_secret_confirm:
            errors.append(
                "Confirm RADIUS Shared Secret is required."
            )
        elif (
            config["radius_secret"]
            != radius_secret_confirm
        ):
            errors.append(
                "RADIUS Shared Secret entries do not match."
            )

        # -------------------------------------------------
        # Assisted provisioning validation
        # -------------------------------------------------

        if assisted_provisioning:
            if not provision_admin_user_id:
                errors.append(
                    "Visualiser Administrator username is required."
                )

            if not provision_helpdesk_user_id:
                errors.append(
                    "Visualiser Helpdesk username is required."
                )

            if (
                provision_admin_user_id
                and provision_helpdesk_user_id
                and provision_admin_user_id
                == provision_helpdesk_user_id
            ):
                errors.append(
                    "Administrator and Helpdesk usernames must be different."
                )

            if not config["nas_identifier"]:
                errors.append(
                    "NAS Identifier is required for ClearPass provisioning."
                )

        if (
            setup_action == "preview"
            and not assisted_provisioning
        ):
            errors.append(
                "Enable assisted provisioning before previewing "
                "ClearPass changes."
            )


        # -------------------------------------------------
        # PostgreSQL Endpoint Profiling validation
        # -------------------------------------------------

        if not config["sql_host"]:
            errors.append(
                "PostgreSQL Host is required."
            )

        if not config["sql_password"]:
            errors.append(
                "PostgreSQL Password is required."
            )
        elif not sql_password_confirm:
            errors.append(
                "Confirm PostgreSQL Password is required."
            )
        elif (
            config["sql_password"]
            != sql_password_confirm
        ):
            errors.append(
                "PostgreSQL Password entries do not match."
            )

        if errors:
            return render_setup(
                errors=errors,
                form=form_data,
            )

        # -------------------------------------------------
        # Validate connectivity
        # -------------------------------------------------

        validation = validate_setup_connectivity(
            config
        )

        if not validation["success"]:
            return render_setup(
                errors=validation["errors"],
                form=form_data,
                validation=validation["results"],
            )

        provisioning_plan = None
        provisioning_result = None

        # -------------------------------------------------
        # Assisted ClearPass provisioning
        # -------------------------------------------------

        if assisted_provisioning:
            try:
                provisioning_login = build_provisioning_login(
                    config
                )

                provisioning_plan = plan_visualiser_configuration(
                    login=provisioning_login,
                    admin_user_id=provision_admin_user_id,
                    helpdesk_user_id=provision_helpdesk_user_id,
                    nas_identifier=config["nas_identifier"],
                )
            except Exception:
                logger.exception(
                    "Unable to build ClearPass provisioning plan."
                )

                return render_setup(
                    errors=[
                        "Unable to inspect the existing ClearPass "
                        "configuration."
                    ],
                    form=form_data,
                    validation=validation["results"],
                )

            if not provisioning_plan["success"]:
                return render_setup(
                    errors=[
                        provisioning_plan.get("error")
                        or "ClearPass provisioning conflicts were found."
                    ],
                    form=form_data,
                    validation=validation["results"],
                    provisioning_plan=provisioning_plan,
                )

            if setup_action == "preview":
                logger.info(
                    "ClearPass provisioning preview completed."
                )

                return render_setup(
                    form=form_data,
                    validation=validation["results"],
                    provisioning_plan=provisioning_plan,
                )

            plan_items = provisioning_plan.get(
                "items",
                [],
            )
            plan_by_name = {
                item.get("name"): item
                for item in plan_items
            }

            admin_user_plan = plan_by_name.get(
                provision_admin_user_id,
                {},
            )
            helpdesk_user_plan = plan_by_name.get(
                provision_helpdesk_user_id,
                {},
            )

            provisioning_errors = []

            if (
                admin_user_plan.get("status")
                == "would_create"
            ):
                if not provision_admin_password:
                    provisioning_errors.append(
                        "Administrator password is required because the "
                        "ClearPass user will be created."
                    )
                elif (
                    provision_admin_password
                    != provision_admin_password_confirm
                ):
                    provisioning_errors.append(
                        "Administrator password entries do not match."
                    )

            if (
                helpdesk_user_plan.get("status")
                == "would_create"
            ):
                if not provision_helpdesk_password:
                    provisioning_errors.append(
                        "Helpdesk password is required because the "
                        "ClearPass user will be created."
                    )
                elif (
                    provision_helpdesk_password
                    != provision_helpdesk_password_confirm
                ):
                    provisioning_errors.append(
                        "Helpdesk password entries do not match."
                    )

            if provisioning_errors:
                return render_setup(
                    errors=provisioning_errors,
                    form=form_data,
                    validation=validation["results"],
                    provisioning_plan=provisioning_plan,
                )

            if setup_action in {
                "provision",
                "save",
            }:
                try:
                    provisioning_result = (
                        provision_visualiser_configuration(
                            login=provisioning_login,
                            admin_user_id=provision_admin_user_id,
                            admin_password=provision_admin_password,
                            helpdesk_user_id=provision_helpdesk_user_id,
                            helpdesk_password=provision_helpdesk_password,
                            nas_identifier=config["nas_identifier"],
                        )
                    )
                except Exception:
                    logger.exception(
                        "ClearPass assisted provisioning failed."
                    )

                    return render_setup(
                        errors=[
                            "ClearPass assisted provisioning failed."
                        ],
                        form=form_data,
                        validation=validation["results"],
                        provisioning_plan=provisioning_plan,
                    )

                if not provisioning_result["success"]:
                    return render_setup(
                        errors=[
                            provisioning_result.get("error")
                            or "ClearPass provisioning did not complete."
                        ],
                        form=form_data,
                        validation=validation["results"],
                        provisioning_plan=provisioning_plan,
                        provisioning_result=provisioning_result,
                    )

                logger.info(
                    "ClearPass assisted provisioning completed successfully."
                )

                provision_admin_password = None
                provision_admin_password_confirm = None
                provision_helpdesk_password = None
                provision_helpdesk_password_confirm = None

        # -------------------------------------------------
        # Save configuration
        # -------------------------------------------------

        save_setup_configuration(
            config
        )

        load_dotenv(
            get_visualiser_env_file(),
            override=True,
        )

        if not is_setup_complete():
            return render_setup(
                errors=[
                    "Configuration was saved, but setup is still incomplete."
                ],
                form=form_data,
                validation=validation["results"],
                provisioning_plan=provisioning_plan,
                provisioning_result=provisioning_result,
            )

        logger.info(
            "Initial setup configuration loaded successfully."
        )

        session.clear()

        logger.info(
            "Existing user session cleared after initial setup."
        )

        session["setup_validation"] = validation["results"]

        if provisioning_result:
            session["setup_provisioning"] = provisioning_result

        return redirect(
            url_for("setup_complete")
        )

    return render_setup()


@app.route("/setup-complete")
def setup_complete():
    if not is_setup_complete():
        return redirect(
            url_for("setup")
        )

    validation = session.pop(
        "setup_validation",
        None,
    )
    provisioning = session.pop(
        "setup_provisioning",
        None,
    )

    return render_template(
        "setup_complete.html",
        version=VERSION,
        validation=validation,
        provisioning=provisioning,
    )


@app.route(
    "/start-visualiser",
    methods=["POST"],
)
def start_visualiser():
    if not is_setup_complete():
        return redirect(
            url_for("setup")
        )

    logger.info(
        "Starting ClearPass Policy Visualiser after initial setup..."
    )

    try:
        initialise_cache()
    except Exception:
        logger.exception(
            "ClearPass Policy Visualiser initialisation failed."
        )

        return render_template(
            "setup_complete.html",
            version=VERSION,
            errors=[
                "The Visualiser could not be started. Check the ClearPass "
                "configuration and application log, then try again."
            ],
        )

    logger.info(
        "ClearPass Policy Visualiser started successfully."
    )

    return redirect(
        url_for("home")
    )


@app.route("/")
@login_required
def home():

    if not cp_cache.initialised:
        logger.warning(
            "Dashboard requested while Visualiser "
            "cache initialisation is incomplete."
        )

        return (
            "ClearPass Policy Visualiser data "
            "initialisation is incomplete. "
            "Check the application log for details.",
            503,
        )

    if (
        cp_cache.health_cache is None
        or time.time()
        - cp_cache.health_cache_time
        > 60
    ):
        logger.info(
            "Refreshing health cache..."
        )

        cp_cache.health_cache = check_clearpass()
        cp_cache.health_cache_time = time.time()

    health = cp_cache.health_cache
    services = cp_cache.services_cache

    real_services = [
        service
        for service in services
        if not service.get(
            "name",
            "",
        ).startswith("--------")
    ]

    hit_counts = [
        int(service["hit_count"])
        for service in real_services
        if service.get("hit_count") is not None
    ]

    top_hits = max(hit_counts) if hit_counts else None
    least_hits = min(hit_counts) if hit_counts else None

    stats = {
        "total_services": len(real_services),
        "enabled_services": len(
            [
                service
                for service in real_services
                if service.get("enabled")
            ]
        ),

        "top_hits": top_hits,
        "least_hits": least_hits,
        "endpoint_count": len(
            cp_env.current_state().fingerprint_cache or {}
        ),

        "tacacs_services": len(
            [
                service
                for service in real_services
                if service.get("type") == "TACACS"
            ]
        ),
        "mac_authentication": len(
            [
                service
                for service in real_services
                if service.get("template")
                == "MAC Authentication"
            ]
        ),
        "application_services": len(
            [
                service
                for service in real_services
                if service.get("type") == "Application"
            ]
        ),
        "webauth_services": len(
            [
                service
                for service in real_services
                if service.get("type") == "WEBAUTH"
            ]
        ),
        "wired_8021x": len(
            [
                service
                for service in real_services
                if service.get("template") == "802.1X Wired"
            ]
        ),
        "wireless_8021x": len(
            [
                service
                for service in real_services
                if service.get("template")
                in (
                    "802.1X Wireless",
                    "Aruba 802.1X Wireless",
                )
            ]
        ),
    }

    unused = cp_cache.unused_objects_cache

    return render_template(
        "index.html",
        services=services,
        health=health,
        stats=stats,
        unused=unused,
        last_refresh=cp_cache.last_refresh,
        load_timings=getattr(cp_env.current_state(), "load_timings", None),
        version=VERSION,
    )

@app.route(
    "/api/impact-analysis/lookup"
)
@login_required
def impact_analysis_lookup():
    """
    Search the cached Impact Analysis object inventory.
    """

    search_text = str(
        request.args.get(
            "q",
            ""
        )
    ).strip()

    object_type = str(
        request.args.get(
            "type",
            "all"
        )
    ).strip()

    valid_types = {
        "all",
        "enforcement_profile",
        "enforcement_policy",
        "role_mapping_policy",
        "role",
    }

    if object_type not in valid_types:

        return jsonify(
            {
                "results": [],
                "error": (
                    "Invalid Impact Analysis object type."
                ),
            }
        ), 400

    if len(search_text) < 2:

        return jsonify(
            {
                "results": [],
            }
        )

    search_text_normalised = (
        search_text.casefold()
    )

    lookup_cache = (
        cp_cache
        .impact_analysis_lookup_cache
        or []
    )

    matching_entries = []

    for entry in lookup_cache:

        if not isinstance(
            entry,
            dict,
        ):

            continue

        entry_type = str(
            entry.get(
                "type",
                ""
            )
        ).strip()

        if (
            object_type != "all"
            and
            entry_type != object_type
        ):

            continue

        entry_name = str(
            entry.get(
                "name",
                ""
            )
        ).strip()

        if not entry_name:
            continue

        entry_name_normalised = (
            entry_name.casefold()
        )

        if (
            search_text_normalised
            not in entry_name_normalised
        ):

            continue

        match_priority = 2

        if (
            entry_name_normalised
            ==
            search_text_normalised
        ):

            match_priority = 0

        elif entry_name_normalised.startswith(
            search_text_normalised
        ):

            match_priority = 1

        matching_entries.append(
            {
                "name": entry_name,
                "type": entry_type,
                "type_label": str(
                    entry.get(
                        "type_label",
                        ""
                    )
                ).strip(),
                "match_priority": (
                    match_priority
                ),
            }
        )

    matching_entries = sorted(
        matching_entries,
        key=lambda entry: (
            entry[
                "match_priority"
            ],
            entry[
                "name"
            ].casefold(),
            entry[
                "type_label"
            ].casefold(),
        ),
    )

    results = []

    for entry in matching_entries[
        :20
    ]:

        entry_type = entry[
            "type"
        ]

        entry_name = entry[
            "name"
        ]

        if (
            entry_type
            ==
            "enforcement_profile"
        ):

            impact_url = url_for(
                "enforcement_profile_impact_analysis",
                name=entry_name,
            )

        elif (
            entry_type
            ==
            "enforcement_policy"
        ):

            impact_url = url_for(
                "enforcement_policy_impact_analysis",
                name=entry_name,
            )

        elif (
            entry_type
            ==
            "role_mapping_policy"
        ):
            impact_url = url_for(
                "role_mapping_policy_impact_analysis",
                name=entry_name,
            )
        elif (
            entry_type
            ==
            "role"
        ):
            impact_url = url_for(
                "role_impact_analysis",
                name=entry_name,
            )
        else:
            continue

        results.append(
            {
                "name": entry_name,
                "type": entry_type,
                "type_label": entry[
                    "type_label"
                ],
                "url": impact_url,
            }
        )

    return jsonify(
        {
            "results": results,
            "total_matches": len(
                matching_entries
            ),
            "result_limit": 20,
        }
    )

@app.route("/refresh-cache", methods=["POST"])
@login_required

def refresh_cache():
    expected = session.get("_csrf", "")
    sent = request.form.get("csrf_token", "")

    if not expected or not secrets.compare_digest(sent, expected):
        abort(400)

    logger.info("Refreshing ClearPass caches...")
    _begin_timings("Refresh")

    # Check ClearPass first. If it cannot be reached, keep the data that is
    # already loaded instead of clearing it and failing part-way.
    with _timed("Health check"):
        health = check_clearpass()
        cp_cache.health_cache = health
        cp_cache.health_cache_time = time.time()

    if not health.get("connected"):
        logger.warning(
            "Refresh skipped: ClearPass is unreachable (%s). The previously "
            "loaded data is kept.",
            health.get("error") or "unknown error",
        )
        return redirect(url_for("home"))

    cp_cache.initialised = False

    cp_cache.services_cache = []
    cp_cache.profile_reference_cache = {}
    cp_cache.role_mapping_reference_cache = {}
    cp_cache.policy_reference_cache = {}
    cp_cache.role_cache = {}
    cp_cache.role_reference_cache = {}
    cp_cache.impact_analysis_lookup_cache = []
    cp_cache.unused_objects_cache = None

    PROFILE_CACHE.clear()
    ENFORCEMENT_POLICY_CACHE.clear()
    ENFORCEMENT_POLICY_LOOKUP_CACHE.clear()
    ROLE_MAPPING_CACHE.clear()
    ROLE_CACHE.clear()

    with _timed("Services and Hit Counts") as step:
        cp_cache.services_cache = sorted(
            get_all_services_with_hit_counts(),
            key=lambda service: service["order_no"],
        )
        step["detail"] = f"{len(cp_cache.services_cache)} Services"

    logger.info("Building Role Cache...")

    with _timed("Roles") as step:
        ROLE_CACHE.update(build_role_cache())
        cp_cache.role_cache = ROLE_CACHE
        step["detail"] = f"{len(ROLE_CACHE)} Roles"

    logger.info(
        "Roles cached: %s",
        len(cp_cache.role_cache),
    )

    with _timed("Enforcement Profile references") as step:
        cp_cache.profile_reference_cache = (
            build_profile_reference_cache()
        )
        step["detail"] = (
            f"{len(cp_cache.profile_reference_cache)} profiles"
        )

    logger.info("Building Role Mapping Reference Cache...")

    with _timed("Role Mapping references") as step:
        cp_cache.role_mapping_reference_cache = (
            build_role_mapping_reference_cache()
        )
        step["detail"] = (
            f"{len(cp_cache.role_mapping_reference_cache)} policies"
        )

    logger.info(
        "Built role mapping cache for %s Role Mapping Policies",
        len(cp_cache.role_mapping_reference_cache),
    )
    logger.info(
        "Built reference cache for %s Enforcement Profiles",
        len(cp_cache.profile_reference_cache),
    )

    logger.info("Building Role Reference Cache...")

    with _timed("Role references") as step:
        cp_cache.role_reference_cache = (
            build_role_reference_cache()
        )
        step["detail"] = (
            f"{len(cp_cache.role_reference_cache)} Roles"
        )

    logger.info(
        "Role references cached: %s",
        len(cp_cache.role_reference_cache),
    )

    logger.info("Building Unused Objects Cache...")

    with _timed("Unused Objects"):
        cp_cache.unused_objects_cache = (
            get_unused_object_summary()
        )

    logger.info("Building Impact Analysis Lookup Cache...")

    with _timed("Impact Analysis lookup") as step:
        cp_cache.impact_analysis_lookup_cache = (
            build_impact_analysis_lookup_cache()
        )
        step["detail"] = (
            f"{len(cp_cache.impact_analysis_lookup_cache)} objects"
        )

    logger.info(
        "Impact Analysis lookup objects cached: %s",
        len(cp_cache.impact_analysis_lookup_cache),
    )

    cp_cache.initialised = True
    cp_cache.last_refresh = time.strftime(
        "%d-%m-%Y %H:%M:%S"
    )
    _finish_timings()

    logger.info("Cache refresh complete.")

    return redirect("/")


@app.route("/service/<int:id>")
@login_required
def service(id):
    service_data = get_service(id)

    cached_service = next(
        (
            cached
            for cached in cp_cache.services_cache
            if str(cached.get("id")) == str(id)
        ),
        None,
    )

    if cached_service is not None:
        service_data["hit_count"] = cached_service.get(
            "hit_count",
            0,
        )

    graph = build_service_graph(
        service_data
    )

    return render_template(
        "service.html",
        service=service_data,
        graph=graph,
    )

# -------------------------------------------------
# Load timings
#
# Each step of a load is timed. The timings of the last
# load that completed are kept on the environment's state
# and shown in the dashboard's Last Refresh panel. A load
# that fails keeps the previous timings.
# -------------------------------------------------

def _begin_timings(kind):
    """Start recording step timings for a load of the active environment."""
    cp_env.current_state().pending_timings = {
        "kind": kind,
        "started": time.perf_counter(),
        "steps": [],
    }


@contextmanager
def _timed(label):
    """Time one load step. The caller may set step["detail"]."""
    step = {"label": label, "detail": ""}
    start = time.perf_counter()

    try:
        yield step
    finally:
        step["seconds"] = time.perf_counter() - start
        pending = getattr(cp_env.current_state(), "pending_timings", None)

        if pending is not None:
            pending["steps"].append(step)


def _finish_timings():
    """Keep the timings of a load that completed."""
    state = cp_env.current_state()
    pending = getattr(state, "pending_timings", None)

    if pending is None:
        return

    pending["total"] = time.perf_counter() - pending.pop("started")
    pending["finished"] = time.strftime("%d-%m-%Y %H:%M:%S")
    state.load_timings = pending
    state.pending_timings = None

    logger.info(
        "%s completed in %.1fs.",
        pending["kind"],
        pending["total"],
    )

# -------------------------------------------------
# Check for a newer release on GitHub
#
# Runs only when an Administrator clicks the button.
# The result is kept for an hour so repeated clicks do
# not hit GitHub's unauthenticated rate limit.
# -------------------------------------------------

LATEST_RELEASE_URL = (
    "https://api.github.com/repos/ariyaparsa-dev/"
    "clearpass-policy-visualiser/releases/latest"
)
_UPDATE_CACHE_SECONDS = 3600
_update_cache = {"time": 0.0, "result": None}


def _version_tuple(value):
    """'v1.7.10' -> (1, 7, 10). Non-numeric parts count as 0."""
    parts = []

    for part in str(value).strip().lstrip("vV").split("."):
        digits = "".join(ch for ch in part if ch.isdigit())
        parts.append(int(digits) if digits else 0)

    return tuple(parts)


@app.route("/api/check-update")
@login_required
def check_update():
    if getattr(current_user, "role", None) != "Admin":
        abort(403)

    now = time.time()

    if (
        _update_cache["result"] is not None
        and now - _update_cache["time"] < _UPDATE_CACHE_SECONDS
    ):
        return jsonify(_update_cache["result"])

    try:
        response = requests.get(
            LATEST_RELEASE_URL,
            timeout=5,
            headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": f"ClearPass-Policy-Visualiser/{VERSION}",
            },
        )
        response.raise_for_status()
        release = response.json()
    except (requests.exceptions.RequestException, ValueError) as exc:
        logger.warning(
            "Update check failed: GitHub could not be reached (%s).",
            type(exc).__name__,
        )
        logger.debug("Update check failure.", exc_info=True)

        return jsonify(
            {
                "status": "error",
                "message": "Could not reach GitHub to check for updates.",
            }
        )

    latest = str(release.get("tag_name") or "").strip()
    url = str(release.get("html_url") or "")

    # Only ever link to the project's own GitHub pages.
    if not url.startswith(
        "https://github.com/ariyaparsa-dev/clearpass-policy-visualiser/"
    ):
        url = ""

    if latest and _version_tuple(latest) > _version_tuple(VERSION):
        result = {
            "status": "available",
            "current": VERSION,
            "latest": latest.lstrip("vV"),
            "url": url,
        }
        logger.info("Update available: v%s (running v%s).", result["latest"], VERSION)
    else:
        result = {"status": "current", "current": VERSION}

    _update_cache["time"] = now
    _update_cache["result"] = result

    return jsonify(result)

def initialise_cache():
    cp_cache.last_refresh = time.strftime(
        "%d-%m-%Y %H:%M:%S"
    )

    logger.info("=" * 60)
    logger.info(
        "ClearPass Policy Visualiser v%s Starting",
        VERSION,
    )
    logger.info("=" * 60)

    if cp_cache.initialised:
        logger.info(
            "ClearPass caches are already initialised."
        )
        return

    cp_cache.initialised = False
    _begin_timings("Full load")

    logger.info("Loading ClearPass services...")

    with _timed("Services and Hit Counts") as step:
        cp_cache.services_cache = sorted(
            get_all_services_with_hit_counts(),
            key=lambda service: service["order_no"],
        )
        step["detail"] = f"{len(cp_cache.services_cache)} Services"

    logger.info(
        "Services cached: %s",
        len(cp_cache.services_cache),
    )

    logger.info("Running initial health check...")

    with _timed("Health check"):
        cp_cache.health_cache = check_clearpass()
        cp_cache.health_cache_time = time.time()

    logger.info("Pre-loading endpoint data...")

    with _timed("Profiled endpoints") as step:
        preload_endpoint_data()
        step["detail"] = (
            f"{len(cp_env.current_state().fingerprint_cache or {}):,} "
            "endpoints"
        )

    logger.info("Building Role Cache...")

    with _timed("Roles") as step:
        role_cache = build_role_cache()
        ROLE_CACHE.clear()
        ROLE_CACHE.update(role_cache)
        cp_cache.role_cache = ROLE_CACHE
        step["detail"] = f"{len(ROLE_CACHE)} Roles"

    logger.info(
        "Roles cached: %s",
        len(cp_cache.role_cache),
    )

    logger.info("Building Enforcement Profile Reference Cache...")

    with _timed("Enforcement Profile references") as step:
        cp_cache.profile_reference_cache = (
            build_profile_reference_cache()
        )
        step["detail"] = (
            f"{len(cp_cache.profile_reference_cache)} profiles"
        )

    logger.info("Building Role Mapping Reference Cache...")

    with _timed("Role Mapping references") as step:
        cp_cache.role_mapping_reference_cache = (
            build_role_mapping_reference_cache()
        )
        step["detail"] = (
            f"{len(cp_cache.role_mapping_reference_cache)} policies"
        )

    logger.info("Building Role Reference Cache...")

    with _timed("Role references") as step:
        cp_cache.role_reference_cache = (
            build_role_reference_cache()
        )
        step["detail"] = (
            f"{len(cp_cache.role_reference_cache)} Roles"
        )

    logger.info(
        "Role references cached: %s",
        len(cp_cache.role_reference_cache),
    )

    logger.info("Building Unused Objects Cache...")

    with _timed("Unused Objects"):
        cp_cache.unused_objects_cache = (
            get_unused_object_summary()
        )

    logger.info("Building Impact Analysis Lookup Cache...")

    with _timed("Impact Analysis lookup") as step:
        cp_cache.impact_analysis_lookup_cache = (
            build_impact_analysis_lookup_cache()
        )
        step["detail"] = (
            f"{len(cp_cache.impact_analysis_lookup_cache)} objects"
        )

    logger.info(
        "Impact Analysis lookup objects cached: %s",
        len(cp_cache.impact_analysis_lookup_cache),
    )

    cp_cache.initialised = True
    _finish_timings()

    logger.info("Cache initialisation complete.")
    logger.info(
        "Services: %s",
        len(cp_cache.services_cache),
    )
    logger.info(
        "Role Mapping Policies: %s",
        len(cp_cache.role_mapping_reference_cache),
    )
    logger.info(
        "Enforcement Profiles: %s",
        len(cp_cache.profile_reference_cache),
    )
    logger.info(
        "Impact Analysis lookup objects: %s",
        len(cp_cache.impact_analysis_lookup_cache),
    )
    logger.info(
        "Profiled endpoints cached: %s",
        len(cp_env.current_state().fingerprint_cache or {}),
    )
    logger.info(
        "Last Refresh: %s",
        cp_cache.last_refresh,
    )


@app.route("/endpoint/<int:id>")
@login_required
def endpoint_details(id):
    from cp_endpoint import get_all_endpoints

    endpoint = None

    for endpoint_item in get_all_endpoints():
        if endpoint_item.get("id") == id:
            endpoint = endpoint_item.copy()
            break

    if endpoint is None:
        return "Endpoint not found", 404

    endpoint["formatted_mac"] = format_mac_with_hyphens(
        endpoint.get(
            "mac_address",
            "",
        )
    )
    endpoint["hostname"] = get_endpoint_profile_value(
        endpoint,
        "Hostname",
    )
    endpoint["source_type"] = request.args.get(
        "source_type",
        "",
    )
    endpoint["attribute_name"] = request.args.get(
        "attribute_name",
        "",
    )
    endpoint["operator"] = request.args.get(
        "operator",
        "",
    )
    endpoint["condition_value"] = request.args.get(
        "value",
        "",
    )
    endpoint["match_count"] = request.args.get(
        "match_count",
        "",
    )
    endpoint["device_name"] = get_endpoint_profile_value(
        endpoint,
        "Device Name",
    )
    endpoint["os_family"] = get_endpoint_profile_value(
        endpoint,
        "OS Family",
    )
    endpoint["device_category"] = get_endpoint_profile_value(
        endpoint,
        "Device Category",
    )
    endpoint["device_type"] = get_endpoint_profile_value(
        endpoint,
        "Device Type",
    )
    endpoint["expanded_device_type"] = get_endpoint_profile_value(
        endpoint,
        "Expanded Device Type",
    )
    endpoint["mac_vendor"] = get_endpoint_profile_value(
        endpoint,
        "MAC Vendor",
    )
    endpoint["ip_address"] = get_endpoint_profile_value(
        endpoint,
        "IPv4 Address",
    )

    return render_template(
        "endpoint_details.html",
        endpoint=endpoint,
        version=VERSION,
    )


@app.route("/repository-search")
@login_required
def repository_search():
    source_type = request.args.get(
        "source_type",
        "",
    )
    attribute_name = request.args.get(
        "attribute_name",
        "",
    )
    operator = request.args.get(
        "operator",
        "",
    )
    value = request.args.get(
        "value",
        "",
    )

    result = get_matching_repository_objects(
        source_type,
        attribute_name,
        operator,
        value,
    )

    return render_template(
        "repository_search.html",
        result=result,
        version=VERSION,
    )


@app.route("/object/rolemap/<path:name>")
@login_required
def object_rolemap(name):
    graph = build_role_mapping_graph(name)

    return render_template(
        "object_detail.html",
        object_name=name,
        object_type_label="Role Mapping Policy",
        graph_kind="rolemap",
        graph=graph,
    )


@app.route("/unused-objects")
@login_required
def unused_objects():
    unused = cp_cache.unused_objects_cache

    if unused is None:
        unused = get_unused_object_summary()
        cp_cache.unused_objects_cache = unused

    return render_template(
        "unused_objects.html",
        unused=unused,
    )


@app.route("/object/policy/<path:name>")
@login_required
def object_policy(name):
    graph = build_enforcement_policy_graph(
        name
    )

    return render_template(
        "object_detail.html",
        object_name=name,
        object_type_label="Enforcement Policy",
        graph_kind="policy",
        graph=graph,
    )


def get_policy_impact_services(
    policy_name,
):
    """
    Return cached Services that assign the selected
    Enforcement Policy.

    Exact policy-name matching is attempted first, followed
    by a case-insensitive comparison.
    """

    services_cache = (
        cp_cache.services_cache
        or []
    )

    requested_policy_name = str(
        policy_name
    ).strip()

    requested_policy_name_normalised = (
        requested_policy_name.casefold()
    )

    matching_services = []

    for service_data in services_cache:

        if not isinstance(
            service_data,
            dict,
        ):

            continue

        service_name = str(
            service_data.get(
                "name",
                ""
            )
        ).strip()

        if service_name.startswith(
            "--------"
        ):

            continue

        assigned_policy_name = str(
            service_data.get(
                "enf_policy",
                ""
            )
        ).strip()

        if not assigned_policy_name:
            continue

        if (
            assigned_policy_name
            ==
            requested_policy_name
        ):

            matching_services.append(
                service_data
            )

            continue

        if (
            assigned_policy_name.casefold()
            ==
            requested_policy_name_normalised
        ):

            matching_services.append(
                service_data
            )

    matching_services = sorted(
        matching_services,
        key=lambda service_data: (
            str(
                service_data.get(
                    "name",
                    ""
                )
            ).casefold()
        ),
    )

    return {
        "cache_available": bool(
            services_cache
        ),
        "services": matching_services,
    }

def get_role_mapping_impact_services(
    policy_name,
):
    """
    Return cached Services that assign the selected
    Role Mapping Policy.

    Exact policy-name matching is attempted first,
    followed by a case-insensitive comparison.
    """

    reference_cache = (
        cp_cache.role_mapping_reference_cache
        or {}
    )

    service_references = (
        reference_cache.get(
            policy_name
        )
    )

    if service_references is None:

        requested_name = str(
            policy_name
        ).strip().casefold()

        for cached_name, cached_services in (
            reference_cache.items()
        ):

            cached_name_normalised = str(
                cached_name
            ).strip().casefold()

            if (
                cached_name_normalised
                ==
                requested_name
            ):

                service_references = (
                    cached_services
                )

                break

    if not isinstance(
        service_references,
        list,
    ):

        service_references = []

    service_references = sorted(
        service_references,
        key=lambda service: (
            str(
                service.get(
                    "name",
                    ""
                )
            ).casefold()
        ),
    )

    return {
        "cache_available": bool(
            reference_cache
        ),
        "services": service_references,
    }

def get_profile_impact_references(
    profile_name,
):
    """
    Return cached Enforcement Policy and Service references
    for an Enforcement Profile.

    Exact name matching is attempted first, followed by a
    case-insensitive fallback.
    """

    cache = (
        cp_cache.profile_reference_cache
        or {}
    )

    references = cache.get(
        profile_name
    )

    if references is None:

        requested_name = str(
            profile_name
        ).strip().casefold()

        for cached_name, cached_data in cache.items():

            cached_name_normalised = str(
                cached_name
            ).strip().casefold()

            if (
                cached_name_normalised
                ==
                requested_name
            ):

                references = cached_data
                break

    if not isinstance(
        references,
        dict,
    ):

        references = {}

    policies = references.get(
        "policies",
        [],
    )

    services = references.get(
        "services",
        [],
    )

    if not isinstance(
        policies,
        list,
    ):

        policies = []

    if not isinstance(
        services,
        list,
    ):

        services = []

    return {
        "cache_available": bool(
            cache
        ),
        "policies": policies,
        "services": services,
    }


@app.route("/object/profile/<path:name>")
@login_required
def object_profile(name):

    try:

        profile = get_enforcement_profile(
            name
        )

    except requests.exceptions.ConnectionError:
        # Handled by clearpass_unreachable.
        raise

    except Exception:

        logger.exception(
            "Unable to retrieve Enforcement Profile: %s",
            name,
        )

        return (
            "Unable to retrieve Enforcement Profile",
            500,
        )

    if not isinstance(
        profile,
        dict,
    ):

        return (
            "Enforcement Profile not found",
            404,
        )

    return render_template(
        "enforcement_profile_detail.html",
        profile=profile,
        version=VERSION,
    )

@app.route(
    "/impact-analysis/enforcement-profile/"
    "<path:name>"
)
@login_required
def enforcement_profile_impact_analysis(
    name,
):
    """
    Display read-only impact analysis for an
    Enforcement Profile.
    """

    try:

        profile = get_enforcement_profile(
            name
        )

    except requests.exceptions.ConnectionError:
        # Handled by clearpass_unreachable.
        raise

    except Exception:

        logger.exception(
            "Unable to retrieve Enforcement Profile "
            "for impact analysis: %s",
            name,
        )

        return (
            "Unable to retrieve Enforcement Profile "
            "for impact analysis",
            500,
        )

    if not isinstance(
        profile,
        dict,
    ):

        return (
            "Enforcement Profile not found",
            404,
        )

    profile_name = (
        profile.get(
            "name"
        )
        or name
    )

    references = (
        get_profile_impact_references(
            profile_name
        )
    )

    if not references[
        "cache_available"
    ]:

        logger.warning(
            "Enforcement Profile reference cache is "
            "unavailable for impact analysis: %s",
            profile_name,
        )

    if references[
        "cache_available"
    ]:

        policy_references = references[
            "policies"
        ]

        service_references = references[
            "services"
        ]

    else:

        policy_references = None
        service_references = None


    impact = analyse_enforcement_profile(
        profile,
        policy_references=policy_references,
        service_references=service_references,
    )

    logger.info(
        "Impact analysis generated for Enforcement "
        "Profile '%s': %s policies, %s services",
        profile_name,
        impact["summary"][
            "affected_policy_count"
        ],
        impact["summary"][
            "affected_service_count"
        ],
    )

    return render_template(
        "impact_analysis.html",
        impact=impact,
        version=VERSION,
    )

@app.route(
    "/impact-analysis/enforcement-policy/"
    "<path:name>"
)
@login_required
def enforcement_policy_impact_analysis(
    name,
):
    """
    Display read-only impact analysis for an
    Enforcement Policy.
    """

    try:

        policy = get_enforcement_details(
            name
        )

    except requests.exceptions.ConnectionError:
        # Handled by clearpass_unreachable.
        raise

    except Exception:

        logger.exception(
            "Unable to retrieve Enforcement Policy "
            "for impact analysis: %s",
            name,
        )

        return (
            "Unable to retrieve Enforcement Policy "
            "for impact analysis",
            500,
        )

    if not isinstance(
        policy,
        dict,
    ):

        return (
            "Enforcement Policy not found",
            404,
        )

    policy_name = (
        policy.get(
            "name"
        )
        or
        name
    )

    service_result = (
        get_policy_impact_services(
            policy_name
        )
    )

    if service_result[
        "cache_available"
    ]:

        service_references = (
            service_result[
                "services"
            ]
        )

    else:

        service_references = None

        logger.warning(
            "Service cache is unavailable for "
            "Enforcement Policy impact analysis: %s",
            policy_name,
        )

    default_profile_name = (
        policy.get(
            "default_enforcement_profile"
        )
    )

    default_profile = None

    if default_profile_name:

        try:

            default_profile = (
                get_enforcement_profile(
                    default_profile_name
                )
            )

        except Exception:

            logger.warning(
                "Unable to retrieve default Enforcement "
                "Profile '%s' for policy '%s'. The report "
                "will retain the default profile name "
                "without complete profile metadata.",
                default_profile_name,
                policy_name,
                exc_info=True,
            )

    impact = analyse_enforcement_policy(
        policy,
        service_references=service_references,
        default_profile=default_profile,
        profile_reference_cache=(
            cp_cache.profile_reference_cache
            or None
        ),
    )

    logger.info(
        "Impact analysis generated for Enforcement "
        "Policy '%s': %s services, %s rules, "
        "%s dependent profiles",
        policy_name,
        impact["summary"][
            "affected_service_count"
        ],
        impact["summary"][
            "rule_count"
        ],
        impact["summary"][
            "dependent_profile_count"
        ],
    )

    return render_template(
        "enforcement_policy_impact_analysis.html",
        impact=impact,
        version=VERSION,
    )


@app.route(
    "/impact-analysis/role-mapping-policy/"
    "<path:name>"
)
@login_required
def role_mapping_policy_impact_analysis(
    name,
):
    """
    Display read-only impact analysis for a
    Role Mapping Policy.
    """

    try:

        policy = get_role_mapping_details(
            name
        )

    except requests.exceptions.ConnectionError:
        # Handled by clearpass_unreachable.
        raise

    except Exception:

        logger.exception(
            "Unable to retrieve Role Mapping Policy "
            "for impact analysis: %s",
            name,
        )

        return (
            "Unable to retrieve Role Mapping Policy "
            "for impact analysis",
            500,
        )

    if not isinstance(
        policy,
        dict,
    ):

        return (
            "Role Mapping Policy not found",
            404,
        )

    policy_name = (
        policy.get(
            "name"
        )
        or
        name
    )

    service_result = (
        get_role_mapping_impact_services(
            policy_name
        )
    )

    if service_result[
        "cache_available"
    ]:

        service_references = (
            service_result[
                "services"
            ]
        )

    else:

        service_references = None

        logger.warning(
            "Role Mapping reference cache is unavailable "
            "for impact analysis: %s",
            policy_name,
        )

    impact = analyse_role_mapping_policy(
        policy,
        service_references=service_references,
    )

    logger.info(
        "Impact analysis generated for Role Mapping "
        "Policy '%s': %s services, %s rules, "
        "%s mapped Roles",
        policy_name,
        impact["summary"][
            "affected_service_count"
        ],
        impact["summary"][
            "rule_count"
        ],
        impact["summary"][
            "mapped_role_count"
        ],
    )

    return render_template(
        "role_mapping_policy_impact_analysis.html",
        impact=impact,
        version=VERSION,
    )

@app.route(
    "/impact-analysis/role/"
    "<path:name>"
)
@login_required
def role_impact_analysis(
    name,
):
    """
    Display read-only impact analysis for a ClearPass Role.
    """
    role = ROLE_CACHE.get(
        name
    )

    if not isinstance(
        role,
        dict,
    ):
        requested_name = (
            str(name)
            .strip()
            .casefold()
        )

        for cached_name, cached_role in (
            ROLE_CACHE.items()
        ):
            if (
                str(cached_name)
                .strip()
                .casefold()
                == requested_name
            ):
                role = cached_role
                break

    if not isinstance(
        role,
        dict,
    ):
        return (
            "Role not found",
            404,
        )

    role_name = (
        role.get(
            "name"
        )
        or
        name
    )

    reference_cache_available = isinstance(
        cp_cache.role_reference_cache,
        dict,
    )

    references = {}

    if reference_cache_available:
        references = (
            cp_cache.role_reference_cache.get(
                role_name,
                {}
            )
        )

        if not references:
            requested_name = (
                str(role_name)
                .strip()
                .casefold()
            )

            for (
                cached_name,
                cached_references,
            ) in (
                cp_cache.role_reference_cache.items()
            ):
                if (
                    str(cached_name)
                    .strip()
                    .casefold()
                    == requested_name
                ):
                    references = (
                        cached_references
                    )
                    break
    else:
        logger.warning(
            "Role reference cache is unavailable "
            "for impact analysis: %s",
            role_name,
        )

    impact = analyse_role(
        role,
        references,
        reference_cache_supplied=(
            reference_cache_available
        ),
    )

    logger.info(
        "Impact analysis generated for Role '%s': "
        "%s Role Mapping Policies, "
        "%s Enforcement Policies, "
        "%s Operator Profiles, %s services",
        role_name,
        impact["summary"][
            "role_mapping_policy_count"
        ],
        impact["summary"][
            "enforcement_policy_count"
        ],
        impact["summary"][
            "operator_profile_count"
        ],
        impact["summary"][
            "affected_service_count"
        ],
    )

    return render_template(
        "role_impact_analysis.html",
        impact=impact,
        version=VERSION,
    )


init_environment_support(app, initialise_cache)

if __name__ == "__main__":
    # Run exactly as server.py does: Waitress, and the protected startup
    # that keeps CPV running when the initial environment is unreachable.
    # Registering this module as "app" stops server.py loading it twice.
    import sys

    sys.modules.setdefault("app", sys.modules[__name__])

    from server import main

    main()
