import os
import secrets
from datetime import timedelta
from dotenv import load_dotenv

from flask_login import login_required, current_user
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from auth import login_manager
from auth.models import RadiusUser
from auth.routes import auth_bp

from cp_unused_objects import (
    get_unused_object_summary
)

from cp_object_graph import (
    build_enforcement_policy_graph,
    build_role_mapping_graph
)


import time
import cp_cache
import logging


load_dotenv(
    ".visualiser.env",
    override=True
)

from cp_endpoint import (
    preload_endpoint_data,
    get_matching_repository_objects,
    get_endpoint_profile_value,
    format_mac_with_hyphens
)


from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session
)

from version import VERSION

from cp_setup import (
    is_setup_complete,
    save_setup_configuration,
    validate_setup_connectivity
)


from cp_graph import build_service_graph
from cp_services import (
    get_all_services,
    get_service
)
from cp_health import check_clearpass

from cp_enforcement import (
    build_profile_reference_cache,
    get_enforcement_profile,
    PROFILE_CACHE,
    ENFORCEMENT_POLICY_CACHE
)

from cp_role_mapping import (
    ROLE_MAPPING_CACHE,
    ROLE_CACHE,
    build_role_cache,
    build_role_mapping_reference_cache
)


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%d-%m-%Y %H:%M:%S"
)

logger = logging.getLogger(__name__)

radius_server = os.getenv(
    "RADIUS_SERVER"
)

if radius_server:

    logger.info(
        "RADIUS_SERVER=%s",
        radius_server
    )

app = Flask(__name__)

FLASK_SECRET_FILE = ".flask_secret"


def get_flask_secret_key():

    # Use explicitly configured key if available.
    env_secret = os.getenv("FLASK_SECRET_KEY")

    if env_secret:
        return env_secret

    # Reuse automatically generated key if it already exists.
    if os.path.exists(FLASK_SECRET_FILE):

        with open(
            FLASK_SECRET_FILE,
            "r",
            encoding="utf-8"
        ) as f:

            existing_secret = f.read().strip()

        if existing_secret:
            return existing_secret

    # First run: generate a new Flask secret.
    new_secret = secrets.token_hex(32)

    with open(
        FLASK_SECRET_FILE,
        "w",
        encoding="utf-8"
    ) as f:

        f.write(new_secret)

    logger.info(
        "Generated new Flask session secret."
    )

    return new_secret


app.config["SECRET_KEY"] = get_flask_secret_key()

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.getenv("SESSION_COOKIE_SECURE", "false").lower() == "true"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=8)

login_manager.init_app(app)
app.register_blueprint(auth_bp)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[],
    storage_uri="memory://",
)

limiter.limit("10 per minute")(app.view_functions["auth.login"])

@login_manager.user_loader
def load_user(username):

    if not username:
        return None

    try:
        role = session.get("role", "ReadOnly")
        radius_attributes = session.get(
            "radius_attributes",
            {}
        )

    except Exception:
        role = "ReadOnly"
        radius_attributes = {}

    return RadiusUser(
        username=username,
        role=role,
        radius_attributes=radius_attributes
    )

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
        )
    }

@app.before_request

def log_request():

    logger.info(
        f"{request.method} {request.path}"
    )

@app.before_request
def require_initial_setup():

    if is_setup_complete():
        return None

    allowed_endpoints = {
        "setup",
        "setup_complete",
        "start_visualiser",
        "static"
    }

    if request.endpoint in allowed_endpoints:
        return None

    return redirect(
        url_for("setup")
    )

@app.route(
    "/setup",
    methods=["GET", "POST"]
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

        endpoint_source = (
            request.form.get(
                "endpoint_source",
                "api"
            )
            .strip()
            .lower()
        )

        clearpass_verify_ssl = (
            request.form.get(
                "clearpass_verify_ssl",
                "false"
            )
            .strip()
            .lower()
        )

        config = {

            # ClearPass REST API

            "clearpass_api_url":
                request.form.get(
                    "clearpass_api_url",
                    ""
                ).strip(),

            "clearpass_client_id":
                request.form.get(
                    "clearpass_client_id",
                    ""
                ).strip(),

            "clearpass_client_secret":
                request.form.get(
                    "clearpass_client_secret",
                    ""
                ),

            "clearpass_verify_ssl":
                clearpass_verify_ssl,

            # RADIUS Authentication

            "radius_server":
                request.form.get(
                    "radius_server",
                    ""
                ).strip(),

            "radius_port":
                request.form.get(
                    "radius_port",
                    "1812"
                ).strip(),

            "radius_secret":
                request.form.get(
                    "radius_secret",
                    ""
                ),

            "nas_identifier":
                request.form.get(
                    "nas_identifier",
                    "clearpass-policy-visualiser"
                ).strip(),

            # Endpoint Profiling

            "endpoint_source":
                endpoint_source,

            "sql_fallback":
                "true",

            # PostgreSQL

            "sql_host":
                request.form.get(
                    "sql_host",
                    ""
                ).strip(),

            "sql_port":
                request.form.get(
                    "sql_port",
                    "5432"
                ).strip(),

            "sql_database":
                request.form.get(
                    "sql_database",
                    "tipsdb"
                ).strip(),

            "sql_username":
                request.form.get(
                    "sql_username",
                    "appexternal"
                ).strip(),

            "sql_password":
                request.form.get(
                    "sql_password",
                    ""
                ),
        }

        clearpass_client_secret_confirm = (
            request.form.get(
                "clearpass_client_secret_confirm",
                ""
            )
        )

        radius_secret_confirm = (
            request.form.get(
                "radius_secret_confirm",
                ""
            )
        )

        sql_password_confirm = (
            request.form.get(
                "sql_password_confirm",
                ""
            )
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
                "Confirm ClearPass Client Secret "
                "is required."
            )

        elif (
            config["clearpass_client_secret"]
            != clearpass_client_secret_confirm
        ):

            errors.append(
                "ClearPass Client Secret entries "
                "do not match."
            )

        if clearpass_verify_ssl not in {
            "true",
            "false"
        }:

            errors.append(
                "Invalid ClearPass SSL "
                "verification setting."
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
                "Confirm RADIUS Shared Secret "
                "is required."
            )

        elif (
            config["radius_secret"]
            != radius_secret_confirm
        ):

            errors.append(
                "RADIUS Shared Secret entries "
                "do not match."
            )

        # -------------------------------------------------
        # Endpoint profiling validation
        # -------------------------------------------------

        if endpoint_source not in {
            "api",
            "sql"
        }:

            errors.append(
                "Invalid endpoint profiling source."
            )

        # -------------------------------------------------
        # PostgreSQL validation
        # -------------------------------------------------

        if endpoint_source == "sql":

            if not config["sql_host"]:

                errors.append(
                    "PostgreSQL Host is required "
                    "when PostgreSQL profiling "
                    "is selected."
                )

            if not config["sql_password"]:

                errors.append(
                    "PostgreSQL Password is required "
                    "when PostgreSQL profiling "
                    "is selected."
                )

            elif not sql_password_confirm:

                errors.append(
                    "Confirm PostgreSQL Password "
                    "is required."
                )

            elif (
                config["sql_password"]
                != sql_password_confirm
            ):

                errors.append(
                    "PostgreSQL Password entries "
                    "do not match."
                )

        # -------------------------------------------------
        # Return form if validation failed
        # -------------------------------------------------

        if errors:

            return render_template(
                "setup.html",
                version=VERSION,
                errors=errors,
                form=config
            )

        # -------------------------------------------------
        # Validate connectivity
        # -------------------------------------------------

        validation = (
            validate_setup_connectivity(
                config
            )
        )

        if not validation["success"]:

            return render_template(
                "setup.html",
                version=VERSION,
                errors=validation["errors"],
                form=config,
                validation=validation[
                    "results"
                ]
            )

        # -------------------------------------------------
        # Save configuration
        # -------------------------------------------------

        save_setup_configuration(
            config
        )

        # Reload generated configuration into
        # the current process.

        load_dotenv(
            ".visualiser.env",
            override=True
        )

        # Verify that everything required for
        # application startup now exists.

        if not is_setup_complete():

            return render_template(
                "setup.html",
                version=VERSION,
                errors=[
                    "Configuration was saved, "
                    "but setup is still incomplete."
                ],
                form=config
            )

        logger.info(
            "Initial setup configuration "
            "loaded successfully."
        )

        # The configuration changed underneath
        # any existing login session, so remove
        # the existing session.

        session.clear()

        logger.info(
            "Existing user session cleared "
            "after initial setup."
        )

        session[
            "setup_validation"
        ] = validation[
            "results"
        ]

        return redirect(
            url_for("setup_complete")
        )

    return render_template(
        "setup.html",
        version=VERSION
    )

@app.route("/setup-complete")
def setup_complete():

    if not is_setup_complete():

        return redirect(
            url_for("setup")
        )

    validation = session.pop(
        "setup_validation",
        None
    )

    return render_template(
        "setup_complete.html",
        version=VERSION,
        validation=validation
    )


@app.route(
    "/start-visualiser",
    methods=["POST"]
)
def start_visualiser():

    if not is_setup_complete():

        return redirect(
            url_for("setup")
        )

    logger.info(
        "Starting ClearPass Policy Visualiser "
        "after initial setup..."
    )

    try:

        initialise_cache()

    except Exception:

        logger.exception(
            "ClearPass Policy Visualiser "
            "initialisation failed."
        )

        return render_template(
            "setup_complete.html",
            version=VERSION,
            errors=[
                "The Visualiser could not be started. "
                "Check the ClearPass configuration and "
                "application log, then try again."
            ]
        )

    logger.info(
        "ClearPass Policy Visualiser started "
        "successfully."
    )

    return redirect(
        url_for("home")
    )


@app.route("/")
@login_required
def home():

    if (
        cp_cache.health_cache is None
        or
        time.time() -
            cp_cache.health_cache_time > 60
    ):

        logger.info(
            "Refreshing health cache..."
        )

        cp_cache.health_cache = (
            check_clearpass()
        )

        cp_cache.health_cache_time = (
            time.time()
        )

    health = (
        cp_cache.health_cache
    )


    services = cp_cache.services_cache

    real_services = [
        s for s in services
        if not s.get("name", "").startswith("--------")
    ]

    stats = {

        "total_services": len(real_services),

        "enabled_services": len(
            [
                s for s in real_services
                if s.get("enabled")
            ]
        ),

        "tacacs_services": len(
            [
                s for s in real_services
                if s.get("type") == "TACACS"
            ]
        ),

        "mac_authentication": len(
            [
                s for s in real_services
                if s.get("template") == "MAC Authentication"
            ]
        ),

        "application_services": len(
            [
                s for s in real_services
                if s.get("type") == "Application"
            ]
        ),

        "webauth_services": len(
            [
                s for s in real_services
                if s.get("type") == "WEBAUTH"
            ]
        ),

        "wired_8021x": len(
            [
                s for s in real_services
                if s.get("template") == "802.1X Wired"
            ]
        ),

        "wireless_8021x": len(
            [
                s for s in real_services
                if s.get("template") in ( 
                    "802.1X Wireless",
                    "Aruba 802.1X Wireless"
                )
            ]
        )
    }
    unused = cp_cache.unused_objects_cache

    return render_template(
        "index.html",
        services=services,
        health=health,
        stats=stats,
        unused=unused,
        last_refresh=cp_cache.last_refresh,
        version=VERSION
    )

@app.route("/refresh-cache")
@login_required
def refresh_cache():

    logger.info("Refreshing ClearPass caches...")

    cp_cache.services_cache = []
    cp_cache.profile_reference_cache = {}
    cp_cache.role_cache = {}

    cp_cache.health_cache = (
        check_clearpass()
    )

    cp_cache.health_cache_time = (
        time.time()
    )

    cp_cache.last_refresh = (
        time.strftime(
            "%d-%m-%Y %H:%M:%S"
        )
    )    

    PROFILE_CACHE.clear()
    ENFORCEMENT_POLICY_CACHE.clear()
    ROLE_MAPPING_CACHE.clear()
    ROLE_CACHE.clear()

    cp_cache.services_cache = (
        get_all_services()
    )

    cp_cache.services_cache = sorted(
        cp_cache.services_cache,
        key=lambda x: x["order_no"]
    )

    logger.info(
        "Building Role Cache..."
    )

    role_cache = build_role_cache()

    ROLE_CACHE.update(
        role_cache
    )

    cp_cache.role_cache = ROLE_CACHE

    logger.info(
        f"Roles cached: "
        f"{len(cp_cache.role_cache)}"
    )

    cp_cache.profile_reference_cache = (
        build_profile_reference_cache()
    )

    logger.info(
        "Building Role Mapping Reference Cache..."
    )

    cp_cache.role_mapping_reference_cache = (
        build_role_mapping_reference_cache()
    )

    logger.info(
        f"Built role mapping cache for "
        f"{len(cp_cache.role_mapping_reference_cache)} "
        f"Role Mapping Policies"
    )

    logger.info(
        f"Built reference cache for "
        f"{len(cp_cache.profile_reference_cache)} "
        f"Enforcement Profiles"
    )

    logger.info(
        "Building Unused Objects Cache..."
    )

    cp_cache.unused_objects_cache = (
        get_unused_object_summary()
    )

    logger.info("Cache refresh complete.")

    return redirect("/")

@app.route("/testservice/<int:id>")
@login_required
def testservice(id):

    svc = get_service(id)

    return svc

@app.route("/service/<int:id>")
@login_required
def service(id):

    svc = get_service(id)

    graph = build_service_graph(svc)
    
    return render_template(
        "service.html",
        service=svc,
        graph=graph
    )

def initialise_cache():

    cp_cache.last_refresh = (
        time.strftime(
            "%d-%m-%Y %H:%M:%S"
        )
    )

    logger.info(
        "=" * 60
    )

    logger.info(
        f"ClearPass Policy Visualiser v{VERSION} Starting"
    )

    logger.info(
        "=" * 60
    )

    if cp_cache.services_cache:
        return
    logger.info(
        "Loading ClearPass services..."
    )


    cp_cache.services_cache = get_all_services()

    cp_cache.services_cache = sorted(
        cp_cache.services_cache,
        key=lambda x: x["order_no"]
    )

    logger.info(
        f"Services cached: "
        f"{len(cp_cache.services_cache)}"
    )

    logger.info(
        "Running initial health check..."
    )

    cp_cache.health_cache = (
        check_clearpass()
    )

    cp_cache.health_cache_time = (
        time.time()
    )

    logger.info(
        "Pre-loading endpoint fingerprint cache via PostgreSQL..."
    )

    preload_endpoint_data()

    logger.info(
        "Building Role Cache..."
    )

    role_cache = build_role_cache()

    ROLE_CACHE.clear()
    ROLE_CACHE.update(
        role_cache
    )

    cp_cache.role_cache = ROLE_CACHE

    logger.info(
        f"Roles cached: "
        f"{len(cp_cache.role_cache)}"
    )

    logger.info(
        "Building Enforcement Profile Reference Cache..."
    )

    cp_cache.profile_reference_cache = (
        build_profile_reference_cache()
    )

    logger.info(
        "Building Role Mapping Reference Cache..."
    )

    cp_cache.role_mapping_reference_cache = (
        build_role_mapping_reference_cache()
    )

    logger.info(
        "Building Unused Objects Cache..."
    )

    cp_cache.unused_objects_cache = (
        get_unused_object_summary()
    )

    logger.info(
        "Cache initialisation complete."
    )

    logger.info(
        f"Services: "
        f"{len(cp_cache.services_cache)}"
    )

    logger.info(
        f"Role Mapping Policies: "
        f"{len(cp_cache.role_mapping_reference_cache)}"
    )

    logger.info(
        f"Enforcement Profiles: "
        f"{len(cp_cache.profile_reference_cache)}"
    )

    logger.info(
        f"Last Refresh: "
        f"{cp_cache.last_refresh}"
    )    

@app.route("/endpoint/<int:id>")
@login_required
def endpoint_details(id):

    from cp_endpoint import (
        get_all_endpoints
    )

    endpoint = None

    for ep in get_all_endpoints():

        if ep.get("id") == id:

            endpoint = ep.copy()
            break

    if endpoint is None:

        return "Endpoint not found", 404

    endpoint["formatted_mac"] = (
        format_mac_with_hyphens(
            endpoint.get(
                "mac_address",
                ""
            )
        )
    )

    endpoint["hostname"] = (
        get_endpoint_profile_value(
            endpoint,
            "Hostname"
        )
    )

    endpoint["source_type"] = request.args.get(
        "source_type",
        ""
    )

    endpoint["attribute_name"] = request.args.get(
        "attribute_name",
        ""
    )

    endpoint["operator"] = request.args.get(
        "operator",
        ""
    )

    endpoint["condition_value"] = request.args.get(
        "value",
        ""
    )

    endpoint["match_count"] = request.args.get(
        "match_count",
        ""
    )
    endpoint["device_name"] = (
        get_endpoint_profile_value(
            endpoint,
            "Device Name"
        )
    )

    endpoint["os_family"] = (
        get_endpoint_profile_value(
            endpoint,
            "OS Family"
        )
    )

    endpoint["device_category"] = (
        get_endpoint_profile_value(
            endpoint,
            "Device Category"
        )
    )

    endpoint["device_type"] = (
        get_endpoint_profile_value(
            endpoint,
            "Device Type"
        )
    )

    endpoint["expanded_device_type"] = (
        get_endpoint_profile_value(
            endpoint,
            "Expanded Device Type"
        )
    )

    endpoint["mac_vendor"] = (
        get_endpoint_profile_value(
            endpoint,
            "MAC Vendor"
        )
    )

    endpoint["ip_address"] = (
        get_endpoint_profile_value(
            endpoint,
            "IPv4 Address"
        )
    )

    return render_template(
        "endpoint_details.html",
        endpoint=endpoint,
        version=VERSION
    )


@app.route("/repository-search")
@login_required
def repository_search():

    source_type = request.args.get(
        "source_type",
        ""
    )

    attribute_name = request.args.get(
        "attribute_name",
        ""
    )

    operator = request.args.get(
        "operator",
        ""
    )

    value = request.args.get(
        "value",
        ""
    )

    result = get_matching_repository_objects(
        source_type,
        attribute_name,
        operator,
        value
    )

    return render_template(
        "repository_search.html",
        result=result,
        version=VERSION
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
        graph=graph
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
        unused=unused
    )

@app.route("/object/policy/<path:name>")
@login_required
def object_policy(name):

    graph = build_enforcement_policy_graph(name)

    return render_template(
        "object_detail.html",
        object_name=name,
        object_type_label="Enforcement Policy",
        graph_kind="policy",
        graph=graph
    )

@app.route("/object/profile/<path:name>")
@login_required
def object_profile(name):

    profile = get_enforcement_profile(
        name
    )

    return render_template(
        "enforcement_profile_detail.html",
        profile=profile
    )

if __name__ == "__main__":

    if is_setup_complete(log_missing=True):

        initialise_cache()

    else:

        logger.warning(
            "Initial setup is incomplete. "
            "Starting Flask without initialising ClearPass caches."
        )

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False,
        #ssl_context=("cert.pem", "key.pem")
    )