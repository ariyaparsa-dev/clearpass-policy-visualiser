import os
from datetime import timedelta
from dotenv import load_dotenv

from flask_login import login_required, current_user
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from auth import login_manager
from auth.models import RadiusUser
from auth.routes import auth_bp

import time
import cp_cache
import logging

load_dotenv()

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
from cp_graph import build_service_graph
from cp_services import (
    get_all_services,
    get_service
)
from cp_health import check_clearpass

from cp_enforcement import (
    build_profile_reference_cache,
    PROFILE_CACHE,
    ENFORCEMENT_POLICY_CACHE
)

from cp_role_mapping import (
    ROLE_MAPPING_CACHE,
    build_role_mapping_reference_cache
)


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%d-%m-%Y %H:%M:%S"
)

logger = logging.getLogger(__name__)

logger.info(
    f"RADIUS_SERVER={os.getenv('RADIUS_SERVER')}"
)

app = Flask(__name__)

app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET_KEY")

if not app.config["SECRET_KEY"]:
    raise RuntimeError("FLASK_SECRET_KEY is not configured.")

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


    return render_template(
        "index.html",
        services=services,
        health=health,
        stats=stats,
        last_refresh=cp_cache.last_refresh,
        version=VERSION
    )

@app.route("/refresh-cache")
@login_required
def refresh_cache():

    logger.info("Refreshing ClearPass caches...")

    cp_cache.services_cache = []
    cp_cache.profile_reference_cache = {}

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

    cp_cache.services_cache = (
        get_all_services()
    )

    cp_cache.services_cache = sorted(
        cp_cache.services_cache,
        key=lambda x: x["order_no"]
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

if __name__ == "__main__":

    initialise_cache()

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False,
        #ssl_context=("cert.pem", "key.pem")
    )