import os
import cp_env
import time
import socket
import logging
from pyclearpass import ApiLocalServerConfiguration
from cp_env import ScopedDict

from urllib.parse import urlparse

from pyclearpass import ApiPolicyElements

from cp_client import get_login


logger = logging.getLogger(__name__)


def tcp_check(host, port=443):
    """
    Test basic TCP connectivity to the
    ClearPass server.
    """

    try:

        sock = socket.create_connection(
            (
                host,
                port
            ),
            timeout=1
        )

        sock.close()

        return True

    except Exception:

        return False

_VERSION_CACHE = ScopedDict("cppm_version_cache")
_VERSION_TTL_SECONDS = 3600


def _extract_version(data):
    """Build a version string from whatever the API returns."""
    if isinstance(data, str):
        return data.strip() or None

    if not isinstance(data, dict):
        return None

    parts = [
        data.get("app_major_version"),
        data.get("app_minor_version"),
        data.get("app_service_release"),
    ]

    if all(part not in (None, "") for part in parts):
        return ".".join(str(part) for part in parts)

    for key, value in data.items():
        if (
            "version" in str(key).lower()
            and isinstance(value, (str, int, float))
            and str(value).strip()
        ):
            return str(value).strip()

    return None


def get_cppm_version_string(login):
    """
    Return the ClearPass version for the active environment.

    Cached per environment for an hour, because the version only changes
    on upgrade. Failures never break the health check.
    """
    cached = _VERSION_CACHE.get("entry")

    if cached and time.time() - cached["time"] < _VERSION_TTL_SECONDS:
        return cached["value"]

    try:
        data = ApiLocalServerConfiguration.get_cppm_version(login)
    except Exception as exc:
        logger.warning("ClearPass version lookup failed: %s", exc)
        return None

    version = _extract_version(data)

    if version is None:
        logger.warning(
            "Unable to read ClearPass version. Response fields: %s",
            list(data) if isinstance(data, dict) else type(data).__name__,
        )
        return None

    _VERSION_CACHE["entry"] = {"value": version, "time": time.time()}
    logger.info("ClearPass version: %s", version)

    return version

def check_clearpass():
    """
    Check ClearPass connectivity, authentication
    and REST API availability using the active
    application configuration.
    """

    logger.info(
        "Running health check..."
    )

    result = {
        "connected": False,
        "authentication": False,
        "service_api": False,
        "response_ms": 0,
        "reachable": False,
        "response_status": "unknown",
        "service_count": 0,
        "error": None,
        "server": None,
        "version": None
    }

    try:

        # -------------------------------------------------
        # Read ClearPass API server from the active
        # environment configuration.
        # -------------------------------------------------

        server_url = cp_env.getenv(
            "CLEARPASS_API_URL"
        )

        if not server_url:

            result["error"] = (
                "CLEARPASS_API_URL is not configured"
            )

            return result

        parsed_url = urlparse(
            server_url
        )

        result["server"] = (
            parsed_url.hostname
        )

        if not result["server"]:

            result["error"] = (
                "CLEARPASS_API_URL is invalid"
            )

            return result

        port = (
            parsed_url.port
            or 443
        )

        start = time.time()

        # -------------------------------------------------
        # TCP connectivity
        # -------------------------------------------------

        if not tcp_check(
            result["server"],
            port
        ):

            result["error"] = (
                "ClearPass server unreachable"
            )

            return result

        result["reachable"] = True

        # -------------------------------------------------
        # ClearPass REST API authentication
        # -------------------------------------------------

        login = get_login()

        # -------------------------------------------------
        # ClearPass Service API
        # -------------------------------------------------

        services = (
            ApiPolicyElements
            .get_config_service(
                login,
                limit=1000
            )
        )

        api_token = getattr(
            login,
            "api_token",
            None
        )

        if not api_token:

            result["error"] = (
                "ClearPass REST API "
                "authentication failed"
            )

            return result

        result["authentication"] = True

        if not isinstance(
            services,
            dict
        ):

            result["error"] = (
                "ClearPass Service API returned "
                "an unexpected response"
            )

            return result

        embedded = services.get(
            "_embedded",
            {}
        )

        items = embedded.get(
            "items",
            []
        )

        result["service_count"] = len(
            items
        )

        result["service_api"] = True

        # -------------------------------------------------
        # Response time
        # -------------------------------------------------

        end = time.time()

        result["response_ms"] = round(
            (end - start) * 1000
        )

        if result["response_ms"] < 250:

            result["response_status"] = (
                "good"
            )

        elif result["response_ms"] < 1000:

            result["response_status"] = (
                "warning"
            )

        else:

            result["response_status"] = (
                "critical"
            )

        result["connected"] = True
        result["version"] = get_cppm_version_string(login)

    except Exception as exc:

        logger.warning(
            "ClearPass health check failed: %s",
            exc
        )

        result["error"] = str(
            exc
        )

    return result