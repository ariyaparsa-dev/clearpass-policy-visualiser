import os
import time
import socket
import logging

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
        "server": None
    }

    try:

        # -------------------------------------------------
        # Read ClearPass API server from the active
        # environment configuration.
        # -------------------------------------------------

        server_url = os.getenv(
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

    except Exception as exc:

        logger.warning(
            "ClearPass health check failed: %s",
            exc
        )

        result["error"] = str(
            exc
        )

    return result