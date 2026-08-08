import time
import yaml 
import socket
import logging
logger = logging.getLogger(__name__)

from urllib.parse import urlparse

from pyclearpass import *
from cp_client import get_login

def tcp_check(host):

    try:

        sock = socket.create_connection(
            (host, 443),
            timeout=1
        )

        sock.close()

        return True

    except Exception:

        return False

def check_clearpass():
    logger.info("Running health check...")
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

        with open("config.yaml", "r") as f:
            cfg = yaml.safe_load(f)

            server_url = cfg["clearpass"]["server"]
            result["server"] = urlparse(server_url).hostname

        start = time.time()

        if not tcp_check(result["server"]):

            result["error"] = "ClearPass server unreachable"

            return result
        result["reachable"] = True

        login = get_login()

        result["authentication"] = True

        services = ApiPolicyElements.get_config_service(
            login,
            limit=1000
        )

        result["service_count"] = len(
            services.get("_embedded", {}).get("items", [])
        )

        result["service_api"] = True

        end = time.time()

        result["response_ms"] = round(
            (end - start) * 1000
        )
        if result["response_ms"] < 250:
            result["response_status"] = "good"
        elif result["response_ms"] < 1000:
            result["response_status"] = "warning"
        else:
            result["response_status"] = "critical"

        result["connected"] = True

    except Exception as e:

        result["error"] = str(e)

    return result