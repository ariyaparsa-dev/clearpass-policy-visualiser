import os
import socket
import logging

from urllib.parse import urlparse

import psycopg

from pyclearpass import (
    ClearPassAPILogin,
    ApiPolicyElements
)

from cp_paths import get_visualiser_env_file


logger = logging.getLogger(__name__)


def secure_setup_configuration_file():
    """
    Restrict access to the Visualiser configuration file
    on POSIX systems when the file already exists.
    """

    if os.name != "posix":
        return

    config_file = get_visualiser_env_file()

    if config_file.exists():
        config_file.chmod(
            0o600
        )


def is_setup_complete(log_missing=False):
    """
    Return True when the minimum configuration required
    to initialise the ClearPass Policy Visualiser exists.

    ClearPass REST API, RADIUS and PostgreSQL endpoint
    profiling configuration are required.
    """

    secure_setup_configuration_file()

    clearpass_required_settings = [
        "CLEARPASS_API_URL",
        "CLEARPASS_CLIENT_ID",
        "CLEARPASS_CLIENT_SECRET",
    ]

    missing_clearpass_settings = [
        setting
        for setting in clearpass_required_settings
        if not os.getenv(setting)
    ]

    if missing_clearpass_settings:

        if log_missing:

            logger.info(
                "Initial setup required. "
                "Missing ClearPass API settings: %s",
                ", ".join(
                    missing_clearpass_settings
                )
            )

        return False

    radius_required_settings = [
        "RADIUS_SERVER",
        "RADIUS_SECRET",
    ]

    missing_radius_settings = [
        setting
        for setting in radius_required_settings
        if not os.getenv(setting)
    ]

    if missing_radius_settings:

        if log_missing:

            logger.info(
                "Initial setup required. "
                "Missing RADIUS settings: %s",
                ", ".join(
                    missing_radius_settings
                )
            )

        return False

    sql_required_settings = [
        "CP_SQL_HOST",
        "CP_SQL_PASSWORD",
    ]

    missing_sql_settings = [
        setting
        for setting in sql_required_settings
        if not os.getenv(setting)
    ]

    if missing_sql_settings:

        if log_missing:

            logger.info(
                "Initial setup required. "
                "Missing PostgreSQL settings: %s",
                ", ".join(
                    missing_sql_settings
                )
            )

        return False

    return True


def test_clearpass_connectivity(config):
    """
    Test basic TCP connectivity to the ClearPass
    REST API endpoint.

    This confirms network reachability only.
    """

    server_url = config[
        "clearpass_api_url"
    ]

    parsed_url = urlparse(
        server_url
    )

    host = parsed_url.hostname

    if not host:

        return {
            "success": False,
            "message": (
                "ClearPass API URL is invalid."
            )
        }

    port = parsed_url.port or 443

    logger.info(
        "Testing ClearPass connectivity "
        "to %s:%s...",
        host,
        port
    )

    try:

        with socket.create_connection(
            (
                host,
                port
            ),
            timeout=3
        ):
            pass

    except Exception:

        logger.warning(
            "ClearPass connectivity test failed "
            "for %s:%s.",
            host,
            port
        )

        return {
            "success": False,
            "message": (
                "Unable to connect to the "
                "ClearPass server at "
                f"{host}:{port}. "
                "Check the server address and "
                "network connectivity."
            )
        }

    logger.info(
        "ClearPass connectivity test successful."
    )

    return {
        "success": True,
        "message": (
            "ClearPass server reachable."
        )
    }


def test_clearpass_api(config):
    """
    Validate the submitted ClearPass REST API
    configuration using a small read-only API request.

    Authentication is considered successful only when
    the API call returns a valid service response.
    """

    verify_ssl = (
        config[
            "clearpass_verify_ssl"
        ].lower()
        == "true"
    )

    logger.info(
        "Testing ClearPass REST API..."
    )

    try:

        login = ClearPassAPILogin(
            server=config[
                "clearpass_api_url"
            ],
            granttype="client_credentials",
            clientsecret=config[
                "clearpass_client_secret"
            ],
            clientid=config[
                "clearpass_client_id"
            ],
            verify_ssl=verify_ssl
        )

        response = (
            ApiPolicyElements
            .get_config_service(
                login,
                limit=1
            )
        )

        # -------------------------------------------------
        # Validate authentication
        # -------------------------------------------------

        api_token = getattr(
            login,
            "api_token",
            None
        )

        if not api_token:

            logger.warning(
                "ClearPass REST API authentication "
                "failed. No API token was obtained."
            )

            return {
                "success": False,
                "message": (
                    "Unable to authenticate to the "
                    "ClearPass REST API. "
                    "Check the API Client ID and "
                    "Client Secret."
                )
            }

        # -------------------------------------------------
        # Validate API response
        # -------------------------------------------------

        if not isinstance(
            response,
            dict
        ):

            logger.warning(
                "ClearPass REST API returned "
                "an unexpected response."
            )

            return {
                "success": False,
                "message": (
                    "The ClearPass REST API returned "
                    "an unexpected response."
                )
            }

        embedded = response.get(
            "_embedded"
        )

        if not isinstance(
            embedded,
            dict
        ):

            logger.warning(
                "ClearPass REST API service request "
                "did not return the expected data."
            )

            return {
                "success": False,
                "message": (
                    "ClearPass REST API authentication "
                    "succeeded, but the service API "
                    "did not return the expected data."
                )
            }

    except Exception as exc:

        logger.warning(
            "ClearPass REST API validation "
            "failed: %s",
            exc
        )

        return {
            "success": False,
            "message": (
                "Unable to authenticate to the "
                "ClearPass REST API. "
                "Check the API URL, Client ID, "
                "Client Secret and SSL setting."
            )
        }

    logger.info(
        "ClearPass REST API validation successful."
    )

    return {
        "success": True,
        "message": (
            "ClearPass REST API authentication "
            "successful."
        )
    }


def test_postgresql(config):
    """
    Validate PostgreSQL connectivity using the
    submitted endpoint profiling configuration.
    """

    logger.info(
        "Testing PostgreSQL endpoint "
        "profiling connection..."
    )

    connection = None
    cursor = None

    try:

        connection = psycopg.connect(
            host=config[
                "sql_host"
            ],
            port=int(
                config[
                    "sql_port"
                ]
            ),
            dbname=config[
                "sql_database"
            ],
            user=config[
                "sql_username"
            ],
            password=config[
                "sql_password"
            ],
            sslmode="prefer",
            connect_timeout=3
        )

        cursor = connection.cursor()

        cursor.execute(
            "SELECT 1"
        )

        result = cursor.fetchone()

        if (
            not result
            or
            result[0] != 1
        ):

            logger.warning(
                "PostgreSQL connectivity test "
                "returned an unexpected result."
            )

            return {
                "success": False,
                "message": (
                    "PostgreSQL connection was "
                    "established, but the validation "
                    "query returned an unexpected "
                    "result."
                )
            }

    except Exception as exc:

        logger.warning(
            "PostgreSQL connectivity validation "
            "failed: %s",
            exc
        )

        return {
            "success": False,
            "message": (
                "Unable to connect to the "
                "PostgreSQL endpoint profiling "
                "database. Check the host, port, "
                "username and password."
            )
        }

    finally:

        if cursor is not None:

            try:

                cursor.close()

            except Exception:

                pass

        if connection is not None:

            try:

                connection.close()

            except Exception:

                pass

    logger.info(
        "PostgreSQL connectivity "
        "validation successful."
    )

    return {
        "success": True,
        "message": (
            "PostgreSQL connection successful."
        )
    }


def validate_setup_connectivity(config):
    """
    Validate the submitted configuration before
    writing .visualiser.env.

    All applicable tests are run so that the user
    can see every detected connectivity problem
    from a single submission.

    ClearPass REST API and PostgreSQL validation
    must both succeed.
    """

    logger.info(
        "Validating initial setup connectivity..."
    )

    results = {
        "clearpass": None,
        "api": None,
        "postgresql": None
    }

    errors = []

    # -------------------------------------------------
    # ClearPass server connectivity
    # -------------------------------------------------

    results["clearpass"] = (
        test_clearpass_connectivity(
            config
        )
    )

    if not results[
        "clearpass"
    ]["success"]:

        errors.append(
            results[
                "clearpass"
            ]["message"]
        )

        results["api"] = {
            "success": False,
            "skipped": True,
            "message": (
                "ClearPass REST API test skipped "
                "because the ClearPass server "
                "could not be reached."
            )
        }

    else:

        # -------------------------------------------------
        # ClearPass REST API
        # -------------------------------------------------

        results["api"] = (
            test_clearpass_api(
                config
            )
        )

        if not results[
            "api"
        ]["success"]:

            errors.append(
                results[
                    "api"
                ]["message"]
            )

    # -------------------------------------------------
    # PostgreSQL endpoint profiling
    # -------------------------------------------------

    results["postgresql"] = (
        test_postgresql(
            config
        )
    )

    if not results[
        "postgresql"
    ]["success"]:

        errors.append(
            results[
                "postgresql"
            ]["message"]
        )

    success = len(errors) == 0

    if success:

        logger.info(
            "Initial setup connectivity "
            "validation successful."
        )

    else:

        logger.warning(
            "Initial setup connectivity "
            "validation failed."
        )

    return {
        "success": success,
        "errors": errors,
        "results": results
    }


def save_setup_configuration(config):
    """
    Save configuration generated by the initial
    setup wizard.

    The generated configuration file may contain
    credentials and must remain excluded from
    source control.

    ClearPass REST API, RADIUS and PostgreSQL
    endpoint profiling configuration are written
    to the configuration file.

    On POSIX systems, restrict access to the
    application owner after writing the file.
    """

    lines = [
        "# ClearPass Policy Visualiser",
        "# Generated by Initial Setup",
        "",
        "# ClearPass REST API",
        (
            "CLEARPASS_API_URL="
            f"{config['clearpass_api_url']}"
        ),
        (
            "CLEARPASS_CLIENT_ID="
            f"{config['clearpass_client_id']}"
        ),
        (
            "CLEARPASS_CLIENT_SECRET="
            f"{config['clearpass_client_secret']}"
        ),
        (
            "CLEARPASS_VERIFY_SSL="
            f"{config['clearpass_verify_ssl']}"
        ),
        "",
        "# RADIUS Authentication",
        (
            "RADIUS_SERVER="
            f"{config['radius_server']}"
        ),
        (
            "RADIUS_AUTH_PORT="
            f"{config['radius_port']}"
        ),
        (
            "RADIUS_SECRET="
            f"{config['radius_secret']}"
        ),
        (
            "RADIUS_NAS_IDENTIFIER="
            f"{config['nas_identifier']}"
        ),
        "",
        "# PostgreSQL Endpoint Profiling",
        (
            "CP_SQL_HOST="
            f"{config['sql_host']}"
        ),
        (
            "CP_SQL_PORT="
            f"{config['sql_port']}"
        ),
        (
            "CP_SQL_DATABASE="
            f"{config['sql_database']}"
        ),
        (
            "CP_SQL_USERNAME="
            f"{config['sql_username']}"
        ),
        (
            "CP_SQL_PASSWORD="
            f"{config['sql_password']}"
        ),
        "CP_SQL_SSLMODE=prefer",
        (
            "CP_SQL_QUERY_FILE="
            "sql/endpoint_profiles.sql"
        ),
        "",
    ]

    config_file = get_visualiser_env_file()

    config_file.write_text(
        "\n".join(
            lines
        ),
        encoding="utf-8"
    )

    if os.name == "posix":

        config_file.chmod(
            0o600
        )

    logger.info(
        "Initial setup configuration saved."
    )