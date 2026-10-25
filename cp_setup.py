import io
import os
import socket
import logging
import tempfile

from cp_netdiag import (
    explain_api_failure,
    explain_postgres_failure,
    failure_message,
    reset_run,
    tcp_probe,
)
from urllib.parse import urlparse

import psycopg
from dotenv import dotenv_values

from pyclearpass import (
    ClearPassAPILogin,
    ApiPolicyElements
)

from cp_default_env import format_value
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

    # The port the REST call will really use: an explicit port, otherwise
    # 80 for http:// and 443 for https://.
    port = parsed_url.port or (
        80 if parsed_url.scheme == "http" else 443
    )

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
            "message": failure_message(
                host,
                port,
                extra_ports=(
                    int(config["sql_port"]),
                ) if str(config.get("sql_port", "")).isdigit()
                  and config.get("sql_host") == host
                  else (),
                prefix=(
                    "Unable to connect to the "
                    f"ClearPass server at {host}:{port}."
                ),
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
                    explain_api_failure(
                        None,
                        config["clearpass_api_url"],
                        verify_ssl,
                    )
                    or (
                        "Unable to authenticate to the "
                        "ClearPass REST API. "
                        "Check the API Client ID and "
                        "Client Secret."
                    )
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
            "message": explain_api_failure(
                exc,
                config["clearpass_api_url"],
                verify_ssl,
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

        # If the TCP port itself is not reachable, explain the
        # network problem. If it is reachable, the cause is more
        # likely the credentials or database name.
        try:
            sql_host = config["sql_host"]
            sql_port = int(config["sql_port"])

            if tcp_probe(sql_host, sql_port) != "open":
                return {
                    "success": False,
                    "message": failure_message(
                        sql_host,
                        sql_port,
                        prefix=(
                            "Unable to connect to PostgreSQL at "
                            f"{sql_host}:{sql_port}."
                        ),
                    )
                }
        except Exception:
            pass

        # The port is open, so say what the server answered when the
        # error is one that is recognised (wrong password, address not
        # allowed). Anything else keeps the generic message below.
        explained = explain_postgres_failure(
            exc,
            config.get("sql_host"),
            config.get("sql_port"),
            config.get("sql_username"),
        )

        if explained:
            return {
                "success": False,
                "message": explained
            }

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


def _setup_settings(config):
    """
    The values Initial Setup writes, in file order.

    Only fields present in config are returned. Initial Setup passes all of
    them; the Environments page validates with a smaller set (no RADIUS
    fields), and must not fail because of that.
    """

    fields = [
        ("CLEARPASS_API_URL", "clearpass_api_url"),
        ("CLEARPASS_CLIENT_ID", "clearpass_client_id"),
        ("CLEARPASS_CLIENT_SECRET", "clearpass_client_secret"),
        ("CLEARPASS_VERIFY_SSL", "clearpass_verify_ssl"),
        ("RADIUS_SERVER", "radius_server"),
        ("RADIUS_AUTH_PORT", "radius_port"),
        ("RADIUS_SECRET", "radius_secret"),
        ("RADIUS_NAS_IDENTIFIER", "nas_identifier"),
        ("CP_SQL_HOST", "sql_host"),
        ("CP_SQL_PORT", "sql_port"),
        ("CP_SQL_DATABASE", "sql_database"),
        ("CP_SQL_USERNAME", "sql_username"),
        ("CP_SQL_PASSWORD", "sql_password"),
    ]

    return [
        (key, config[name])
        for key, name in fields
        if name in config
    ]


def unstorable_settings(config):
    """
    Names of settings whose value would not read back unchanged from the
    configuration file.

    Values are quoted when written, so '#', spaces, quotes and backslashes
    are safe. What cannot be stored is a value containing a variable
    reference such as ${NAME}, which the file reader replaces with the
    variable's value. The values are never included in the result.
    """

    try:
        text = "".join(
            f"{key}={format_value(str(value))}\n"
            for key, value in _setup_settings(config)
        )

        stored = dotenv_values(stream=io.StringIO(text))

        return [
            key
            for key, value in _setup_settings(config)
            if stored.get(key) != str(value)
        ]

    except Exception:
        return [key for key, _ in _setup_settings(config)]


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

    reset_run()

    results = {
        "clearpass": None,
        "api": None,
        "postgresql": None
    }

    errors = []

    # A value that cannot be stored would be saved wrongly and then fail
    # at the next start, so say so before testing anything.
    unstorable = unstorable_settings(config)

    if unstorable:

        logger.warning(
            "Settings that cannot be stored safely: %s.",
            ", ".join(unstorable)
        )

        message = (
            "A value cannot be stored safely in the configuration file "
            "(" + ", ".join(unstorable) + "). A value containing a "
            "variable reference such as ${NAME} is not supported."
        )

        return {
            "success": False,
            "errors": [message],
            "results": {
                "settings": {
                    "success": False,
                    "message": message
                }
            }
        }

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

    Values are quoted, so a secret containing '#', spaces or quotes is read
    back exactly as it was typed. The file is read back before it replaces
    the old one, and is created with owner-only permissions from the start.
    """

    values = dict(_setup_settings(config))

    unstorable = unstorable_settings(config)

    if unstorable:
        raise ValueError(
            "A value cannot be stored safely in the configuration file: "
            + ", ".join(unstorable)
        )

    def line(key):
        return f"{key}={format_value(str(values[key]))}"

    lines = [
        "# ClearPass Policy Visualiser",
        "# Generated by Initial Setup",
        "",
        "# ClearPass REST API",
        line("CLEARPASS_API_URL"),
        line("CLEARPASS_CLIENT_ID"),
        line("CLEARPASS_CLIENT_SECRET"),
        line("CLEARPASS_VERIFY_SSL"),
        "",
        "# RADIUS Authentication",
        line("RADIUS_SERVER"),
        line("RADIUS_AUTH_PORT"),
        line("RADIUS_SECRET"),
        line("RADIUS_NAS_IDENTIFIER"),
        "",
        "# PostgreSQL Endpoint Profiling",
        line("CP_SQL_HOST"),
        line("CP_SQL_PORT"),
        line("CP_SQL_DATABASE"),
        line("CP_SQL_USERNAME"),
        line("CP_SQL_PASSWORD"),
        "CP_SQL_SSLMODE=prefer",
        "CP_SQL_QUERY_FILE=sql/endpoint_profiles.sql",
        "",
    ]

    config_file = get_visualiser_env_file()

    descriptor, temp_name = tempfile.mkstemp(
        dir=str(config_file.parent),
        prefix=config_file.name + ".",
        suffix=".tmp"
    )

    try:

        with os.fdopen(
            descriptor,
            "w",
            encoding="utf-8",
            newline=""
        ) as handle:
            handle.write("\n".join(lines))
            handle.flush()
            os.fsync(handle.fileno())

        if os.name == "posix":
            os.chmod(temp_name, 0o600)

        stored = dotenv_values(temp_name)

        if any(
            stored.get(key) != str(value)
            for key, value in values.items()
        ):
            raise ValueError(
                "The configuration file did not read back as written. "
                "Nothing was changed."
            )

        os.replace(temp_name, config_file)

    except BaseException:

        try:
            os.unlink(temp_name)
        except OSError:
            pass

        raise

    logger.info(
        "Initial setup configuration saved."
    )
