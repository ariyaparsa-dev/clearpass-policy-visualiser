import os
import time
import logging
from pathlib import Path

import psycopg
from psycopg.rows import dict_row


logger = logging.getLogger(__name__)


class EndpointSqlError(Exception):
    """Raised when endpoint profile data cannot be loaded from SQL."""


def _required_env(name):
    value = os.getenv(name)

    if not value:
        raise EndpointSqlError(
            f"{name} is not configured."
        )

    return value


def _normalise_mac(mac):
    if not mac:
        return ""

    return (
        str(mac)
        .replace("-", "")
        .replace(":", "")
        .replace(".", "")
        .lower()
    )


def _get_sql_query():
    query_file = os.getenv(
        "CP_SQL_QUERY_FILE",
        "sql/endpoint_profiles.sql"
    )

    path = Path(query_file)

    if not path.exists():
        raise EndpointSqlError(
            f"SQL query file not found: {query_file}"
        )

    return path.read_text(
        encoding="utf-8"
    )


def _normalise_endpoint_row(row):
    device_category = (
        row.get("device_category")
        or row.get("other_category")
        or ""
    )

    device_family = (
        row.get("device_family")
        or row.get("other_family")
        or ""
    )

    device_name = (
        row.get("device_name")
        or row.get("other_name")
        or ""
    )

    mac_address = (
        row.get("mac_address")
        or ""
    )

    return {
        "id": row.get("id"),
        "mac_address": mac_address,
        "normalised_mac": _normalise_mac(mac_address),
        "ip_address": row.get("ip_address") or "",
        "hostname": row.get("hostname") or "",
        "mac_vendor": row.get("mac_vendor") or "",
        "device_category": device_category,
        "device_family": device_family,
        "device_name": device_name,
        "device_type": device_family,
        "expanded_device_type": device_name,
        "fingerprint": row.get("fingerprint") or "",
        "extras": row.get("extras") or {},
        "updated_at": row.get("updated_at"),
        "added_at": row.get("added_at"),
        "profiled_by": row.get("profiled_by") or "",
    }


def get_endpoint_profiles_from_sql():
    start = time.time()

    host = _required_env("CP_SQL_HOST")
    port = int(os.getenv("CP_SQL_PORT", "5432"))
    database = _required_env("CP_SQL_DATABASE")
    username = _required_env("CP_SQL_USERNAME")
    password = _required_env("CP_SQL_PASSWORD")
    sslmode = os.getenv("CP_SQL_SSLMODE", "prefer")

    query = _get_sql_query()

    conninfo = (
        f"host={host} "
        f"port={port} "
        f"dbname={database} "
        f"user={username} "
        f"password={password} "
        f"sslmode={sslmode}"
    )

    try:
        with psycopg.connect(
            conninfo,
            row_factory=dict_row
        ) as conn:

            with conn.cursor() as cur:
                cur.execute(query)
                rows = cur.fetchall()

    except Exception as exc:
        logger.exception(
            "Failed to load endpoint profiling data from SQL."
        )

        raise EndpointSqlError(
            "Failed to load endpoint profiling data from SQL."
        ) from exc

    endpoints = [
        _normalise_endpoint_row(row)
        for row in rows
    ]

    logger.info(
        "Endpoint profiling SQL load complete: %s rows in %.3fs",
        len(endpoints),
        time.time() - start
    )

    return endpoints


def build_fingerprint_cache_from_sql():
    endpoints = get_endpoint_profiles_from_sql()

    cache = {}

    for endpoint in endpoints:
        normalised_mac = endpoint.get("normalised_mac")

        if not normalised_mac:
            continue

        cache[normalised_mac] = endpoint

 #   logger.info(
 #       "Fingerprint cache built from SQL: %s entries",
 #       len(cache)
 #   )

    return cache