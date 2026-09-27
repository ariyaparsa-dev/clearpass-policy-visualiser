import logging
import os

import psycopg
from dotenv import load_dotenv
from psycopg.rows import dict_row

from cp_paths import get_visualiser_env_file


logger = logging.getLogger(__name__)


load_dotenv(
    get_visualiser_env_file(),
    override=False,
)


def get_current_hour_service_hit_counts():
    """
    Return ClearPass Service hit counts for the current hour.

    The result is a dictionary keyed by Service name:

        {
            "Service A": 10,
            "Service B": 3,
        }

    An empty dictionary means the query completed successfully
    but no Services have authentication records in the current hour.

    Database or query failures are raised to the caller so they
    cannot be mistaken for genuine zero hit counts.
    """

    sql_host = os.getenv("CP_SQL_HOST")
    sql_username = os.getenv(
        "CP_SQL_USERNAME",
        "appexternal",
    )
    sql_password = os.getenv("CP_SQL_PASSWORD")
    sql_sslmode = os.getenv(
        "CP_SQL_SSLMODE",
        "prefer",
    )

    if not sql_host:
        raise RuntimeError(
            "CP_SQL_HOST is not configured."
        )

    if not sql_password:
        raise RuntimeError(
            "CP_SQL_PASSWORD is not configured."
        )

    query = """
        SELECT
            service,
            COUNT(*)::bigint AS hit_count
        FROM public.auth
        WHERE "timestamp" >= date_trunc(
            'hour',
            CURRENT_TIMESTAMP
        )
          AND "timestamp" < CURRENT_TIMESTAMP
          AND service IS NOT NULL
        GROUP BY service
        ORDER BY hit_count DESC, service;
    """

    logger.info(
        "Loading current-hour Service hit counts "
        "from ClearPass Insight..."
    )

    try:
        with psycopg.connect(
            host=sql_host,
            port=5433,
            dbname="insightdb",
            user=sql_username,
            password=sql_password,
            sslmode=sql_sslmode,
            row_factory=dict_row,
            connect_timeout=5,
        ) as connection:
            with connection.cursor() as cursor:
                cursor.execute(query)
                rows = cursor.fetchall()

    except Exception:
        logger.exception(
            "Unable to load Service hit counts "
            "from ClearPass Insight."
        )
        raise

    hit_counts = {
        str(row["service"]): int(
            row["hit_count"]
        )
        for row in rows
        if row.get("service")
    }

    logger.info(
        "Current-hour Service hit counts loaded: "
        "%s Services with hits.",
        len(hit_counts),
    )

    return hit_counts