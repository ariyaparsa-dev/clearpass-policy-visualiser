import logging

from pyclearpass import *

from cp_client import get_login
from cp_insight_sql import get_current_hour_service_hit_counts


logger = logging.getLogger(__name__)


def get_all_services():
    login = get_login()

    result = ApiPolicyElements.get_config_service(
        login,
        limit=1000,
    )

    return result.get(
        "_embedded",
        {},
    ).get(
        "items",
        [],
    )


def get_service(service_id):
    login = get_login()

    return ApiPolicyElements.get_config_service_by_services_id(
        login,
        services_id=str(service_id),
    )


def get_all_services_with_hit_counts():
    """
    Return all configured ClearPass Services enriched with
    current-hour Hit Count data from ClearPass Insight.

    A Service with no Insight authentication records during
    the current hour receives a Hit Count of zero.

    Insight database failures are raised to the caller rather
    than being presented as zero activity.
    """

    services = get_all_services()

    hit_counts = get_current_hour_service_hit_counts()

    for service in services:
        service_name = str(
            service.get(
                "name",
                "",
            )
        )

        service["hit_count"] = hit_counts.get(
            service_name,
            0,
        )

    logger.info(
        "Service Hit Counts applied: "
        "%s Services with current-hour hits.",
        len(hit_counts),
    )

    return services