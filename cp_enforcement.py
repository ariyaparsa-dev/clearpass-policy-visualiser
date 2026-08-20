import logging
import time
logger = logging.getLogger(__name__)

from pyclearpass import *
from cp_client import get_login
from cp_endpoint import get_matching_endpoint_count

PROFILE_CACHE = {}
ENFORCEMENT_POLICY_CACHE = {}
ENFORCEMENT_POLICY_LOOKUP_CACHE = {}

def build_qualified_attribute(
    condition_type,
    condition_name
):
    if not condition_type:
        return condition_name

    return f"{condition_type}:{condition_name}"

def get_enforcement_policy(policy_name):

    if policy_name in ENFORCEMENT_POLICY_LOOKUP_CACHE:
        return ENFORCEMENT_POLICY_LOOKUP_CACHE[
            policy_name
        ]

    login = get_login()

    policy = (
        ApiPolicyElements
        .get_enforcement_policy_name_by_name(
            login,
            name=policy_name
        )
    )

    ENFORCEMENT_POLICY_LOOKUP_CACHE[
        policy_name
    ] = policy

    return policy


def get_enforcement_profile(profile_name):

    if profile_name in PROFILE_CACHE:

        return PROFILE_CACHE[
            profile_name
        ]

    login = get_login()

    profile = (
        ApiEnforcementProfile
        .get_enforcement_profile_name_by_name(
            login,
            name=profile_name
        )
    )

    PROFILE_CACHE[
        profile_name
    ] = profile

    return profile

def get_all_enforcement_policies():
    """
    Retrieve all Enforcement Policies from ClearPass.

    The collection response uses:

        {
            "count": ...,
            "_embedded": {
                "items": [...]
            }
        }

    Pagination is used so the result is not limited by the
    ClearPass collection endpoint.
    """

    login = get_login()

    policies = []

    offset = 0
    page_size = 100
    total_count = None

    while True:

        response = (
            ApiPolicyElements
            .get_enforcement_policy(
                login,
                offset=offset,
                limit=page_size,
                calculate_count="true",
            )
        )

        if not isinstance(
            response,
            dict,
        ):

            logger.warning(
                "Unexpected Enforcement Policy collection "
                "response type: %s",
                type(response).__name__,
            )

            break

        embedded = response.get(
            "_embedded",
            {},
        )

        if not isinstance(
            embedded,
            dict,
        ):

            logger.warning(
                "Enforcement Policy collection response "
                "did not contain an _embedded dictionary."
            )

            break

        items = embedded.get(
            "items",
            [],
        )

        if not isinstance(
            items,
            list,
        ):

            logger.warning(
                "Enforcement Policy collection response "
                "did not contain an items list."
            )

            break

        if total_count is None:

            count_value = response.get(
                "count"
            )

            try:

                total_count = int(
                    count_value
                )

            except (
                TypeError,
                ValueError,
            ):

                total_count = None

        policies.extend(
            items
        )

        if not items:
            break

        offset += len(
            items
        )

        if (
            total_count is not None
            and
            offset >= total_count
        ):

            break

        if len(
            items
        ) < page_size:

            break

    logger.info(
        "Retrieved %s Enforcement Policies from "
        "ClearPass",
        len(
            policies
        ),
    )

    return policies
def build_profile_reference_cache():
    """
    Build complete Enforcement Profile references.

    Pass 1 records profile references from every
    Enforcement Policy, including policies that are not
    assigned to a Service.

    Pass 2 attaches Services to the Enforcement Policies
    used by those Services.
    """

    from cp_services import get_all_services

    cache_start = time.perf_counter()

    references = {}

    policies_by_name = {}

    services = get_all_services()

    policy_summaries = (
        get_all_enforcement_policies()
    )


    def ensure_profile_reference(
        profile_name,
    ):
        """
        Ensure an Enforcement Profile cache entry exists.
        """

        if not profile_name:
            return None

        if profile_name not in references:

            references[
                profile_name
            ] = {
                "policies": {},
                "services": {},
            }

        return references[
            profile_name
        ]


    def ensure_policy_reference(
        profile_name,
        policy,
    ):
        """
        Ensure an Enforcement Policy is associated with an
        Enforcement Profile.
        """

        profile_reference = (
            ensure_profile_reference(
                profile_name
            )
        )

        if profile_reference is None:
            return None

        policy_name = policy.get(
            "name"
        )

        if not policy_name:
            return None

        existing_policy = profile_reference[
            "policies"
        ].get(
            policy_name
        )

        if existing_policy is None:

            existing_policy = {
                "id": policy.get(
                    "id"
                ),
                "name": policy_name,
                "description": policy.get(
                    "description"
                ),
                "services": {},
            }

            profile_reference[
                "policies"
            ][
                policy_name
            ] = existing_policy

        else:

            if (
                existing_policy.get(
                    "id"
                )
                is None
            ):

                existing_policy[
                    "id"
                ] = policy.get(
                    "id"
                )

            if (
                not existing_policy.get(
                    "description"
                )
            ):

                existing_policy[
                    "description"
                ] = policy.get(
                    "description"
                )

        return existing_policy


    def get_policy_profile_names(
        policy,
    ):
        """
        Return all Enforcement Profile names referenced by
        an Enforcement Policy.

        This includes the default Enforcement Profile and
        every profile assigned to a policy rule.
        """

        profile_names = []

        default_profile = policy.get(
            "default_enforcement_profile"
        )

        if default_profile:

            profile_names.append(
                default_profile
            )

        for rule in policy.get(
            "rules",
            [],
        ):

            if not isinstance(
                rule,
                dict,
            ):

                continue

            for profile_name in rule.get(
                "enforcement_profile_names",
                [],
            ):

                if (
                    profile_name
                    and
                    profile_name
                    not in profile_names
                ):

                    profile_names.append(
                        profile_name
                    )

        return profile_names


    # -------------------------------------------------
    # Pass 1
    #
    # Retrieve every Enforcement Policy by name so the
    # complete policy rules are available.
    #
    # This includes policies unused by any Service.
    # -------------------------------------------------

    for policy_summary in policy_summaries:

        if not isinstance(
            policy_summary,
            dict,
        ):

            continue

        policy_name = policy_summary.get(
            "name"
        )

        if not policy_name:
            continue

        try:

            policy = get_enforcement_policy(
                policy_name
            )

        except Exception:

            logger.exception(
                "Unable to retrieve Enforcement Policy "
                "while building profile references: %s",
                policy_name,
            )

            continue

        if not isinstance(
            policy,
            dict,
        ):

            continue

        policies_by_name[
            policy_name
        ] = policy

        for profile_name in (
            get_policy_profile_names(
                policy
            )
        ):

            ensure_policy_reference(
                profile_name,
                policy,
            )


    # -------------------------------------------------
    # Pass 2
    #
    # Attach Services to each profile and policy
    # relationship.
    # -------------------------------------------------

    unique_service_policy_names = set()

    for service in services:

        if not isinstance(
            service,
            dict,
        ):

            continue

        service_name = service.get(
            "name",
            "Unknown Service",
        )

        if service_name.startswith(
            "--------"
        ):

            continue

        policy_name = service.get(
            "enf_policy"
        )

        if not policy_name:
            continue

        unique_service_policy_names.add(
            policy_name
        )

        policy = policies_by_name.get(
            policy_name
        )

        if policy is None:

            try:

                policy = get_enforcement_policy(
                    policy_name
                )

            except Exception:

                logger.exception(
                    "Unable to retrieve Service-assigned "
                    "Enforcement Policy while building "
                    "profile references: %s",
                    policy_name,
                )

                continue

            if not isinstance(
                policy,
                dict,
            ):

                continue

            policies_by_name[
                policy_name
            ] = policy

            for profile_name in (
                get_policy_profile_names(
                    policy
                )
            ):

                ensure_policy_reference(
                    profile_name,
                    policy,
                )

        service_reference = {
            "name": service_name,
            "id": service.get(
                "id"
            ),
        }

        for profile_name in (
            get_policy_profile_names(
                policy
            )
        ):

            policy_reference = (
                ensure_policy_reference(
                    profile_name,
                    policy,
                )
            )

            if policy_reference is None:
                continue

            references[
                profile_name
            ][
                "services"
            ][
                service_name
            ] = service_reference

            policy_reference[
                "services"
            ][
                service_name
            ] = service_reference


    logger.info(
        "Enforcement profile reference cache built: "
        "%s profiles, %s total policies, "
        "%s Service-assigned policies in %.3fs",
        len(
            references
        ),
        len(
            policies_by_name
        ),
        len(
            unique_service_policy_names
        ),
        time.perf_counter()
        -
        cache_start,
    )


    return {

        profile_name: {

            "policies": sorted(
                [
                    {
                        "id": policy.get(
                            "id"
                        ),
                        "name": policy.get(
                            "name"
                        ),
                        "description": policy.get(
                            "description"
                        ),
                        "services": sorted(
                            list(
                                policy.get(
                                    "services",
                                    {}
                                ).values()
                            ),
                            key=lambda service: (
                                service.get(
                                    "name",
                                    ""
                                )
                            ),
                        ),
                    }
                    for policy in profile_data[
                        "policies"
                    ].values()
                ],
                key=lambda policy: (
                    policy.get(
                        "name",
                        ""
                    )
                ),
            ),

            "services": sorted(
                list(
                    profile_data[
                        "services"
                    ].values()
                ),
                key=lambda service: (
                    service.get(
                        "name",
                        ""
                    )
                ),
            ),

        }

        for profile_name, profile_data
        in references.items()

    }

def get_enforcement_details(policy_name):
    if policy_name in ENFORCEMENT_POLICY_CACHE:

        return ENFORCEMENT_POLICY_CACHE[
            policy_name
        ]


    policy = get_enforcement_policy(
        policy_name
    )


    result = {
        "name": policy["name"],
        "description": policy.get("description"),

        "default_enforcement_profile":
            policy.get(
                "default_enforcement_profile"
            ),

        "rule_eval_algo":
            policy.get(
                "rule_eval_algo"
            ),

        "rules": []
    }

    for rule in policy.get("rules", []):
   
        condition_text = "Unknown"

        if rule.get("condition"):

            conditions = []
            condition_attributes = []

            for c in rule.get("condition", []):
           
                value = c.get("value", "")

                if value == "&nbsp;":
                    value = ""

                condition_type = c.get(
                    "type",
                    ""
                )

                condition_name = c.get(
                    "name",
                    ""
                )

                condition_oper = c.get(
                    "oper",
                    ""
                )

                oper_map = {
                    "EQUALS": "=",
                    "NOT_EQUALS": "!=",
                    "EXISTS": "EXISTS",
                    "NOT_EXISTS": "NOT EXISTS",
                    "CONTAINS": "CONTAINS",
                    "BELONGS_TO": "BELONGS_TO",
                    "IN_RANGE": "IN_RANGE",
                    "GREATER_THAN": ">",
                    "LESS_THAN": "<",
                    "GREATER_THAN_OR_EQUALS": ">=",
                    "LESS_THAN_OR_EQUALS": "<=",
                    "MATCHES_ALL": "ALL",
                    "MATCHES_ANY": "ANY"
                }

                condition_oper = oper_map.get(
                    condition_oper,
                    condition_oper
                )

                qualified_name = build_qualified_attribute(
                    condition_type,
                    condition_name
                )

                condition = (
                    f"{qualified_name} "
                    f"{condition_oper}"
                )

                if value:

                    condition += (
                        f" {value}"
                    )

                endpoint_count = get_matching_endpoint_count(
                    condition_type,
                    condition_name,
                    condition_oper,
                    value
                )
                        
                condition_attributes.append(
                    {
                        "source_type": condition_type,
                        "attribute_name": condition_name,
                        "operator": condition_oper,
                        "value": value,
                        "endpoint_count": endpoint_count
                    }
                )

                conditions.append(
                    condition
                )
          
            condition_text = (
                "\nAND\n".join(
                    conditions
                )
            )


        rule_data = {
            "condition": condition_text,
            "match_type": "AND",
            "attributes": condition_attributes,
            "profiles": []
        }


        for profile_name in rule.get(
            "enforcement_profile_names",
            []
        ):

            try:

                if profile_name not in PROFILE_CACHE:

                    PROFILE_CACHE[
                        profile_name
                    ] = get_enforcement_profile(
                        profile_name
                    )



                profile = PROFILE_CACHE[
                    profile_name
                ]


                rule_data["profiles"].append(
                    {
                        "name": profile["name"],
                        "profile_id":
                            profile.get("id"),
                        "description":
                            profile.get("description"),

                        "action": profile.get(
                            "action"
                        ),
                        "attributes": profile.get(
                            "attributes",
                            []
                        ),
                        "profile_type": profile.get(
                            "type"
                        )
                    }
                )

            except Exception:

                rule_data["profiles"].append(
                    {
                        "name": profile_name,
                        "action": None,
                        "attributes": []
                    }
                )

        result["rules"].append(
            rule_data
        )

    ENFORCEMENT_POLICY_CACHE[
        policy_name
    ] = result

    return result

