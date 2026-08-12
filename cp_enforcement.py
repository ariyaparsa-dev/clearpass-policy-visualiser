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

def build_profile_reference_cache():

    unique_policy_names = set()

    from cp_services import get_all_services
    cache_start = time.perf_counter()

    references = {}

    services = get_all_services()

    for service in services:

        policy_name = service.get(
            "enf_policy"
        )

        if not policy_name:
            continue

        unique_policy_names.add(
            policy_name
        )

        try:

            policy = get_enforcement_policy(
                policy_name
            )

            service_name = service.get(
                "name",
                "Unknown Service"
            )

            default_profile = policy.get(
                "default_enforcement_profile"
            )

            if (
                default_profile
                and not service_name.startswith("--------")
            ):

                if default_profile not in references:

                    references[default_profile] = {
                        "policies": {},
                        "services": {}
                    }

                if (
                    policy_name
                    not in references[default_profile]["policies"]
                ):

                    references[default_profile]["policies"][policy_name] = {
                        "name": policy_name,
                        "services": {}
                    }

                references[default_profile]["policies"][policy_name]["services"][service_name] = {
                    "name": service_name,
                    "id": service.get("id")
                }

                references[default_profile]["services"][service_name] = {
                    "name": service_name,
                    "id": service.get("id")
                }

            for rule in policy.get(
                "rules",
                []
            ):

                for profile_name in rule.get(
                    "enforcement_profile_names",
                    []
                ):
                    if profile_name not in references:

                        references[
                            profile_name
                        ] = {
                            "policies": {},
                            "services": {}
                        }

                    service_name = service.get(
                        "name",
                        "Unknown Service"
                    )
                    if service_name.startswith(
                        "--------"
                    ):
                        continue

                    if (
                        policy_name
                        not in references[
                            profile_name
                        ]["policies"]
                    ):

                        references[
                            profile_name
                        ]["policies"][
                            policy_name
                        ] = {
                            "name": policy_name,
                            "services": {}
                        }

                    references[
                        profile_name
                    ]["policies"][
                        policy_name
                    ]["services"][
                        service_name
                    ] = {
                        "name": service_name,
                        "id": service.get("id")
                    }


                    references[
                        profile_name
                    ]["services"][
                        service_name
                    ] = {
                        "name": service_name,
                        "id": service.get(
                            "id"
                        )
                    }

        except Exception:

            continue

    logger.info(
        "Enforcement profile reference cache used %s unique enforcement policies",
        len(unique_policy_names)
    )

    logger.info(
        "Enforcement profile reference cache built: %s profiles, %s unique policies in %.3fs",
        len(references),
        len(unique_policy_names),
        time.perf_counter() - cache_start
    )

    return {

        profile: {

            "policies": sorted(
                [
                    {
                        "name": policy["name"],
                        "services": sorted(
                            list(
                                policy["services"].values()
                            ),
                            key=lambda x: x.get(
                                "name",
                                ""
                            )
                        )
                    }
                    for policy in
                    data["policies"].values()
                ],
                key=lambda x: x["name"]
            ),

            "services": sorted(
                list(
                    data["services"].values()
                ),
                key=lambda x: x.get(
                    "name",
                    ""
                )
            )

        }

        for profile, data
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

