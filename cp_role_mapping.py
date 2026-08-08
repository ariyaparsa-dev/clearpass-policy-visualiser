from pyclearpass import *
from cp_endpoint import (
    get_matching_endpoint_count,
    get_matching_rule_count,
    get_rule_match_label
)

from cp_client import get_login
ROLE_MAPPING_CACHE = {}

def build_qualified_attribute(
    condition_type,
    condition_name
):
    if not condition_type:
        return condition_name

    return f"{condition_type}:{condition_name}"

def get_role_mapping_policy(policy_name):

    login = get_login()

    return ApiPolicyElements.get_role_mapping_name_by_name(
        login,
        name=policy_name
    )

def build_role_mapping_reference_cache():

    from cp_services import get_all_services

    references = {}

    services = get_all_services()

    for service in services:

        role_mapping = service.get(
            "role_mapping_policy"
        )

        if not role_mapping:
            continue

        if role_mapping not in references:

            references[
                role_mapping
            ] = []

        references[
            role_mapping
        ].append(
            {
                "name": service.get(
                    "name",
                    "Unknown Service"
                ),
                "id": service.get(
                    "id"
                )
            }
        )

    return {

        role_mapping: sorted(
            service_list,
            key=lambda x: x.get(
                "name",
                ""
            )
        )

        for role_mapping, service_list
        in references.items()

    }

def get_role_mapping_details(policy_name):

    if policy_name in ROLE_MAPPING_CACHE:

        return ROLE_MAPPING_CACHE[
            policy_name
        ]

    policy = get_role_mapping_policy(
        policy_name
    )

    result = {
        "name": policy.get("name"),
        "default_role_name": policy.get(
            "default_role_name"
        ),
        "rule_combine_algo": policy.get(
            "rule_combine_algo"
        ),
        "rules": []
    }

    for rule in policy.get("rules", []):

        conditions = []
        condition_attributes = []

        for condition in rule.get("condition", []):

            condition_type = condition.get(
                "type",
                ""
            )

            condition_name = condition.get(
                "name",
                ""
            )

            condition_name = (
                condition_name
                    .replace("TEAP-Method-1-Status", "Method1")
                    .replace("TEAP-Method-2-Status", "Method2")
            )

            condition_oper = condition.get(
                "oper",
                ""
            )

            condition_value = condition.get(
                "value_disp_name"
            )

            if (
                not condition_value
                or condition_value == "&nbsp;"
            ):

                condition_value = condition.get(
                    "value",
                    ""
                )

            # Shorten common prefixes
            #if condition_type.startswith("Authentication"):
            #    condition_type = "Auth"
 
            #elif condition_type.startswith("Authorization"):
            #    condition_type = "AuthZ"

            # Shorten operators

            oper_map = {
                "EQUALS": "=",
                "NOT_EQUALS": "!=",
                "EXISTS": "EXISTS",
                "NOT_EXISTS": "NOT EXISTS",
                "CONTAINS": "CONTAINS",
                "BELONGS_TO": "BELONGS_TO",
                "IN_RANGE": "IN_RANGE",
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

            condition_text = (
                f"{qualified_name} "
                f"{condition_oper}"
            )

            if condition_value:

                condition_text += (
                    f" {condition_value}"
                )

            endpoint_count = get_matching_endpoint_count(
                condition_type,
                condition_name,
                condition_oper,
                condition_value
            ) 

            match_count_label = "Matching Endpoints"

            if condition_type == "GuestUser":

                match_count_label = "Matching Guest Users"

            condition_attributes.append(
                {
                    "source_type": condition_type,
                    "attribute_name": condition_name,
                    "operator": condition_oper,
                    "condition_value": condition_value,
                    "value": condition_value,
                    "endpoint_count": endpoint_count,
                    "match_count_label": match_count_label
                }
            )

            conditions.append(
                condition_text
            )

        match_type = rule.get(
            "match_type",
            "and"
        )

        if conditions:

            condition_label = (
                f" {match_type.upper()} ".join(
                    conditions
                )
            )

        else:

            condition_label = "Unknown Condition"

        rule_match_count = (
            get_matching_rule_count(
                condition_attributes,
                match_type
            )
        )

        rule_match_label = (
            get_rule_match_label(
                condition_attributes
            )
        )

#        print(
#            f"{policy_name} | "
#            f"{rule.get('role_name')} | "
#            f"{rule_match_count}"
#        )

        result["rules"].append(
            {
                "condition": condition_label,
                "match_type": match_type,
                "role_name": rule.get(
                    "role_name"
                ),
                "attributes": condition_attributes,
                "rule_match_count": rule_match_count,
                "rule_match_label": rule_match_label
            }
        )

    ROLE_MAPPING_CACHE[
        policy_name
    ] = result

    return result