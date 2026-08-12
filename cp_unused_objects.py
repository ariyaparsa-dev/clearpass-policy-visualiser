import logging

from pyclearpass import *
from pyclearpass.api_globalserverconfiguration import (
    ApiGlobalServerConfiguration
)

from cp_client import get_login
from cp_services import get_all_services

import cp_cache

logger = logging.getLogger(__name__)


def is_builtin_object(name):

    return (
        name
        and name.startswith("[")
        and name.endswith("]")
    )


def get_items(result):

    return (
        result.get("_embedded", {})
              .get("items", [])
    )


def value_as_list(value):

    if value is None:
        return []

    if isinstance(value, list):
        return [
            str(item).strip()
            for item in value
            if str(item).strip()
        ]

    return [
        item.strip()
        for item in str(value).split(",")
        if item.strip()
    ]


def get_condition_role_values(condition):

    condition_type = str(
        condition.get("type", "")
    ).strip()

    condition_name = str(
        condition.get("name", "")
    ).strip()

    if (
        condition_type != "Tips"
        or condition_name != "Role"
    ):
        return []

    value_as_list_field = condition.get(
        "valueAsList"
    )

    if value_as_list_field:
        return value_as_list(
            value_as_list_field
        )

    return value_as_list(
        condition.get("value")
    )


def get_unused_enforcement_profiles():

    login = get_login()

    result = ApiEnforcementProfile.get_enforcement_profile(
        login,
        limit=1000
    )

    profiles = get_items(result)

    referenced = set(
        cp_cache.profile_reference_cache.keys()
    )

    unused = []
    total = 0

    for profile in profiles:

        name = profile.get(
            "name",
            ""
        )

        if is_builtin_object(name):
            continue

        total += 1

        if name not in referenced:
            unused.append(name)

    logger.debug(
        "Unused Enforcement Profiles: %s",
        sorted(unused)
    )

    return {
        "unused": sorted(unused),
        "unused_count": len(unused),
        "total_count": total
    }


def get_unused_enforcement_policies():

    login = get_login()

    result = ApiPolicyElements.get_enforcement_policy(
        login,
        limit=1000
    )

    policies = get_items(result)

    referenced = set()

    for service in get_all_services():

        policy_name = service.get(
            "enf_policy"
        )

        if policy_name:
            referenced.add(policy_name)

    unused = []
    total = 0

    for policy in policies:

        name = policy.get(
            "name",
            ""
        )

        if is_builtin_object(name):
            continue

        total += 1

        if name not in referenced:
            unused.append(name)

    logger.debug(
        "Unused Enforcement Policies: %s",
        sorted(unused)
    )

    return {
        "unused": sorted(unused),
        "unused_count": len(unused),
        "total_count": total
    }


def get_unused_role_mapping_policies():

    login = get_login()

    result = ApiPolicyElements.get_role_mapping(
        login,
        limit=1000
    )

    role_maps = get_items(result)

    referenced = set(
        cp_cache.role_mapping_reference_cache.keys()
    )

    unused = []
    total = 0

    for role_map in role_maps:

        name = role_map.get(
            "name",
            ""
        )

        if is_builtin_object(name):
            continue

        total += 1

        if name not in referenced:
            unused.append(name)

    logger.debug(
        "Unused Role Mapping Policies: %s",
        sorted(unused)
    )

    return {
        "unused": sorted(unused),
        "unused_count": len(unused),
        "total_count": total
    }


def get_used_roles_from_role_mappings():

    login = get_login()

    result = ApiPolicyElements.get_role_mapping(
        login,
        limit=1000
    )

    role_maps = get_items(result)

    used_roles = set()

    for role_map in role_maps:

        default_role_name = role_map.get(
            "default_role_name"
        )

        if default_role_name:
            used_roles.add(default_role_name)

        for rule in role_map.get(
            "rules",
            []
        ):

            role_name = rule.get(
                "role_name"
            )

            if role_name:
                used_roles.add(role_name)

            for condition in rule.get(
                "condition",
                []
            ):

                for role_value in get_condition_role_values(
                    condition
                ):

                    used_roles.add(role_value)

    return used_roles


def get_used_roles_from_enforcement_policies():

    login = get_login()

    result = ApiPolicyElements.get_enforcement_policy(
        login,
        limit=1000
    )

    policies = get_items(result)

    used_roles = set()

    for policy in policies:

        for rule in policy.get(
            "rules",
            []
        ):

            for condition in rule.get(
                "condition",
                []
            ):

                for role_value in get_condition_role_values(
                    condition
                ):

                    used_roles.add(role_value)

    return used_roles

def get_guest_role_id_map():

    login = get_login()

    result = (
        ApiPolicyElements
        .get_role_mapping_name_by_name(
            login,
            "[Guest Roles]"
        )
    )

    role_id_map = {}

    for rule in result.get(
        "rules",
        []
    ):

        role_name = rule.get(
            "role_name"
        )

        if not role_name:
            continue

        for condition in rule.get(
            "condition",
            []
        ):

            if (
                condition.get("type") == "GuestUser"
                and
                condition.get("name") == "Role ID"
            ):

                role_id = str(
                    condition.get(
                        "value",
                        ""
                    )
                ).strip()

                if role_id:

                    role_id_map[
                        role_id
                    ] = role_name

    logger.debug(
        "Guest Role ID Map: %s",
        role_id_map
    )

    return role_id_map

def get_used_roles_from_operator_profiles():

    login = get_login()

    result = (
        ApiGlobalServerConfiguration
        .get_operator_profile(
            login,
            limit=1000
        )
    )

    operator_profiles = get_items(
        result
    )

    guest_role_id_map = (
        get_guest_role_id_map()
    )

    used_roles = set()

    for profile in operator_profiles:

        if not profile.get(
            "enabled",
            False
        ):
            continue

        user_dbs_list = str(
            profile.get(
                "user_dbs_list",
                ""
            )
        )

        for item in user_dbs_list.split(","):

            item = item.strip()

            if not item:
                continue

            #
            # 3
            # 3:4
            # 3:3039
            #

            if ":" in item:

                role_id = (
                    item.split(
                        ":",
                        1
                    )[1]
                    .strip()
                )

            else:

                role_id = item

            role_name = (
                guest_role_id_map.get(
                    role_id
                )
            )

            if role_name:

                used_roles.add(
                    role_name
                )

    logger.debug(
        "Roles used by Operator Profiles: %s",
        sorted(used_roles)
    )

    return used_roles

def get_unused_roles():

    login = get_login()

    result = ApiPolicyElements.get_role(
        login,
        limit=1000
    )

    roles = get_items(result)

    used_roles = set()

    used_roles.update(
        get_used_roles_from_role_mappings()
    )

    used_roles.update(
        get_used_roles_from_enforcement_policies()
    )

    used_roles.update(
        get_used_roles_from_operator_profiles()
    )

    unused = []
    total = 0

    for role in roles:

        name = role.get(
            "name",
            ""
        )

        if is_builtin_object(name):
            continue

        total += 1

        if name not in used_roles:
            unused.append(name)

    logger.debug(
        "Unused Roles: %s",
        sorted(unused)
    )

    return {
        "unused": sorted(unused),
        "unused_count": len(unused),
        "total_count": total
    }


def get_unused_object_summary():

    return {

        "profiles":
            get_unused_enforcement_profiles(),

        "policies":
            get_unused_enforcement_policies(),

        "role_maps":
            get_unused_role_mapping_policies(),

        "roles":
            get_unused_roles()
    }