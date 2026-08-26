"""
ClearPass Policy Visualiser
Role Reference Cache

Builds read-only reverse references for ClearPass Roles.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Iterable, Mapping
from typing import Any

from pyclearpass import ApiPolicyElements
from pyclearpass.api_globalserverconfiguration import (
    ApiGlobalServerConfiguration,
)

from cp_client import get_login
from cp_enforcement import (
    get_all_enforcement_policies,
    get_enforcement_policy,
)
from cp_role_mapping import (
    get_all_role_mapping_policies,
    get_role_mapping_policy,
)
from cp_services import get_all_services


logger = logging.getLogger(__name__)


def _normalise_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _value_as_list(value: Any) -> list[str]:
    if value is None:
        return []

    if isinstance(value, list):
        return [
            _normalise_text(item)
            for item in value
            if _normalise_text(item)
        ]

    return [
        item.strip()
        for item in str(value).split(",")
        if item.strip()
    ]


def _condition_role_values(
    condition: Mapping[str, Any] | None,
) -> list[str]:
    condition = condition or {}

    if (
        _normalise_text(condition.get("type")) != "Tips"
        or _normalise_text(condition.get("name")) != "Role"
    ):
        return []

    value_as_list = condition.get("valueAsList")
    if value_as_list:
        return _value_as_list(value_as_list)

    return _value_as_list(condition.get("value"))


def _ensure_role_reference(
    references: dict[str, dict[str, Any]],
    role_name: str,
) -> dict[str, Any] | None:
    role_name = _normalise_text(role_name)
    if not role_name:
        return None

    if role_name not in references:
        references[role_name] = {
            "role_mapping_policies": {},
            "enforcement_policies": {},
            "operator_profiles": {},
            "services": {},
        }

    return references[role_name]


def _ensure_policy_reference(
    role_reference: dict[str, Any],
    collection_name: str,
    policy: Mapping[str, Any],
) -> dict[str, Any] | None:
    policy_name = _normalise_text(policy.get("name"))
    if not policy_name:
        return None

    policies = role_reference[collection_name]
    existing = policies.get(policy_name)

    if existing is None:
        existing = {
            "id": policy.get("id"),
            "name": policy_name,
            "description": policy.get("description"),
            "reference_types": [],
            "rule_numbers": [],
            "conditions": [],
            "services": {},
        }
        policies[policy_name] = existing

    return existing


def _append_unique(
    values: list[Any],
    value: Any,
) -> None:
    if value not in values:
        values.append(value)


def _condition_summary(
    condition: Mapping[str, Any],
) -> dict[str, str]:
    value = condition.get("value_disp_name")
    if not value or value == "&nbsp;":
        value = condition.get("value")

    return {
        "source_type": _normalise_text(condition.get("type")),
        "attribute_name": _normalise_text(condition.get("name")),
        "operator": _normalise_text(condition.get("oper")),
        "value": _normalise_text(value),
    }


def _service_reference(
    service: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "id": service.get("id"),
        "name": _normalise_text(
            service.get("name") or "Unknown Service"
        ),
        "description": service.get("description"),
        "enabled": service.get("enabled"),
    }


def _attach_service(
    references: dict[str, dict[str, Any]],
    role_name: str,
    collection_name: str,
    policy_name: str,
    service: Mapping[str, Any],
) -> None:
    role_reference = references.get(role_name)
    if not role_reference:
        return

    policy_reference = role_reference[
        collection_name
    ].get(policy_name)
    if not policy_reference:
        return

    service_data = _service_reference(service)
    service_name = service_data["name"]

    policy_reference["services"][service_name] = (
        service_data
    )
    role_reference["services"][service_name] = (
        service_data
    )


def _get_guest_role_id_map() -> dict[str, str]:
    login = get_login()
    result = (
        ApiPolicyElements
        .get_role_mapping_name_by_name(
            login,
            name="[Guest Roles]",
        )
    )

    role_id_map: dict[str, str] = {}

    if not isinstance(result, Mapping):
        return role_id_map

    for rule in result.get("rules", []):
        if not isinstance(rule, Mapping):
            continue

        role_name = _normalise_text(
            rule.get("role_name")
        )
        if not role_name:
            continue

        for condition in rule.get("condition", []):
            if not isinstance(condition, Mapping):
                continue

            if (
                _normalise_text(condition.get("type"))
                == "GuestUser"
                and _normalise_text(condition.get("name"))
                == "Role ID"
            ):
                role_id = _normalise_text(
                    condition.get("value")
                )
                if role_id:
                    role_id_map[role_id] = role_name

    return role_id_map


def _attach_operator_profile_references(
    references: dict[str, dict[str, Any]],
) -> None:
    login = get_login()
    result = (
        ApiGlobalServerConfiguration
        .get_operator_profile(
            login,
            limit=1000,
        )
    )

    if not isinstance(result, Mapping):
        return

    embedded = result.get("_embedded", {})
    if not isinstance(embedded, Mapping):
        return

    operator_profiles = embedded.get("items", [])
    if not isinstance(operator_profiles, list):
        return

    guest_role_id_map = _get_guest_role_id_map()

    for profile in operator_profiles:
        if not isinstance(profile, Mapping):
            continue

        if not profile.get("enabled", False):
            continue

        profile_name = _normalise_text(
            profile.get("name")
            or profile.get("profile_name")
            or "Unknown Operator Profile"
        )

        for item in str(
            profile.get("user_dbs_list", "")
        ).split(","):
            item = item.strip()
            if not item:
                continue

            role_id = (
                item.split(":", 1)[1].strip()
                if ":" in item
                else item
            )
            role_name = guest_role_id_map.get(role_id)
            if not role_name:
                continue

            role_reference = _ensure_role_reference(
                references,
                role_name,
            )
            if role_reference is None:
                continue

            role_reference["operator_profiles"][
                profile_name
            ] = {
                "id": profile.get("id"),
                "name": profile_name,
                "enabled": profile.get("enabled"),
                "guest_role_id": role_id,
            }


def _serialise_policy_references(
    policies: Mapping[str, Mapping[str, Any]],
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []

    for policy in policies.values():
        result = dict(policy)
        result["reference_types"] = sorted(
            set(result.get("reference_types", []))
        )
        result["rule_numbers"] = sorted(
            set(result.get("rule_numbers", []))
        )
        result["services"] = sorted(
            list(result.get("services", {}).values()),
            key=lambda service: _normalise_text(
                service.get("name")
            ).casefold(),
        )
        results.append(result)

    return sorted(
        results,
        key=lambda policy: _normalise_text(
            policy.get("name")
        ).casefold(),
    )


def build_role_reference_cache() -> dict[str, dict[str, Any]]:
    """
    Build complete reverse references for every discovered
    ClearPass Role.

    The cache includes Role Mapping rule assignments,
    default Roles, Tips:Role conditions, Enforcement Policy
    Tips:Role conditions, associated Services, and enabled
    Operator Profile references.
    """
    cache_start = time.perf_counter()
    references: dict[str, dict[str, Any]] = {}

    services = get_all_services()

    role_mapping_policies_by_name: dict[
        str,
        Mapping[str, Any],
    ] = {}
    enforcement_policies_by_name: dict[
        str,
        Mapping[str, Any],
    ] = {}

    for policy_summary in get_all_role_mapping_policies():
        if not isinstance(policy_summary, Mapping):
            continue

        policy_name = _normalise_text(
            policy_summary.get("name")
        )
        if not policy_name:
            continue

        try:
            policy = get_role_mapping_policy(policy_name)
        except Exception:
            logger.exception(
                "Unable to retrieve Role Mapping Policy "
                "while building Role references: %s",
                policy_name,
            )
            continue

        if not isinstance(policy, Mapping):
            continue

        role_mapping_policies_by_name[policy_name] = policy

        default_role = _normalise_text(
            policy.get("default_role_name")
        )
        if default_role:
            role_reference = _ensure_role_reference(
                references,
                default_role,
            )
            if role_reference is not None:
                policy_reference = _ensure_policy_reference(
                    role_reference,
                    "role_mapping_policies",
                    policy,
                )
                if policy_reference is not None:
                    _append_unique(
                        policy_reference["reference_types"],
                        "default",
                    )

        for rule_number, rule in enumerate(
            policy.get("rules", []),
            start=1,
        ):
            if not isinstance(rule, Mapping):
                continue

            assigned_role = _normalise_text(
                rule.get("role_name")
            )
            if assigned_role:
                role_reference = _ensure_role_reference(
                    references,
                    assigned_role,
                )
                if role_reference is not None:
                    policy_reference = (
                        _ensure_policy_reference(
                            role_reference,
                            "role_mapping_policies",
                            policy,
                        )
                    )
                    if policy_reference is not None:
                        _append_unique(
                            policy_reference[
                                "reference_types"
                            ],
                            "rule_assignment",
                        )
                        _append_unique(
                            policy_reference["rule_numbers"],
                            rule_number,
                        )

            for condition in rule.get("condition", []):
                if not isinstance(condition, Mapping):
                    continue

                for role_name in _condition_role_values(
                    condition
                ):
                    role_reference = _ensure_role_reference(
                        references,
                        role_name,
                    )
                    if role_reference is None:
                        continue

                    policy_reference = _ensure_policy_reference(
                        role_reference,
                        "role_mapping_policies",
                        policy,
                    )
                    if policy_reference is None:
                        continue

                    _append_unique(
                        policy_reference["reference_types"],
                        "condition",
                    )
                    _append_unique(
                        policy_reference["rule_numbers"],
                        rule_number,
                    )
                    condition_data = _condition_summary(
                        condition
                    )
                    if (
                        condition_data
                        not in policy_reference["conditions"]
                    ):
                        policy_reference["conditions"].append(
                            condition_data
                        )

    for policy_summary in get_all_enforcement_policies():
        if not isinstance(policy_summary, Mapping):
            continue

        policy_name = _normalise_text(
            policy_summary.get("name")
        )
        if not policy_name:
            continue

        try:
            policy = get_enforcement_policy(policy_name)
        except Exception:
            logger.exception(
                "Unable to retrieve Enforcement Policy "
                "while building Role references: %s",
                policy_name,
            )
            continue

        if not isinstance(policy, Mapping):
            continue

        enforcement_policies_by_name[policy_name] = policy

        for rule_number, rule in enumerate(
            policy.get("rules", []),
            start=1,
        ):
            if not isinstance(rule, Mapping):
                continue

            for condition in rule.get("condition", []):
                if not isinstance(condition, Mapping):
                    continue

                for role_name in _condition_role_values(
                    condition
                ):
                    role_reference = _ensure_role_reference(
                        references,
                        role_name,
                    )
                    if role_reference is None:
                        continue

                    policy_reference = _ensure_policy_reference(
                        role_reference,
                        "enforcement_policies",
                        policy,
                    )
                    if policy_reference is None:
                        continue

                    _append_unique(
                        policy_reference["reference_types"],
                        "condition",
                    )
                    _append_unique(
                        policy_reference["rule_numbers"],
                        rule_number,
                    )
                    condition_data = _condition_summary(
                        condition
                    )
                    if (
                        condition_data
                        not in policy_reference["conditions"]
                    ):
                        policy_reference["conditions"].append(
                            condition_data
                        )

    for service in services:
        if not isinstance(service, Mapping):
            continue

        service_name = _normalise_text(
            service.get("name")
        )
        if service_name.startswith("--------"):
            continue

        role_mapping_policy_name = _normalise_text(
            service.get("role_mapping_policy")
        )
        enforcement_policy_name = _normalise_text(
            service.get("enf_policy")
        )

        if role_mapping_policy_name:
            for role_name, role_reference in references.items():
                if (
                    role_mapping_policy_name
                    in role_reference["role_mapping_policies"]
                ):
                    _attach_service(
                        references,
                        role_name,
                        "role_mapping_policies",
                        role_mapping_policy_name,
                        service,
                    )

        if enforcement_policy_name:
            for role_name, role_reference in references.items():
                if (
                    enforcement_policy_name
                    in role_reference["enforcement_policies"]
                ):
                    _attach_service(
                        references,
                        role_name,
                        "enforcement_policies",
                        enforcement_policy_name,
                        service,
                    )

    try:
        _attach_operator_profile_references(references)
    except Exception:
        logger.exception(
            "Unable to retrieve Operator Profile Role "
            "references. The remaining Role reference "
            "cache will still be used."
        )

    result = {
        role_name: {
            "role_mapping_policies": (
                _serialise_policy_references(
                    role_data["role_mapping_policies"]
                )
            ),
            "enforcement_policies": (
                _serialise_policy_references(
                    role_data["enforcement_policies"]
                )
            ),
            "operator_profiles": sorted(
                list(
                    role_data[
                        "operator_profiles"
                    ].values()
                ),
                key=lambda profile: _normalise_text(
                    profile.get("name")
                ).casefold(),
            ),
            "services": sorted(
                list(role_data["services"].values()),
                key=lambda service: _normalise_text(
                    service.get("name")
                ).casefold(),
            ),
        }
        for role_name, role_data in sorted(
            references.items(),
            key=lambda item: item[0].casefold(),
        )
    }

    logger.info(
        "Role reference cache built: %s referenced "
        "Roles in %.3fs",
        len(result),
        time.perf_counter() - cache_start,
    )

    return result
