"""
ClearPass Policy Visualiser
Impact Analysis Reporting

Provides read-only impact analysis for ClearPass policy
objects, beginning with Enforcement Profiles and
Enforcement Policies.

The analysis engine does not perform ClearPass API calls.
It consumes profile, Enforcement Policy reference and
Service reference data already retrieved or cached by the
Visualiser.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any


IMPACT_SCHEMA_VERSION = "1.0"


def _normalise_text(
    value: Any,
) -> str:
    """
    Convert a value to clean display text.
    """

    if value is None:
        return ""

    return str(value).strip()


def _normalise_identifier(
    value: Any,
) -> str:
    """
    Return a stable string representation of an object ID.
    """

    if value is None:
        return ""

    return str(value).strip()


def _first_value(
    source: Mapping[str, Any] | None,
    *keys: str,
    default: Any = "",
) -> Any:
    """
    Return the first populated value found in a mapping.

    Empty strings, empty lists and empty dictionaries are
    ignored.
    """

    if not source:
        return default

    for key in keys:

        value = source.get(
            key
        )

        if value not in (
            None,
            "",
            [],
            {},
        ):

            return value

    return default


def _object_identity(
    item: Mapping[str, Any],
) -> tuple[str, str]:
    """
    Return an identity suitable for object deduplication.

    Object ID is preferred. The lowercase object name is
    used as a secondary identifier.
    """

    object_id = _normalise_identifier(
        item.get(
            "id"
        )
    )

    object_name = _normalise_text(
        item.get(
            "name"
        )
    ).casefold()

    return (
        object_id,
        object_name,
    )


def _deduplicate_objects(
    items: Iterable[
        Mapping[str, Any]
    ],
) -> list[dict[str, Any]]:
    """
    Deduplicate normalised objects while preserving order.
    """

    results: list[
        dict[str, Any]
    ] = []

    seen: set[
        tuple[str, str]
    ] = set()

    for item in items:

        normalised_item = dict(
            item
        )

        identity = _object_identity(
            normalised_item
        )

        if identity in seen:
            continue

        seen.add(
            identity
        )

        results.append(
            normalised_item
        )

    return results


def _normalise_service(
    service: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """
    Convert a Service reference to the impact-report schema.
    """

    service = service or {}

    service_id = _normalise_identifier(
        _first_value(
            service,
            "id",
            "service_id",
            "serviceId",
            "uuid",
        )
    )

    service_name = _normalise_text(
        _first_value(
            service,
            "name",
            "service_name",
            "serviceName",
            default="Unknown Service",
        )
    )

    return {
        "id": service_id,
        "name": service_name,
        "description": _normalise_text(
            _first_value(
                service,
                "description",
                "desc",
            )
        ),
        "enabled": _first_value(
            service,
            "enabled",
            "is_enabled",
            "status",
            default=None,
        ),
        "url": _normalise_text(
            _first_value(
                service,
                "url",
                "href",
            )
        ),
    }


def _normalise_policy(
    policy: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """
    Convert an Enforcement Policy reference to the
    impact-report schema.
    """

    policy = policy or {}

    policy_id = _normalise_identifier(
        _first_value(
            policy,
            "id",
            "policy_id",
            "policyId",
            "uuid",
        )
    )

    policy_name = _normalise_text(
        _first_value(
            policy,
            "name",
            "policy_name",
            "policyName",
            default=(
                "Unknown Enforcement Policy"
            ),
        )
    )

    services: list[
        dict[str, Any]
    ] = []

    raw_services = _first_value(
        policy,
        "services",
        "service_references",
        "serviceReferences",
        default=[],
    )

    if (
        isinstance(
            raw_services,
            Iterable,
        )
        and not isinstance(
            raw_services,
            (
                str,
                bytes,
                Mapping,
            ),
        )
    ):

        services = [
            _normalise_service(
                service
            )
            for service in raw_services
            if isinstance(
                service,
                Mapping,
            )
        ]

    return {
        "id": policy_id,
        "name": policy_name,
        "description": _normalise_text(
            _first_value(
                policy,
                "description",
                "desc",
            )
        ),
        "default_profile": _normalise_text(
            _first_value(
                policy,
                "default_profile",
                "defaultProfile",
            )
        ),
        "services": _deduplicate_objects(
            services
        ),
    }


def _normalise_profile_attributes(
    profile: Mapping[str, Any],
) -> list[dict[str, str]]:
    """
    Extract Enforcement Profile attributes.
    """

    raw_attributes = _first_value(
        profile,
        "attributes",
        "enforcement_attributes",
        "enforcementAttributes",
        default=[],
    )

    if (
        not isinstance(
            raw_attributes,
            Iterable,
        )
        or isinstance(
            raw_attributes,
            (
                str,
                bytes,
                Mapping,
            ),
        )
    ):

        return []

    attributes: list[
        dict[str, str]
    ] = []

    for attribute in raw_attributes:

        if not isinstance(
            attribute,
            Mapping,
        ):

            continue

        attributes.append(
            {
                "type": _normalise_text(
                    _first_value(
                        attribute,
                        "type",
                        "attr_type",
                        "attribute_type",
                    )
                ),
                "name": _normalise_text(
                    _first_value(
                        attribute,
                        "name",
                        "attr_name",
                        "attribute_name",
                    )
                ),
                "value": _normalise_text(
                    _first_value(
                        attribute,
                        "value",
                        "attr_value",
                        "attribute_value",
                    )
                ),
            }
        )

    return attributes


def _normalise_enforcement_profile(
    profile: Mapping[str, Any],
) -> dict[str, Any]:
    """
    Convert an Enforcement Profile to the impact-report
    schema.
    """

    return {
        "id": _normalise_identifier(
            _first_value(
                profile,
                "id",
                "profile_id",
                "profileId",
                "uuid",
            )
        ),
        "name": _normalise_text(
            _first_value(
                profile,
                "name",
                "profile_name",
                "profileName",
                default=(
                    "Unknown Enforcement Profile"
                ),
            )
        ),
        "description": _normalise_text(
            _first_value(
                profile,
                "description",
                "desc",
            )
        ),
        "profile_type": _normalise_text(
            _first_value(
                profile,
                "type",
                "profile_type",
                "profileType",
            )
        ),
        "action": _normalise_text(
            _first_value(
                profile,
                "action",
                "enforcement_action",
                "enforcementAction",
            )
        ),
        "attributes": (
            _normalise_profile_attributes(
                profile
            )
        ),
    }


def _collect_services_from_policies(
    policies: Iterable[
        Mapping[str, Any]
    ],
) -> list[dict[str, Any]]:
    """
    Extract and deduplicate Services embedded in
    Enforcement Policy references.
    """

    services: list[
        dict[str, Any]
    ] = []

    for policy in policies:

        raw_services = policy.get(
            "services",
            [],
        )

        if (
            not isinstance(
                raw_services,
                Iterable,
            )
            or isinstance(
                raw_services,
                (
                    str,
                    bytes,
                    Mapping,
                ),
            )
        ):

            continue

        for service in raw_services:

            if not isinstance(
                service,
                Mapping,
            ):

                continue

            services.append(
                dict(
                    service
                )
            )

    return _deduplicate_objects(
        services
    )


def _build_observations(
    affected_policies: list[
        dict[str, Any]
    ],
    affected_services: list[
        dict[str, Any]
    ],
) -> list[str]:
    """
    Create objective, evidence-based observations.

    These observations do not assign a risk score and do
    not state that a configuration change is safe or
    unsafe.
    """

    observations: list[str] = []

    policy_count = len(
        affected_policies
    )

    service_count = len(
        affected_services
    )

    if policy_count == 0:

        observations.append(
            "No Enforcement Policy references were found "
            "for this Enforcement Profile."
        )

    elif policy_count == 1:

        observations.append(
            "The Enforcement Profile is referenced by "
            "one Enforcement Policy."
        )

    else:

        observations.append(
            "The Enforcement Profile is shared across "
            f"{policy_count} Enforcement Policies."
        )

    if service_count == 0:

        if policy_count == 1:

            observations.append(
                "The referencing Enforcement Policy is not "
                "currently assigned to any discovered "
                "ClearPass Service."
            )

        elif policy_count > 1:

            observations.append(
                "The referencing Enforcement Policies are "
                "not currently assigned to any discovered "
                "ClearPass Service."
            )

        else:

            observations.append(
                "No affected Service references were found."
            )

    elif service_count == 1:

        observations.append(
            "One ClearPass Service is associated with the "
            "referencing Enforcement Policies."
        )

    else:

        observations.append(
            f"{service_count} ClearPass Services are "
            "associated with the referencing Enforcement "
            "Policies."
        )

    if (
        policy_count > 1
        and service_count > 1
    ):

        observations.append(
            "The Enforcement Profile is shared across "
            "multiple policies and Services. Changes to "
            "the profile can therefore influence more "
            "than one authentication workflow."
        )

    elif policy_count > 1:

        observations.append(
            "The Enforcement Profile is shared across "
            "multiple Enforcement Policies."
        )

    elif service_count > 1:

        observations.append(
            "The Enforcement Profile is associated with "
            "multiple ClearPass Services."
        )

    return observations


def _build_warnings(
    profile: Mapping[str, Any],
    policy_references_supplied: bool,
    service_references_supplied: bool,
) -> list[str]:
    """
    Build data-availability warnings for the report.
    """

    warnings: list[str] = []

    if not _normalise_identifier(
        profile.get(
            "id"
        )
    ):

        warnings.append(
            "The Enforcement Profile ID was not available "
            "in the supplied data."
        )

    if not policy_references_supplied:

        warnings.append(
            "Policy-reference data was not supplied. The "
            "report can only describe dependencies found "
            "in the available Visualiser data."
        )

    if not service_references_supplied:

        warnings.append(
            "Direct Service-reference data was not "
            "supplied. Affected Services are derived only "
            "from the available Enforcement Policy "
            "references."
        )

    return warnings


def analyse_enforcement_profile(
    profile: Mapping[str, Any],
    *,
    policy_references: Iterable[
        Mapping[str, Any]
    ] | None = None,
    service_references: Iterable[
        Mapping[str, Any]
    ] | None = None,
) -> dict[str, Any]:
    """
    Build an impact-analysis report for an Enforcement
    Profile.

    Parameters
    ----------
    profile:
        Enforcement Profile data.

    policy_references:
        Enforcement Policies that reference the profile.

        Each policy can optionally include a ``services``
        collection.

    service_references:
        Services known to be affected by the profile or by
        its referencing Enforcement Policies.

    Returns
    -------
    dict
        A serialisable report suitable for HTML or JSON
        output.
    """

    if not isinstance(
        profile,
        Mapping,
    ):

        raise TypeError(
            "profile must be a mapping"
        )

    normalised_profile = (
        _normalise_enforcement_profile(
            profile
        )
    )

    policies: list[
        dict[str, Any]
    ] = []

    policy_references_supplied = (
        policy_references is not None
    )

    service_references_supplied = (
        service_references is not None
    )

    for policy in (
        policy_references
        or []
    ):

        if not isinstance(
            policy,
            Mapping,
        ):

            continue

        policies.append(
            _normalise_policy(
                policy
            )
        )

    policies = _deduplicate_objects(
        policies
    )

    direct_services: list[
        dict[str, Any]
    ] = []

    for service in (
        service_references
        or []
    ):

        if not isinstance(
            service,
            Mapping,
        ):

            continue

        direct_services.append(
            _normalise_service(
                service
            )
        )

    policy_services = (
        _collect_services_from_policies(
            policies
        )
    )

    affected_services = (
        _deduplicate_objects(
            [
                *direct_services,
                *policy_services,
            ]
        )
    )

    policy_count = len(
        policies
    )

    service_count = len(
        affected_services
    )

    attribute_count = len(
        normalised_profile[
            "attributes"
        ]
    )

    is_referenced = bool(
        policy_count
        or service_count
    )

    observations = (
        _build_observations(
            policies,
            affected_services,
        )
    )

    warnings = _build_warnings(
        normalised_profile,
        policy_references_supplied,
        service_references_supplied,
    )

    return {
        "schema_version": (
            IMPACT_SCHEMA_VERSION
        ),
        "analysis_type": (
            "enforcement_profile"
        ),
        "object": {
            "type": (
                "Enforcement Profile"
            ),
            **normalised_profile,
        },
        "summary": {
            "referenced": (
                is_referenced
            ),
            "affected_policy_count": (
                policy_count
            ),
            "affected_service_count": (
                service_count
            ),
            "attribute_count": (
                attribute_count
            ),
            "shared_across_multiple_policies": (
                policy_count > 1
            ),
            "shared_across_multiple_services": (
                service_count > 1
            ),
        },
        "direct_dependencies": {
            "enforcement_policies": (
                policies
            ),
        },
        "extended_impact": {
            "services": (
                affected_services
            ),
        },
        "observations": (
            observations
        ),
        "warnings": (
            warnings
        ),
    }



def _normalise_policy_profile(
    profile: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """
    Convert an Enforcement Profile dependency to the
    Enforcement Policy impact-report schema.

    The returned object includes fields used by both the
    unique dependent-profile inventory and individual
    Enforcement Policy rules.
    """

    profile = profile or {}

    return {
        "id": _normalise_identifier(
            _first_value(
                profile,
                "id",
                "profile_id",
                "profileId",
                "uuid",
            )
        ),
        "name": _normalise_text(
            _first_value(
                profile,
                "name",
                "profile_name",
                "profileName",
                default=(
                    "Unknown Enforcement Profile"
                ),
            )
        ),
        "description": _normalise_text(
            _first_value(
                profile,
                "description",
                "desc",
            )
        ),
        "profile_type": _normalise_text(
            _first_value(
                profile,
                "profile_type",
                "profileType",
                "type",
            )
        ),
        "action": _normalise_text(
            _first_value(
                profile,
                "action",
                "enforcement_action",
                "enforcementAction",
            )
        ),
        "attributes": (
            _normalise_profile_attributes(
                profile
            )
        ),
        "reference_types": [],
        "rule_numbers": [],
    }


def _normalise_policy_condition_attribute(
    attribute: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """
    Convert an Enforcement Policy rule condition attribute
    to the impact-report schema.
    """

    attribute = attribute or {}

    endpoint_count = _first_value(
        attribute,
        "endpoint_count",
        "endpointCount",
        default=None,
    )

    return {
        "source_type": _normalise_text(
            _first_value(
                attribute,
                "source_type",
                "sourceType",
                "type",
            )
        ),
        "attribute_name": _normalise_text(
            _first_value(
                attribute,
                "attribute_name",
                "attributeName",
                "name",
            )
        ),
        "operator": _normalise_text(
            _first_value(
                attribute,
                "operator",
                "oper",
            )
        ),
        "value": _normalise_text(
            _first_value(
                attribute,
                "value",
            )
        ),
        "endpoint_count": endpoint_count,
    }


def _normalise_policy_rule(
    rule: Mapping[str, Any],
    rule_number: int,
) -> dict[str, Any]:
    """
    Convert an Enforcement Policy rule to the
    impact-report schema.

    The rule retains its original ordering, structured
    condition attributes, condition text and applied
    Enforcement Profiles.
    """

    condition_attributes: list[
        dict[str, Any]
    ] = []

    raw_attributes = _first_value(
        rule,
        "attributes",
        "condition_attributes",
        "conditionAttributes",
        default=[],
    )

    if (
        isinstance(
            raw_attributes,
            Iterable,
        )
        and not isinstance(
            raw_attributes,
            (
                str,
                bytes,
                Mapping,
            ),
        )
    ):

        for attribute in raw_attributes:

            if not isinstance(
                attribute,
                Mapping,
            ):

                continue

            condition_attributes.append(
                _normalise_policy_condition_attribute(
                    attribute
                )
            )

    profiles: list[
        dict[str, Any]
    ] = []

    raw_profiles = _first_value(
        rule,
        "profiles",
        "enforcement_profiles",
        "enforcementProfiles",
        default=[],
    )

    if (
        isinstance(
            raw_profiles,
            Iterable,
        )
        and not isinstance(
            raw_profiles,
            (
                str,
                bytes,
                Mapping,
            ),
        )
    ):

        for profile in raw_profiles:

            if not isinstance(
                profile,
                Mapping,
            ):

                continue

            normalised_profile = (
                _normalise_policy_profile(
                    profile
                )
            )

            normalised_profile[
                "reference_types"
            ] = [
                "rule"
            ]

            normalised_profile[
                "rule_numbers"
            ] = [
                rule_number
            ]

            profiles.append(
                normalised_profile
            )

    profiles = _deduplicate_objects(
        profiles
    )

    condition_text = _normalise_text(
        _first_value(
            rule,
            "condition",
            "condition_text",
            "conditionText",
            default="Unknown Condition",
        )
    )

    match_type = _normalise_text(
        _first_value(
            rule,
            "match_type",
            "matchType",
            default="AND",
        )
    ).upper()

    return {
        "rule_number": rule_number,
        "condition": condition_text,
        "match_type": match_type,
        "condition_attributes": (
            condition_attributes
        ),
        "condition_count": len(
            condition_attributes
        ),
        "profiles": profiles,
        "profile_count": len(
            profiles
        ),
    }


def _merge_policy_profile(
    profiles: list[
        dict[str, Any]
    ],
    profile: Mapping[str, Any],
) -> None:
    """
    Merge an Enforcement Profile dependency into the
    unique dependent-profile inventory.

    Profiles are matched by ID when both records have an
    ID. A case-insensitive name comparison is used when an
    ID is unavailable.

    This supports profiles that appear in multiple rules,
    as the default profile, or in both contexts.
    """

    candidate = dict(
        profile
    )

    candidate_id = _normalise_identifier(
        candidate.get(
            "id"
        )
    )

    candidate_name = _normalise_text(
        candidate.get(
            "name"
        )
    ).casefold()

    existing_profile = None

    for stored_profile in profiles:

        stored_id = _normalise_identifier(
            stored_profile.get(
                "id"
            )
        )

        stored_name = _normalise_text(
            stored_profile.get(
                "name"
            )
        ).casefold()

        same_profile = False

        if (
            candidate_id
            and
            stored_id
        ):

            same_profile = (
                candidate_id
                ==
                stored_id
            )

        elif (
            candidate_name
            and
            stored_name
        ):

            same_profile = (
                candidate_name
                ==
                stored_name
            )

        if same_profile:

            existing_profile = stored_profile
            break

    if existing_profile is None:

        candidate[
            "reference_types"
        ] = list(
            dict.fromkeys(
                candidate.get(
                    "reference_types",
                    [],
                )
            )
        )

        candidate[
            "rule_numbers"
        ] = sorted(
            set(
                candidate.get(
                    "rule_numbers",
                    [],
                )
            )
        )

        profiles.append(
            candidate
        )

        return

    for field_name in (
        "id",
        "name",
        "description",
        "profile_type",
        "action",
    ):

        if (
            not existing_profile.get(
                field_name
            )
            and
            candidate.get(
                field_name
            )
        ):

            existing_profile[
                field_name
            ] = candidate[
                field_name
            ]

    if (
        not existing_profile.get(
            "attributes"
        )
        and
        candidate.get(
            "attributes"
        )
    ):

        existing_profile[
            "attributes"
        ] = candidate[
            "attributes"
        ]

    existing_profile[
        "reference_types"
    ] = list(
        dict.fromkeys(
            [
                *existing_profile.get(
                    "reference_types",
                    [],
                ),
                *candidate.get(
                    "reference_types",
                    [],
                ),
            ]
        )
    )

    existing_profile[
        "rule_numbers"
    ] = sorted(
        set(
            [
                *existing_profile.get(
                    "rule_numbers",
                    [],
                ),
                *candidate.get(
                    "rule_numbers",
                    [],
                ),
            ]
        )
    )


def _get_profile_reference_data(
    profile_name: str,
    profile_reference_cache: Mapping[
        str,
        Any
    ] | None,
) -> dict[str, Any]:
    """
    Return cached dependency data for an Enforcement
    Profile.

    Exact name matching is attempted first, followed by a
    case-insensitive name comparison.
    """

    if not isinstance(
        profile_reference_cache,
        Mapping,
    ):

        return {}

    reference_data = (
        profile_reference_cache.get(
            profile_name
        )
    )

    if isinstance(
        reference_data,
        Mapping,
    ):

        return dict(
            reference_data
        )

    requested_name = _normalise_text(
        profile_name
    ).casefold()

    for cached_name, cached_data in (
        profile_reference_cache.items()
    ):

        cached_name_normalised = (
            _normalise_text(
                cached_name
            ).casefold()
        )

        if (
            cached_name_normalised
            !=
            requested_name
        ):

            continue

        if isinstance(
            cached_data,
            Mapping,
        ):

            return dict(
                cached_data
            )

    return {}


def _build_policy_profile_usage(
    profile: Mapping[str, Any],
    selected_policy_id: str,
    selected_policy_name: str,
    selected_services: Iterable[
        Mapping[str, Any]
    ],
    profile_reference_cache: Mapping[
        str,
        Any
    ] | None,
) -> dict[str, Any]:
    """
    Build shared-usage information for one dependent
    Enforcement Profile.

    The selected Enforcement Policy and its directly
    assigned Services are excluded from the corresponding
    other-policy and other-Service results.
    """

    if not isinstance(
        profile_reference_cache,
        Mapping,
    ):

        return {
            "available": False,
            "total_policy_count": 0,
            "other_policy_count": 0,
            "total_service_count": 0,
            "other_service_count": 0,
            "shared_with_other_policies": False,
            "shared_with_other_services": False,
            "other_policies": [],
            "other_services": [],
        }

    profile_name = _normalise_text(
        profile.get(
            "name"
        )
    )

    reference_data = (
        _get_profile_reference_data(
            profile_name,
            profile_reference_cache,
        )
    )

    raw_policies = reference_data.get(
        "policies",
        [],
    )

    raw_services = reference_data.get(
        "services",
        [],
    )

    policies: list[
        dict[str, Any]
    ] = []

    services: list[
        dict[str, Any]
    ] = []

    if (
        isinstance(
            raw_policies,
            Iterable,
        )
        and not isinstance(
            raw_policies,
            (
                str,
                bytes,
                Mapping,
            ),
        )
    ):

        for policy_reference in raw_policies:

            if not isinstance(
                policy_reference,
                Mapping,
            ):

                continue

            policies.append(
                _normalise_policy(
                    policy_reference
                )
            )

    if (
        isinstance(
            raw_services,
            Iterable,
        )
        and not isinstance(
            raw_services,
            (
                str,
                bytes,
                Mapping,
            ),
        )
    ):

        for service_reference in raw_services:

            if not isinstance(
                service_reference,
                Mapping,
            ):

                continue

            services.append(
                _normalise_service(
                    service_reference
                )
            )

    policies = _deduplicate_objects(
        policies
    )

    services = _deduplicate_objects(
        services
    )

    selected_policy_id_normalised = (
        _normalise_identifier(
            selected_policy_id
        )
    )

    selected_policy_name_normalised = (
        _normalise_text(
            selected_policy_name
        ).casefold()
    )

    other_policies: list[
        dict[str, Any]
    ] = []

    for policy_reference in policies:

        reference_policy_id = (
            _normalise_identifier(
                policy_reference.get(
                    "id"
                )
            )
        )

        reference_policy_name = (
            _normalise_text(
                policy_reference.get(
                    "name"
                )
            ).casefold()
        )

        is_selected_policy = False

        if (
            selected_policy_id_normalised
            and
            reference_policy_id
        ):

            is_selected_policy = (
                selected_policy_id_normalised
                ==
                reference_policy_id
            )

        if (
            not is_selected_policy
            and
            selected_policy_name_normalised
            and
            reference_policy_name
        ):

            is_selected_policy = (
                selected_policy_name_normalised
                ==
                reference_policy_name
            )

        if not is_selected_policy:

            other_policies.append(
                policy_reference
            )

    selected_service_ids: set[str] = set()

    selected_service_names: set[str] = set()

    for selected_service in selected_services:

        if not isinstance(
            selected_service,
            Mapping,
        ):

            continue

        selected_service_id = (
            _normalise_identifier(
                selected_service.get(
                    "id"
                )
            )
        )

        selected_service_name = (
            _normalise_text(
                selected_service.get(
                    "name"
                )
            ).casefold()
        )

        if selected_service_id:

            selected_service_ids.add(
                selected_service_id
            )

        if selected_service_name:

            selected_service_names.add(
                selected_service_name
            )

    other_services: list[
        dict[str, Any]
    ] = []

    for service_reference in services:

        reference_service_id = (
            _normalise_identifier(
                service_reference.get(
                    "id"
                )
            )
        )

        reference_service_name = (
            _normalise_text(
                service_reference.get(
                    "name"
                )
            ).casefold()
        )

        is_selected_service = False

        if (
            reference_service_id
            and
            reference_service_id
            in selected_service_ids
        ):

            is_selected_service = True

        if (
            not is_selected_service
            and
            reference_service_name
            and
            reference_service_name
            in selected_service_names
        ):

            is_selected_service = True

        if not is_selected_service:

            other_services.append(
                service_reference
            )

    other_policies = sorted(
        other_policies,
        key=lambda policy_reference: (
            _normalise_text(
                policy_reference.get(
                    "name"
                )
            ).casefold()
        ),
    )

    other_services = sorted(
        other_services,
        key=lambda service_reference: (
            _normalise_text(
                service_reference.get(
                    "name"
                )
            ).casefold()
        ),
    )

    return {
        "available": True,
        "total_policy_count": len(
            policies
        ),
        "other_policy_count": len(
            other_policies
        ),
        "total_service_count": len(
            services
        ),
        "other_service_count": len(
            other_services
        ),
        "shared_with_other_policies": bool(
            other_policies
        ),
        "shared_with_other_services": bool(
            other_services
        ),
        "other_policies": (
            other_policies
        ),
        "other_services": (
            other_services
        ),
    }


def _build_enforcement_policy_observations(
    affected_services: list[
        dict[str, Any]
    ],
    dependent_profiles: list[
        dict[str, Any]
    ],
    policy_rules: list[
        dict[str, Any]
    ],
    default_profile_name: str,
) -> list[str]:
    """
    Create objective observations for an Enforcement
    Policy impact report.

    The observations describe discovered dependencies and
    do not assign a subjective risk score or state that a
    configuration change is safe or unsafe.
    """

    observations: list[str] = []

    service_count = len(
        affected_services
    )

    profile_count = len(
        dependent_profiles
    )

    rule_count = len(
        policy_rules
    )

    condition_count = sum(
        rule.get(
            "condition_count",
            0,
        )
        for rule in policy_rules
    )

    if service_count == 0:

        observations.append(
            "The Enforcement Policy is not currently "
            "assigned to any discovered ClearPass Service."
        )

    elif service_count == 1:

        observations.append(
            "The Enforcement Policy is assigned to one "
            "ClearPass Service."
        )

    else:

        observations.append(
            "The Enforcement Policy is shared across "
            f"{service_count} ClearPass Services."
        )

    if rule_count == 0:

        observations.append(
            "The Enforcement Policy does not contain any "
            "discovered policy rules."
        )

    elif rule_count == 1:

        observations.append(
            "The Enforcement Policy contains one policy "
            "rule."
        )

    else:

        observations.append(
            "The Enforcement Policy contains "
            f"{rule_count} policy rules."
        )

    if condition_count == 0:

        if rule_count > 0:

            observations.append(
                "No structured rule conditions were found "
                "in the available policy data."
            )

    elif condition_count == 1:

        observations.append(
            "One structured rule condition was found "
            "across the policy rules."
        )

    else:

        observations.append(
            f"{condition_count} structured rule "
            "conditions were found across the policy "
            "rules."
        )

    if profile_count == 0:

        observations.append(
            "No dependent Enforcement Profiles were found "
            "for this Enforcement Policy."
        )

    elif profile_count == 1:

        observations.append(
            "The Enforcement Policy references one unique "
            "Enforcement Profile."
        )

    else:

        observations.append(
            "The Enforcement Policy references "
            f"{profile_count} unique Enforcement Profiles."
        )

    if default_profile_name:

        observations.append(
            "A default Enforcement Profile is configured "
            "for unmatched policy outcomes."
        )

    else:

        observations.append(
            "No default Enforcement Profile was found in "
            "the available policy data."
        )

    if (
        service_count > 1
        and
        profile_count > 0
    ):

        observations.append(
            "Changes to this shared Enforcement Policy can "
            "influence enforcement decisions across multiple "
            "authentication workflows, including when the "
            "listed Enforcement Profiles are applied."
        )

    elif (
        service_count == 1
        and
        profile_count > 0
    ):

        observations.append(
            "Changes to this Enforcement Policy can "
            "influence enforcement decisions for the "
            "assigned Service, including when the listed "
            "Enforcement Profiles are applied."
        )

    return observations


def _build_enforcement_policy_warnings(
    policy: Mapping[str, Any],
    service_references_supplied: bool,
) -> list[str]:
    """
    Build data-availability warnings for an Enforcement
    Policy impact report.
    """

    warnings: list[str] = []

    if not _normalise_identifier(
        policy.get(
            "id"
        )
    ):

        warnings.append(
            "The Enforcement Policy ID was not available "
            "in the supplied data."
        )

    if not service_references_supplied:

        warnings.append(
            "Service-reference data was not supplied. The "
            "report cannot determine whether the "
            "Enforcement Policy is assigned to a "
            "ClearPass Service."
        )

    return warnings


def analyse_enforcement_policy(
    policy: Mapping[str, Any],
    service_references: Iterable[
        Mapping[str, Any]
    ] | None = None,
    default_profile: Mapping[str, Any] | None = None,
    profile_reference_cache: Mapping[
        str,
        Any
    ] | None = None,
) -> dict[str, Any]:
    """
    Build an impact-analysis report for an Enforcement
    Policy.

    Parameters
    ----------
    policy:
        Enforcement Policy data returned by
        ``get_enforcement_details()``.

    service_references:
        Services that assign the selected Enforcement
        Policy.

        An empty collection means the policy is confirmed
        as not assigned to a discovered Service. ``None``
        means Service-reference data was not supplied.

    default_profile:
        Optional complete Enforcement Profile data for the
        policy's default Enforcement Profile.

    profile_reference_cache:
        Cached Enforcement Profile policy and Service
        references used to identify wider shared usage.

    Returns
    -------
    dict
        A serialisable Enforcement Policy impact report.
    """

    if not isinstance(
        policy,
        Mapping,
    ):

        raise TypeError(
            "policy must be a mapping"
        )

    service_references_supplied = (
        service_references is not None
    )

    policy_id = _normalise_identifier(
        _first_value(
            policy,
            "id",
            "policy_id",
            "policyId",
            "uuid",
        )
    )

    policy_name = _normalise_text(
        _first_value(
            policy,
            "name",
            "policy_name",
            "policyName",
            default=(
                "Unknown Enforcement Policy"
            ),
        )
    )

    policy_description = _normalise_text(
        _first_value(
            policy,
            "description",
            "desc",
        )
    )

    rule_eval_algo = _normalise_text(
        _first_value(
            policy,
            "rule_eval_algo",
            "ruleEvalAlgo",
            "evaluation_algorithm",
        )
    )

    default_profile_name = _normalise_text(
        _first_value(
            policy,
            "default_enforcement_profile",
            "default_profile",
            "defaultProfile",
        )
    )

    affected_services: list[
        dict[str, Any]
    ] = []

    for service in (
        service_references
        or []
    ):

        if not isinstance(
            service,
            Mapping,
        ):

            continue

        affected_services.append(
            _normalise_service(
                service
            )
        )

    affected_services = (
        _deduplicate_objects(
            affected_services
        )
    )

    policy_rules: list[
        dict[str, Any]
    ] = []

    dependent_profiles: list[
        dict[str, Any]
    ] = []

    raw_rules = _first_value(
        policy,
        "rules",
        default=[],
    )

    if (
        isinstance(
            raw_rules,
            Iterable,
        )
        and not isinstance(
            raw_rules,
            (
                str,
                bytes,
                Mapping,
            ),
        )
    ):

        for rule_number, rule in enumerate(
            raw_rules,
            start=1,
        ):

            if not isinstance(
                rule,
                Mapping,
            ):

                continue

            normalised_rule = (
                _normalise_policy_rule(
                    rule,
                    rule_number,
                )
            )

            policy_rules.append(
                normalised_rule
            )

            for profile in normalised_rule.get(
                "profiles",
                [],
            ):

                _merge_policy_profile(
                    dependent_profiles,
                    profile,
                )

    if default_profile_name:

        if isinstance(
            default_profile,
            Mapping,
        ):

            normalised_default_profile = (
                _normalise_policy_profile(
                    default_profile
                )
            )

        else:

            normalised_default_profile = {
                "id": "",
                "name": default_profile_name,
                "description": "",
                "profile_type": "",
                "action": "Default",
                "attributes": [],
                "reference_types": [],
                "rule_numbers": [],
            }

        if not normalised_default_profile.get(
            "name"
        ):

            normalised_default_profile[
                "name"
            ] = default_profile_name

        normalised_default_profile[
            "reference_types"
        ] = [
            "default"
        ]

        normalised_default_profile[
            "rule_numbers"
        ] = []

        _merge_policy_profile(
            dependent_profiles,
            normalised_default_profile,
        )

    for dependent_profile in dependent_profiles:

        dependent_profile[
            "profile_usage"
        ] = _build_policy_profile_usage(
            dependent_profile,
            policy_id,
            policy_name,
            affected_services,
            profile_reference_cache,
        )

    dependent_profiles = sorted(
        dependent_profiles,
        key=lambda profile: (
            _normalise_text(
                profile.get(
                    "name"
                )
            ).casefold()
        ),
    )

    condition_count = sum(
        rule.get(
            "condition_count",
            0,
        )
        for rule in policy_rules
    )

    service_count = len(
        affected_services
    )

    rule_count = len(
        policy_rules
    )

    dependent_profile_count = len(
        dependent_profiles
    )

    observations = (
        _build_enforcement_policy_observations(
            affected_services,
            dependent_profiles,
            policy_rules,
            default_profile_name,
        )
    )

    warnings = (
        _build_enforcement_policy_warnings(
            {
                "id": policy_id,
            },
            service_references_supplied,
        )
    )

    return {
        "schema_version": (
            IMPACT_SCHEMA_VERSION
        ),
        "analysis_type": (
            "enforcement_policy"
        ),
        "object": {
            "type": (
                "Enforcement Policy"
            ),
            "id": policy_id,
            "name": policy_name,
            "description": (
                policy_description
            ),
            "rule_eval_algo": (
                rule_eval_algo
            ),
            "default_profile": (
                default_profile_name
            ),
        },
        "summary": {
            "referenced": (
                service_count > 0
            ),
            "usage_status": (
                "Assigned"
                if service_count > 0
                else "Not Assigned"
            ),
            "affected_service_count": (
                service_count
            ),
            "rule_count": (
                rule_count
            ),
            "dependent_profile_count": (
                dependent_profile_count
            ),
            "condition_count": (
                condition_count
            ),
            "default_profile_configured": bool(
                default_profile_name
            ),
            "shared_across_multiple_services": (
                service_count > 1
            ),
        },
        "direct_dependencies": {
            "services": (
                affected_services
            ),
            "enforcement_profiles": (
                dependent_profiles
            ),
        },
        "policy_rules": (
            policy_rules
        ),
        "extended_impact": {
            "services": (
                affected_services
            ),
        },
        "observations": (
            observations
        ),
        "warnings": (
            warnings
        ),
    }


def _normalise_mapped_role(
    role: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """
    Convert a mapped role dependency to the Role Mapping
    Policy impact-report schema.
    """

    role = role or {}

    return {
        "id": _normalise_identifier(
            _first_value(
                role,
                "id",
                "role_id",
                "roleId",
                "uuid",
            )
        ),
        "name": _normalise_text(
            _first_value(
                role,
                "name",
                "role_name",
                "roleName",
                default="Unknown Role",
            )
        ),
        "description": _normalise_text(
            _first_value(
                role,
                "description",
                "desc",
                "role_description",
                "roleDescription",
            )
        ),
        "reference_types": [],
        "rule_numbers": [],
    }

def _normalise_role_mapping_rule(
    rule: Mapping[str, Any],
    rule_number: int,
) -> dict[str, Any]:
    """
    Convert a Role Mapping Policy rule to the
    impact-report schema.

    The result preserves the rule order, condition text,
    structured conditions, mapped Role and available
    match-count information.
    """

    condition_attributes: list[
        dict[str, Any]
    ] = []

    raw_attributes = _first_value(
        rule,
        "attributes",
        "condition_attributes",
        "conditionAttributes",
        default=[],
    )

    if (
        isinstance(
            raw_attributes,
            Iterable,
        )
        and not isinstance(
            raw_attributes,
            (
                str,
                bytes,
                Mapping,
            ),
        )
    ):

        for attribute in raw_attributes:

            if not isinstance(
                attribute,
                Mapping,
            ):

                continue

            normalised_attribute = (
                _normalise_policy_condition_attribute(
                    attribute
                )
            )

            normalised_attribute[
                "match_count_label"
            ] = _normalise_text(
                _first_value(
                    attribute,
                    "match_count_label",
                    "matchCountLabel",
                    default="Matching Endpoints",
                )
            )

            condition_attributes.append(
                normalised_attribute
            )

    condition_text = _normalise_text(
        _first_value(
            rule,
            "condition",
            "condition_text",
            "conditionText",
            default="Unknown Condition",
        )
    )

    match_type = _normalise_text(
        _first_value(
            rule,
            "match_type",
            "matchType",
            default="AND",
        )
    ).upper()

    role_name = _normalise_text(
        _first_value(
            rule,
            "role_name",
            "roleName",
            default="Unknown Role",
        )
    )

    role_description = _normalise_text(
        _first_value(
            rule,
            "role_description",
            "roleDescription",
        )
    )

    mapped_role = _normalise_mapped_role(
        {
            "name": role_name,
            "description": role_description,
        }
    )

    mapped_role[
        "reference_types"
    ] = [
        "rule"
    ]

    mapped_role[
        "rule_numbers"
    ] = [
        rule_number
    ]

    rule_match_count = _first_value(
        rule,
        "rule_match_count",
        "ruleMatchCount",
        default=None,
    )

    rule_match_label = _normalise_text(
        _first_value(
            rule,
            "rule_match_label",
            "ruleMatchLabel",
            default="Matching Rule Endpoints",
        )
    )

    return {
        "rule_number": rule_number,
        "condition": condition_text,
        "match_type": match_type,
        "condition_attributes": (
            condition_attributes
        ),
        "condition_count": len(
            condition_attributes
        ),
        "mapped_role": mapped_role,
        "rule_match_count": (
            rule_match_count
        ),
        "rule_match_label": (
            rule_match_label
        ),
    }

def _merge_mapped_role(
    roles: list[
        dict[str, Any]
    ],
    role: Mapping[str, Any],
) -> None:
    """
    Merge a mapped Role dependency into the unique
    Role inventory.

    Roles are matched by ID when both records contain an
    ID. A case-insensitive name comparison is used when an
    ID is unavailable.

    This supports Roles that appear in multiple rules,
    as the default Role, or in both contexts.
    """

    candidate = dict(
        role
    )

    candidate_id = _normalise_identifier(
        candidate.get(
            "id"
        )
    )

    candidate_name = _normalise_text(
        candidate.get(
            "name"
        )
    ).casefold()

    existing_role = None

    for stored_role in roles:

        stored_id = _normalise_identifier(
            stored_role.get(
                "id"
            )
        )

        stored_name = _normalise_text(
            stored_role.get(
                "name"
            )
        ).casefold()

        same_role = False

        if (
            candidate_id
            and
            stored_id
        ):

            same_role = (
                candidate_id
                ==
                stored_id
            )

        elif (
            candidate_name
            and
            stored_name
        ):

            same_role = (
                candidate_name
                ==
                stored_name
            )

        if same_role:

            existing_role = stored_role
            break

    if existing_role is None:

        candidate[
            "reference_types"
        ] = list(
            dict.fromkeys(
                candidate.get(
                    "reference_types",
                    [],
                )
            )
        )

        candidate[
            "rule_numbers"
        ] = sorted(
            set(
                candidate.get(
                    "rule_numbers",
                    [],
                )
            )
        )

        roles.append(
            candidate
        )

        return

    for field_name in (
        "id",
        "name",
        "description",
    ):

        if (
            not existing_role.get(
                field_name
            )
            and
            candidate.get(
                field_name
            )
        ):

            existing_role[
                field_name
            ] = candidate[
                field_name
            ]

    existing_role[
        "reference_types"
    ] = list(
        dict.fromkeys(
            [
                *existing_role.get(
                    "reference_types",
                    [],
                ),
                *candidate.get(
                    "reference_types",
                    [],
                ),
            ]
        )
    )

    existing_role[
        "rule_numbers"
    ] = sorted(
        set(
            [
                *existing_role.get(
                    "rule_numbers",
                    [],
                ),
                *candidate.get(
                    "rule_numbers",
                    [],
                ),
            ]
        )
    )



from collections.abc import Mapping
from typing import Any


def _normalise_identifier(
    value: Any,
) -> str:
    """
    Minimal local definition used only to validate this
    downloadable helper file.

    Do not copy this function into cp_impact_analysis.py
    because it already exists there.
    """

    if value is None:
        return ""

    return str(value).strip()


def _build_role_mapping_observations(
    affected_services: list[
        dict[str, Any]
    ],
    mapped_roles: list[
        dict[str, Any]
    ],
    mapping_rules: list[
        dict[str, Any]
    ],
    default_role_name: str,
) -> list[str]:
    """
    Create objective observations for a Role Mapping
    Policy impact report.

    The observations describe discovered dependencies and
    do not assign a subjective risk score or state that a
    configuration change is safe or unsafe.
    """

    observations: list[str] = []

    service_count = len(
        affected_services
    )

    role_count = len(
        mapped_roles
    )

    rule_count = len(
        mapping_rules
    )

    condition_count = sum(
        rule.get(
            "condition_count",
            0,
        )
        for rule in mapping_rules
    )

    if service_count == 0:

        observations.append(
            "The Role Mapping Policy is not currently "
            "assigned to any discovered ClearPass Service."
        )

    elif service_count == 1:

        observations.append(
            "The Role Mapping Policy is assigned to one "
            "ClearPass Service."
        )

    else:

        observations.append(
            "The Role Mapping Policy is shared across "
            f"{service_count} ClearPass Services."
        )

    if rule_count == 0:

        observations.append(
            "The Role Mapping Policy does not contain any "
            "discovered mapping rules."
        )

    elif rule_count == 1:

        observations.append(
            "The Role Mapping Policy contains one mapping "
            "rule."
        )

    else:

        observations.append(
            "The Role Mapping Policy contains "
            f"{rule_count} mapping rules."
        )

    if condition_count == 0:

        if rule_count > 0:

            observations.append(
                "No structured rule conditions were found "
                "in the available Role Mapping Policy data."
            )

    elif condition_count == 1:

        observations.append(
            "One structured rule condition was found "
            "across the mapping rules."
        )

    else:

        observations.append(
            f"{condition_count} structured rule "
            "conditions were found across the mapping "
            "rules."
        )

    if role_count == 0:

        observations.append(
            "No mapped Roles were found for this Role "
            "Mapping Policy."
        )

    elif role_count == 1:

        observations.append(
            "The Role Mapping Policy references one "
            "unique mapped Role."
        )

    else:

        observations.append(
            "The Role Mapping Policy references "
            f"{role_count} unique mapped Roles."
        )

    if default_role_name:

        observations.append(
            "A default Role is configured for requests "
            "that do not match a mapping rule."
        )

    else:

        observations.append(
            "No default Role was found in the available "
            "Role Mapping Policy data."
        )

    if (
        service_count > 1
        and
        role_count > 0
    ):

        observations.append(
            "Changes to this shared Role Mapping Policy "
            "can influence Role assignment across multiple "
            "authentication workflows."
        )

    elif (
        service_count == 1
        and
        role_count > 0
    ):

        observations.append(
            "Changes to this Role Mapping Policy can "
            "influence Role assignment for the assigned "
            "Service."
        )

    return observations


def _build_role_mapping_warnings(
    policy: Mapping[str, Any],
    service_references_supplied: bool,
) -> list[str]:
    """
    Build data-availability warnings for a Role Mapping
    Policy impact report.
    """

    warnings: list[str] = []

    if not _normalise_identifier(
        policy.get(
            "id"
        )
    ):

        warnings.append(
            "The Role Mapping Policy ID was not available "
            "in the supplied data."
        )

    if not service_references_supplied:

        warnings.append(
            "Service-reference data was not supplied. The "
            "report cannot determine whether the Role "
            "Mapping Policy is assigned to a ClearPass "
            "Service."
        )

    return warnings


def analyse_role_mapping_policy(
    policy: Mapping[str, Any],
    service_references: Iterable[
        Mapping[str, Any]
    ] | None = None,
) -> dict[str, Any]:
    """
    Build an impact-analysis report for a Role Mapping
    Policy.

    Parameters
    ----------
    policy:
        Role Mapping Policy data returned by
        ``get_role_mapping_details()``.

    service_references:
        Services that assign the selected Role Mapping
        Policy.

        An empty collection means the policy is confirmed
        as not assigned to a discovered Service. ``None``
        means Service-reference data was not supplied.

    Returns
    -------
    dict
        A serialisable Role Mapping Policy impact report.
    """

    if not isinstance(
        policy,
        Mapping,
    ):

        raise TypeError(
            "policy must be a mapping"
        )

    service_references_supplied = (
        service_references is not None
    )

    policy_id = _normalise_identifier(
        _first_value(
            policy,
            "id",
            "policy_id",
            "policyId",
            "uuid",
        )
    )

    policy_name = _normalise_text(
        _first_value(
            policy,
            "name",
            "policy_name",
            "policyName",
            default=(
                "Unknown Role Mapping Policy"
            ),
        )
    )

    policy_description = _normalise_text(
        _first_value(
            policy,
            "description",
            "desc",
        )
    )

    rule_combine_algo = _normalise_text(
        _first_value(
            policy,
            "rule_combine_algo",
            "ruleCombineAlgo",
            "evaluation_algorithm",
        )
    )

    default_role_name = _normalise_text(
        _first_value(
            policy,
            "default_role_name",
            "defaultRoleName",
            "default_role",
            "defaultRole",
        )
    )

    default_role_description = _normalise_text(
        _first_value(
            policy,
            "default_role_description",
            "defaultRoleDescription",
        )
    )

    affected_services: list[
        dict[str, Any]
    ] = []

    for service in (
        service_references
        or []
    ):

        if not isinstance(
            service,
            Mapping,
        ):

            continue

        affected_services.append(
            _normalise_service(
                service
            )
        )

    affected_services = _deduplicate_objects(
        affected_services
    )

    mapping_rules: list[
        dict[str, Any]
    ] = []

    mapped_roles: list[
        dict[str, Any]
    ] = []

    raw_rules = _first_value(
        policy,
        "rules",
        default=[],
    )

    if (
        isinstance(
            raw_rules,
            Iterable,
        )
        and not isinstance(
            raw_rules,
            (
                str,
                bytes,
                Mapping,
            ),
        )
    ):

        for rule_number, rule in enumerate(
            raw_rules,
            start=1,
        ):

            if not isinstance(
                rule,
                Mapping,
            ):

                continue

            normalised_rule = (
                _normalise_role_mapping_rule(
                    rule,
                    rule_number,
                )
            )

            mapping_rules.append(
                normalised_rule
            )

            mapped_role = normalised_rule.get(
                "mapped_role"
            )

            if isinstance(
                mapped_role,
                Mapping,
            ):

                _merge_mapped_role(
                    mapped_roles,
                    mapped_role,
                )

    if default_role_name:

        normalised_default_role = (
            _normalise_mapped_role(
                {
                    "name": default_role_name,
                    "description": (
                        default_role_description
                    ),
                }
            )
        )

        normalised_default_role[
            "reference_types"
        ] = [
            "default"
        ]

        normalised_default_role[
            "rule_numbers"
        ] = []

        _merge_mapped_role(
            mapped_roles,
            normalised_default_role,
        )

    mapped_roles = sorted(
        mapped_roles,
        key=lambda role: (
            _normalise_text(
                role.get(
                    "name"
                )
            ).casefold()
        ),
    )

    condition_count = sum(
        rule.get(
            "condition_count",
            0,
        )
        for rule in mapping_rules
    )

    service_count = len(
        affected_services
    )

    rule_count = len(
        mapping_rules
    )

    mapped_role_count = len(
        mapped_roles
    )

    observations = (
        _build_role_mapping_observations(
            affected_services,
            mapped_roles,
            mapping_rules,
            default_role_name,
        )
    )

    warnings = (
        _build_role_mapping_warnings(
            {
                "id": policy_id,
            },
            service_references_supplied,
        )
    )

    return {
        "schema_version": (
            IMPACT_SCHEMA_VERSION
        ),
        "analysis_type": (
            "role_mapping_policy"
        ),
        "object": {
            "type": (
                "Role Mapping Policy"
            ),
            "id": policy_id,
            "name": policy_name,
            "description": (
                policy_description
            ),
            "rule_combine_algo": (
                rule_combine_algo
            ),
            "default_role": (
                default_role_name
            ),
            "default_role_description": (
                default_role_description
            ),
        },
        "summary": {
            "referenced": (
                service_count > 0
            ),
            "usage_status": (
                "Assigned"
                if service_count > 0
                else "Not Assigned"
            ),
            "affected_service_count": (
                service_count
            ),
            "rule_count": (
                rule_count
            ),
            "mapped_role_count": (
                mapped_role_count
            ),
            "condition_count": (
                condition_count
            ),
            "default_role_configured": bool(
                default_role_name
            ),
            "shared_across_multiple_services": (
                service_count > 1
            ),
        },
        "direct_dependencies": {
            "services": (
                affected_services
            ),
            "mapped_roles": (
                mapped_roles
            ),
        },
        "mapping_rules": (
            mapping_rules
        ),
        "extended_impact": {
            "services": (
                affected_services
            ),
        },
        "observations": (
            observations
        ),
        "warnings": (
            warnings
        ),
    }
