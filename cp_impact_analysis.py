"""
ClearPass Policy Visualiser
Impact Analysis Reporting

Phase 1 provides read-only impact analysis for an
Enforcement Profile.

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