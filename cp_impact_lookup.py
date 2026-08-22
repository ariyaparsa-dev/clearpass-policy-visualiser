"""
ClearPass Policy Visualiser
Impact Analysis Lookup

Builds a searchable index of objects that support
Impact Analysis.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from cp_enforcement import (
    get_all_enforcement_policies,
    get_all_enforcement_profiles,
)
from cp_role_mapping import (
    get_all_role_mapping_policies,
)


def _normalise_lookup_name(
    value: Any,
) -> str:
    """
    Convert an object name to clean lookup text.
    """

    if value is None:
        return ""

    return str(
        value
    ).strip()


def _add_lookup_entries(
    lookup_entries: list[
        dict[str, str]
    ],
    seen: set[
        tuple[str, str]
    ],
    objects: Iterable[
        Mapping[str, Any]
    ],
    object_type: str,
    type_label: str,
) -> None:
    """
    Add unique objects of one type to the lookup index.

    Identity is based on object type and a
    case-insensitive object name.
    """

    for item in objects:

        if not isinstance(
            item,
            Mapping,
        ):

            continue

        object_name = _normalise_lookup_name(
            item.get(
                "name"
            )
        )

        if not object_name:
            continue

        identity = (
            object_type,
            object_name.casefold(),
        )

        if identity in seen:
            continue

        seen.add(
            identity
        )

        lookup_entries.append(
            {
                "name": object_name,
                "type": object_type,
                "type_label": type_label,
            }
        )


def build_impact_analysis_lookup_cache() -> list[
    dict[str, str]
]:
    """
    Build the complete Impact Analysis lookup index.

    The index includes both used and unused:

    - Enforcement Profiles
    - Enforcement Policies
    - Role Mapping Policies

    Built-in objects are retained because they can support
    Impact Analysis even though Unused Objects excludes
    them from cleanup results.
    """

    lookup_entries: list[
        dict[str, str]
    ] = []

    seen: set[
        tuple[str, str]
    ] = set()

    enforcement_profiles = (
        get_all_enforcement_profiles()
    )

    enforcement_policies = (
        get_all_enforcement_policies()
    )

    role_mapping_policies = (
        get_all_role_mapping_policies()
    )

    _add_lookup_entries(
        lookup_entries,
        seen,
        enforcement_profiles,
        "enforcement_profile",
        "Enforcement Profile",
    )

    _add_lookup_entries(
        lookup_entries,
        seen,
        enforcement_policies,
        "enforcement_policy",
        "Enforcement Policy",
    )

    _add_lookup_entries(
        lookup_entries,
        seen,
        role_mapping_policies,
        "role_mapping_policy",
        "Role Mapping Policy",
    )

    return sorted(
        lookup_entries,
        key=lambda entry: (
            entry[
                "name"
            ].casefold(),
            entry[
                "type_label"
            ].casefold(),
        ),
    )