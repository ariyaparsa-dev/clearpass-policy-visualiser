import logging

from cp_enforcement import get_enforcement_details
from cp_role_mapping import get_role_mapping_details
from cp_enforcement import (
    get_enforcement_details,
    get_enforcement_profile
)


logger = logging.getLogger(__name__)

def build_role_mapping_graph(rolemap_name):
    """
    Build a standalone Cytoscape graph for a single role mapping policy.

    Structure:
        Role Mapping (root)
            ├── RM Rule N (condition) → Mapped Role
            └── Default Role
    """

    elements = []

    details = get_role_mapping_details(rolemap_name)

    root_id = "role_mapping_root"

    # Root: the role mapping node
    elements.append({
        "data": {
            "id": root_id,
            "label": f"RM: {rolemap_name}",
            "type": "role_mapping",
            "expandable": True,
            "collapsed": False,
            "description": details.get("description"),
            "rule_combine_algo":
                details.get("rule_combine_algo"),

            "default_role":
                details.get("default_role_name"),

            "rule_count":
                len(details.get("rules", []))
                
        }
    })

    # Rules
    for rule_index, rule in enumerate(
        details.get("rules", [])
    ):

        rule_node = f"rm_condition_{rule_index}"

        elements.append({
            "data": {
                "id": rule_node,
                "label": f"RM Rule {rule_index + 1}",
                "type": "role_mapping_condition",

                "condition":
                    rule.get("condition", "Unknown Condition"),

                "attributes":
                    rule.get("attributes", []),

                "rule_match_count":
                    rule.get("rule_match_count"),

                "rule_match_label":
                    rule.get("rule_match_label"),

                "rule_number": rule_index + 1,

                "match_type":
                    rule.get("match_type", "").upper(),

                "parent_branch": root_id,
                "expandable": True,
                "collapsed": False
            }
        })

        elements.append({
            "data": {
                "source": root_id,
                "target": rule_node
            }
        })

        # Mapped role for this rule
        mapped_role = rule.get("role_name")

        if mapped_role:

            mapped_role_node = f"rm_role_{rule_index}"

            elements.append({
                "data": {
                    "id": mapped_role_node,
                    "label": f"Role: {mapped_role}",
                    "type": "mapped_role",
                    "role_name": mapped_role,
                    "description": rule.get("role_description"),
                    "parent_branch": rule_node
                }
            })

            elements.append({
                "data": {
                    "source": rule_node,
                    "target": mapped_role_node
                }
            })

    # Default role
    default_role = details.get("default_role_name")

    if default_role:

        default_node = "rm_default_role"

        elements.append({
            "data": {
                "id": default_node,
                "label": f"Default Role\n{default_role}",
                "type": "mapped_role",
                "role_name": default_role,
                "description":
                    details.get("default_role_description"),
                "parent_branch": root_id
            }
        })

        elements.append({
            "data": {
                "source": root_id,
                "target": default_node
            }
        })

    return elements

def build_enforcement_policy_graph(policy_name):
    """
    Build a standalone Cytoscape graph for a single enforcement policy.

    Structure:
        Enforcement Policy (root)
            ├── EP Rule N (condition)
            │      └── Enforcement Profile
            │             └── Attribute
            └── Default Profile
    """

    elements = []

    details = get_enforcement_details(policy_name)

    root_id = "enforcement_policy_root"

    # Root: the enforcement policy node
    elements.append({
        "data": {
            "id": root_id,
            "label": f"EP: {policy_name}",
            "type": "enforcement_policy",
            "expandable": True,
            "collapsed": False,
            "description": details.get("description"),

            "default_profile":
                details.get("default_enforcement_profile"),

            "rule_eval_algo":
                details.get("rule_eval_algo"),

            "rule_count":
                len(details.get("rules", []))
        }
    })

    # Rules
    for rule_index, rule in enumerate(
        details.get("rules", [])
    ):

        condition_node = f"ep_condition_{rule_index}"

        profile_names = [
            profile.get("name", "Unknown Profile")
            for profile in rule.get("profiles", [])
        ]

        elements.append({
            "data": {
                "id": condition_node,
                "label": f"EP Rule {rule_index + 1}",
                "type": "enforcement_condition",

                "condition":
                    rule.get("condition", "Unknown Condition"),

                "attributes":
                    rule.get("attributes", []),

                "rule_number": rule_index + 1,

                "profile_count":
                    len(rule.get("profiles", [])),

                "profile_names": profile_names,

                "match_type":
                    rule.get("match_type", "").upper(),

                "parent_branch": root_id,
                "expandable": True,
                "collapsed": True
            }
        })

        elements.append({
            "data": {
                "source": root_id,
                "target": condition_node
            }
        })

        # Profiles in this rule
        for profile_index, profile in enumerate(
            rule.get("profiles", [])
        ):

            profile_node = (
                f"ep_profile_{rule_index}_{profile_index}"
            )

            profile_name = profile.get(
                "name",
                "Unknown Profile"
            )

            elements.append({
                "data": {
                    "id": profile_node,
                    "label": f"EProf: {profile_name}",
                    "type": "enforcement_profile",

                    "description":
                        profile.get("description"),

                    "profile_type":
                        profile.get("profile_type"),

                    "action": profile.get("action"),

                    "attributes":
                        profile.get("attributes", []),

                    "parent_branch": condition_node
                }
            })

            elements.append({
                "data": {
                    "source": condition_node,
                    "target": profile_node
                }
            })

            # Attributes of this profile
            for attr_index, attr in enumerate(
                profile.get("attributes", [])
            ):

                attr_node = (
                    f"ep_attr_"
                    f"{rule_index}_"
                    f"{profile_index}_"
                    f"{attr_index}"
                )

                elements.append({
                    "data": {
                        "id": attr_node,
                        "label": attr.get(
                            "name",
                            "Unknown Attribute"
                        ),
                        "type": "enforcement_attribute",
                        "attr_name": attr.get("name", ""),
                        "attr_value": attr.get("value", ""),
                        "attr_type": attr.get("type", ""),
                        "parent_branch": profile_node
                    }
                })

                elements.append({
                    "data": {
                        "source": profile_node,
                        "target": attr_node
                    }
                })

    # Default enforcement profile
    default_profile = details.get(
        "default_enforcement_profile"
    )

    if default_profile:

        default_node = "ep_default_profile"

        elements.append({
            "data": {
                "id": default_node,
                "label": f"Default\n{default_profile}",
                "type": "enforcement_profile",
                "action": "Default",
                "parent_branch": root_id
            }
        })

        elements.append({
            "data": {
                "source": root_id,
                "target": default_node
            }
        })

    return elements