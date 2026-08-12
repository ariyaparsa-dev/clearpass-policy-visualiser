import cp_cache
import logging

logger = logging.getLogger(__name__)
from cp_enforcement import get_enforcement_details
from cp_role_mapping import get_role_mapping_details

def build_service_graph(service):
    """
    Build Cytoscape graph elements from a ClearPass service object.
    Graph v1 uses data already available in get_config_service_by_services_id().
    """

    elements = []
    service_role_rule_count = 0
    service_enforcement_rule_count = 0
    service_profile_count = 0

    service_id = f"service_{service.get('id')}"

    # Service node
    elements.append({
        "data": {
            "id": service_id,
            "label": service.get("name", "Unknown Service"),
            "type": "service",
            "description":
                service.get("description"),

            "auth_method_count":
                len(
                    service.get(
                        "auth_methods",
                        []
                    )
                ),

            "auth_source_count":
                len(
                    service.get(
                        "auth_sources",
                        []
                    )
                ),

            "authz_source_count":
                len(
                    service.get(
                        "authz_sources",
                        []
                    )
                )
        }
    })

    previous_node = service_id

    # Authentication group
    auth_methods = service.get("auth_methods", [])
    auth_sources = service.get("auth_sources", [])

    authentication_node = None

    if auth_methods or auth_sources:

        authentication_node = f"authentication_{service.get('id')}"

        elements.append({
            "data": {
                "id": authentication_node,
                "label": "Authentication",
                "type": "authentication",
                "expandable": True,
                "collapsed": False
            }
        })

        elements.append({
            "data": {
                "source": previous_node,
                "target": authentication_node
            }
        })

        for index, method in enumerate(auth_methods):

            node_id = (
                f"auth_method_"
                f"{service.get('id')}_{index}"
            )

            elements.append({
                "data": {
                    "id": node_id,
                    "label": method,
                    "type": "auth_method",
                    "parent_branch": authentication_node
                }
            })

            elements.append({
                "data": {
                    "source": authentication_node,
                    "target": node_id
                }
            })

        for index, source in enumerate(auth_sources):

            node_id = (
                f"auth_source_"
                f"{service.get('id')}_{index}"
            )

            elements.append({
                "data": {
                    "id": node_id,
                    "label": source,
                    "type": "auth_source",
                    "parent_branch": authentication_node
                }
            })

            elements.append({
                "data": {
                    "source": authentication_node,
                    "target": node_id
                }
            })

        previous_node = authentication_node

    # Authorisation group
    authz_sources = service.get("authz_sources", [])

    if authz_sources:

        authorisation_node = f"authorisation_{service.get('id')}"

        elements.append({
            "data": {
                "id": authorisation_node,
                "label": "Authorisation",
                "type": "authorisation",
                "expandable": True,
                "collapsed": False
            }
        })

        elements.append({
            "data": {
                "source": previous_node,
                "target": authorisation_node
            }
        })

        for index, source in enumerate(authz_sources):

            node_id = (
                f"authz_source_"
                f"{service.get('id')}_{index}"
            )

            elements.append({
                "data": {
                    "id": node_id,
                    "label": source,
                    "type": "authz_source",
                    "parent_branch": authorisation_node
                }
            })

            elements.append({
                "data": {
                    "source": authorisation_node,
                    "target": node_id
                }
            })

        previous_node = authorisation_node

    # Role mapping policy
    role_mapping = service.get("role_mapping_policy")

    if role_mapping:

        role_node = f"role_mapping_{service.get('id')}"

        role_details = get_role_mapping_details(
            role_mapping
        )

        service_role_rule_count = len(
            role_details.get(
                "rules",
                []
            )
        )

        current_service_name = service.get(
            "name",
            "Unknown Service"
        )

        role_mapping_services = [
            svc
            for svc in cp_cache.role_mapping_reference_cache.get(
                role_mapping,
                []
            )
            if svc.get(
                "name"
            ) != current_service_name
        ]

        elements.append({
            "data": {
                "id": role_node,
                "label": f"RM: {role_mapping}",
                "type": "role_mapping",
                "expandable": True,
                "collapsed": True,
                "description":
                    role_details.get("description"),

                "rule_combine_algo": role_details.get(
                    "rule_combine_algo"
                ),

                "default_role": role_details.get(
                    "default_role_name"
                ),

                "rule_count": len(
                    role_details.get(
                        "rules",
                        []
                    )
                ),

                "service_references":
                    role_mapping_services,

                "service_reference_count":
                    len(
                        role_mapping_services
                    )
            }
        })


        elements.append({
            "data": {
                "source": previous_node,
                "target": role_node
            }
        })

        try:

            #role_details = get_role_mapping_details(
            #    role_mapping
            #)
            
            
            for rule_index, rule in enumerate(
                role_details.get("rules", [])
            ):

                rule_node = (
                    f"role_mapping_condition_"
                    f"{service.get('id')}_"
                    f"{rule_index}"
                )

                condition_label = (
                    f"RM Rule {rule_index + 1}"
                )

                elements.append({
                    "data": {
                        "id": rule_node,
                        "label": condition_label,
                        "type": "role_mapping_condition",

                        "condition": rule.get(
                            "condition",
                            "Unknown Condition"
                        ),

                        "attributes": rule.get(
                            "attributes",
                            []
                        ),

                        "rule_match_count": rule.get(
                            "rule_match_count"
                        ),

                        "rule_match_label": rule.get(
                            "rule_match_label"
                        ),

                        "rule_number":
                            rule_index + 1,

                        "match_type": (
                            rule.get(
                                "match_type",
                                ""
                            ).upper()
                        ),

                        "parent_branch": role_node,
                        "expandable": True,
                        "collapsed": True
                    }
                })

                elements.append({
                    "data": {
                        "source": role_node,
                        "target": rule_node
                    }
                })

                mapped_role = rule.get("role_name")

                if mapped_role:

                    mapped_role_node = (
                        f"mapped_role_"
                        f"{service.get('id')}_"
                        f"{rule_index}"
                    )

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

            default_role = role_details.get(
                "default_role_name"
            )

            if default_role:

                default_role_node = (
                    f"default_role_"
                    f"{service.get('id')}"
                )

                elements.append({
                    "data": {
                        "id": default_role_node,
                        "label": f"Default Role\n{default_role}",
                        "type": "mapped_role",
                        "role_name": default_role,
                        "description":
                            role_details.get("default_role_description"),
                        "parent_branch": role_node
                    }
                })

                elements.append({
                    "data": {
                        "source": role_node,
                        "target": default_role_node
                    }
                })

        except Exception as e:

            role_error_node = (
                f"role_mapping_error_"
                f"{service.get('id')}"
            )

            elements.append({
                "data": {
                    "id": role_error_node,
                    "label": "Role Mapping Rules\nUnavailable",
                    "type": "role_mapping_condition",
                    "error": str(e),
                    "parent_branch": role_node
                }
            })

            elements.append({
                "data": {
                    "source": role_node,
                    "target": role_error_node
                }
            })

        previous_node = role_node


    # Enforcement policy
    enforcement_policy = service.get("enf_policy")

    
    if enforcement_policy:

        enforcement_node = f"enforcement_policy_{service.get('id')}"

        enforcement_details = {}

        try:

            enforcement_details = get_enforcement_details(
                enforcement_policy
            )

            service_enforcement_rule_count = len(
                enforcement_details.get(
                    "rules",
                    []
                )
            )

        except Exception as e:

            logger.warning(
                f"Failed to retrieve enforcement details: {e}"
            )

        elements.append({
            "data": {
                "id": enforcement_node,
                "label": f"EP: {enforcement_policy}",
                "type": "enforcement_policy",
                "expandable": True,
                "collapsed": True,
                "description":
                    enforcement_details.get("description"),

                "default_profile":
                    enforcement_details.get(
                        "default_enforcement_profile"
                    ),

                "rule_eval_algo":
                    enforcement_details.get(
                        "rule_eval_algo"
                    ),

                "rule_count":
                    len(
                        enforcement_details.get(
                            "rules",
                            []
                        )
                    )
            }
        })   

        elements.append({
            "data": {
                "source": previous_node,
                "target": enforcement_node
            }
        })

        try:

            #enforcement_details = get_enforcement_details(
            #    enforcement_policy
            #)
            #
            # (enforcement_details)

            for rule_index, rule in enumerate(
                enforcement_details.get("rules", [])
            ):

                service_profile_count += len(
                    rule.get(
                        "profiles",
                        []
                    )
                )

                condition_node = (
                    f"enforcement_condition_"
                    f"{service.get('id')}_{rule_index}"
                )

                condition_label = (
                    f"EP Rule {rule_index + 1}"
                )              

                profile_names = [
                    profile.get(
                        "name",
                        "Unknown Profile"
                    )
                    for profile in rule.get(
                        "profiles",
                        []
                    )
                ]

                elements.append({
                    "data": {
                        "id": condition_node,
                        "label": condition_label,
                        "type": "enforcement_condition",

                        "condition": rule.get(
                            "condition",
                            "Unknown Condition"
                        ),

                        "attributes": rule.get(
                            "attributes",
                            []
                        ),

                        "rule_number":
                            rule_index + 1,

                        "profile_count":
                            len(
                                rule.get(
                                    "profiles",
                                    []
                                )
                            ),

                        "profile_names":
                            profile_names,

                        "match_type": (
                            rule.get(
                                "match_type",
                                ""
                            ).upper()
                        ),

                        "parent_branch": enforcement_node,
                        "expandable": True,
                        "collapsed": True
                    }
                })

                elements.append({
                    "data": {
                        "source": enforcement_node,
                        "target": condition_node
                    }
                })

                for profile_index, profile in enumerate(
                    rule.get("profiles", [])
                ):

                    profile_node = (
                        f"enforcement_profile_"
                        f"{service.get('id')}_"
                        f"{rule_index}_"
                        f"{profile_index}"
                    )

                    profile_name = profile.get(
                        "name",
                        "Unknown Profile"
                    )

                    profile_refs = (
                        cp_cache.profile_reference_cache.get(
                            profile_name,
                            {}
                        )
                    )

                    current_service_name = service.get(
                        "name",
                        "Unknown Service"
                    )


                    elements.append({
                        "data": {
                            "id": profile_node,
                            "label": f"EProf: {profile_name}",
                            "type": "enforcement_profile",
                            "description":
                                profile.get("description"),

                            "profile_type":
                                profile.get(
                                    "profile_type"
                                ),

                            "policy_references":
                                profile_refs.get(
                                    "policies",
                                    []
                                ),

                            "service_references":
                                [
                                    svc
                                    for svc in profile_refs.get(
                                        "services",
                                        []
                                    )
                                    if svc.get(
                                        "name"
                                    ) != current_service_name
                                ],

                            "policy_reference_count":
                                max(
                                    len(
                                        profile_refs.get(
                                            "policies",
                                            []
                                        )
                                    ) - 1,
                                    0
                                ),

                             "service_reference_count":
                                len(
                                    [
                                        svc
                                        for svc in profile_refs.get(
                                            "services",
                                            []
                                        )
                                        if svc.get(
                                            "name"
                                        ) != current_service_name
                                    ]
                                ),

                            "current_policy":
                                enforcement_policy,


                            "action": profile.get("action"),
                            "attributes": profile.get(
                                "attributes",
                                []
                            ),
                            "parent_branch": condition_node
                        }
                    })

                    elements.append({
                        "data": {
                            "source": condition_node,
                            "target": profile_node
                        }
                    })

                    for attr_index, attr in enumerate(
                        profile.get("attributes", [])
                    ):

                        attr_name = attr.get(
                            "name",
                            "Unknown Attribute"
                        )

                        attr_value = attr.get(
                            "value",
                            ""
                        )

                        attr_type = attr.get(
                            "type",
                            ""
                        )

                        attr_node = (
                            f"enforcement_attribute_"
                            f"{service.get('id')}_"
                            f"{rule_index}_"
                            f"{profile_index}_"
                            f"{attr_index}"
                        )

                        attr_label = attr_name


                        elements.append({
                            "data": {
                                "id": attr_node,
                                "label": attr_label,
                                "type": "enforcement_attribute",
                                "attr_name": attr_name,
                                "attr_value": attr_value,
                                "attr_type": attr_type,
                                "parent_branch": profile_node
                            }
                        })

                        elements.append({
                            "data": {
                                "source": profile_node,
                                "target": attr_node
                            }
                        })

            default_profile = enforcement_details.get(
                "default_enforcement_profile"
            )

            if default_profile:

                default_node = (
                    f"default_enforcement_profile_"
                    f"{service.get('id')}"
                )

                elements.append({
                    "data": {
                        "id": default_node,
                        "label": f"Default\n{default_profile}",
                        "type": "enforcement_profile",
                        "action": "Default",
                        "parent_branch": enforcement_node
                    }
                })

                elements.append({
                    "data": {
                        "source": enforcement_node,
                        "target": default_node
                    }
                })

        except Exception as e:

            fallback_node = (
                f"enforcement_profiles_"
                f"{service.get('id')}"
            )

            elements.append({
                "data": {
                    "id": fallback_node,
                    "label": "Enforcement Profiles\nUnavailable",
                    "type": "enforcement_profile_placeholder",
                    "error": str(e)
                }
            })

            elements.append({
                "data": {
                    "source": enforcement_node,
                    "target": fallback_node
                }
            })


    elements[0]["data"][
        "role_rule_count"
    ] = service_role_rule_count

    elements[0]["data"][
        "enforcement_rule_count"
    ] = service_enforcement_rule_count

    elements[0]["data"][
        "enforcement_profile_count"
    ] = service_profile_count

    return elements