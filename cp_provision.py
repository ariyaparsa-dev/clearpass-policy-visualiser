"""Safe, idempotent ClearPass provisioning for Policy Visualiser.

The module creates only missing objects, validates matching existing objects,
and reports conflicts without replacing or updating existing ClearPass objects.
Passwords are accepted only for creating missing local users and are never
returned in results or logged by this module.
"""

from dataclasses import dataclass, field
from typing import Any

from pyclearpass import ApiEnforcementProfile
from pyclearpass import ApiIdentities
from pyclearpass import ApiPolicyElements


DEFAULT_OBJECT_NAMES = {
    "admin_local_role": "Visualiser-Admin",
    "helpdesk_local_role": "Visualiser-Helpdesk",
    "admin_profile": "Visualiser Admin access",
    "readonly_profile": "Visualiser Helpdesk access",
    "enforcement_policy": "Visualiser Access Policy",
    "service": "Policy Visualiser",
}

DEFAULT_DENY_PROFILE = "[Deny Access Profile]"


class ProvisioningError(RuntimeError):
    """Base error for provisioning failures."""


class ProvisioningConflict(ProvisioningError):
    """Raised when an existing object differs from the required object."""


@dataclass
class ProvisioningItem:
    object_type: str
    name: str
    status: str
    message: str
    created: bool = False
    details: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "object_type": self.object_type,
            "name": self.name,
            "status": self.status,
            "message": self.message,
            "created": self.created,
            "details": self.details,
        }


@dataclass
class ProvisioningResult:
    success: bool = True
    items: list[ProvisioningItem] = field(default_factory=list)
    error: str | None = None

    def add(self, item: ProvisioningItem) -> None:
        self.items.append(item)

    def fail(self, message: str) -> None:
        self.success = False
        self.error = message

    def as_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "items": [item.as_dict() for item in self.items],
            "error": self.error,
        }


def _api_failed(response: Any) -> bool:
    return (
        isinstance(response, dict)
        and isinstance(response.get("status"), int)
        and response["status"] >= 400
    )


def _is_missing(response: Any) -> bool:
    return (
        isinstance(response, dict)
        and response.get("status") == 404
        and response.get("title") == "Not Found"
    )


def _api_error_message(response: Any, operation: str) -> str:
    if not isinstance(response, dict):
        return f"{operation} returned an unexpected response."

    status = response.get("status")
    title = response.get("title")
    detail = response.get("detail")

    parts = [operation]
    if status is not None:
        parts.append(f"HTTP {status}")
    if title:
        parts.append(str(title))
    if detail:
        parts.append(str(detail))

    return ": ".join(parts)


def _require_text(value: Any, label: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise ProvisioningError(f"{label} is required.")
    return text


def _normalise_string_list(values: Any) -> list[str]:
    if not isinstance(values, list):
        return []
    return [str(value) for value in values]


def _local_user_matches(user: dict[str, Any], user_id: str, role_name: str) -> bool:
    return (
        user.get("user_id") == user_id
        and user.get("username") == user_id
        and user.get("role_name") == role_name
        and user.get("enabled") is True
    )

def _role_matches(
    role: dict[str, Any],
    role_name: str,
) -> bool:
    """
    Return True when the ClearPass role matches
    the required role name.

    Role descriptions are intentionally ignored.
    """

    return (
        isinstance(
            role,
            dict
        )
        and
        role.get(
            "name"
        )
        == role_name
    )


def ensure_role(
    login: Any,
    role_name: str,
) -> ProvisioningItem:
    """
    Create a missing ClearPass role or validate
    an existing matching role.

    Existing roles are never updated or replaced.
    """

    role_name = _require_text(
        role_name,
        "Role name"
    )

    existing = (
        ApiPolicyElements
        .get_role_name_by_name(
            login,
            name=role_name
        )
    )

    if not _is_missing(
        existing
    ):

        if _api_failed(
            existing
        ):

            raise ProvisioningError(
                _api_error_message(
                    existing,
                    f"Lookup role {role_name}"
                )
            )

        if not _role_matches(
            existing,
            role_name
        ):

            raise ProvisioningConflict(
                f"Role {role_name} already exists "
                "but does not match the required role."
            )

        return ProvisioningItem(
            object_type="role",
            name=role_name,
            status="existing",
            message=(
                "Matching ClearPass role already exists."
            ),
            created=False
        )

    response = (
        ApiPolicyElements
        .new_role(
            login,
            body={
                "name": role_name
            }
        )
    )

    if _api_failed(
        response
    ):

        raise ProvisioningError(
            _api_error_message(
                response,
                f"Create role {role_name}"
            )
        )

    verified = (
        ApiPolicyElements
        .get_role_name_by_name(
            login,
            name=role_name
        )
    )

    if not _role_matches(
        verified,
        role_name
    ):

        raise ProvisioningError(
            f"Role {role_name} was created "
            "but could not be verified."
        )

    return ProvisioningItem(
        object_type="role",
        name=role_name,
        status="created",
        message=(
            "ClearPass role created and verified."
        ),
        created=True
    )

def ensure_local_user(
    login: Any,
    user_id: str,
    password: str,
    role_name: str,
) -> ProvisioningItem:
    user_id = _require_text(user_id, "Local user ID")
    role_name = _require_text(role_name, "Local user role")

    existing = ApiIdentities.get_local_user_user_id_by_user_id(
        login,
        user_id=user_id,
    )

    if not _is_missing(existing):
        if _api_failed(existing):
            raise ProvisioningError(
                _api_error_message(existing, f"Lookup local user {user_id}")
            )

        if not _local_user_matches(existing, user_id, role_name):
            raise ProvisioningConflict(
                f"Local user {user_id} already exists but does not match "
                f"the required enabled account and role {role_name}."
            )

        return ProvisioningItem(
            object_type="local_user",
            name=user_id,
            status="existing",
            message="Matching ClearPass local user already exists.",
            details={"role_name": role_name, "enabled": True},
        )

    password = _require_text(password, f"Password for {user_id}")

    response = ApiIdentities.new_local_user(
        login,
        body={
            "user_id": user_id,
            "username": user_id,
            "password": password,
            "role_name": role_name,
        },
    )

    if _api_failed(response):
        raise ProvisioningError(
            _api_error_message(response, f"Create local user {user_id}")
        )

    verified = ApiIdentities.get_local_user_user_id_by_user_id(
        login,
        user_id=user_id,
    )

    if not isinstance(verified, dict) or not _local_user_matches(
        verified,
        user_id,
        role_name,
    ):
        raise ProvisioningError(
            f"Local user {user_id} was created but could not be verified."
        )

    return ProvisioningItem(
        object_type="local_user",
        name=user_id,
        status="created",
        message="ClearPass local user created and verified.",
        created=True,
        details={"role_name": role_name, "enabled": True},
    )


def _expected_profile_attribute(role_value: str) -> dict[str, str]:
    return {
        "type": "Radius:Aruba",
        "name": "Aruba-User-Role",
        "value": role_value,
    }


def _profile_matches(
    profile: dict[str, Any],
    profile_name: str,
    role_value: str,
) -> bool:
    return (
        profile.get("name") == profile_name
        and profile.get("type") == "RADIUS"
        and profile.get("action") == "Accept"
        and _expected_profile_attribute(role_value)
        in profile.get("attributes", [])
    )


def ensure_enforcement_profile(
    login: Any,
    profile_name: str,
    role_value: str,
) -> ProvisioningItem:
    profile_name = _require_text(profile_name, "Enforcement Profile name")
    role_value = _require_text(role_value, "Aruba-User-Role value")

    existing = ApiEnforcementProfile.get_enforcement_profile_name_by_name(
        login,
        name=profile_name,
    )

    if not _is_missing(existing):
        if _api_failed(existing):
            raise ProvisioningError(
                _api_error_message(
                    existing,
                    f"Lookup Enforcement Profile {profile_name}",
                )
            )

        if not _profile_matches(existing, profile_name, role_value):
            raise ProvisioningConflict(
                f"Enforcement Profile {profile_name} already exists but "
                "does not match the required RADIUS Accept profile."
            )

        return ProvisioningItem(
            object_type="enforcement_profile",
            name=profile_name,
            status="existing",
            message="Matching Enforcement Profile already exists.",
            details={"Aruba-User-Role": role_value},
        )

    response = ApiEnforcementProfile.new_enforcement_profile(
        login,
        body={
            "name": profile_name,
            "type": "RADIUS",
            "action": "Accept",
            "attributes": [_expected_profile_attribute(role_value)],
        },
    )

    if _api_failed(response):
        raise ProvisioningError(
            _api_error_message(
                response,
                f"Create Enforcement Profile {profile_name}",
            )
        )

    verified = ApiEnforcementProfile.get_enforcement_profile_name_by_name(
        login,
        name=profile_name,
    )

    if not isinstance(verified, dict) or not _profile_matches(
        verified,
        profile_name,
        role_value,
    ):
        raise ProvisioningError(
            f"Enforcement Profile {profile_name} was created but could "
            "not be verified."
        )

    return ProvisioningItem(
        object_type="enforcement_profile",
        name=profile_name,
        status="created",
        message="Enforcement Profile created and verified.",
        created=True,
        details={"Aruba-User-Role": role_value},
    )


def _find_policy_rule(policy: dict[str, Any], role_name: str) -> dict[str, Any] | None:
    for rule in policy.get("rules", []):
        for condition in rule.get("condition", []):
            if (
                condition.get("type") == "Tips"
                and condition.get("name") == "Role"
                and condition.get("oper") == "EQUALS"
                and condition.get("value") == role_name
            ):
                return rule
    return None


def _policy_matches(
    policy: dict[str, Any],
    policy_name: str,
    admin_local_role: str,
    helpdesk_local_role: str,
    admin_profile: str,
    readonly_profile: str,
) -> bool:
    if (
        policy.get("name") != policy_name
        or policy.get("enforcement_type") != "RADIUS"
        or policy.get("default_enforcement_profile") != DEFAULT_DENY_PROFILE
        or policy.get("rule_eval_algo") != "evaluate-all"
    ):
        return False

    expected = [
        (helpdesk_local_role, readonly_profile),
        (admin_local_role, admin_profile),
    ]

    for role_name, profile_name in expected:
        rule = _find_policy_rule(policy, role_name)
        if rule is None:
            return False
        if profile_name not in _normalise_string_list(
            rule.get("enforcement_profile_names")
        ):
            return False

    return True


def ensure_enforcement_policy(
    login: Any,
    policy_name: str,
    admin_local_role: str,
    helpdesk_local_role: str,
    admin_profile: str,
    readonly_profile: str,
) -> ProvisioningItem:
    policy_name = _require_text(policy_name, "Enforcement Policy name")

    existing = ApiPolicyElements.get_enforcement_policy_name_by_name(
        login,
        name=policy_name,
    )

    match_args = (
        policy_name,
        admin_local_role,
        helpdesk_local_role,
        admin_profile,
        readonly_profile,
    )

    if not _is_missing(existing):
        if _api_failed(existing):
            raise ProvisioningError(
                _api_error_message(existing, f"Lookup policy {policy_name}")
            )

        if not _policy_matches(existing, *match_args):
            raise ProvisioningConflict(
                f"Enforcement Policy {policy_name} already exists but "
                "does not match the required Visualiser policy."
            )

        return ProvisioningItem(
            object_type="enforcement_policy",
            name=policy_name,
            status="existing",
            message="Matching Enforcement Policy already exists.",
        )

    body = {
        "name": policy_name,
        "enforcement_type": "RADIUS",
        "default_enforcement_profile": DEFAULT_DENY_PROFILE,
        "rule_eval_algo": "evaluate-all",
        "rules": [
            {
                "enforcement_profile_names": [readonly_profile],
                "condition": [
                    {
                        "type": "Tips",
                        "name": "Role",
                        "oper": "EQUALS",
                        "value": helpdesk_local_role,
                        "valueAsList": [helpdesk_local_role],
                    }
                ],
            },
            {
                "enforcement_profile_names": [admin_profile],
                "condition": [
                    {
                        "type": "Tips",
                        "name": "Role",
                        "oper": "EQUALS",
                        "value": admin_local_role,
                        "valueAsList": [admin_local_role],
                    }
                ],
            },
        ],
    }

    response = ApiPolicyElements.new_enforcement_policy(login, body=body)
    if _api_failed(response):
        raise ProvisioningError(
            _api_error_message(response, f"Create policy {policy_name}")
        )

    verified = ApiPolicyElements.get_enforcement_policy_name_by_name(
        login,
        name=policy_name,
    )

    if not isinstance(verified, dict) or not _policy_matches(
        verified,
        *match_args,
    ):
        raise ProvisioningError(
            f"Enforcement Policy {policy_name} was created but could not "
            "be verified."
        )

    return ProvisioningItem(
        object_type="enforcement_policy",
        name=policy_name,
        status="created",
        message="Enforcement Policy created and verified.",
        created=True,
    )


def _find_service_condition(
    service: dict[str, Any],
    condition_name: str,
) -> dict[str, Any] | None:
    for condition in service.get("rules_conditions", []):
        if condition.get("name") == condition_name:
            return condition
    return None


def _normalise_csv(value: Any) -> list[str]:
    return [part.strip() for part in str(value or "").split(",") if part.strip()]


def _service_matches(
    service: dict[str, Any],
    service_name: str,
    enforcement_policy: str,
    admin_user_id: str,
    helpdesk_user_id: str,
    nas_identifier: str,
) -> bool:
    if (
        service.get("name") != service_name
        or service.get("type") != "RADIUS"
        or service.get("template") != "802.1X Wired"
        or service.get("enabled") is not True
        or service.get("rules_match_type") != "MATCHES_ALL"
        or service.get("auth_methods") != ["[PAP]"]
        or service.get("auth_sources") != ["[Local User Repository]"]
        or service.get("enf_policy") != enforcement_policy
    ):
        return False

    user_condition = _find_service_condition(service, "User-Name")
    nas_condition = _find_service_condition(service, "NAS-Identifier")

    if user_condition is None or nas_condition is None:
        return False

    expected_users = sorted([admin_user_id, helpdesk_user_id])
    actual_users = sorted(_normalise_csv(user_condition.get("value")))

    return (
        user_condition.get("type") == "Radius:IETF"
        and user_condition.get("operator") == "BELONGS_TO"
        and actual_users == expected_users
        and nas_condition.get("type") == "Radius:IETF"
        and nas_condition.get("operator") == "EQUALS"
        and nas_condition.get("value") == nas_identifier
    )


def ensure_service(
    login: Any,
    service_name: str,
    enforcement_policy: str,
    admin_user_id: str,
    helpdesk_user_id: str,
    nas_identifier: str,
) -> ProvisioningItem:
    service_name = _require_text(service_name, "Service name")
    nas_identifier = _require_text(nas_identifier, "NAS Identifier")

    existing = ApiPolicyElements.get_config_service_name_by_services_name(
        login,
        services_name=service_name,
    )

    match_args = (
        service_name,
        enforcement_policy,
        admin_user_id,
        helpdesk_user_id,
        nas_identifier,
    )

    if not _is_missing(existing):
        if _api_failed(existing):
            raise ProvisioningError(
                _api_error_message(existing, f"Lookup Service {service_name}")
            )

        if not _service_matches(existing, *match_args):
            raise ProvisioningConflict(
                f"Service {service_name} already exists but does not match "
                "the required enabled Visualiser RADIUS Service."
            )

        return ProvisioningItem(
            object_type="service",
            name=service_name,
            status="existing",
            message="Matching enabled ClearPass Service already exists.",
            details={"nas_identifier": nas_identifier},
        )

    user_list = f"{admin_user_id}, {helpdesk_user_id}"
    body = {
        "name": service_name,
        "template": "802.1X Wired",
        "enabled": True,
        "monitor_mode": False,
        "rules_match_type": "MATCHES_ALL",
        "rules_conditions": [
            {
                "type": "Radius:IETF",
                "name": "User-Name",
                "operator": "BELONGS_TO",
                "value": user_list,
            },
            {
                "type": "Radius:IETF",
                "name": "NAS-Identifier",
                "operator": "EQUALS",
                "value": nas_identifier,
            },
        ],
        "auth_methods": ["[PAP]"],
        "auth_sources": ["[Local User Repository]"],
        "strip_username": False,
        "enf_policy": enforcement_policy,
        "use_cached_policy_results": False,
        "posture_enabled": False,
        "audit_enabled": False,
        "profiler_enabled": False,
        "acct_proxy_enabled": False,
    }

    response = ApiPolicyElements.new_config_service(login, body=body)
    if _api_failed(response):
        raise ProvisioningError(
            _api_error_message(response, f"Create Service {service_name}")
        )

    verified = ApiPolicyElements.get_config_service_name_by_services_name(
        login,
        services_name=service_name,
    )

    if not isinstance(verified, dict) or not _service_matches(
        verified,
        *match_args,
    ):
        raise ProvisioningError(
            f"Service {service_name} was created but could not be verified."
        )

    return ProvisioningItem(
        object_type="service",
        name=service_name,
        status="created",
        message="Enabled ClearPass Service created and verified.",
        created=True,
        details={"nas_identifier": nas_identifier},
    )


def provision_visualiser_configuration(
    login: Any,
    admin_user_id: str,
    admin_password: str,
    helpdesk_user_id: str,
    helpdesk_password: str,
    nas_identifier: str,
    object_names: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Provision or validate the full ClearPass Visualiser configuration.

    Existing matching objects are preserved. Existing conflicting objects stop
    provisioning. Objects created before a later failure are not deleted
    automatically; the returned result identifies every object created.
    """

    names = dict(DEFAULT_OBJECT_NAMES)
    if object_names:
        names.update(object_names)

    admin_user_id = _require_text(admin_user_id, "Admin user ID")
    helpdesk_user_id = _require_text(helpdesk_user_id, "Helpdesk user ID")
    nas_identifier = _require_text(nas_identifier, "NAS Identifier")

    result = ProvisioningResult()

    try:
        result.add(
            ensure_role(
                login,
                names["admin_local_role"]
            )
        )
        result.add(
            ensure_role(
                login,
                names["helpdesk_local_role"]
            )
        )
        result.add(
            ensure_local_user(
                login,
                admin_user_id,
                admin_password,
                names["admin_local_role"],
            )
        )
        result.add(
            ensure_local_user(
                login,
                helpdesk_user_id,
                helpdesk_password,
                names["helpdesk_local_role"],
            )
        )
        result.add(
            ensure_enforcement_profile(
                login,
                names["admin_profile"],
                "Admin",
            )
        )
        result.add(
            ensure_enforcement_profile(
                login,
                names["readonly_profile"],
                "ReadOnly",
            )
        )
        result.add(
            ensure_enforcement_policy(
                login,
                names["enforcement_policy"],
                names["admin_local_role"],
                names["helpdesk_local_role"],
                names["admin_profile"],
                names["readonly_profile"],
            )
        )
        result.add(
            ensure_service(
                login,
                names["service"],
                names["enforcement_policy"],
                admin_user_id,
                helpdesk_user_id,
                nas_identifier,
            )
        )

    except ProvisioningError as exc:
        result.fail(str(exc))

    return result.as_dict()



def _plan_item(
    object_type: str,
    name: str,
    response: Any,
    matches: bool,
    existing_message: str,
    create_message: str,
    conflict_message: str,
    details: dict[str, Any] | None = None,
) -> ProvisioningItem:
    """Build a read-only plan item from a ClearPass lookup response."""

    if _is_missing(response):
        return ProvisioningItem(
            object_type=object_type,
            name=name,
            status="would_create",
            message=create_message,
            created=False,
            details=details or {},
        )

    if _api_failed(response):
        raise ProvisioningError(
            _api_error_message(response, f"Inspect {object_type} {name}")
        )

    if matches:
        return ProvisioningItem(
            object_type=object_type,
            name=name,
            status="existing",
            message=existing_message,
            created=False,
            details=details or {},
        )

    return ProvisioningItem(
        object_type=object_type,
        name=name,
        status="conflict",
        message=conflict_message,
        created=False,
        details=details or {},
    )


def plan_visualiser_configuration(
    login: Any,
    admin_user_id: str,
    helpdesk_user_id: str,
    nas_identifier: str,
    object_names: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Inspect ClearPass and return a read-only provisioning plan.

    This function performs GET operations only. It never creates, updates,
    replaces, enables, disables, reorders or deletes ClearPass objects.

    Status values:
      existing     - the object exists and matches the required configuration
      would_create - the object is missing and provisioning would create it
      conflict     - the object exists but differs; provisioning must stop
    """

    names = dict(DEFAULT_OBJECT_NAMES)
    if object_names:
        names.update(object_names)

    admin_user_id = _require_text(admin_user_id, "Admin user ID")
    helpdesk_user_id = _require_text(helpdesk_user_id, "Helpdesk user ID")
    nas_identifier = _require_text(nas_identifier, "NAS Identifier")

    result = ProvisioningResult()

    try:

        admin_role = (
            ApiPolicyElements
            .get_role_name_by_name(
                login,
                name=names["admin_local_role"]
            )
        )

        result.add(
            _plan_item(
                object_type="role",
                name=names["admin_local_role"],
                response=admin_role,
                matches=(
                    isinstance(
                        admin_role,
                        dict
                    )
                    and
                    _role_matches(
                        admin_role,
                        names["admin_local_role"]
                    )
                ),
                existing_message=(
                    "Matching ClearPass role "
                    "already exists."
                ),
                create_message=(
                    "ClearPass Admin role is missing "
                    "and would be created."
                ),
                conflict_message=(
                    "ClearPass Admin role exists but "
                    "does not match the required role."
                )
            )
        )

        helpdesk_role = (
            ApiPolicyElements
            .get_role_name_by_name(
                login,
                name=names["helpdesk_local_role"]
            )
        )

        result.add(
            _plan_item(
                object_type="role",
                name=names["helpdesk_local_role"],
                response=helpdesk_role,
                matches=(
                    isinstance(
                        helpdesk_role,
                        dict
                    )
                    and
                    _role_matches(
                        helpdesk_role,
                        names["helpdesk_local_role"]
                    )
                ),
                existing_message=(
                    "Matching ClearPass role "
                    "already exists."
                ),
                create_message=(
                    "ClearPass Helpdesk role is missing "
                    "and would be created."
                ),
                conflict_message=(
                    "ClearPass Helpdesk role exists but "
                    "does not match the required role."
                )
            )
        )
        admin_user = ApiIdentities.get_local_user_user_id_by_user_id(
            login,
            user_id=admin_user_id,
        )
        result.add(
            _plan_item(
                object_type="local_user",
                name=admin_user_id,
                response=admin_user,
                matches=(
                    isinstance(admin_user, dict)
                    and _local_user_matches(
                        admin_user,
                        admin_user_id,
                        names["admin_local_role"],
                    )
                ),
                existing_message=(
                    "Matching ClearPass local user already exists."
                ),
                create_message=(
                    "ClearPass local user is missing and would be created."
                ),
                conflict_message=(
                    "ClearPass local user exists but does not match the "
                    "required enabled Admin account and role."
                ),
                details={
                    "role_name": names["admin_local_role"],
                    "enabled": True,
                },
            )
        )

        helpdesk_user = ApiIdentities.get_local_user_user_id_by_user_id(
            login,
            user_id=helpdesk_user_id,
        )
        result.add(
            _plan_item(
                object_type="local_user",
                name=helpdesk_user_id,
                response=helpdesk_user,
                matches=(
                    isinstance(helpdesk_user, dict)
                    and _local_user_matches(
                        helpdesk_user,
                        helpdesk_user_id,
                        names["helpdesk_local_role"],
                    )
                ),
                existing_message=(
                    "Matching ClearPass local user already exists."
                ),
                create_message=(
                    "ClearPass local user is missing and would be created."
                ),
                conflict_message=(
                    "ClearPass local user exists but does not match the "
                    "required enabled Helpdesk account and role."
                ),
                details={
                    "role_name": names["helpdesk_local_role"],
                    "enabled": True,
                },
            )
        )

        admin_profile = (
            ApiEnforcementProfile.get_enforcement_profile_name_by_name(
                login,
                name=names["admin_profile"],
            )
        )
        result.add(
            _plan_item(
                object_type="enforcement_profile",
                name=names["admin_profile"],
                response=admin_profile,
                matches=(
                    isinstance(admin_profile, dict)
                    and _profile_matches(
                        admin_profile,
                        names["admin_profile"],
                        "Admin",
                    )
                ),
                existing_message=(
                    "Matching Enforcement Profile already exists."
                ),
                create_message=(
                    "Admin Enforcement Profile is missing and would be "
                    "created."
                ),
                conflict_message=(
                    "Admin Enforcement Profile exists but does not match "
                    "the required RADIUS Accept profile."
                ),
                details={"Aruba-User-Role": "Admin"},
            )
        )

        readonly_profile = (
            ApiEnforcementProfile.get_enforcement_profile_name_by_name(
                login,
                name=names["readonly_profile"],
            )
        )
        result.add(
            _plan_item(
                object_type="enforcement_profile",
                name=names["readonly_profile"],
                response=readonly_profile,
                matches=(
                    isinstance(readonly_profile, dict)
                    and _profile_matches(
                        readonly_profile,
                        names["readonly_profile"],
                        "ReadOnly",
                    )
                ),
                existing_message=(
                    "Matching Enforcement Profile already exists."
                ),
                create_message=(
                    "ReadOnly Enforcement Profile is missing and would be "
                    "created."
                ),
                conflict_message=(
                    "ReadOnly Enforcement Profile exists but does not match "
                    "the required RADIUS Accept profile."
                ),
                details={"Aruba-User-Role": "ReadOnly"},
            )
        )

        policy = ApiPolicyElements.get_enforcement_policy_name_by_name(
            login,
            name=names["enforcement_policy"],
        )
        result.add(
            _plan_item(
                object_type="enforcement_policy",
                name=names["enforcement_policy"],
                response=policy,
                matches=(
                    isinstance(policy, dict)
                    and _policy_matches(
                        policy,
                        names["enforcement_policy"],
                        names["admin_local_role"],
                        names["helpdesk_local_role"],
                        names["admin_profile"],
                        names["readonly_profile"],
                    )
                ),
                existing_message=(
                    "Matching Enforcement Policy already exists."
                ),
                create_message=(
                    "Enforcement Policy is missing and would be created."
                ),
                conflict_message=(
                    "Enforcement Policy exists but does not match the "
                    "required Visualiser role rules."
                ),
            )
        )

        service = ApiPolicyElements.get_config_service_name_by_services_name(
            login,
            services_name=names["service"],
        )
        result.add(
            _plan_item(
                object_type="service",
                name=names["service"],
                response=service,
                matches=(
                    isinstance(service, dict)
                    and _service_matches(
                        service,
                        names["service"],
                        names["enforcement_policy"],
                        admin_user_id,
                        helpdesk_user_id,
                        nas_identifier,
                    )
                ),
                existing_message=(
                    "Matching enabled ClearPass Service already exists."
                ),
                create_message=(
                    "ClearPass Service is missing and would be created "
                    "enabled."
                ),
                conflict_message=(
                    "ClearPass Service exists but does not match the required "
                    "enabled Service, usernames, policy or NAS Identifier."
                ),
                details={"nas_identifier": nas_identifier},
            )
        )

        conflicts = [
            item
            for item in result.items
            if item.status == "conflict"
        ]
        if conflicts:
            result.fail(
                "Provisioning conflicts were found. Existing objects were "
                "not modified."
            )

    except ProvisioningError as exc:
        result.fail(str(exc))

    return result.as_dict()
