
import os
import time
import logging
logger = logging.getLogger(__name__)

from pyclearpass import *
from pyclearpass.api_endpointvisibility import ApiEndpointVisibility

from cp_client import get_login


ENDPOINT_CACHE = None
ATTRIBUTE_CATALOG_CACHE = None
FINGERPRINT_CACHE = {}
GUEST_CACHE = None

def build_fingerprint_cache():

    cache_start = time.perf_counter()

    global FINGERPRINT_CACHE

    if FINGERPRINT_CACHE:
        logger.info(
            "Fingerprint cache already populated: %s entries",
            len(FINGERPRINT_CACHE)
        )
        return

    print("Building fingerprint cache...")

    login = get_login()

    endpoints = get_all_endpoints()

    for endpoint in endpoints:

        mac_address = endpoint.get(
            "mac_address"
        )

        if not mac_address:
            continue

        mac_cache_key = normalise_mac(
            mac_address
        )

        if mac_cache_key in FINGERPRINT_CACHE:
            continue

        lookup_values = [
            mac_address,
            format_mac_with_hyphens(
                mac_address
            )
        ]

        fingerprint = {}

        for lookup_value in lookup_values:

            try:

                response = (
                    ApiEndpointVisibility
                    .get_device_profiler_device_fingerprint_by_mac_or_ip(
                        login,
                        mac_or_ip=lookup_value
                    )
                )

                if (
                    isinstance(response, dict)
                    and response.get("status") not in [404, "404"]
                ):

                    fingerprint = response
                    break

            except Exception:
                continue

        FINGERPRINT_CACHE[
            mac_cache_key
        ] = fingerprint

    print(
        f"Fingerprint cache built: "
        f"{len(FINGERPRINT_CACHE)} entries "
        f"in {time.perf_counter() - cache_start:.3f}s"
    )

def normalise_mac(mac_address):

    return (
        str(mac_address or "")
        .replace("-", "")
        .replace(":", "")
        .replace(".", "")
        .lower()
    )

def format_mac_with_hyphens(mac_address):

    mac = normalise_mac(
        mac_address
    )

    if len(mac) != 12:

        return mac_address

    return "-".join(
        mac[index:index + 2]
        for index in range(
            0,
            12,
            2
        )
    ).upper()

def get_endpoint_fingerprint(
    mac_address
):

    return FINGERPRINT_CACHE.get(
        normalise_mac(mac_address),
        {}
    )


def preload_endpoint_data():

    source = os.getenv(
        "ENDPOINT_PROFILE_SOURCE",
        "api"
    ).lower()

    if source == "sql":

        try:
            from cp_endpoint_sql import build_fingerprint_cache_from_sql

            start = time.time()

            sql_cache = build_fingerprint_cache_from_sql()

            global FINGERPRINT_CACHE
            FINGERPRINT_CACHE = sql_cache

            logger.info(
                "Endpoint pre-load complete using SQL: %s fingerprint entries in %.3fs",
                len(FINGERPRINT_CACHE),
                time.time() - start
            )

            return

        except Exception:

            logger.exception(
                "SQL endpoint pre-load failed."
            )

            fallback = os.getenv(
                "ENDPOINT_SQL_FALLBACK_TO_API",
                "true"
            ).lower() == "true"

            if not fallback:
                raise

            logger.warning(
                "Falling back to API endpoint pre-load."
            )

    # Existing API-based preload code continues below this point



    print("Pre-loading endpoint cache...")

    get_all_endpoints()

    print("Pre-loading guest cache...")

    get_all_guests()

    print("Pre-loading fingerprint cache...")

    build_fingerprint_cache()

    print("Endpoint pre-load complete")

def get_all_endpoints():

    global ENDPOINT_CACHE

    if ENDPOINT_CACHE is not None:
        return ENDPOINT_CACHE

    login = get_login()

    response = ApiIdentities.get_endpoint(
        login,
        limit=500,
        profile_details="true"
    )

    ENDPOINT_CACHE = response.get(
        "_embedded",
        {}
    ).get(
        "items",
        []
    )

    return ENDPOINT_CACHE

def get_all_guests():

    global GUEST_CACHE

    if GUEST_CACHE is not None:
        return GUEST_CACHE

    login = get_login()

    response = ApiIdentities.get_guest(
        login,
        limit=500
    )

    GUEST_CACHE = response.get(
        "_embedded",
        {}
    ).get(
        "items",
        []
    )

    return GUEST_CACHE

def build_attribute_catalog():

    global ATTRIBUTE_CATALOG_CACHE

    if ATTRIBUTE_CATALOG_CACHE is not None:
        return ATTRIBUTE_CATALOG_CACHE

    catalog = {}

    endpoints = get_all_endpoints()

    for endpoint in endpoints:

        attributes = endpoint.get(
            "attributes",
            {}
        )

        for attr_name, attr_value in attributes.items():

            if attr_name not in catalog:

                catalog[attr_name] = {
                    "endpoint_count": 0,
                    "values": set()
                }

            catalog[attr_name]["endpoint_count"] += 1

            if (
                attr_value is not None and
                str(attr_value).strip()
            ):

                catalog[attr_name]["values"].add(
                    str(attr_value)
                )

    for attr_name in catalog:

        catalog[attr_name]["values"] = sorted(
            list(
                catalog[attr_name]["values"]
            )
        )

    ATTRIBUTE_CATALOG_CACHE = catalog

    return catalog


def get_attribute_count(attribute_name):

    catalog = build_attribute_catalog()

    return catalog.get(
        attribute_name,
        {}
    ).get(
        "endpoint_count",
        0
    )


def get_status_count(status_name):

    endpoints = get_all_endpoints()

    count = 0

    expected_status = normalise_value(
        status_name
    )

    for endpoint in endpoints:

        endpoint_status = normalise_value(
            endpoint.get(
                "status",
                ""
            )
        )

        if endpoint_status == expected_status:

            count += 1

    return count


def get_attribute_details(attribute_name):

    endpoints = get_all_endpoints()

    matches = []

    for endpoint in endpoints:

        attributes = endpoint.get(
            "attributes",
            {}
        )

        if attribute_name in attributes:

            matches.append(
                {
                    "id": endpoint.get("id"),
                    "mac_address": endpoint.get(
                        "mac_address"
                    ),
                    "value": attributes.get(
                        attribute_name
                    ),
                    "description": endpoint.get(
                        "description"
                    ),
                    "status": endpoint.get(
                        "status"
                    ),
                    "device_insight_tags": endpoint.get(
                        "device_insight_tags",
                        []
                    )
                }
            )

    return matches


def normalise_key(value):

    return (
        str(value or "")
        .strip()
        .lower()
        .replace("-", "")
        .replace("_", "")
        .replace(" ", "")
    )


def normalise_value(value):

    return (
        str(value or "")
        .strip()
        .lower()
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


def find_nested_value(data, attribute_name):

    attribute_key = normalise_key(
        attribute_name
    )

    if isinstance(data, dict):

        for key, value in data.items():

            if normalise_key(key) == attribute_key:

                return value

            nested_value = find_nested_value(
                value,
                attribute_name
            )

            if nested_value is not None:

                return nested_value

    elif isinstance(data, list):

        for item in data:

            nested_value = find_nested_value(
                item,
                attribute_name
            )

            if nested_value is not None:

                return nested_value

    return None

def get_endpoint_profile_value(
    endpoint,
    attribute_name
):

    attribute_name_normalised = normalise_key(
        attribute_name
    )

    attributes = endpoint.get(
        "attributes",
        {}
    )

    alias_map = {
        "status": [
            "status"
        ],
        "deviceinsighttags": [
            "device_insight_tags",
            "device_insight_tag",
            "deviceInsightTags",
            "Device Insight Tags"
        ],
        "deviceosfamily": [
            "device_os_family",
            "device_os",
            "os_family",
            "osFamily",
            "Device OS Family",
            "OS Family"
        ],
        "osfamily": [
            "device_os_family",
            "device_os",
            "os_family",
            "osFamily",
            "Device OS Family",
            "OS Family"
        ],
        "devicename": [
            "device_name",
            "deviceName",
            "Device Name"
        ],
        "devicetype": [
            "device_type",
            "deviceType",
            "Device Type"
        ],
        "expandeddevicetype": [
            "expanded_device_type",
            "expandedDeviceType",
            "Expanded Device Type"
        ],
        "devicecategory": [
            "device_category",
            "deviceCategory",
            "Device Category",
            "Category"
        ],
        "category": [
            "device_category",
            "deviceCategory",
            "Device Category",
            "Category"
        ],
        "hostname": [
            "hostname",
            "host_name",
            "Host Name"
        ],
        "ipv4address": [
            "ip_address",
            "ipv4_address",
            "IPv4 Address"
        ],
        "ipv6address": [
            "ipv6_address",
            "IPv6 Address"
        ],
        "macvendor": [
            "mac_vendor",
            "macVendor",
            "MAC Vendor"
        ],
        "connectiontype": [
            "connection_type",
            "connectionType",
            "Connection Type"
        ],
        "networkssid": [
            "network_ssid",
            "networkSSID",
            "Network SSID"
        ],
        "accesspoint": [
            "access_point",
            "accessPoint",
            "Access Point"
        ]
    }

    possible_keys = alias_map.get(
        attribute_name_normalised,
        []
    )

    lookup_keys = [
        attribute_name
    ] + possible_keys

    for lookup_key in lookup_keys:

        lookup_key_normalised = normalise_key(
            lookup_key
        )

        for key, value in attributes.items():

            if normalise_key(key) == lookup_key_normalised:

                return value

    for lookup_key in lookup_keys:

        if lookup_key in endpoint:

            return endpoint.get(
                lookup_key
            )

    for lookup_key in lookup_keys:

        lookup_key_normalised = normalise_key(
            lookup_key
        )

        for key, value in endpoint.items():

            if normalise_key(key) == lookup_key_normalised:

                return value

    for lookup_key in lookup_keys:

        nested_value = find_nested_value(
            endpoint,
            lookup_key
        )

        if nested_value is not None:

            return nested_value

    fingerprint_attributes = {
        "devicecategory",
        "category",
        "deviceosfamily",
        "osfamily",
        "devicefamily",
        "devicename",
        "devicetype",
        "expandeddevicetype",
        "hostname",
        "macvendor",
        "ipv4address",
        "ipaddress"
    }

    if (
        attribute_name_normalised
        not in fingerprint_attributes
    ):

        return None

    mac_address = endpoint.get(
        "mac_address"
    )

    if mac_address:

        fingerprint = (
            get_endpoint_fingerprint(
                mac_address
            )
        )

        fingerprint_map = {
            "devicecategory":
                "device_category",

            "category":
                "device_category",

            "deviceosfamily":
                "device_family",

            "osfamily":
                "device_family",

            "devicefamily":
                "device_family",

            "devicename":
                "device_name",

            "devicetype":
                "device_type",

            "expandeddevicetype":
                "expanded_device_type",

            "hostname":
                "hostname",

            "macvendor":
                "mac_vendor",

            "ipv4address":
                "ip_address",

            "ipaddress":
                "ip_address"
        }

        fingerprint_key = (
            fingerprint_map.get(
                attribute_name_normalised
            )
        )

        if fingerprint_key:

            return fingerprint.get(
                fingerprint_key
            )
    

    return None

def get_guest_profile_value(
    guest,
    attribute_name
):

    attribute_name_normalised = normalise_key(
        attribute_name
    )

    alias_map = {
        "roleid": [
            "role_id"
        ],
        "rolename": [
            "role_name"
        ],
        "username": [
            "username"
        ],
        "email": [
            "email"
        ],
        "enabled": [
            "enabled"
        ],
        "currentstate": [
            "current_state"
        ],
        "sponsorname": [
            "sponsor_name"
        ],
        "sponsoremail": [
            "sponsor_email"
        ],
        "visitorname": [
            "visitor_name"
        ],
        "visitorcompany": [
            "visitor_company"
        ],
        "source": [
            "source"
        ]
    }

    possible_keys = alias_map.get(
        attribute_name_normalised,
        []
    )

    lookup_keys = [
        attribute_name
    ] + possible_keys

    for lookup_key in lookup_keys:

        lookup_key_normalised = normalise_key(
            lookup_key
        )

        for key, value in guest.items():

            if normalise_key(key) == lookup_key_normalised:

                return value

    return None

def endpoint_value_matches(
    endpoint_value,
    operator,
    expected_value
):

    operator = str(
        operator or ""
    ).strip().upper()

    expected_value = str(
        expected_value or ""
    ).strip()

    if operator == "=":
        operator = "EQUALS"

    if operator == "!=":
        operator = "NOT_EQUALS"

    if endpoint_value is None:

        if operator == "EXISTS":

            return False

        if operator in [
            "NOT EXISTS",
            "NOT_EXISTS"
        ]:

            return True

        return False

    actual_values = value_as_list(
        endpoint_value
    )

    actual_text = normalise_value(
        ", ".join(
            actual_values
        )
    )

    expected_text = normalise_value(
        expected_value
    )

    if operator == "EXISTS":

        return bool(
            actual_values
        )

    if operator in [
        "NOT EXISTS",
        "NOT_EXISTS"
    ]:

        return not actual_values

    if operator == "EQUALS":

        return any(
            normalise_value(item) == expected_text
            for item in actual_values
        )

    if operator == "NOT_EQUALS":

        return all(
            normalise_value(item) != expected_text
            for item in actual_values
        )

    if operator == "CONTAINS":

        return expected_text in actual_text

    if operator == "BELONGS_TO":

        expected_values = value_as_list(
            expected_value
        )

        return any(
            normalise_value(actual_item)
            ==
            normalise_value(expected_item)
            for actual_item in actual_values
            for expected_item in expected_values
        )

    if operator == "IN_RANGE":

        return actual_text == expected_text

    if operator in [
        "GREATER_THAN",
        ">"
    ]:

        try:
            return float(actual_text) > float(expected_text)
        except ValueError:
            return False

    if operator in [
        "LESS_THAN",
        "<"
    ]:

        try:
            return float(actual_text) < float(expected_text)
        except ValueError:
            return False

    if operator in [
        "GREATER_THAN_OR_EQUALS",
        ">="
    ]:

        try:
            return float(actual_text) >= float(expected_text)
        except ValueError:
            return False

    if operator in [
        "LESS_THAN_OR_EQUALS",
        "<="
    ]:

        try:
            return float(actual_text) <= float(expected_text)
        except ValueError:
            return False

    return any(
        normalise_value(item) == expected_text
        for item in actual_values
    )

def endpoint_matches_condition(
    endpoint,
    source_type,
    attribute_name,
    operator,
    expected_value
):

    if not source_type:

        return False

    source_type = str(
        source_type
    ).strip()

    if not (
        source_type == "Endpoint"
        or source_type.startswith(
            "Authorization:[Endpoints Repository]"
        )
    ):

        return False

    endpoint_value = get_endpoint_profile_value(
        endpoint,
        attribute_name
    )

    return endpoint_value_matches(
        endpoint_value,
        operator,
        expected_value
    )

def guest_matches_condition(
    guest,
    source_type,
    attribute_name,
    operator,
    expected_value
):

    if source_type != "GuestUser":

        return False

    guest_value = get_guest_profile_value(
        guest,
        attribute_name
    )

    return endpoint_value_matches(
        guest_value,
        operator,
        expected_value
    )

def get_matching_endpoint_count(
    source_type,
    attribute_name,
    operator,
    expected_value
):

    if not source_type:

        return None

    source_type = str(
        source_type
    ).strip()

    if (
        source_type == "Endpoint"
        or source_type.startswith(
            "Authorization:[Endpoints Repository]"
        )
    ):

        endpoints = get_all_endpoints()

        count = 0

        for endpoint in endpoints:

            if endpoint_matches_condition(
                endpoint,
                source_type,
                attribute_name,
                operator,
                expected_value
            ):

                count += 1

        return count

    if source_type == "GuestUser":

        guests = get_all_guests()

        count = 0

        for guest in guests:

            if guest_matches_condition(
                guest,
                source_type,
                attribute_name,
                operator,
                expected_value
            ):

                count += 1

        return count

    return None

def get_matching_rule_count(
    conditions,
    match_type
):

    has_endpoint_conditions = False
    has_guest_conditions = False
    has_unsupported_conditions = False

    for condition in conditions:

        source_type = str(
            condition.get(
                "source_type",
                ""
            )
        ).strip()

        if (
            source_type == "Endpoint"
            or source_type.startswith(
                "Authorization:[Endpoints Repository]"
            )
        ):

            has_endpoint_conditions = True

        elif source_type == "GuestUser":

            has_guest_conditions = True

        else:

            has_unsupported_conditions = True

    if has_unsupported_conditions:

        return None

    if (
        has_endpoint_conditions
        and has_guest_conditions
    ):

        return None

    match_type = str(
        match_type or "AND"
    ).upper()

    count = 0

    if has_endpoint_conditions:

        endpoints = get_all_endpoints()

        for endpoint in endpoints:

            results = []

            for condition in conditions:

                results.append(
                    endpoint_matches_condition(
                        endpoint,
                        condition.get(
                            "source_type"
                        ),
                        condition.get(
                            "attribute_name"
                        ),
                        condition.get(
                            "operator"
                        ),
                        condition.get(
                            "condition_value"
                        )
                    )
                )

            if (
                match_type == "AND"
                and all(results)
            ):

                count += 1

            elif (
                match_type == "OR"
                and any(results)
            ):

                count += 1

        return count

    if has_guest_conditions:

        guests = get_all_guests()

        for guest in guests:

            results = []

            for condition in conditions:

                results.append(
                    guest_matches_condition(
                        guest,
                        condition.get(
                            "source_type"
                        ),
                        condition.get(
                            "attribute_name"
                        ),
                        condition.get(
                            "operator"
                        ),
                        condition.get(
                            "condition_value"
                        )
                    )
                )

            if (
                match_type == "AND"
                and all(results)
            ):

                count += 1

            elif (
                match_type == "OR"
                and any(results)
            ):

                count += 1

        return count

    return None


def get_rule_match_label(
    conditions
):

    has_endpoint_conditions = False
    has_guest_conditions = False
    has_unsupported_conditions = False

    for condition in conditions:

        source_type = str(
            condition.get(
                "source_type",
                ""
            )
        ).strip()

        if (
            source_type == "Endpoint"
            or source_type.startswith(
                "Authorization:[Endpoints Repository]"
            )
        ):

            has_endpoint_conditions = True

        elif source_type == "GuestUser":

            has_guest_conditions = True

        else:

            has_unsupported_conditions = True

    if has_unsupported_conditions:

        return None

    if (
        has_endpoint_conditions
        and has_guest_conditions
    ):

        return None

    if has_guest_conditions:

        return "Matching Guest Users"

    if has_endpoint_conditions:

        return "Matching Endpoints"

    return None

def get_matching_repository_objects(
    source_type,
    attribute_name,
    operator,
    expected_value
):

    source_type = str(
        source_type or ""
    ).strip()

    results = {
        "source_type": source_type,
        "attribute_name": attribute_name,
        "operator": operator,
        "expected_value": expected_value,
        "repository_type": None,
        "match_label": None,
        "items": [],
        "supported": False
    }

    if (
        source_type == "Endpoint"
        or source_type.startswith(
            "Authorization:[Endpoints Repository]"
        )
    ):

        results["repository_type"] = "endpoint"
        results["match_label"] = "Matching Endpoints"
        results["supported"] = True

        endpoints = get_all_endpoints()

        for endpoint in endpoints:

            if not endpoint_matches_condition(
                endpoint,
                source_type,
                attribute_name,
                operator,
                expected_value
            ):

                continue

            mac_address = endpoint.get(
                "mac_address",
                ""
            )

            results["items"].append(
                {

                    "id": endpoint.get(
                        "id"
                    ),

                    "mac_address": format_mac_with_hyphens(
                        mac_address
                    ),

                    "status": endpoint.get(
                        "status",
                        ""
                    ),


                    "description": endpoint.get(
                        "description",
                        ""
                    ),
                    "hostname": get_endpoint_profile_value(
                        endpoint,
                        "Hostname"
                    ),
                    "device_name": get_endpoint_profile_value(
                        endpoint,
                        "Device Name"
                    ),
                    "os_family": get_endpoint_profile_value(
                        endpoint,
                        "OS Family"
                    ),
                    "device_category": get_endpoint_profile_value(
                        endpoint,
                        "Device Category"
                    ),
                    "device_insight_tags": ", ".join(
                        endpoint.get(
                            "device_insight_tags",
                            []
                        )
                    )
                }
            )

        return results

    if source_type == "GuestUser":

        results["repository_type"] = "guest"
        results["match_label"] = "Matching Guest Users"
        results["supported"] = True

        guests = get_all_guests()

        for guest in guests:

            if not guest_matches_condition(
                guest,
                source_type,
                attribute_name,
                operator,
                expected_value
            ):

                continue

            results["items"].append(
                {
                    "username": guest.get(
                        "username",
                        ""
                    ),
                    "role_id": guest.get(
                        "role_id",
                        ""
                    ),
                    "role_name": guest.get(
                        "role_name",
                        ""
                    ),
                    "email": guest.get(
                        "email",
                        ""
                    ),
                    "enabled": guest.get(
                        "enabled",
                        ""
                    ),
                    "current_state": guest.get(
                        "current_state",
                        ""
                    ),
                    "sponsor_name": guest.get(
                        "sponsor_name",
                        ""
                    ),
                    "sponsor_email": guest.get(
                        "sponsor_email",
                        ""
                    ),
                    "visitor_name": guest.get(
                        "visitor_name",
                        ""
                    ),
                    "visitor_company": guest.get(
                        "visitor_company",
                        ""
                    ),
                    "source": guest.get(
                        "source",
                        ""
                    )
                }
            )

        return results

    return results