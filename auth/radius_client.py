import os
import socket
import struct
import hashlib
import secrets
import logging


logger = logging.getLogger(__name__)


RADIUS_ACCESS_REQUEST = 1
RADIUS_ACCESS_ACCEPT = 2
RADIUS_ACCESS_REJECT = 3
RADIUS_ACCESS_CHALLENGE = 11

ATTR_USER_NAME = 1
ATTR_USER_PASSWORD = 2
ATTR_NAS_IDENTIFIER = 32
ATTR_FILTER_ID = 11
ATTR_REPLY_MESSAGE = 18
ATTR_CLASS = 25
ATTR_VENDOR_SPECIFIC = 26

ARUBA_VENDOR_ID = 14823
ARUBA_USER_ROLE_ATTR = 1


class RadiusAuthenticationError(Exception):
    """Raised when RADIUS authentication fails or cannot be completed."""


def _get_env_int(name, default):
    value = os.getenv(name, str(default))

    try:
        return int(value)

    except ValueError:
        logger.warning(
            "Invalid integer for %s=%r. Falling back to %s.",
            name,
            value,
            default
        )

        return default


def _parse_csv_env(name, default=""):
    value = os.getenv(name, default)

    return [
        item.strip()
        for item in value.split(",")
        if item.strip()
    ]


def _normalise_radius_value(value):
    if value is None:
        return []

    if isinstance(value, list):
        return [
            str(item)
            for item in value
        ]

    return [
        str(value)
    ]


def _xor_bytes(left, right):
    return bytes(
        a ^ b
        for a, b in zip(left, right)
    )


def _encode_text_attribute(attribute_type, value):
    value_bytes = str(value).encode("utf-8")

    if len(value_bytes) > 253:
        raise RadiusAuthenticationError(
            f"RADIUS attribute {attribute_type} is too long."
        )

    return struct.pack(
        "!BB",
        attribute_type,
        len(value_bytes) + 2
    ) + value_bytes


def _encode_user_password(password, secret, request_authenticator):
    """
    Encode User-Password for RADIUS PAP.

    This follows the RADIUS password hiding method used for PAP
    Access-Request packets.
    """

    password_bytes = password.encode("utf-8")

    if len(password_bytes) > 128:
        raise RadiusAuthenticationError(
            "RADIUS password is too long. Maximum supported length is 128 bytes."
        )

    padded_length = ((len(password_bytes) + 15) // 16) * 16

    if padded_length == 0:
        padded_length = 16

    padded_password = password_bytes.ljust(
        padded_length,
        b"\x00"
    )

    encrypted = b""
    previous = request_authenticator

    for offset in range(
        0,
        len(padded_password),
        16
    ):
        block = padded_password[offset:offset + 16]

        digest = hashlib.md5(
            secret + previous
        ).digest()

        encrypted_block = _xor_bytes(
            block,
            digest
        )

        encrypted += encrypted_block
        previous = encrypted_block

    return struct.pack(
        "!BB",
        ATTR_USER_PASSWORD,
        len(encrypted) + 2
    ) + encrypted


def _build_access_request(
    identifier,
    username,
    password,
    secret,
    nas_identifier
):
    request_authenticator = secrets.token_bytes(16)

    attributes = b""

    attributes += _encode_text_attribute(
        ATTR_USER_NAME,
        username
    )

    attributes += _encode_user_password(
        password,
        secret,
        request_authenticator
    )

    if nas_identifier:
        attributes += _encode_text_attribute(
            ATTR_NAS_IDENTIFIER,
            nas_identifier
        )

    packet_length = 20 + len(attributes)

    header = struct.pack(
        "!BBH",
        RADIUS_ACCESS_REQUEST,
        identifier,
        packet_length
    )

    packet = (
        header
        + request_authenticator
        + attributes
    )

    return packet, request_authenticator


def _verify_response_authenticator(
    response_packet,
    request_authenticator,
    secret
):
    if len(response_packet) < 20:
        return False

    response_code = response_packet[0]
    response_identifier = response_packet[1]
    response_length = struct.unpack(
        "!H",
        response_packet[2:4]
    )[0]

    received_authenticator = response_packet[4:20]
    response_attributes = response_packet[20:response_length]

    calculated_authenticator = hashlib.md5(
        struct.pack(
            "!BBH",
            response_code,
            response_identifier,
            response_length
        )
        + request_authenticator
        + response_attributes
        + secret
    ).digest()

    return received_authenticator == calculated_authenticator


def _decode_text(value):
    try:
        return value.decode("utf-8", errors="replace")

    except Exception:
        return str(value)


def _add_attribute(attributes, name, value):
    if name not in attributes:
        attributes[name] = []

    attributes[name].append(value)


def _parse_vendor_specific_attribute(value, attributes):
    if len(value) < 6:
        return

    vendor_id = struct.unpack(
        "!I",
        value[0:4]
    )[0]

    vendor_data = value[4:]

    offset = 0

    while offset + 2 <= len(vendor_data):
        vendor_type = vendor_data[offset]
        vendor_length = vendor_data[offset + 1]

        if vendor_length < 2:
            break

        vendor_value = vendor_data[
            offset + 2:offset + vendor_length
        ]

        if vendor_id == ARUBA_VENDOR_ID and vendor_type == ARUBA_USER_ROLE_ATTR:
            _add_attribute(
                attributes,
                "Aruba-User-Role",
                _decode_text(vendor_value)
            )

        else:
            _add_attribute(
                attributes,
                f"Vendor-{vendor_id}-Attr-{vendor_type}",
                _decode_text(vendor_value)
            )

        offset += vendor_length


def _parse_response_attributes(response_packet):
    attributes = {}

    if len(response_packet) < 20:
        return attributes

    response_length = struct.unpack(
        "!H",
        response_packet[2:4]
    )[0]

    offset = 20

    while offset + 2 <= response_length:
        attr_type = response_packet[offset]
        attr_length = response_packet[offset + 1]

        if attr_length < 2:
            break

        value = response_packet[
            offset + 2:offset + attr_length
        ]

        if attr_type == ATTR_FILTER_ID:
            _add_attribute(
                attributes,
                "Filter-Id",
                _decode_text(value)
            )

        elif attr_type == ATTR_REPLY_MESSAGE:
            _add_attribute(
                attributes,
                "Reply-Message",
                _decode_text(value)
            )

        elif attr_type == ATTR_CLASS:
            _add_attribute(
                attributes,
                "Class",
                _decode_text(value)
            )

        elif attr_type == ATTR_VENDOR_SPECIFIC:
            _parse_vendor_specific_attribute(
                value,
                attributes
            )

        else:
            _add_attribute(
                attributes,
                f"Attr-{attr_type}",
                _decode_text(value)
            )

        offset += attr_length

    return attributes


def _determine_role(reply_attributes):
    """
    Role mapping is intentionally conservative.

    If a configured RADIUS reply attribute contains an admin value, user is Admin.
    If it contains a readonly value, user is ReadOnly.
    Otherwise default to AUTH_DEFAULT_ROLE.
    """

    default_role = os.getenv(
        "AUTH_DEFAULT_ROLE",
        "ReadOnly"
    )

    admin_values = set(
        _parse_csv_env(
            "AUTH_ADMIN_RADIUS_VALUES",
            "Admin"
        )
    )

    readonly_values = set(
        _parse_csv_env(
            "AUTH_READONLY_RADIUS_VALUES",
            "ReadOnly"
        )
    )

    role_attributes = _parse_csv_env(
        "RADIUS_ROLE_ATTRIBUTES",
        "Aruba-User-Role,Filter-Id,Class"
    )

    for attr_name in role_attributes:
        values = _normalise_radius_value(
            reply_attributes.get(attr_name)
        )

        for value in values:
            if value in admin_values:
                return "Admin"

            if value in readonly_values:
                return "ReadOnly"

    return default_role


def authenticate_radius(username, password):
    """
    Authenticate a username/password pair against ClearPass RADIUS.

    Returns:
        dict:
            {
                "authenticated": bool,
                "username": str,
                "role": "Admin" | "ReadOnly" | None,
                "radius_attributes": dict
            }
    """

    radius_server = os.getenv("RADIUS_SERVER")
    radius_secret = os.getenv("RADIUS_SECRET")

    if not radius_server:
        raise RadiusAuthenticationError(
            "RADIUS_SERVER is not configured."
        )

    if not radius_secret:
        raise RadiusAuthenticationError(
            "RADIUS_SECRET is not configured."
        )

    radius_port = _get_env_int(
        "RADIUS_AUTH_PORT",
        1812
    )

    radius_timeout = _get_env_int(
        "RADIUS_TIMEOUT",
        5
    )

    radius_retries = _get_env_int(
        "RADIUS_RETRIES",
        2
    )

    nas_identifier = os.getenv(
        "RADIUS_NAS_IDENTIFIER",
        "clearpass-policy-visualiser"
    )

    secret = radius_secret.encode("utf-8")

    identifier = secrets.randbelow(256)

    request_packet, request_authenticator = _build_access_request(
        identifier=identifier,
        username=username,
        password=password,
        secret=secret,
        nas_identifier=nas_identifier
    )

    last_error = None

    for attempt in range(radius_retries + 1):

        try:
            with socket.socket(
                socket.AF_INET,
                socket.SOCK_DGRAM
            ) as sock:

                sock.settimeout(radius_timeout)

                logger.info(
                    "Sending RADIUS Access-Request for user %s to %s:%s, attempt %s.",
                    username,
                    radius_server,
                    radius_port,
                    attempt + 1
                )

                sock.sendto(
                    request_packet,
                    (
                        radius_server,
                        radius_port
                    )
                )

                response_packet, source = sock.recvfrom(4096)

        except socket.timeout as exc:
            last_error = exc

            logger.warning(
                "RADIUS timeout for user %s against %s:%s, attempt %s.",
                username,
                radius_server,
                radius_port,
                attempt + 1
            )

            continue

        except OSError as exc:
            logger.exception(
                "RADIUS socket error for user %s.",
                username
            )

            raise RadiusAuthenticationError(
                "RADIUS authentication failed due to a socket error."
            ) from exc

        if len(response_packet) < 20:
            raise RadiusAuthenticationError(
                "Invalid RADIUS response received."
            )

        response_code = response_packet[0]
        response_identifier = response_packet[1]

        if response_identifier != identifier:
            logger.warning(
                "Ignoring RADIUS response with unexpected identifier. Expected %s, received %s.",
                identifier,
                response_identifier
            )

            continue

        if not _verify_response_authenticator(
            response_packet,
            request_authenticator,
            secret
        ):
            raise RadiusAuthenticationError(
                "Invalid RADIUS response authenticator. Check the shared secret."
            )

        reply_attributes = _parse_response_attributes(
            response_packet
        )

        if response_code == RADIUS_ACCESS_ACCEPT:
            role = _determine_role(
                reply_attributes
            )

            logger.info(
                "RADIUS Access-Accept for user %s with role %s.",
                username,
                role
            )

            return {
                "authenticated": True,
                "username": username,
                "role": role,
                "radius_attributes": reply_attributes
            }

        if response_code == RADIUS_ACCESS_REJECT:
            logger.warning(
                "RADIUS Access-Reject for user %s.",
                username
            )

            return {
                "authenticated": False,
                "username": username,
                "role": None,
                "radius_attributes": reply_attributes
            }

        if response_code == RADIUS_ACCESS_CHALLENGE:
            logger.warning(
                "RADIUS Access-Challenge received for user %s. This client supports PAP only.",
                username
            )

            raise RadiusAuthenticationError(
                "RADIUS Access-Challenge received. Configure the ClearPass service for PAP authentication."
            )

        raise RadiusAuthenticationError(
            f"Unexpected RADIUS response code: {response_code}"
        )

    raise RadiusAuthenticationError(
        "RADIUS server did not respond."
    ) from last_error