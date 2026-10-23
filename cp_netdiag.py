"""
Plain-language network diagnosis for failed ClearPass connections.

Used when a connectivity check fails, so the message can say what kind of
failure it was and not only that it failed.

Everything here runs from the Visualiser container, so it describes the
network path from the container to the ClearPass server. It sends only a few
small probes to the host that was entered in the form: a DNS lookup, one ICMP
echo request, and TCP connections to a couple of well-known ports. Nothing is
changed on either side.

Real ICMP "ping" needs a raw socket or the ping binary, neither of which is
normally available to a non-root container user. This module uses Linux's
unprivileged ICMP datagram socket instead. It works only when the kernel
allows it for the container's group, so the result can be "unavailable".
"""

import errno
import logging
import os
import socket
import struct
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

PROBE_TIMEOUT = 2.0

# Other well-known ports, probed only to tell "host is up but this port is
# blocked" from "nothing answers at all".
PROBE_PORTS = (80, 22)

PORT_NAMES = {
    22: "SSH",
    80: "HTTP",
    443: "HTTPS",
    5432: "PostgreSQL",
    5433: "PostgreSQL",
}

# Failures that describe the whole host, not one port. When one of these is
# found, later checks against the same host in the same validation run reuse
# it instead of repeating the probes and the same paragraph.
_HOST_WIDE_KINDS = {"dns", "no_answer", "no_route"}
_RUN_TTL_SECONDS = 30

_run_lock = threading.Lock()
_run_results = {}


def reset_run():
    """Forget earlier results. Call at the start of each validation run."""
    with _run_lock:
        _run_results.clear()


def _remember(host, port, kind):
    if kind in _HOST_WIDE_KINDS or kind == "port_blocked":
        with _run_lock:
            _run_results[str(host).lower()] = (time.monotonic(), port, kind)


def _recall(host, port):
    """Return the kind found earlier for this host on a different port."""
    with _run_lock:
        entry = _run_results.get(str(host).lower())

    if not entry:
        return None

    stamp, earlier_port, kind = entry

    if time.monotonic() - stamp > _RUN_TTL_SECONDS or earlier_port == port:
        return None

    return kind


def _port_label(port):
    name = PORT_NAMES.get(port)

    return f"{port} ({name})" if name else str(port)


# -------------------------------------------------------------------
# Probes
# -------------------------------------------------------------------

def _checksum(data):
    if len(data) % 2:
        data += b"\x00"

    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16

    return ~total & 0xFFFF


def icmp_ping(ip, timeout=PROBE_TIMEOUT):
    """
    Send one ICMP echo request.

    Returns "reply", "no_reply", or "unavailable" when the container is not
    allowed to send ICMP at all.
    """
    try:
        sock = socket.socket(
            socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP
        )
    except (PermissionError, OSError):
        return "unavailable"

    try:
        sock.settimeout(timeout)

        ident = os.getpid() & 0xFFFF
        header = struct.pack("!BBHHH", 8, 0, 0, ident, 1)
        payload = b"cpv-netdiag"
        csum = _checksum(header + payload)
        packet = struct.pack("!BBHHH", 8, 0, csum, ident, 1) + payload

        sock.sendto(packet, (ip, 0))

        deadline = time.monotonic() + timeout

        while time.monotonic() < deadline:
            try:
                data, _ = sock.recvfrom(1024)
            except socket.timeout:
                return "no_reply"

            if data and data[0] == 0:
                return "reply"

        return "no_reply"

    except PermissionError:
        return "unavailable"
    except OSError:
        return "no_reply"
    finally:
        sock.close()


def tcp_probe(ip, port, timeout=PROBE_TIMEOUT):
    """
    Try one TCP connection.

    Returns one of: open, refused, timeout, no_route, reset, error.
    """
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return "open"
    except ConnectionRefusedError:
        return "refused"
    except (socket.timeout, TimeoutError):
        return "timeout"
    except ConnectionResetError:
        return "reset"
    except OSError as exc:
        if exc.errno in (errno.EHOSTUNREACH, errno.ENETUNREACH):
            return "no_route"
        if exc.errno == errno.ECONNREFUSED:
            return "refused"
        if exc.errno == errno.ETIMEDOUT:
            return "timeout"
        return "error"


# -------------------------------------------------------------------
# Proxy awareness
# -------------------------------------------------------------------

def proxy_for(host, scheme="https"):
    """
    Return "host:port" of the proxy that HTTP(S) clients would use for this
    host, or None. Credentials in the proxy URL are never returned.

    The REST API calls use the requests library, which honours the proxy
    environment variables. The TCP check does not, so the two can disagree.
    """
    try:
        proxies = urllib.request.getproxies()
        proxy_url = proxies.get(scheme) or proxies.get("all")

        if not proxy_url:
            return None

        if urllib.request.proxy_bypass(host):
            return None

        parsed = urlparse(
            proxy_url if "://" in proxy_url else "http://" + proxy_url
        )

        if not parsed.hostname:
            return None

        return f"{parsed.hostname}:{parsed.port}" if parsed.port else parsed.hostname

    except Exception:
        return None


# -------------------------------------------------------------------
# Diagnosis of a failed TCP connection
# -------------------------------------------------------------------

def diagnose(host, port, extra_ports=()):
    """
    Work out why a TCP connection to host:port failed.

    Returns a dict:
        kind     machine-readable category
        message  one or two plain sentences for the user
        details  the raw probe results, for the log
    """
    details = {"host": host, "port": port}

    # 1. Name resolution
    try:
        infos = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
        ip = infos[0][4][0]
    except socket.gaierror:
        return {
            "kind": "dns",
            "message": (
                f"The name '{host}' could not be resolved. Check the "
                "spelling and the DNS settings, or use the IP address."
            ),
            "details": details,
        }
    except Exception:
        ip = host

    details["ip"] = ip

    # 2. Probe the port, ping, and a few other ports at the same time
    other_ports = [
        p for p in dict.fromkeys(tuple(PROBE_PORTS) + tuple(extra_ports))
        if p != port
    ]

    with ThreadPoolExecutor(max_workers=2 + len(other_ports)) as pool:
        main_future = pool.submit(tcp_probe, ip, port)
        ping_future = pool.submit(icmp_ping, ip)
        port_futures = {p: pool.submit(tcp_probe, ip, p) for p in other_ports}

        main_result = main_future.result()
        ping_result = ping_future.result()
        port_results = {p: f.result() for p, f in port_futures.items()}

    details["port_result"] = main_result
    details["ping"] = ping_result
    details["other_ports"] = port_results

    open_other = sorted(p for p, r in port_results.items() if r == "open")
    refused_other = sorted(p for p, r in port_results.items() if r == "refused")
    host_is_up = (
        ping_result == "reply" or bool(open_other) or bool(refused_other)
    )

    # 3. Interpret
    if main_result == "open":
        kind = "intermittent"
        message = (
            "The first attempt failed but a retry connected. The network "
            "path may be unstable, or the server was busy."
        )

    elif main_result == "refused":
        kind = "refused"
        message = (
            f"The host {ip} is up but refused the connection on port {port}. "
            "Nothing is listening there, or a firewall is rejecting it. "
            "Check the port."
        )

    elif main_result == "no_route":
        kind = "no_route"
        message = (
            f"There is no network route to {ip}. Check the address, and any "
            "VPN or routing to it."
        )

    elif main_result == "reset":
        kind = "reset"
        message = (
            "The connection was reset. A firewall, proxy or load balancer on "
            "the path may be closing it."
        )

    elif host_is_up:
        kind = "port_blocked"
        evidence = []

        if ping_result == "reply":
            evidence.append("it replies to ping")

        if open_other:
            evidence.append(
                "port "
                + ", ".join(_port_label(p) for p in open_other)
                + " is open"
            )

        if refused_other and not evidence:
            evidence.append("it answers on other ports")

        message = (
            f"The host {ip} is up ({'; '.join(evidence)}) but port {port} "
            "does not answer. A firewall or access list is probably dropping "
            "it, or the service is not running. If this host is not the "
            "ClearPass server, check the address."
        )

    else:
        kind = "no_answer"
        message = f"Nothing answered from {ip}."

        if ping_result == "unavailable":
            message += (
                f" There was no response on port {port}, and ping could not "
                "be tested from here."
            )
        else:
            message += (
                f" There was no reply to ping and no response on port {port}."
            )

        message += (
            " The host may be down or the address may be wrong. "
            "(Some networks block ping.)"
        )

    proxy = proxy_for(host)

    if main_result != "open":
        if proxy:
            details["proxy"] = proxy
            message += (
                f" This container uses the web proxy {proxy} for HTTPS. The "
                "REST API calls go through it, but this check connects "
                "directly, so the two can differ."
            )
        elif kind == "port_blocked":
            message += (
                " If your network requires a web proxy or inspects this "
                "traffic, it may be blocking the connection."
            )

    return {"kind": kind, "message": message, "details": details}


def failure_message(host, port, extra_ports=(), prefix=None):
    """
    Build the full user-facing message for a failed connection, and log the
    raw probe results. Never raises.

    If an earlier check in the same validation run already failed on the same
    host, say so briefly instead of probing and repeating the explanation.
    """
    base = prefix or f"Unable to connect to {host}:{port}."

    try:
        earlier = _recall(host, port)

        if earlier:
            logger.warning(
                "Connection to %s:%s failed (same host as an earlier "
                "check in this run, %s).",
                host,
                port,
                earlier,
            )

            if earlier == "port_blocked":
                return (
                    f"{base} The host is up but port {_port_label(port)} "
                    "does not answer either. If this host is not the "
                    "ClearPass server, check the address."
                )

            return (
                f"{base} This is the same host as the failed check above, "
                "so the same problem applies."
            )

        result = diagnose(host, port, extra_ports=extra_ports)

    except Exception:
        logger.exception("Network diagnosis failed for %s:%s.", host, port)
        return f"{base} Check the server address and network connectivity."

    _remember(host, port, result["kind"])

    logger.warning(
        "Connection to %s:%s failed (%s): %s",
        host,
        port,
        result["kind"],
        result["details"],
    )

    return f"{base} {result['message']}"


# -------------------------------------------------------------------
# REST API failures after the TCP check has already passed
# -------------------------------------------------------------------

def _exception_text(exc):
    """The text of an exception and everything it wraps, lower-cased."""
    parts = []
    seen = set()
    current = exc

    while current is not None and id(current) not in seen:
        seen.add(id(current))
        parts.append(f"{type(current).__name__} {current}")

        for arg in getattr(current, "args", ()):
            if isinstance(arg, BaseException):
                parts.append(f"{type(arg).__name__} {arg}")
                reason = getattr(arg, "reason", None)
                if reason is not None:
                    parts.append(f"{type(reason).__name__} {reason}")

        current = current.__cause__ or current.__context__

    return " ".join(parts).lower()


def _api_url_advice(parsed, host, port):
    """
    One sentence about a URL that probably should be HTTPS on port 443,
    ending with a corrected URL to try. Empty when the URL looks fine.
    """
    uses_http = parsed.scheme == "http"
    plain_port = port == 80

    if not (uses_http or plain_port):
        return ""

    shown_host = f"[{host}]" if ":" in host else host
    suggested_port = "" if port in (80, 443) else f":{port}"
    path = parsed.path if parsed.path not in ("", "/") else "/api"
    suggestion = f"https://{shown_host}{suggested_port}{path}"

    if uses_http and plain_port:
        reason = (
            "The URL uses http:// on port 80, but the ClearPass REST API "
            "uses HTTPS, normally on port 443."
        )
    elif uses_http:
        reason = (
            "The URL starts with http://, but the ClearPass REST API "
            "uses HTTPS."
        )
    else:
        reason = (
            "Port 80 is the plain web port, but the ClearPass REST API "
            "is normally on port 443."
        )

    return f" {reason} Try: {suggestion}"


def explain_api_failure(exc, api_url, verify_ssl=False):
    """
    Turn an exception from the ClearPass REST API test into a message that
    says what went wrong, using the URL the user entered for hints.

    Pass exc=None when the call returned without a token. The result is then
    a message only if the URL itself looks wrong, otherwise None.

    The TCP check only proves that something accepts connections on the
    port. A web server on port 80, a proxy, or a service that does not speak
    HTTPS all pass it, then fail here.
    """
    try:
        parsed = urlparse(str(api_url or ""))
        host = parsed.hostname or "the server"
        port = parsed.port or (80 if parsed.scheme == "http" else 443)
    except Exception:
        parsed = urlparse("")
        host = "the server"
        port = 443

    target = f"{host}:{port}"
    text = _exception_text(exc) if exc is not None else ""

    advice = _api_url_advice(parsed, host, port)

    if "certificate verify failed" in text or "certificate_verify_failed" in text:
        return (
            f"The server at {target} answered, but its certificate could not "
            "be verified. Set Verify SSL Certificate to No, or install a "
            "certificate that is trusted by the Visualiser."
        )

    if any(
        marker in text
        for marker in (
            "wrong version number",
            "unknown protocol",
            "http request",
            "record layer failure",
            "packet length too long",
        )
    ):
        return (
            f"The server at {target} accepted the connection but does not "
            "speak HTTPS on that port."
            + (advice if advice else " The port is probably wrong, or the URL should use https://.")
        )

    if "timed out" in text or "timeout" in text:
        return (
            f"The connection to {target} was made, but ClearPass did not "
            "answer in time. The server may be busy, or a firewall or proxy "
            "may be holding the traffic." + advice
        )

    if "connection reset" in text or "connection aborted" in text or "remotedisconnected" in text:
        return (
            f"The connection to {target} was closed by the other side. A "
            "firewall, proxy or load balancer on the path may be dropping "
            "it." + advice
        )

    if "proxyerror" in text or ("proxy" in text and "tunnel" in text):
        return (
            f"The connection to {target} failed at the web proxy. Check the "
            "proxy settings of the Visualiser container."
        )

    if "refused" in text:
        return (
            f"{target} refused the connection. Nothing is listening on that "
            "port. Check the port in the API URL." + advice
        )

    if "jsondecodeerror" in text or "expecting value" in text:
        return (
            f"{target} answered, but not with ClearPass API data. Something "
            "else may be answering on that address, such as a web server or "
            "proxy. Check the URL, port and the /api path." + advice
        )

    if advice:
        return f"Unable to use the ClearPass REST API at {target}." + advice

    if exc is None:
        # No exception and no URL hint: nothing more specific to say.
        return None

    return (
        "Unable to authenticate to the ClearPass REST API. "
        "Check the API URL, Client ID, Client Secret and SSL setting."
    )

# -------------------------------------------------------------------
# RADIUS reachability probe
# -------------------------------------------------------------------

import hashlib
import hmac


def _radius_attr(attr_type, value):
    return struct.pack("!BB", attr_type, len(value) + 2) + value


def _pap_password_block(password, secret, authenticator):
    """RFC 2865 section 5.2: hide the User-Password with the shared secret."""
    data = password.encode("utf-8")
    data += b"\x00" * (-len(data) % 16 or (16 if not data else 0))
    result = b""
    last = authenticator

    for start in range(0, len(data), 16):
        key = hashlib.md5(secret + last).digest()
        block = bytes(a ^ b for a, b in zip(data[start:start + 16], key))
        result += block
        last = block

    return result


def _build_access_request(
    secret, nas_identifier, username, password, message_authenticator=False
):
    """
    Build a PAP Access-Request.

    Return (packet_bytes, request_authenticator, identifier).

    Message-Authenticator (RFC 3579) is optional and is left out by default.
    Against ClearPass, a request that carried one was silently dropped while
    the same request without it was answered, even though the shared secret
    was right, so it is only added when asked for.
    """
    identifier = os.urandom(1)[0]
    authenticator = os.urandom(16)

    attributes = (
        _radius_attr(1, username.encode("utf-8"))
        + _radius_attr(2, _pap_password_block(password, secret, authenticator))
        + _radius_attr(32, nas_identifier.encode("utf-8"))
    )

    if not message_authenticator:
        header = struct.pack("!BBH", 1, identifier, 20 + len(attributes))

        return header + authenticator + attributes, authenticator, identifier

    # Message-Authenticator (attribute 80) is computed over the whole packet
    # with the attribute's own value set to zeros (RFC 3579).
    attributes += _radius_attr(80, b"\x00" * 16)
    header = struct.pack("!BBH", 1, identifier, 20 + len(attributes))
    digest = hmac.new(
        secret, header + authenticator + attributes, hashlib.md5
    ).digest()
    attributes = attributes[:-16] + digest

    return header + authenticator + attributes, authenticator, identifier


def _valid_response(data, request_authenticator, identifier, secret):
    """Check the Response Authenticator, which proves the shared secret."""
    if len(data) < 20 or data[1] != identifier:
        return False

    length = struct.unpack("!H", data[2:4])[0]

    if length < 20 or length > len(data):
        return False

    expected = hashlib.md5(
        data[0:4] + request_authenticator + data[20:length] + secret
    ).digest()

    return hmac.compare_digest(expected, data[4:20])


def probe_radius(
    host,
    port,
    secret,
    nas_identifier,
    timeout=2.5,
    attempts=2,
    message_authenticator=False,
):
    """
    Send one PAP Access-Request for a throw-away user and see how the server
    answers.

    The shared secret is the one passed in, which is the secret the user
    typed for this environment. Nothing generic is used.

    RADIUS uses UDP, so there is no connection to test. Any answer from
    the server, even Access-Reject, proves three things: the server is
    reachable, it accepts requests from this host, and the shared secret
    matches (the Response Authenticator is verified). Silence is ambiguous:
    ClearPass drops requests silently when the source address is not a
    defined Network Device or the secret is wrong.

    The request is sent once and, if nothing comes back, sent again as an
    identical retransmission (same identifier and authenticator, as RFC 2865
    describes). A reply to either send is accepted at any point in the whole
    window, because a slow Reject would otherwise be thrown away.

    The request shows up in ClearPass Access Tracker as a rejected
    authentication for the user "cpv-connectivity-test". The password is
    random and never leaves this function.

    Returns {"state": ..., "message": ...} where state is one of:
    ok, bad_secret, no_reply, refused, dns, bad_input, error.
    """
    host = str(host or "").strip()
    nas_identifier = str(nas_identifier or "").strip()

    try:
        port = int(port)
        if not 1 <= port <= 65535:
            raise ValueError
    except (TypeError, ValueError):
        return {"state": "bad_input", "message": "The RADIUS port is not valid."}

    if not host or not secret or not nas_identifier:
        return {
            "state": "bad_input",
            "message": (
                "The RADIUS server, shared secret and NAS Identifier are all "
                "needed to test the RADIUS server."
            ),
        }

    try:
        ip = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_DGRAM)[0][4][0]
    except socket.gaierror:
        return {
            "state": "dns",
            "message": (
                f"The RADIUS server name '{host}' could not be resolved from "
                "the Visualiser. Signing in to this environment will fail "
                "until it resolves."
            ),
        }
    except Exception:
        return {"state": "error", "message": "The RADIUS server could not be tested."}

    secret_bytes = secret.encode("utf-8")
    target = f"{host}:{port}"

    packet, authenticator, identifier = _build_access_request(
        secret_bytes,
        nas_identifier,
        "cpv-connectivity-test",
        os.urandom(8).hex(),
        message_authenticator=message_authenticator,
    )

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except OSError:
        return {"state": "error", "message": "The RADIUS server could not be tested."}

    try:
        sock.connect((ip, port))

        for _ in range(max(1, attempts)):
            try:
                sock.send(packet)
                deadline = time.monotonic() + timeout

                while True:
                    remaining = deadline - time.monotonic()

                    if remaining <= 0:
                        raise socket.timeout

                    sock.settimeout(remaining)
                    data = sock.recv(4096)

                    if _valid_response(data, authenticator, identifier, secret_bytes):
                        return {
                            "state": "ok",
                            "message": (
                                f"RADIUS server {target} answered and accepted "
                                "the shared secret."
                            ),
                        }

                    if len(data) >= 20 and data[1] == identifier:
                        return {
                            "state": "bad_secret",
                            "message": (
                                f"RADIUS server {target} answered, but not with "
                                "this shared secret. Check the RADIUS Shared "
                                "Secret matches the one set for this Network "
                                "Device in ClearPass. Signing in to this "
                                "environment will fail."
                            ),
                        }

            except socket.timeout:
                continue
            except ConnectionRefusedError:
                return {
                    "state": "refused",
                    "message": (
                        f"{target} reported that nothing is listening on "
                        f"UDP port {port}. Check the RADIUS port. Signing in "
                        "to this environment will fail."
                    ),
                }

    except OSError:
        return {"state": "error", "message": "The RADIUS server could not be tested."}
    finally:
        sock.close()

    return {
        "state": "no_reply",
        "message": (
            f"No reply from RADIUS server {target}. ClearPass may not answer "
            "a request it cannot match to a service, so the test request may "
            "still have arrived. Look for a rejected 'cpv-connectivity-test' "
            "entry in Access Tracker. If it is there, even with 'Service "
            "Categorization failed', the server, Network Device and shared "
            "secret are fine. If it is not, check that this host is defined "
            "as a Network Device, that the shared secret matches, and that "
            f"UDP {port} is not blocked. The address ClearPass sees is "
            "usually the Docker host's, not the container's."
        ),
    }

