"""
Environment registry for ClearPass Policy Visualiser.

The "default" environment is the existing .visualiser.env, loaded into
os.environ at startup exactly as in v1.6.1. Up to two further environments
live as small .env files in an "environments" folder beside it:

    <data dir>/.visualiser.env            -> default environment
    <data dir>/environments/test.env      -> environment id "test"
    <data dir>/environments/lab.env       -> environment id "lab"

Each extra file uses the same keys as .visualiser.env plus:

    ENV_NAME=Test
    ENV_PRODUCTION=false

The display name is free text chosen by the administrator. The id is
derived from it and is only used for the file name.
"""

import logging
import os
import re
import tempfile
import threading
from pathlib import Path
from urllib.parse import urlparse

from dotenv import dotenv_values

from cp_paths import get_visualiser_env_file

logger = logging.getLogger(__name__)

DEFAULT_ENV_ID = "default"
MAX_ENVIRONMENTS = 3
MAX_NAME_LENGTH = 40
_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")

_lock = threading.Lock()
_cache = {"stamp": None, "settings": {}}


class UnknownEnvironment(KeyError):
    """Raised when an environment id is not configured."""


def is_valid_id(env_id):
    return bool(_ID_PATTERN.match(str(env_id or "")))


def environments_dir() -> Path:
    return Path(get_visualiser_env_file()).parent / "environments"


def invalidate():
    """Force the extra environment files to be read again."""
    with _lock:
        _cache["stamp"] = None


def _env_files():
    folder = environments_dir()
    if not folder.is_dir():
        return []
    valid = []
    for path in sorted(folder.glob("*.env")):
        if is_valid_id(path.stem):
            valid.append(path)
        else:
            logger.warning(
                "Ignoring environment file with invalid name: %s", path.name
            )
    return valid[: MAX_ENVIRONMENTS - 1]


def _stamp(files):
    return tuple((str(p), p.stat().st_mtime_ns) for p in files)


def _load_extra():
    files = _env_files()
    stamp = _stamp(files)

    with _lock:
        if _cache["stamp"] == stamp:
            return _cache["settings"]

        settings = {}
        for path in files:
            if os.name == "posix":
                path.chmod(0o600)
            settings[path.stem] = {
                key: value
                for key, value in dotenv_values(path).items()
                if value is not None
            }

        _cache["stamp"] = stamp
        _cache["settings"] = settings
        return settings


def _truthy(value):
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def environment_settings(env_id):
    """Return the settings mapping for one environment, never mixed."""
    if env_id == DEFAULT_ENV_ID:
        return os.environ

    extra = _load_extra()
    if env_id not in extra:
        raise UnknownEnvironment(env_id)
    return extra[env_id]


def list_environments():
    """Return [{id, name, production}] with the default environment first."""
    result = [
        {
            "id": DEFAULT_ENV_ID,
            "name": os.environ.get("ENV_NAME") or "Default",
            "production": _truthy(os.environ.get("ENV_PRODUCTION")),
        }
    ]

    for env_id, values in _load_extra().items():
        result.append(
            {
                "id": env_id,
                "name": values.get("ENV_NAME") or env_id,
                "production": _truthy(values.get("ENV_PRODUCTION")),
            }
        )

    import cp_env

    cp_env.set_display_names(
        {environment["id"]: environment["name"] for environment in result}
    )

    return result


def get_environment(env_id):
    for environment in list_environments():
        if environment["id"] == env_id:
            return environment
    raise UnknownEnvironment(env_id)


def is_known(env_id):
    try:
        get_environment(env_id)
        return True
    except UnknownEnvironment:
        return False


# -------------------------------------------------------------------
# Names and ids
# -------------------------------------------------------------------


def validate_name(name, exclude_id=None):
    """Return an error message for a display name, or None when it is fine."""
    name = str(name or "").strip()

    if not name:
        return "Environment name is required."

    if len(name) > MAX_NAME_LENGTH:
        return f"Environment name must be {MAX_NAME_LENGTH} characters or fewer."

    if any(ord(char) < 32 or ord(char) == 127 for char in name):
        return "Environment name cannot contain control characters."

    for environment in list_environments():
        if environment["id"] == exclude_id:
            continue
        if environment["name"].strip().casefold() == name.casefold():
            return f"An environment named '{environment['name']}' already exists."

    return None


def make_environment_id(name):
    """Build a unique, file-safe id from a display name."""
    base = re.sub(r"[^a-z0-9]+", "-", str(name).lower()).strip("-")[:28]
    base = base or "env"

    taken = {environment["id"] for environment in list_environments()}
    taken.add(DEFAULT_ENV_ID)

    candidate = base
    counter = 2
    while candidate in taken:
        candidate = f"{base}-{counter}"
        counter += 1

    return candidate


# -------------------------------------------------------------------
# Writing
# -------------------------------------------------------------------


def _quote(value):
    text = str(value)
    if any(char in text for char in "\r\n\x00"):
        raise ValueError("Values cannot contain line breaks.")
    return "'" + text.replace("\\", "\\\\").replace("'", "\\'") + "'"


def _atomic_write(path, text):
    """Write a file in one step with owner-only permissions."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    descriptor, temp_name = tempfile.mkstemp(
        dir=path.parent, prefix=".tmp-", suffix=".part"
    )

    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(text)
        if os.name == "posix":
            os.chmod(temp_name, 0o600)
        os.replace(temp_name, path)
    except Exception:
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise


def write_environment(env_id, values):
    """Create or replace an extra environment file."""
    if env_id == DEFAULT_ENV_ID or not is_valid_id(env_id):
        raise ValueError("Invalid environment id.")

    lines = [
        "# ClearPass Policy Visualiser environment",
        "# Managed by the Environments page",
        "",
    ]
    lines += [f"{key}={_quote(value)}" for key, value in values.items()]

    _atomic_write(
        environments_dir() / f"{env_id}.env", "\n".join(lines) + "\n"
    )
    invalidate()


def delete_environment(env_id):
    if env_id == DEFAULT_ENV_ID or not is_valid_id(env_id):
        raise ValueError("Invalid environment id.")

    (environments_dir() / f"{env_id}.env").unlink(missing_ok=True)
    invalidate()


def set_default_metadata(name, production):
    """Store the default environment's display name and production flag."""
    path = Path(get_visualiser_env_file())

    lines = (
        path.read_text(encoding="utf-8").splitlines()
        if path.exists()
        else []
    )

    kept = [
        line
        for line in lines
        if not re.match(r"\s*(export\s+)?ENV_(NAME|PRODUCTION)\s*=", line)
    ]

    while kept and not kept[-1].strip():
        kept.pop()

    kept += [
        "",
        "# Environment display",
        f"ENV_NAME={_quote(name)}",
        f"ENV_PRODUCTION={'true' if production else 'false'}",
    ]

    _atomic_write(path, "\n".join(kept) + "\n")

    os.environ["ENV_NAME"] = name
    os.environ["ENV_PRODUCTION"] = "true" if production else "false"


# -------------------------------------------------------------------
# Host sanity checks
# -------------------------------------------------------------------


def _host(value):
    """Return the lower-case host from a URL or bare host name."""
    value = str(value or "").strip()

    if not value:
        return ""

    parsed = urlparse(value if "://" in value else f"//{value}")

    return (parsed.hostname or "").lower()


def host_warnings(env_id, settings):
    """
    Return warnings when an environment's RADIUS or PostgreSQL host looks
    wrong. The common mistake is copying the default environment's settings
    and forgetting to change a host, so the environment quietly reads
    another ClearPass. Nothing is blocked; the caller shows the warnings.
    """
    if env_id == DEFAULT_ENV_ID:
        return []

    api_host = _host(settings.get("CLEARPASS_API_URL"))
    default_api_host = _host(os.environ.get("CLEARPASS_API_URL"))

    if not api_host:
        return [f"Environment '{env_id}': CLEARPASS_API_URL is not set."]

    warnings = []

    for key, label in (
        ("RADIUS_SERVER", "RADIUS server"),
        ("CP_SQL_HOST", "PostgreSQL host"),
    ):
        host = _host(settings.get(key))

        if not host:
            warnings.append(f"Environment '{env_id}': {key} is not set.")
            continue

        default_host = _host(os.environ.get(key))

        if (
            default_api_host
            and api_host != default_api_host
            and host == default_host
        ):
            warnings.append(
                f"Environment '{env_id}': the {label} ({host}) is the same "
                f"as the default environment's, but CLEARPASS_API_URL "
                f"points to {api_host}. This environment may be reading "
                f"another ClearPass."
            )
        elif host != api_host:
            warnings.append(
                f"Environment '{env_id}': the {label} ({host}) differs "
                f"from the CLEARPASS_API_URL host ({api_host}). "
                f"Check this is intended."
            )

    return warnings


def check_environment_hosts(env_id):
    if env_id == DEFAULT_ENV_ID:
        return []

    return host_warnings(env_id, environment_settings(env_id))
