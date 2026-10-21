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
"""

import logging
import os
import re
import threading
from pathlib import Path

from dotenv import dotenv_values

from cp_paths import get_visualiser_env_file

logger = logging.getLogger(__name__)

DEFAULT_ENV_ID = "default"
MAX_ENVIRONMENTS = 3
_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")

_lock = threading.Lock()
_cache = {"stamp": None, "settings": {}}


class UnknownEnvironment(KeyError):
    """Raised when an environment id is not configured."""


def environments_dir() -> Path:
    return Path(get_visualiser_env_file()).parent / "environments"


def _env_files():
    folder = environments_dir()
    if not folder.is_dir():
        return []
    valid = []
    for path in sorted(folder.glob("*.env")):
        if _ID_PATTERN.match(path.stem):
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
