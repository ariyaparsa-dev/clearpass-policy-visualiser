"""
Per-environment context for ClearPass Policy Visualiser.

Every request and thread runs in one active environment. The "default"
environment is the existing .visualiser.env loaded into os.environ, so
behaviour is identical to v1.6.1 when no other environment is configured.
"""

import contextlib
import contextvars
import os
import threading
from collections.abc import MutableMapping

DEFAULT_ENV_ID = "default"

_SCOPED_PREFIXES = ("CLEARPASS_", "CP_SQL_")
_SCOPED_NAMES = {
    "RADIUS_SERVER",
    "RADIUS_SECRET",
    "RADIUS_AUTH_PORT",
    "RADIUS_NAS_IDENTIFIER",
}
_APP_WIDE_NAMES = {"CP_SQL_QUERY_FILE"}

_active = contextvars.ContextVar("cpv_env_id", default=DEFAULT_ENV_ID)
_states = {}
_states_lock = threading.Lock()


class EnvState:
    """All cached data for a single ClearPass environment."""

    def __init__(self, env_id):
        self.env_id = env_id
        self.lock = threading.RLock()

        self.services_cache = []
        self.profile_reference_cache = {}
        self.role_mapping_reference_cache = {}
        self.policy_reference_cache = {}
        self.role_cache = {}
        self.role_reference_cache = {}
        self.impact_analysis_lookup_cache = []
        self.health_cache = None
        self.health_cache_time = 0
        self.last_refresh = None
        self.unused_objects_cache = None
        self.initialised = False

        # Lazy-load tracking: not_loaded, loading, ready or error.
        self.load_status = "not_loaded"
        self.load_error = None

        self.endpoint_cache = None
        self.attribute_catalog_cache = None
        self.fingerprint_cache = {}
        self.guest_cache = None

        # Separate storage for ScopedDict instances.
        self.dicts = {}


def current_env_id():
    return _active.get()


def current_state():
    env_id = _active.get()
    with _states_lock:
        state = _states.get(env_id)
        if state is None:
            state = EnvState(env_id)
            _states[env_id] = state
        return state


def activate(env_id):
    return _active.set(env_id)


def deactivate(token):
    _active.reset(token)


@contextlib.contextmanager
def use(env_id):
    token = _active.set(env_id)
    try:
        yield
    finally:
        _active.reset(token)


def getenv(name, default=None):
    """
    Drop-in replacement for os.getenv() for per-environment settings.

    The default environment reads os.environ exactly as before. Other
    environments read only their own settings and never fall back to
    os.environ for scoped keys, so credentials cannot leak between
    environments.
    """
    env_id = _active.get()

    scoped = (
        name not in _APP_WIDE_NAMES
        and (name.startswith(_SCOPED_PREFIXES) or name in _SCOPED_NAMES)
    )

    if env_id == DEFAULT_ENV_ID or not scoped:
        return os.getenv(name, default)

    from cp_environments import environment_settings

    return environment_settings(env_id).get(name, default)


class ScopedDict(MutableMapping):
    """A dict whose contents belong to the active environment."""

    def __init__(self, name):
        self._name = name

    def _store(self):
        return current_state().dicts.setdefault(self._name, {})

    def __getitem__(self, key):
        return self._store()[key]

    def __setitem__(self, key, value):
        self._store()[key] = value

    def __delitem__(self, key):
        del self._store()[key]

    def __iter__(self):
        return iter(self._store())

    def __len__(self):
        return len(self._store())

    def __repr__(self):
        return f"ScopedDict({self._name!r}, {self._store()!r})"