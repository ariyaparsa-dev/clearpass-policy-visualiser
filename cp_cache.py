"""
Per-environment cache proxy.

Existing code keeps using ``cp_cache.services_cache`` and so on. Reads
and writes are forwarded to the active environment's EnvState.
"""

import sys
import types

from cp_env import current_state


class _CacheModule(types.ModuleType):

    def __getattr__(self, name):
        if name.startswith("__"):
            raise AttributeError(name)

        state = current_state()

        if not hasattr(state, name):
            raise AttributeError(
                f"cp_cache has no attribute {name!r}"
            )

        return getattr(state, name)

    def __setattr__(self, name, value):
        if name.startswith("__"):
            super().__setattr__(name, value)
            return

        state = current_state()

        if not hasattr(state, name):
            raise AttributeError(
                f"cp_cache has no attribute {name!r}"
            )

        setattr(state, name, value)


sys.modules[__name__].__class__ = _CacheModule
