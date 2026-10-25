"""
Editing the default environment's connection settings.

The default environment is the one created by Initial Setup. Its settings
live in the application's .visualiser.env file and in os.environ, which is
where every module reads them from. Other environments are separate files,
so editing them needs none of this.

Changing the default's settings means three things must happen together:

1. the file is rewritten, keeping everything else in it,
2. os.environ is updated, so the running application uses the new values,
3. the cached data is dropped and loaded again (done by the caller).

The file is replaced in one step, a copy of the previous version is kept as
.visualiser.env.prev, and the new file is read back and compared with what
was meant to be written. If anything differs, the previous file is left as
it was and nothing is changed.
"""

import logging
import os
import re
import shutil
import tempfile
from pathlib import Path

from dotenv import dotenv_values

from cp_paths import get_visualiser_env_file

logger = logging.getLogger(__name__)

_ASSIGNMENT = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=")


class SettingsNotSaved(Exception):
    """The new settings could not be stored safely. Nothing was changed."""


def current_settings(keys):
    """The default environment's settings, as the application sees them."""
    return {key: os.environ.get(key, "") for key in keys}


def format_value(value):
    """
    A value quoted so that python-dotenv reads it back unchanged.

    Single quotes keep '#', spaces and '=' literal. Backslashes and single
    quotes inside the value are escaped.
    """
    escaped = value.replace("\\", "\\\\").replace("'", "\\'")

    return f"'{escaped}'"


def _rewrite(text, updates):
    """Return the file text with the given keys replaced or appended."""
    newline = "\r\n" if "\r\n" in text else "\n"
    done = set()
    lines = []

    for line in text.splitlines(keepends=True):
        match = _ASSIGNMENT.match(line)

        if match and match.group(1) in updates:
            key = match.group(1)
            lines.append(f"{key}={format_value(updates[key])}{newline}")
            done.add(key)
        else:
            lines.append(line)

    missing = [key for key in updates if key not in done]

    if missing:
        if lines and not lines[-1].endswith(("\n", "\r")):
            lines[-1] += newline

        for key in missing:
            lines.append(f"{key}={format_value(updates[key])}{newline}")

    return "".join(lines)


def _restrict(path):
    if os.name == "posix":
        os.chmod(path, 0o600)


def save_default_settings(updates, path=None):
    """
    Store the given settings in the default environment's file and in
    os.environ. Returns the path of the copy of the previous file.

    Raises SettingsNotSaved, with the existing file untouched, when a value
    cannot be stored safely. The usual cause is a value containing "${",
    which the file reader treats as a variable reference.
    """
    path = Path(path) if path else Path(get_visualiser_env_file())
    updates = {str(key): str(value) for key, value in updates.items()}

    if not updates:
        return None

    previous = path.with_name(path.name + ".prev")

    if path.exists():
        # newline="" keeps CRLF line endings instead of converting them.
        with open(path, "r", encoding="utf-8", newline="") as handle:
            existing = handle.read()
    else:
        existing = ""

    descriptor, temp_name = tempfile.mkstemp(
        dir=str(path.parent), prefix=path.name + ".", suffix=".tmp"
    )

    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
            handle.write(_rewrite(existing, updates))
            handle.flush()
            os.fsync(handle.fileno())

        _restrict(temp_name)

        # Read the new file the way the application will, before using it.
        stored = dotenv_values(temp_name)

        wrong = [key for key, value in updates.items() if stored.get(key) != value]

        if wrong:
            raise SettingsNotSaved(
                "A value cannot be stored safely in the configuration file. "
                "Values containing ${ are read as variable references."
            )

        # Only now keep the file as it was, byte for byte, so it can be put
        # back. A refused or failed save leaves the earlier copy alone.
        if path.exists():
            shutil.copyfile(path, previous)
            _restrict(previous)

        os.replace(temp_name, path)

    except BaseException:
        try:
            os.unlink(temp_name)
        except OSError:
            pass

        raise

    os.environ.update(updates)

    logger.info(
        "Default environment settings updated: %s.", ", ".join(sorted(updates))
    )

    return previous
