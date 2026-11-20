import threading
import time

import cp_env
from pyclearpass import ClearPassAPILogin

# Reuse one API login (and its token) per environment. Kept short so a
# token is never used close to ClearPass's expiry; pyclearpass does not
# renew an expired token by itself.
_LOGIN_TTL_SECONDS = 600
_lock = threading.Lock()
_logins = {}


def get_login():
    server = cp_env.getenv("CLEARPASS_API_URL", "").strip()
    client_id = cp_env.getenv("CLEARPASS_CLIENT_ID", "").strip()
    client_secret = cp_env.getenv("CLEARPASS_CLIENT_SECRET", "")
    verify_ssl = (
        cp_env.getenv("CLEARPASS_VERIFY_SSL", "false").strip().lower() == "true"
    )

    settings = (server, client_id, client_secret, verify_ssl)
    env_id = cp_env.current_env_id()

    with _lock:
        cached = _logins.get(env_id)

        if (
            cached
            and cached[0] == settings
            and time.monotonic() - cached[2] < _LOGIN_TTL_SECONDS
        ):
            return cached[1]

        login = ClearPassAPILogin(
            server=server,
            granttype="client_credentials",
            clientid=client_id,
            clientsecret=client_secret,
            verify_ssl=verify_ssl,
        )
        _logins[env_id] = (settings, login, time.monotonic())

        return login