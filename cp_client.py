import os
import cp_env

from pyclearpass import ClearPassAPILogin


def get_login():

    server = cp_env.getenv(
        "CLEARPASS_API_URL",
        ""
    ).strip()

    client_id = cp_env.getenv(
        "CLEARPASS_CLIENT_ID",
        ""
    ).strip()

    client_secret = cp_env.getenv(
        "CLEARPASS_CLIENT_SECRET",
        ""
    )

    verify_ssl = (
        cp_env.getenv(
            "CLEARPASS_VERIFY_SSL",
            "false"
        )
        .strip()
        .lower()
        == "true"
    )

    return ClearPassAPILogin(
        server=server,
        granttype="client_credentials",
        clientid=client_id,
        clientsecret=client_secret,
        verify_ssl=verify_ssl
    )