import os

from pyclearpass import ClearPassAPILogin


def get_login():

    server = os.getenv(
        "CLEARPASS_API_URL",
        ""
    ).strip()

    client_id = os.getenv(
        "CLEARPASS_CLIENT_ID",
        ""
    ).strip()

    client_secret = os.getenv(
        "CLEARPASS_CLIENT_SECRET",
        ""
    )

    verify_ssl = (
        os.getenv(
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