import os
from pathlib import Path


def get_data_dir():
    """
    Return the directory used for persistent Visualiser data.

    Native installations default to the current working
    directory. Container deployments can override the
    location using VISUALISER_DATA_DIR.
    """

    data_dir = Path(
        os.getenv(
            "VISUALISER_DATA_DIR",
            ".",
        )
    )

    data_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    return data_dir


def get_visualiser_env_file():
    """
    Return the path to the persistent Visualiser
    configuration file.
    """

    return (
        get_data_dir()
        / ".visualiser.env"
    )


def get_flask_secret_file():
    """
    Return the path to the persistent Flask
    session secret.
    """

    return (
        get_data_dir()
        / ".flask_secret"
    )