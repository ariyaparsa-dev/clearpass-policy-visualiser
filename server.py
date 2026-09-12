import logging
import os

from waitress import serve

from app import (
    app,
    initialise_cache,
)
from cp_setup import is_setup_complete

logger = logging.getLogger(__name__)

waitress_logger = logging.getLogger("waitress")
waitress_logger.setLevel(logging.WARNING)


def initialise_visualiser():
    """
    Initialise ClearPass Policy Visualiser data when
    configuration is complete.

    Initial Setup must remain available when configuration
    has not yet been completed.
    """

    if is_setup_complete(
        log_missing=True
    ):
        initialise_cache()
    else:
        logger.warning(
            "Initial setup is incomplete. "
            "Starting the web server without "
            "initialising ClearPass caches."
        )


def main():
    """
    Start the ClearPass Policy Visualiser using
    the production WSGI server.
    """

    initialise_visualiser()

    host = os.getenv(
        "VISUALISER_HOST",
        "0.0.0.0",
    )

    port = int(
        os.getenv(
            "VISUALISER_PORT",
            "5000",
        )
    )

    logger.info(
        "Starting ClearPass Policy Visualiser "
        "web server."
    )

    logger.info(
        "Open http://127.0.0.1:%s "
        "in your browser.",
        port,
    )

    serve(
        app,
        host=host,
        port=port,
    )


if __name__ == "__main__":
    main()