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

    A failure to load the initial environment, for example when its
    ClearPass cannot be reached, must not stop the web server. The
    environment is marked as failed, and the dashboard shows Unable to
    load with Try again.
    """
    if not is_setup_complete(log_missing=True):
        logger.warning(
            "Initial setup is incomplete. "
            "Starting the web server without "
            "initialising ClearPass caches."
        )
        return

    try:
        initialise_cache()
    except Exception:
        import cp_env

        logger.exception(
            "The initial environment could not be loaded. Starting the "
            "web server anyway; use Try again once ClearPass is reachable."
        )

        state = cp_env.current_state()
        state.initialised = False
        state.load_status = "error"
        state.load_error = "StartupFailed"


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