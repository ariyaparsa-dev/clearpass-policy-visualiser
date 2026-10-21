"""
Web glue for multiple ClearPass environments.

Call init_environment_support(app, initialise_cache) once, after the Flask
app, login manager and initialise_cache() exist. It adds:

- the active-environment request hooks
- the per-environment login lookup (Flask-Login user loader)
- lazy background loading of non-default environments
- the environment selector context for templates
"""

import functools
import logging
import threading

from flask import g, jsonify, redirect, render_template_string, request, session, url_for
from flask_login import current_user, login_required

import cp_env
import cp_environments
from auth import login_manager
from auth.models import RadiusUser

logger = logging.getLogger(__name__)

# Endpoints that must work before an environment has finished loading.
_EXEMPT_ENDPOINTS = {
    "static",
    "auth.login",
    "auth.logout",
    "auth.switch_environment",
    "environment_status",
    "environment_reload",
    "setup",
    "setup_provisioning_preview",
    "setup_complete",
    "start_visualiser",
}

_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Loading {{ name }} - ClearPass Policy Visualiser</title>
{% if status == "loading" %}<meta http-equiv="refresh" content="5">{% endif %}
<style>
body{background:#0B111B;color:#E2E8F0;font-family:Segoe UI,Arial,sans-serif;
display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0}
.box{background:#151D29;border:1px solid #2D3748;border-radius:12px;padding:32px;
max-width:520px;text-align:center}
h2{margin-top:0}.g{color:#01A982}.m{color:#9CA3AF;font-size:.9rem}
button,a.b{background:#01A982;border:0;color:#000;font-weight:600;border-radius:6px;
padding:8px 16px;text-decoration:none;cursor:pointer}
</style>
</head>
<body><div class="box">
{% if status == "error" %}
<h2>Unable to load {{ name }}</h2>
<p class="m">The environment could not be loaded. Check the application log,
then try again.</p>
<form method="post" action="{{ url_for('environment_reload') }}">
<button type="submit">Try again</button></form>
{% else %}
<h2>Loading <span class="g">{{ name }}</span></h2>
<p class="m">Reading Services, Roles, policies and endpoints from ClearPass.
Large environments can take several minutes. This page refreshes automatically.</p>
{% endif %}
<p class="m"><a href="{{ url_for('auth.logout') }}" style="color:#F87171">Log out</a></p>
</div></body></html>
"""


def _start_load(env_id, initialise_cache):
    """Start a background load once; returns True when this call started it."""
    with cp_env.use(env_id):
        state = cp_env.current_state()

    with state.lock:
        if state.load_status in ("loading", "ready") or state.initialised:
            return False
        state.load_status = "loading"
        state.load_error = None

    def worker():
        try:
            # New threads start on the default environment, so be explicit.
            with cp_env.use(env_id):
                initialise_cache()
            state.load_status = "ready"
            logger.info("Environment '%s' loaded.", env_id)
        except Exception as exc:
            logger.exception("Environment '%s' failed to load.", env_id)
            state.load_error = type(exc).__name__
            state.load_status = "error"

    threading.Thread(
        target=worker,
        name=f"load-{env_id}",
        daemon=True,
    ).start()

    logger.info("Loading environment '%s' in the background...", env_id)
    return True


def init_environment_support(app, initialise_cache):
    # ---------------------------------------------------------------
    # Per-environment login lookup
    # ---------------------------------------------------------------
    @login_manager.user_loader
    def load_user(user_id):
        entry = session.get("env_auth", {}).get(cp_env.current_env_id())

        if not entry:
            return None

        return RadiusUser(
            username=entry["username"],
            role=entry.get("role", "ReadOnly"),
        )

    # ---------------------------------------------------------------
    # Active environment for the duration of a request
    # ---------------------------------------------------------------
    @app.before_request
    def activate_environment():
        env_id = session.get("env_id") or cp_env.DEFAULT_ENV_ID

        if not cp_environments.is_known(env_id):
            env_id = cp_env.DEFAULT_ENV_ID
            session["env_id"] = env_id

        g._cpv_env_token = cp_env.activate(env_id)

    @app.teardown_request
    def deactivate_environment(exception=None):
        token = g.pop("_cpv_env_token", None)

        if token is None:
            return

        try:
            cp_env.deactivate(token)
        except ValueError:
            # Different context: never leave the request's environment behind.
            cp_env.activate(cp_env.DEFAULT_ENV_ID)

    # ---------------------------------------------------------------
    # Lazy loading of non-default environments
    # ---------------------------------------------------------------
    @app.before_request
    def ensure_environment_loaded():
        env_id = cp_env.current_env_id()

        # The default environment keeps its v1.6.x startup behaviour.
        if env_id == cp_env.DEFAULT_ENV_ID:
            return None

        if request.endpoint in _EXEMPT_ENDPOINTS or request.endpoint is None:
            return None

        if not current_user.is_authenticated:
            return None

        state = cp_env.current_state()

        if state.initialised and state.load_status != "loading":
            return None

        if state.load_status == "not_loaded":
            _start_load(env_id, initialise_cache)

        status = state.load_status

        if status == "ready":
            return None

        name = cp_environments.get_environment(env_id)["name"]

        if request.path.startswith("/api/"):
            return jsonify({"status": status}), 503

        return render_template_string(_PAGE, name=name, status=status), 503

    @app.route("/environment/status")
    @login_required
    def environment_status():
        state = cp_env.current_state()

        return jsonify(
            {
                "environment": cp_env.current_env_id(),
                "status": (
                    "ready"
                    if state.initialised and state.load_status != "loading"
                    else state.load_status
                ),
            }
        )

    @app.route("/environment/reload", methods=["POST"])
    @login_required
    def environment_reload():
        state = cp_env.current_state()

        with state.lock:
            if state.load_status == "error":
                state.load_status = "not_loaded"

        return redirect(url_for("home"))

    # ---------------------------------------------------------------
    # Mark loading while Refresh Services runs, without editing it
    # ---------------------------------------------------------------
    refresh = app.view_functions.get("refresh_cache")

    if refresh is not None:

        @functools.wraps(refresh)
        def tracked_refresh(*args, **kwargs):
            state = cp_env.current_state()
            state.load_status = "loading"

            try:
                response = refresh(*args, **kwargs)
            except Exception:
                state.load_status = "error"
                state.load_error = "RefreshFailed"
                raise

            state.load_status = "ready"
            return response

        app.view_functions["refresh_cache"] = tracked_refresh

    # ---------------------------------------------------------------
    # Template context for the navbar selector
    # ---------------------------------------------------------------
    @app.context_processor
    def inject_environment_context():
        env_id = cp_env.current_env_id()

        try:
            active = cp_environments.get_environment(env_id)
        except cp_environments.UnknownEnvironment:
            active = None

        signed_in = set(session.get("env_auth", {}))

        environments = [
            dict(environment, signed_in=environment["id"] in signed_in)
            for environment in cp_environments.list_environments()
        ]

        return {
            "environments": environments,
            "active_environment": active,
        }
