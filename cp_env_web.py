"""
Web glue for multiple ClearPass environments.

Call init_environment_support(app, initialise_cache) once, after the Flask
app, login manager and initialise_cache() exist. It adds:

- the active-environment request hooks
- the per-environment login lookup (Flask-Login user loader)
- lazy background loading of non-default environments
- reloading of an environment after its settings were changed
- the Environments administration page
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

# Set by init_environment_support(), so an environment can be reloaded from
# code that does not have the application's initialise_cache() to hand.
_initialise_cache = None

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
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{% if status == "error" %}Unable to load{% else %}Loading{% endif %} {{ name }} - ClearPass Policy Visualiser</title>
<link rel="icon" type="image/x-icon" href="{{ url_for('static', filename='favicon.ico') }}">
{% if status != "error" %}<noscript><meta http-equiv="refresh" content="5;url={{ url_for('home') }}"></noscript>{% endif %}
<style>
:root{--hpe-green:#01A982}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;font-family:Arial,Helvetica,sans-serif;background:#0f172a;color:#e2e8f0}
.navbar{background:#111827;border-bottom:3px solid var(--hpe-green);padding:8px 16px}
.navbar-brand{display:inline-block;color:#fff;font-size:20px;line-height:1.5}
.brand-green{color:var(--hpe-green);font-weight:700}
.stage{display:flex;align-items:center;justify-content:center;min-height:calc(100vh - 60px);padding:24px}
.loading-panel{width:min(460px,100%);padding:32px;background:#1e293b;border:1px solid #475569;
border-radius:12px;box-shadow:0 24px 60px rgba(0,0,0,.4);text-align:center}
.loading-panel h2{margin:22px 0 10px;color:#fff;font-size:22px}
.loading-panel p{margin:0;color:#cbd5e1;font-size:14px;line-height:1.6}
.env-name{color:var(--hpe-green)}
.loading-detail{margin-top:12px;color:#64748b;font-size:13px}
.loading-bars{display:flex;align-items:center;justify-content:center;gap:7px;height:48px}
.loading-bars span{display:block;width:4px;height:18px;background:var(--hpe-green);border-radius:2px;
animation:loading-bar-pulse 1.1s ease-in-out infinite}
.loading-bars span:nth-child(1){animation-delay:0s}
.loading-bars span:nth-child(2){animation-delay:.1s}
.loading-bars span:nth-child(3){animation-delay:.2s}
.loading-bars span:nth-child(4){animation-delay:.3s}
.loading-bars span:nth-child(5){animation-delay:.4s}
@keyframes loading-bar-pulse{0%,100%{height:16px;opacity:.45}50%{height:44px;opacity:1}}
@keyframes loading-bar-fade{0%,100%{opacity:.35}50%{opacity:1}}
@media (prefers-reduced-motion:reduce){
.loading-bars span{height:28px;animation:loading-bar-fade 1.2s ease-in-out infinite}
.loading-bars span:nth-child(2){animation-delay:.12s}
.loading-bars span:nth-child(3){animation-delay:.24s}
.loading-bars span:nth-child(4){animation-delay:.36s}
.loading-bars span:nth-child(5){animation-delay:.48s}}
.error-icon{display:flex;align-items:center;justify-content:center;width:48px;height:48px;margin:0 auto;
border-radius:50%;background:#450a0a;border:1px solid #991b1b;color:#ef4444;font-size:26px;font-weight:700}
button{margin-top:22px;border:0;border-radius:6px;padding:12px 22px;background:#22c55e;color:#052e16;
font-size:14px;font-weight:700;cursor:pointer}
button:hover{background:#16a34a}
.logout{margin-top:18px;font-size:13px}
.logout a{color:#f87171;text-decoration:none}
</style>
</head>
<body>
<nav class="navbar"><span class="navbar-brand"><span class="brand-green">ClearPass</span> Policy Visualiser</span></nav>
<main class="stage">
<div class="loading-panel" role="status" aria-live="polite">
{% if status == "error" %}
<div class="error-icon" aria-hidden="true">!</div>
<h2>Unable to load <span class="env-name">{{ name }}</span></h2>
<p>The environment could not be loaded. Check the application log, then try again.</p>
<form method="post" action="{{ url_for('environment_reload') }}"><button type="submit">Try again</button></form>
{% else %}
<div class="loading-bars" aria-hidden="true"><span></span><span></span><span></span><span></span><span></span></div>
<h2>Loading <span class="env-name">{{ name }}</span></h2>
<p>Loading ClearPass services, policies, roles, profiles and endpoint data.</p>
<div class="loading-detail">Large environments can take several minutes. Please keep this page open.</div>
{% endif %}
<div class="logout"><a href="{{ url_for('auth.logout') }}">Log out</a></div>
</div>
</main>
{% if status != "error" %}
<script>
(function () {
    var statusUrl = {{ url_for('environment_status') | tojson }};
    var homeUrl = {{ url_for('home') | tojson }};
    function check() {
        fetch(statusUrl, {headers: {"Accept": "application/json"}, credentials: "same-origin"})
            .then(function (r) { return r.ok ? r.json() : null; })
            .then(function (d) {
                if (!d || d.status !== "loading") { window.location.href = homeUrl; return; }
                window.setTimeout(check, 3000);
            })
            .catch(function () { window.setTimeout(check, 5000); });
    }
    window.setTimeout(check, 3000);
})();
</script>
{% endif %}
</body>
</html>
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
                # The default environment is what the others are compared with.
                if env_id != cp_env.DEFAULT_ENV_ID:
                    for message in cp_environments.check_environment_hosts(env_id):
                        logger.warning(message)

                initialise_cache()

                state.load_status = "ready"
                logger.info(
                    "Environment '%s' loaded.", cp_env.display_name(env_id)
                )
        except Exception as exc:
            with cp_env.use(env_id):
                logger.exception(
                    "Environment '%s' failed to load.",
                    cp_env.display_name(env_id),
                )
            state.load_error = type(exc).__name__
            state.load_status = "error"

    threading.Thread(
        target=worker,
        name=f"load-{env_id}",
        daemon=True,
    ).start()

    logger.info(
        "Loading environment '%s' in the background...",
        cp_env.display_name(env_id),
    )

    return True


def reload_environment(env_id):
    """
    Drop an environment's cached data and load it again in the background.

    Used after the settings of an environment have been changed, because
    everything cached came from the old settings.
    """
    cp_env.drop_state(env_id)

    with cp_env.use(env_id):
        state = cp_env.current_state()

    # initialise_cache() returns at once when the state says it is already
    # initialised, so make sure it does not, whatever drop_state() did.
    state.initialised = False
    state.load_status = "not_loaded"
    state.load_error = None

    if _initialise_cache is None:
        return False

    return _start_load(env_id, _initialise_cache)


def init_environment_support(app, initialise_cache):
    global _initialise_cache
    _initialise_cache = initialise_cache

    # ---------------------------------------------------------------
    # Environments administration page
    # ---------------------------------------------------------------
    from env_admin import env_admin_bp

    app.register_blueprint(env_admin_bp)

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

    # Run first, so request logging and every other hook see the
    # environment. log_request is registered earlier, in app.py.
    hooks = app.before_request_funcs.setdefault(None, [])
    hooks.remove(activate_environment)
    hooks.insert(0, activate_environment)

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

        # The default environment loads at startup, as in v1.6.x. It shows
        # the loading page only while it is reloading after its settings
        # were changed, or when that reload failed.
        if env_id == cp_env.DEFAULT_ENV_ID:
            if cp_env.current_state().load_status not in ("loading", "error"):
                return None

        endpoint = request.endpoint

        if (
            endpoint is None
            or endpoint in _EXEMPT_ENDPOINTS
            or endpoint.startswith("env_admin.")
        ):
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
        env_id = cp_env.current_env_id()
        state = cp_env.current_state()

        if env_id == cp_env.DEFAULT_ENV_ID:
            # The default is not loaded on demand, so start the load here.
            if state.load_status == "error":
                reload_environment(env_id)
        else:
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

    # Load the display names now, so startup log lines are tagged too.
    cp_environments.list_environments()
