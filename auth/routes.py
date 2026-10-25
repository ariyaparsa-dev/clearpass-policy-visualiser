from flask import (
    Blueprint,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_login import current_user, login_required, login_user, logout_user

import cp_env
import cp_environments
from auth.models import RadiusUser
from auth.radius_client import RadiusAuthenticationError, authenticate_radius

auth_bp = Blueprint("auth", __name__)


def _is_safe_next_url(next_url):
    """
    Keep redirects local to avoid open redirect issues.

    This allows:
    - /repository-search
    - /endpoint/123
    - /

    It blocks:
    - https://evil.example
    - //evil.example
    """
    if not next_url:
        return False

    return next_url.startswith("/") and not next_url.startswith("//")


def _selected_environment(requested=None):
    """Return a known environment id, falling back to the session or default."""
    env_id = requested or session.get("env_id") or cp_env.DEFAULT_ENV_ID

    if not cp_environments.is_known(env_id):
        return cp_env.DEFAULT_ENV_ID

    return env_id


def _login_page(next_url, env_id, status=200):
    return (
        render_template(
            "login.html",
            next=next_url,
            environments=cp_environments.list_environments(),
            selected_environment=env_id,
        ),
        status,
    )


def _sign_in(env_id, username, role):
    """Record a login for one environment and make it the active one."""
    env_auth = dict(session.get("env_auth", {}))
    env_auth[env_id] = {"username": username, "role": role}

    session["env_auth"] = env_auth
    session["env_id"] = env_id

    login_user(RadiusUser(username=username, role=role))


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        target = _selected_environment(request.args.get("environment"))
        next_url = request.args.get("next")

        entry = session.get("env_auth", {}).get(target)

        # Already signed in to the requested environment.
        if entry:
            _sign_in(target, entry["username"], entry["role"])
            return redirect(url_for("home"))

        return _login_page(next_url, target)

    env_id = _selected_environment(request.form.get("environment"))
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    next_url = request.form.get("next") or request.args.get("next")

    if not username or not password:
        flash("Username and password are required.", "danger")
        return _login_page(next_url, env_id, 400)

    try:
        # RADIUS server, secret and NAS Identifier belong to the chosen
        # environment, so authenticate inside that environment's context.
        with cp_env.use(env_id):
            result = authenticate_radius(username, password)
    except RadiusAuthenticationError as exc:
        flash(str(exc), "danger")
        return _login_page(next_url, env_id, 503)

    if not result["authenticated"]:
        flash("Invalid username or password.", "danger")
        return _login_page(next_url, env_id, 401)

    _sign_in(env_id, result["username"], result["role"])

    environment = cp_environments.get_environment(env_id)
    flash(
        f"Logged in as {result['username']} on {environment['name']}.",
        "success",
    )

    if _is_safe_next_url(next_url):
        return redirect(next_url)

    return redirect(url_for("home"))


@auth_bp.route("/switch-environment", methods=["POST"])
@login_required
def switch_environment():
    env_id = request.form.get("environment", "")

    if not cp_environments.is_known(env_id):
        flash("Unknown environment.", "danger")
        return redirect(url_for("home"))

    entry = session.get("env_auth", {}).get(env_id)

    if entry:
        _sign_in(env_id, entry["username"], entry["role"])
        return redirect(url_for("home"))

    # Each environment has its own RADIUS login.
    return redirect(url_for("auth.login", environment=env_id))


@auth_bp.route("/logout")
@login_required
def logout():
    env_id = _selected_environment()
    username = current_user.username

    env_auth = dict(session.get("env_auth", {}))
    env_auth.pop(env_id, None)

    logout_user()

    # Still signed in elsewhere: stay signed in there.
    if env_auth:
        next_env, entry = next(iter(env_auth.items()))

        session["env_auth"] = env_auth
        _sign_in(next_env, entry["username"], entry["role"])

        flash(f"Logged out {username}.", "info")
        return redirect(url_for("home"))

    session.clear()

    flash(f"Logged out {username}.", "info")
    return redirect(url_for("auth.login"))
