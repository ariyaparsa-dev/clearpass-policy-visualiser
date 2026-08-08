from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from flask_login import login_user, logout_user, login_required, current_user

from auth.models import RadiusUser
from auth.radius_client import authenticate_radius, RadiusAuthenticationError


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


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("home"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        next_url = request.form.get("next") or request.args.get("next")

        if not username or not password:
            flash("Username and password are required.", "danger")
            return render_template("login.html", next=next_url), 400

        try:
            result = authenticate_radius(username, password)

        except RadiusAuthenticationError as exc:
            flash(str(exc), "danger")
            return render_template("login.html", next=next_url), 503

        if not result["authenticated"]:
            flash("Invalid username or password.", "danger")
            return render_template("login.html", next=next_url), 401

        user = RadiusUser(
            username=result["username"],
            role=result["role"],
            radius_attributes=result["radius_attributes"],
        )

        login_user(user)

        session["username"] = user.username
        session["role"] = user.role
        session["radius_attributes"] = user.radius_attributes

        flash(f"Logged in as {user.username}.", "success")

        if _is_safe_next_url(next_url):
            return redirect(next_url)

        return redirect(url_for("home"))

    next_url = request.args.get("next")

    return render_template("login.html", next=next_url)


@auth_bp.route("/logout")
@login_required
def logout():
    username = current_user.username

    logout_user()
    session.clear()

    flash(f"Logged out {username}.", "info")

    return redirect(url_for("auth.login"))