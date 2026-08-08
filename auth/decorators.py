from functools import wraps

from flask import abort
from flask_login import current_user


def admin_required(view_func):
    """
    Use this later for routes that should only be available to Admin users.
    """

    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if not current_user.is_authenticated:
            abort(401)

        if not getattr(current_user, "is_admin", False):
            abort(403)

        return view_func(*args, **kwargs)

    return wrapped