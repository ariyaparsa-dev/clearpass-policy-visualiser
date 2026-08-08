from flask_login import UserMixin


class RadiusUser(UserMixin):
    """
    Lightweight user object stored by Flask-Login.

    No local password storage.
    Identity is established by ClearPass RADIUS Access-Accept.
    """

    def __init__(self, username, role="ReadOnly", radius_attributes=None):
        self.id = username
        self.username = username
        self.role = role
        self.radius_attributes = radius_attributes or {}

    @property
    def is_admin(self):
        return self.role == "Admin"

    @property
    def is_readonly(self):
        return self.role == "ReadOnly"

    def get_id(self):
        return self.username