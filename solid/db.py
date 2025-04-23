import datetime

from flask_login import UserMixin

from solid.extensions import bcrypt, db


class User(db.Model, UserMixin):
    """A user of the app."""

    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    user = db.Column(db.String(80), unique=True, nullable=False, index=True)
    #: The hashed password
    password = db.Column(db.LargeBinary(128), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow)
    is_admin = db.Column(db.Boolean(), default=False)

    def __init__(self, user, password=None, **kwargs):
        """Create instance."""
        db.Model.__init__(self, user=user, **kwargs)
        if password:
            self.set_password(password)
        else:
            self.password = None

    def set_password(self, password):
        """Set password."""
        self.password = bcrypt.generate_password_hash(password)

    def check_password(self, value):
        """Check password."""
        return bcrypt.check_password_hash(self.password, value)

    def get_id(self):
        return self.user

    def __repr__(self):
        """Represent instance as a unique string."""
        return f"<User({self.user!r})>"
