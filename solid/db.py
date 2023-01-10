import datetime

from flask_login import UserMixin
from sqlalchemy import Index
from sqlalchemy.dialects import postgresql

from solid.extensions import bcrypt, db


class User(db.Model, UserMixin):
    """A user of the app."""
    __tablename__ = 'users'
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
        return f'<User({self.user!r})>'



class RelyingPartyKey(db.Model):
    """Keys for the client, there should only be one of these"""
    __tablename__ = 'relying_party'
    id = db.Column(db.Integer, primary_key=True)
    data = db.Column(postgresql.JSONB)

    def __repr__(self):
        return f'<RelyingPartyKey {self.id}>'


class ResourceServerConfiguration(db.Model):
    __tablename__ = 'resource_server_configuration'
    id = db.Column(db.Integer, primary_key=True, unique=True)
    provider = db.Column(db.Text, nullable=False, index=True)
    data = db.Column(postgresql.JSONB)

    def __repr__(self):
        return f'<ResourceServerConfiguration {self.id} ({self.provider})>'


class ResourceServerKeys(db.Model):
    __tablename__ = 'resource_server_keys'
    id = db.Column(db.Integer, primary_key=True)
    provider = db.Column(db.Text, nullable=False, index=True, unique=True)
    data = db.Column(postgresql.JSONB)

    def __repr__(self):
        return f'<ResourceServerKeys {self.id} ({self.provider})>'


class ClientRegistration(db.Model):
    __tablename__ = 'client_registration'
    id = db.Column(db.Integer, primary_key=True)
    provider = db.Column(db.Text, nullable=False, index=True, unique=True)
    data = db.Column(postgresql.JSONB)

    def __repr__(self):
        return f'<ClientRegistration {self.id} ({self.provider})>'


class ConfigurationToken(db.Model):
    __tablename__ = 'configuration_token'
    id = db.Column(db.Integer, primary_key=True)
    issuer = db.Column(db.Text, nullable=False, index=True)
    sub = db.Column(db.Text, nullable=False, index=True)
    data = db.Column(postgresql.JSONB)
    __table_args__ = (Index('configuration_token_idx_issuer_sub', "issuer", "sub", unique=True), )

    def __repr__(self):
        return f'<ConfigurationToken {self.id} ({self.issuer}, {self.sub})>'
