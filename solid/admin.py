from flask_admin.contrib.sqla import ModelView

from solid import db, extensions


def init_admin():
    extensions.admin.add_view(ModelView(db.User, extensions.db.session))
    extensions.admin.add_view(ModelView(db.ClientRegistration, extensions.db.session))
    extensions.admin.add_view(ModelView(db.ConfigurationToken, extensions.db.session))
    extensions.admin.add_view(ModelView(db.RelyingPartyKey, extensions.db.session))
    extensions.admin.add_view(ModelView(db.ResourceServerKeys, extensions.db.session))
    extensions.admin.add_view(ModelView(db.ResourceServerConfiguration, extensions.db.session))
