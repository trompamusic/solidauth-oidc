from flask_admin.contrib.sqla import ModelView

from solid import extensions
import solid.db
import trompasolid.db


def init_admin():
    extensions.admin.add_view(ModelView(solid.db.User, extensions.db.session))
    extensions.admin.add_view(ModelView(trompasolid.db.ClientRegistration, extensions.db.session))
    extensions.admin.add_view(ModelView(trompasolid.db.ConfigurationToken, extensions.db.session))
    extensions.admin.add_view(ModelView(trompasolid.db.RelyingPartyKey, extensions.db.session))
    extensions.admin.add_view(ModelView(trompasolid.db.ResourceServerKeys, extensions.db.session))
    extensions.admin.add_view(ModelView(trompasolid.db.ResourceServerConfiguration, extensions.db.session))
