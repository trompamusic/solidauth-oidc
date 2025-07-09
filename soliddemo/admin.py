from flask import redirect, url_for, request
from flask_admin import BaseView, AdminIndexView
from flask_login import current_user
from flask_admin.contrib.sqla import ModelView

from soliddemo import extensions

import solidauth.db


class AuthBaseView(BaseView):
    def is_accessible(self):
        return current_user.is_authenticated

    def inaccessible_callback(self, name, **kwargs):
        # redirect to login page if user doesn't have access
        return redirect(url_for("register.login", next=request.url))


class AuthIndexView(AuthBaseView, AdminIndexView):
    pass


class AuthModelView(AuthBaseView, ModelView):
    pass


class ClientRegistrationModelView(AuthModelView):
    column_list = ("provider", "data")


def init_admin():
    import soliddemo.db

    extensions.admin.add_view(AuthModelView(soliddemo.db.User, extensions.db.session))
    extensions.admin.add_view(ClientRegistrationModelView(solidauth.db.ClientRegistration, extensions.db.session))
    extensions.admin.add_view(AuthModelView(solidauth.db.ConfigurationToken, extensions.db.session))
    extensions.admin.add_view(AuthModelView(solidauth.db.RelyingPartyKey, extensions.db.session))
    extensions.admin.add_view(AuthModelView(solidauth.db.ResourceServerKeys, extensions.db.session))
    extensions.admin.add_view(AuthModelView(solidauth.db.ResourceServerConfiguration, extensions.db.session))
