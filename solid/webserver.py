from typing import Optional

import flask
from flask import request, current_app, jsonify, session
from flask_login import login_user, login_required, logout_user

import solid
from solid.admin import init_admin
from trompasolid.authentication import generate_authentication_url, NoProviderError, authentication_callback
from trompasolid.backend import SolidBackend
from trompasolid.backend.db_backend import DBBackend
from trompasolid.backend.redis_backend import RedisBackend
from solid import extensions
from solid import db
from solid.auth import is_safe_url, LoginForm

backend: Optional[SolidBackend] = None


def create_app():
    app = flask.Flask(__name__, template_folder="../templates")
    app.config.from_pyfile("../config.py")
    extensions.admin.init_app(app)
    extensions.db.init_app(app)
    extensions.redis_client.init_app(app)
    extensions.login_manager.init_app(app)
    init_admin()

    global backend
    if app.config["BACKEND"] == "db":
        backend = DBBackend(extensions.db.session)
    elif app.config["BACKEND"] == "redis":
        backend = RedisBackend(extensions.redis_client)

    @extensions.login_manager.user_loader
    def load_user(user_id):
        return db.User.query.filter_by(user=user_id).first()

    with app.app_context():
        # On startup, generate keys if they don't exist
        if backend.is_ready():
            if not backend.get_relying_party_keys():
                print("On startup generating new RP keys")
                new_key = trompasolid.solid.generate_keys()
                backend.save_relying_party_keys(new_key)
        else:
            print("Warning: Backend isn't ready yet")

    return app


webserver_bp = flask.Blueprint('register', __name__)


@webserver_bp.route("/logo.png")
def logo():
    return flask.current_app.send_static_file("solid-app-logo.png")


@webserver_bp.route("/client/<string:cid>.jsonld")
def client_id_url(cid):
    # In Solid-OIDC you can register a client by having the "client_id" field be a URL to a json-ld document
    # It's normally recommended that this is a static file, but for simplicity serve it from flask

    baseurl = current_app.config['BASE_URL']
    if not baseurl.endswith("/"):
        baseurl += "/"

    client_information = {
        "@context": ["https://www.w3.org/ns/solid/oidc-context.jsonld"],

        "client_id": baseurl + f"client/{cid}.jsonld",
        "client_name": "Alastair's cool test application",
        "redirect_uris": [current_app.config['REDIRECT_URL']],
        "post_logout_redirect_uris": [baseurl + "logout"],
        "client_uri": baseurl,
        "logo_uri": baseurl + "logo.png",
        "tos_uri": baseurl + "tos.html",
        "scope": "openid webid offline_access",
        "grant_types": ["refresh_token", "authorization_code"],
        "response_types": ["code"],
        "default_max_age": 3600,
        "require_auth_time": True
    }

    response = jsonify(client_information)
    response.content_type = "application/ld+json"
    return response


@webserver_bp.route("/")
def web_index():
    profile_url = request.args.get("profile")
    if not profile_url:
        profile_url = ""
    redirect_after = request.args.get("redirect")
    if redirect_after:
        session["redirect_after"] = redirect_after
    return flask.render_template("index.html", profile_url=profile_url)


@webserver_bp.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        # Login and validate the user.

        login_user(form.user)

        flask.flash('Logged in successfully.')

        next = request.args.get('next')
        # is_safe_url should check if the url is safe for redirects.
        # See http://flask.pocoo.org/snippets/62/ for an example.
        if not is_safe_url(next):
            return flask.abort(400)

        return flask.redirect(next or flask.url_for('admin.index'))
    return flask.render_template('login.html', form=form)


@webserver_bp.route("/logout")
@login_required
def logout():
    logout_user()
    return flask.redirect("/")


@webserver_bp.route("/register", methods=["POST"])
def web_register():

    webid = request.form.get("webid_or_provider")

    redirect_url = current_app.config['REDIRECT_URL']
    always_use_client_url = current_app.config['ALWAYS_USE_CLIENT_URL']
    try:
        data = generate_authentication_url(backend, webid, redirect_url, always_use_client_url)
        provider = data['provider']
        auth_url = data['auth_url']
        log_messages = data['log_messages']

        flask.session['provider'] = provider

        return flask.render_template("register.html", log_messages=log_messages, auth_url=auth_url)

    except NoProviderError as e:
        return flask.render_template("register.html", log_messages=[str(e)])


@webserver_bp.route("/redirect")
def web_redirect():
    auth_code = flask.request.args.get("code")
    state = flask.request.args.get("state")
    iss = flask.request.args.get("iss")

    if iss:
        provider = iss
    else:
        provider = flask.session["provider"]

    redirect_uri = current_app.config["REDIRECT_URL"]
    always_use_client_url = current_app.config["ALWAYS_USE_CLIENT_URL"]
    success, data = authentication_callback(
        backend, auth_code, state, provider, redirect_uri, always_use_client_url
    )

    if success:
        # TODO: If we want, we can make the original auth page include a redirect URL field, and redirect the user
        #  back to that when this has finished
        # return flask.redirect(STATE_STORAGE[state].pop('redirect_url'))
        redirect_after = session.get("redirect_after")
        return flask.render_template("success.html", redirect_after=redirect_after)
    else:
        print("Error when validating auth callback")
        return "Error when validating auth callback", 500
