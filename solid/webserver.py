from logging.config import dictConfig
from typing import Optional

import flask
from flask import current_app, jsonify, request, session, url_for
from flask_login import login_required, login_user, logout_user

import trompasolid.solid
from solid import db, extensions, get_sample_client_registration
from solid.admin import init_admin
from solid.auth import LoginForm, is_safe_url
from trompasolid.authentication import (
    BadClientIdError,
    NoProviderError,
    authentication_callback,
    generate_authentication_url,
)
from trompasolid.backend import SolidBackend
from trompasolid.backend.db_backend import DBBackend
from trompasolid.backend.redis_backend import RedisBackend

backend: Optional[SolidBackend] = None

# Some providers cache this url, so during testing we may want to change it to break the cache
CLIENT_ID_DOCUMENT_SUFFIX = ""


def configure_logging():
    dictConfig(
        {
            "version": 1,
            "formatters": {
                "default": {
                    "format": "[%(asctime)s] %(levelname)s in %(module)s: %(message)s",
                }
            },
            "handlers": {
                "wsgi": {
                    "class": "logging.StreamHandler",
                    "stream": "ext://flask.logging.wsgi_errors_stream",
                    "formatter": "default",
                },
                "console": {
                    "class": "logging.StreamHandler",
                    "stream": "ext://sys.stdout",
                    "formatter": "default",
                },
            },
            "loggers": {
                "trompasolid": {"level": "DEBUG", "handlers": ["console"], "propagate": False},
                "solid": {"level": "DEBUG", "handlers": ["console"], "propagate": False},
            },
        }
    )


def create_app():
    configure_logging()
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


webserver_bp = flask.Blueprint("register", __name__)


@webserver_bp.route("/logo.png")
def logo():
    return flask.current_app.send_static_file("solid-app-logo.png")


@webserver_bp.route("/client/solid-oidc-client.jsonld")
@webserver_bp.route("/client/solid-oidc-client<string:suffix>.jsonld")
def client_id_url(suffix=""):
    # In Solid-OIDC you can register a client by having the "client_id" field be a URL to a json-ld document
    # It's normally recommended that this is a static file, but for simplicity serve it from flask

    baseurl = current_app.config["BASE_URL"]

    sample_client_registration = get_sample_client_registration(baseurl, [current_app.config["REDIRECT_URL"]])
    # Set a different name so that we can differentiate between a client id documents and dynamic registration during testing
    sample_client_registration["client_name"] = "Solid-OIDC client id document app"

    client_information = {
        "@context": ["https://www.w3.org/ns/solid/oidc-context.jsonld"],
        "client_id": baseurl + url_for("register.client_id_url", suffix=suffix),
        **sample_client_registration,
    }

    response = jsonify(client_information)
    response.content_type = "application/ld+json"
    response.headers["Access-Control-Allow-Origin"] = "*"
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


@webserver_bp.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        # Login and validate the user.

        login_user(form.user)

        flask.flash("Logged in successfully.")

        next = request.args.get("next")
        # is_safe_url should check if the url is safe for redirects.
        # See http://flask.pocoo.org/snippets/62/ for an example.
        if not is_safe_url(next):
            return flask.abort(400)

        return flask.redirect(next or flask.url_for("admin.index"))
    return flask.render_template("login.html", form=form)


@webserver_bp.route("/logout")
@login_required
def logout():
    logout_user()
    return flask.redirect("/")


@webserver_bp.route("/register", methods=["POST"])
def web_register():
    webid = request.form.get("webid_or_provider")
    use_client_id_document = request.form.get("use_client_id_document") == "on"

    redirect_url = current_app.config["REDIRECT_URL"]
    base_url = current_app.config["BASE_URL"]
    if use_client_id_document:
        client_id_document_url = base_url + url_for("register.client_id_url", suffix=CLIENT_ID_DOCUMENT_SUFFIX)
        print(f"Client id document url: {client_id_document_url}")
    else:
        client_id_document_url = None
    try:
        registration_request = get_sample_client_registration(base_url, [redirect_url])
        registration_request["client_name"] = "Solid-OIDC client id document app (dynamic registration)"
        data = generate_authentication_url(backend, webid, registration_request, redirect_url, client_id_document_url)
        provider = data["provider"]
        auth_url = data["auth_url"]
        log_messages = data["log_messages"]

        flask.session["provider"] = provider
        flask.session["use_client_id_document"] = use_client_id_document

        return flask.render_template("register.html", log_messages=log_messages, auth_url=auth_url)

    except NoProviderError as e:
        return flask.render_template("register.html", log_messages=[str(e)])


@webserver_bp.route("/redirect")
def web_redirect():
    auth_code = flask.request.args.get("code")
    state = flask.request.args.get("state")
    iss = flask.request.args.get("iss")

    # TODO: We may get `error` and `error_description` query parameters instead of code and state

    if iss:
        provider = iss
    else:
        provider = flask.session["provider"]

    redirect_uri = current_app.config["REDIRECT_URL"]
    base_url = current_app.config["BASE_URL"]
    use_client_id_document = flask.session.get("use_client_id_document", False)
    if use_client_id_document:
        client_id_document_url = base_url + url_for("register.client_id_url", suffix=CLIENT_ID_DOCUMENT_SUFFIX)
    else:
        client_id_document_url = None

    try:
        success, data = authentication_callback(
            backend, auth_code, state, provider, redirect_uri, client_id_document_url
        )
    except BadClientIdError as e:
        error_message = f"Client registration error: {str(e)}"
        return flask.render_template("error.html", error_message=error_message)

    if success:
        # TODO: If we want, we can make the original auth page include a redirect URL field, and redirect the user
        #  back to that when this has finished
        # return flask.redirect(STATE_STORAGE[state].pop('redirect_url'))
        redirect_after = session.get("redirect_after")
        return flask.render_template("success.html", redirect_after=redirect_after)
    else:
        print(data)

        # Handle specific error cases
        if data.get("error") == "invalid_state":
            error_message = "This authentication link has already been used or has expired. Please start a new authentication process."
            return flask.render_template("error.html", error_message=error_message)

        return "Error when validating auth callback", 500
