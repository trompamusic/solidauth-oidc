import json

import jwt
from flask import Blueprint, render_template, request, jsonify, Flask, current_app
from flask_redis import FlaskRedis

import solid


redis_client = FlaskRedis()
REDIS_KEY_PREFIX = "solidauth-"


def create_app():
    app = Flask(__name__, template_folder="../templates")
    app.config.from_pyfile("../config.py")
    redis_client.init_app(app)

    # On startup, generate keys if they don't exist
    if not get_redis_str(CONFIG_RP_KEYS):
        new_key = solid.generate_keys()
        store_redis_str(CONFIG_RP_KEYS, new_key)

    return app


def get_redis_dict(key):
    """Load a dict from redis"""
    value = get_redis_str(key)
    if value:
        return json.loads(value)
    else:
        return value


def store_redis_dict(key, value):
    """Store a dict in redis (stored as a json-dumped string)"""
    value = json.dumps(value)
    return store_redis_str(key, value)


def get_redis_str(key):
    """Load a string value from redis"""
    key = REDIS_KEY_PREFIX + key
    return redis_client.get(key)


def store_redis_str(key, value):
    key = REDIS_KEY_PREFIX + key
    return redis_client.set(key, value)


def make_redis_key(key_template, *args):
    return key_template.format(*args)


webserver_bp = Blueprint('register', __name__)


# Server configuration for a Resource Server (key has provider url as a suffix)
CONFIG_RS_CONFIGURATION = "rs-configuration-{}"
# JWKS (public keys) for a Resource Server (key has provider url as a suffix)
CONFIG_RS_JWKS = "rs-jwks-{}"
# Registration information for this app on a Resource Server (key has provider url as a suffix)
CONFIG_CLIENT_REGISTRATION = "rs-registration-{}"
# Private key for this app
CONFIG_RP_KEYS = "local-key"
# Auth tokens to act as a particular user on a Resource Server (key has providerurl-userid as a suffix)
CONFIG_TOKENS = "rs-token-{}-{}"


@webserver_bp.route("/")
def web_index():
    return render_template("index.html")


@webserver_bp.route("/register", methods=["POST"])
def web_register():
    client_key = solid.load_key(get_redis_str(CONFIG_RP_KEYS))
    log_messages = []

    webid = request.form.get("webid")
    provider = solid.lookup_provider_from_profile(webid)
    if not provider:
        print("Cannot find provider, quitting")
        log_messages.append(f"Cannot find a provider for webid {webid}")
        return render_template("register.html", log_messages=log_messages)

    log_messages.append(f"Provider for this user is: {provider}")
    print(f"Provider for this user is: {provider}")

    provider_config = get_redis_dict(make_redis_key(CONFIG_RS_CONFIGURATION, provider))
    provider_jwks = get_redis_dict(make_redis_key(CONFIG_RS_JWKS, provider))
    if provider_config and provider_jwks:
        log_messages.append(f"Configuration for {provider} already exists, skipping setup")
        print(f"Configuration for {provider} already exists, quitting")
    else:
        provider_config = solid.get_openid_configuration(provider)
        store_redis_dict(make_redis_key(CONFIG_RS_CONFIGURATION, provider), provider_config)

        keys = solid.load_op_jwks(provider_config)
        store_redis_dict(make_redis_key(CONFIG_RS_JWKS, provider), keys)
        log_messages.append("Got configuration and jwks for provider")

    client_registration = get_redis_dict(make_redis_key(CONFIG_CLIENT_REGISTRATION, provider))
    if client_registration:
        # TODO: Check if redirect url is the same as the one configured here
        log_messages.append(f"Registration for {provider} already exists, skipping")
        print(f"Registration for {provider} already exists, quitting")
    else:
        client_registration = solid.dynamic_registration(provider, current_app.config['REDIRECT_URL'], provider_config)
        store_redis_dict(make_redis_key(CONFIG_CLIENT_REGISTRATION, provider), client_registration)

        log_messages.append("Registered client with provider")

    auth_url = solid.generate_authorization_request(provider_config,
                                                    client_registration,
                                                    current_app.config['REDIRECT_URL'],
                                                    client_key)
    log_messages.append("Got an auth url")

    return render_template("register.html", log_messages=log_messages, auth_url=auth_url)


@webserver_bp.route("/redirect")
def web_redirect():
    return render_template("redirect.html")


@webserver_bp.route("/redirect_post", methods=["POST"])
def web_redirect_save():
    body = request.json
    # TODO: If the required fields aren't set
    id_token = body['id_token']
    decoded_token = jwt.decode(id_token, algorithms=["RS256"], options={"verify_signature": False})
    issuer = decoded_token['iss']
    sub = decoded_token['sub']

    # TODO: We need to store more information here, including token expiry information, and
    #  a method to renew the key if needed
    store_redis_str(make_redis_key(CONFIG_TOKENS, issuer, sub), id_token)

    return jsonify({"status": "ok"})
