import json
import os

import click
from flask import Blueprint, current_app

import solid

cli_bp = Blueprint('cli', __name__)

LOCAL_KEYS_PATH = "local-keys.jwks"
CONFIGURATION_PATH = "rs-configuration.json"
JWKS_PATH = "rs-keys.jwks"
REGISTRATION_PATH = "rs-registration.json"


@cli_bp.cli.command()
def create_key():
    """Step 1, Create a local key for use by the service"""
    keys = solid.generate_keys()
    with open(LOCAL_KEYS_PATH, "w") as fp:
        fp.write(keys)


@cli_bp.cli.command('lookup-op')
@click.argument('profileurl')
def lookup_op_configuration(profileurl):
    """Step 2, Look-up a user's vcard and find their OP (OpenID Provider).
    Once you have it, look up the provider's OpenID configuration and save it. If it's previously been saved,
    just load it
    """

    if os.path.exists(CONFIGURATION_PATH):
        conf = json.load(open(CONFIGURATION_PATH))
    else:
        conf = {}

    if os.path.exists(JWKS_PATH):
        jwks = json.load(open(JWKS_PATH))
    else:
        jwks = {}

    provider = solid.lookup_provider_from_profile(profileurl)
    if not provider:
        print("Cannot find provider, quitting")
        return
    print(f"Provider for this user is: {provider}")

    if provider in conf and provider in jwks:
        print(f"Configuration for {provider} already exists, quitting")
        return

    openid_conf = solid.get_openid_configuration(provider)
    conf[provider] = openid_conf
    with open(CONFIGURATION_PATH, "w") as fp:
        json.dump(conf, fp)

    j = solid.load_op_jwks(openid_conf)
    jwks[provider] = j
    with open(JWKS_PATH, "w") as fp:
        json.dump(jwks, fp)


@cli_bp.cli.command()
@click.argument("provider")
def register(provider):
    """Step 3, Register with the OP.
    Pass in the provider url from `lookup-op`"""

    if not os.path.exists(CONFIGURATION_PATH):
        print("No config file, use `lookup-op` first")
        return

    with open(CONFIGURATION_PATH) as fp:
        configuration = json.load(fp)

    if os.path.exists(REGISTRATION_PATH):
        reg = json.load(open(REGISTRATION_PATH))
    else:
        reg = {}

    if provider in reg:
        print(f"Registration for {provider} already exists, quitting")
        return

    if provider not in configuration:
        print(f"{provider} not in config, use `lookup-op`")
        return

    provider_conf = configuration[provider]
    client_registration = solid.dynamic_registration(provider, current_app.config['REDIRECT_URL'], provider_conf)
    reg[provider] = client_registration

    with open(REGISTRATION_PATH, "w") as fp:
        json.dump(reg, fp)


@cli_bp.cli.command()
@click.argument('profileurl')
def auth_request(profileurl):
    """Step 4, Perform an authorization request.

    Provide a user's profile url
    """
    provider = solid.lookup_provider_from_profile(profileurl)

    with open(REGISTRATION_PATH) as fp:
        registration = json.load(fp)
    key = solid.load_key(LOCAL_KEYS_PATH)
    with open(CONFIGURATION_PATH) as fp:
        configuration = json.load(fp)

    auth = solid.generate_authorization_request(configuration[provider], registration[provider], key)
    print(auth)
