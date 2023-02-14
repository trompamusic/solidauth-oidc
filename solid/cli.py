import click
from flask import Blueprint, current_app

import solid
from solid import extensions
from trompasolid.backend import SolidBackend
from trompasolid.backend.db_backend import DBBackend
from trompasolid.backend.redis_backend import RedisBackend
from solid.webserver import validate_auth_callback

cli_bp = Blueprint('cli', __name__)


def get_backend() -> SolidBackend:
    # function so that we have access to current_app. This should be an extension
    if current_app.config["BACKEND"] == "db":
        backend = DBBackend(extensions.db.session)
    elif current_app.config["BACKEND"] == "redis":
        backend = RedisBackend(extensions.redis_client)
    return backend


@cli_bp.cli.command()
def create_key():
    """Step 1, Create a local key for use by the service"""
    existing_keys = get_backend().get_relying_party_keys()
    if existing_keys:
        print("Got keys, not generating more")
        return
    keys = solid.generate_keys()
    get_backend().save_relying_party_keys(keys)


@cli_bp.cli.command('lookup-op')
@click.argument('profileurl')
def lookup_op_configuration(profileurl):
    """Step 2, Look-up a user's vcard and find their OP (OpenID Provider).
    Once you have it, look up the provider's OpenID configuration and save it. If it's previously been saved,
    just load it
    """

    provider = solid.lookup_provider_from_profile(profileurl)
    if not provider:
        print("Cannot find provider, quitting")
        return
    print(f"Provider for this user is: {provider}")

    provider_configuration = get_backend().get_resource_server_configuration(provider)
    provider_keys = get_backend().get_resource_server_keys(provider)

    if provider_configuration and provider_keys:
        print(f"Configuration for {provider} already exists, quitting")
        return

    openid_conf = solid.get_openid_configuration(provider)
    get_backend().save_resource_server_configuration(provider, openid_conf)

    provider_keys = solid.load_op_jwks(openid_conf)
    get_backend().save_resource_server_keys(provider, provider_keys)


@cli_bp.cli.command()
@click.argument("provider")
def register(provider):
    """Step 3, Register with the OP.
    Pass in the provider url from `lookup-op`"""

    provider_config = get_backend().get_resource_server_configuration(provider)

    if not provider_config:
        print("No configuration exists for this provider, use `lookup-op` first")

    existing_registration = get_backend().get_client_registration(provider)
    if existing_registration:
        print(f"Registration for {provider} already exists, quitting")
        return

    do_dynamic_registration = solid.op_can_do_dynamic_registration(provider_config) and not current_app.config['ALWAYS_USE_CLIENT_URL']
    print("Can do dynamic:", solid.op_can_do_dynamic_registration(provider_config))

    if do_dynamic_registration:
        print(f"Requested to do dynamic client registration")
        client_registration = get_backend().get_client_registration(provider)
        if client_registration:
            print(f"Registration for {provider} already exists, skipping")
        else:
            client_registration = solid.dynamic_registration(provider, current_app.config['REDIRECT_URL'], provider_config)
            get_backend().save_client_registration(provider, client_registration)

            print("Registered client with provider")
        client_id = client_registration["client_id"]
        print(f"Client ID is {client_id}")
    else:
        print("Cannot do dynamic registration (either the provider doesn't support it or config.ALWAYS_USE_CLIENT_URL is True")
        print("Requests to this provider require that the `client_id` parameter is a public URL, and this CLI doesn't")
        print("   include a webserver, so cannot continue")


@cli_bp.cli.command()
@click.argument('profileurl')
def auth_request(profileurl):
    """Step 4, Perform an authorization request.

    Provide a user's profile url
    """
    provider = solid.lookup_provider_from_profile(profileurl)
    provider_configuration = get_backend().get_resource_server_configuration(provider)
    client_registration = get_backend().get_client_registration(provider)
    if client_registration is None:
        print("No client registration, use `register` first")
        return

    client_id = client_registration["client_id"]
    code_verifier, code_challenge = solid.make_verifier_challenge()
    state = solid.make_random_string()

    assert get_backend().get_state_data(state) is None
    get_backend().set_state_data(state, code_verifier)

    auth_url = solid.generate_authorization_request(
        provider_configuration, current_app.config['REDIRECT_URL'],
        client_id,
        state, code_challenge
    )
    print(auth_url)


@cli_bp.cli.command()
@click.argument('provider')
@click.argument('code')
@click.argument('state')
def exchange_auth(provider, code, state):
    """Step 5, Exchange a code for a long-term token.

    Provide a provider url, and the code and state that were returned in the redirect by the provider
    """

    client_registration = get_backend().get_client_registration(provider)
    if not client_registration:
        raise Exception("Expected to find a registration for a backend but can't get one")
    client_id = client_registration["client_id"]
    provider_config = get_backend().get_resource_server_configuration(provider)

    redirect_uri = current_app.config['REDIRECT_URL']
    resp = validate_auth_callback(code, state, provider_config, client_id, redirect_uri)
    print(resp)
    result = resp["result"]
