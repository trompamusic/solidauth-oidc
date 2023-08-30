import json

import click
import jwcrypto.jwk
import jwcrypto.jwt
from flask import Blueprint, current_app

from trompasolid import solid
from solid import extensions
from trompasolid.backend import SolidBackend
from trompasolid.backend.db_backend import DBBackend
from trompasolid.backend.redis_backend import RedisBackend
from trompasolid.dpop import make_random_string

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
        return

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
    state = make_random_string()

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
    provider_config = get_backend().get_resource_server_configuration(provider)

    redirect_uri = current_app.config['REDIRECT_URL']

    signing_algorithm = solid.get_signing_algorithm(provider_config)
    code_verifier = get_backend().get_state_data(state)
    keypair = solid.load_key(get_backend().get_relying_party_keys(signing_algorithm))
    assert code_verifier is not None, f"state {state} not in backend?"

    client_id = client_registration['client_id']
    client_secret = client_registration['client_secret']
    auth = (client_id, client_secret)
    success, resp = solid.validate_auth_callback(signing_algorithm, keypair, code_verifier, code, provider_config, client_id, redirect_uri, auth=auth)

    if success:
        print(resp)
        id_token = resp['id_token']
        server_key = get_backend().get_resource_server_keys(provider)
        # TODO: It seems like a server may give more than one key, is this the correct one?
        key = server_key['keys'][0]
        key = jwcrypto.jwk.JWK.from_json(json.dumps(key))
        decoded_id_token = jwcrypto.jwt.JWT()
        decoded_id_token.deserialize(id_token, key=key)

        claims = json.loads(decoded_id_token.claims)

        issuer = claims['iss']
        sub = claims['sub']
        print(claims)

        get_backend().save_configuration_token(issuer, profile=sub, sub=sub, token=resp)
        print(f"Saved {issuer=}, {sub=}")
    else:
        print("No response - error when exchanging key")


@cli_bp.cli.command()
@click.argument('profile')
def refresh(profile):
    provider = solid.lookup_provider_from_profile(profile)
    print(f"{profile=}")
    print(f"{provider=}")
    keypair = solid.load_key(get_backend().get_relying_party_keys())
    provider_info = get_backend().get_resource_server_configuration(provider)

    configuration_token = get_backend().get_configuration_token(provider, profile)
    if not configuration_token.has_expired():
        print("Configuration token has not expired, skipping refresh")
        return

    client_registration = get_backend().get_client_registration(provider)

    refresh_token = configuration_token.data["refresh_token"]
    status, resp = solid.refresh_auth_token(keypair, provider_info, client_registration["client_id"], refresh_token)

    if status and False:
        resp.update({"refresh_token": refresh_token})
        get_backend().update_configuration_token(provider, profile, resp)
        print("Token updated")
    else:
        print(f"Failure updating token: {status}")
