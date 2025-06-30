import json
import urllib.parse

import click
import jwcrypto.jwk
import jwcrypto.jwt
from flask import Blueprint, current_app

from solid import extensions
from trompasolid import solid
from trompasolid.authentication import (
    generate_authentication_url,
    get_client_id_and_secret_for_provider,
    get_jwt_kid,
    select_jwk_by_kid,
)
from trompasolid.backend import SolidBackend
from trompasolid.backend.db_backend import DBBackend
from trompasolid.backend.redis_backend import RedisBackend
from trompasolid.dpop import make_random_string

cli_bp = Blueprint("cli", __name__)


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


@cli_bp.cli.command("lookup-op")
@click.argument("profileurl")
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
    # Get the canonical provider url from the openid configuration (e.g. https://solidcommunity.net vs https://solidcommunity.net/)
    provider = openid_conf.get("issuer", provider)
    get_backend().save_resource_server_configuration(provider, openid_conf)
    print(f"Saved configuration for {provider}")

    provider_keys = solid.load_op_jwks(openid_conf)
    get_backend().save_resource_server_keys(provider, provider_keys)
    print(f"Saved keys for {provider}")


@cli_bp.cli.command()
@click.argument("provider")
def get_provider_configuration(provider):
    """Step 2b if not using step 2, just get the provider configuration without knowing the user's profile"""

    provider_configuration = get_backend().get_resource_server_configuration(provider)
    provider_keys = get_backend().get_resource_server_keys(provider)

    if provider_configuration and provider_keys:
        print(f"Configuration for {provider} already exists, quitting")
        return

    openid_conf = solid.get_openid_configuration(provider)
    # Get the canonical provider url from the openid configuration (e.g. https://solidcommunity.net vs https://solidcommunity.net/)
    provider = openid_conf.get("issuer", provider)
    get_backend().save_resource_server_configuration(provider, openid_conf)

    provider_keys = solid.load_op_jwks(openid_conf)
    get_backend().save_resource_server_keys(provider, provider_keys)


@cli_bp.cli.command()
@click.argument("provider")
def register(provider):
    """Step 3, Register with the OP.
    Pass in the provider url from `lookup-op`"""

    backend = get_backend()
    always_use_client_url = current_app.config["ALWAYS_USE_CLIENT_URL"]
    if always_use_client_url:
        print("Won't do dynamic registration (config.ALWAYS_USE_CLIENT_URL is True)")
        print("when ALWAYS_USE_CLIENT_URL is True, the `client_id` parameter must be a public URL, and ")
        print("   this CLI doesn't include a webserver, so cannot continue")
        return

    redirect_url = current_app.config["REDIRECT_URL"]
    base_url = current_app.config["BASE_URL"]
    generate_authentication_url(backend, provider, redirect_url, base_url, always_use_client_url)

    provider_config = get_backend().get_resource_server_configuration(provider)

    if not provider_config:
        print("No configuration exists for this provider, use `lookup-op` or `get-provider-configuration` first")
        return

    existing_registration = get_backend().get_client_registration(provider)
    if existing_registration:
        print(f"Registration for {provider} already exists, quitting")
        return

    do_dynamic_registration = (
        solid.op_can_do_dynamic_registration(provider_config) and not current_app.config["ALWAYS_USE_CLIENT_URL"]
    )
    print("Can do dynamic:", solid.op_can_do_dynamic_registration(provider_config))

    if do_dynamic_registration:
        print("Requested to do dynamic client registration")
        client_registration = get_backend().get_client_registration(provider)
        if client_registration:
            print(f"Registration for {provider} already exists, skipping")
        else:
            client_registration = solid.dynamic_registration(
                provider, current_app.config["REDIRECT_URL"], provider_config
            )
            get_backend().save_client_registration(provider, client_registration)

            print("Registered client with provider")
        client_id = client_registration["client_id"]
        print(f"Client ID is {client_id}")
    else:
        print(
            "Cannot do dynamic registration (either the provider doesn't support it or config.ALWAYS_USE_CLIENT_URL is True"
        )
        print("Requests to this provider require that the `client_id` parameter is a public URL, and this CLI doesn't")
        print("   include a webserver, so cannot continue")


@cli_bp.cli.command()
@click.argument("profileurl")
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
        provider_configuration, current_app.config["REDIRECT_URL"], client_id, state, code_challenge
    )
    print(auth_url)


@cli_bp.cli.command()
@click.argument("provider")
@click.argument("code")
@click.argument("state")
def exchange_auth(provider, code, state):
    """Step 5, Exchange a code for a long-term token.

    Provide a provider url, and the code and state that were returned in the redirect by the provider

    This is the same code as `authentication_callback`, but copied here so that we can
    add additional debugging output when testing.
    """

    backend = get_backend()
    redirect_uri = current_app.config["REDIRECT_URL"]
    base_url = current_app.config["BASE_URL"]
    always_use_client_url = current_app.config["ALWAYS_USE_CLIENT_URL"]

    client_id, client_secret = get_client_id_and_secret_for_provider(backend, provider, base_url, always_use_client_url)
    auth = (client_id, client_secret) if client_secret else None
    provider_config = backend.get_resource_server_configuration(provider)

    code_verifier = backend.get_state_data(state)

    keypair = solid.load_key(backend.get_relying_party_keys())
    assert code_verifier is not None, f"state {state} not in backend?"

    success, resp = solid.validate_auth_callback(
        keypair, code_verifier, code, provider_config, client_id, redirect_uri, auth
    )

    if success:
        id_token = resp["id_token"]
        server_jwks = backend.get_resource_server_keys(provider)

        # Extract the key ID from the JWT header
        kid = get_jwt_kid(id_token)

        try:
            # Select the correct key based on the kid
            key = select_jwk_by_kid(server_jwks, kid)

            # Validate and decode the ID token
            decoded_id_token = jwcrypto.jwt.JWT()
            decoded_id_token.deserialize(id_token, key=key)

            claims = json.loads(decoded_id_token.claims)

            if "webid" in claims:
                # The user's web id should be in the 'webid' key, but this doesn't always exist
                # (used to be 'sub'). Node Solid Server still uses sub, but other services put a
                # different value in this field
                webid = claims["webid"]
            else:
                webid = claims["sub"]
            issuer = claims["iss"]
            sub = claims["sub"]
            backend.save_configuration_token(issuer, webid, sub, resp)
            print("Successfully validated ID token and saved configuration")
            return True, resp

        except ValueError as e:
            print(f"Error selecting JWK: {e}")
            return False, {"error": "invalid_token", "error_description": str(e)}
        except (
            jwcrypto.jwt.JWTExpiredError,
            jwcrypto.jwt.JWTInvalidSignatureError,
            jwcrypto.jwt.JWTInvalidClaimError,
            ValueError,
            TypeError,
        ) as e:
            # JWTExpiredError: Token has expired
            # JWTInvalidSignatureError: Invalid signature
            # JWTInvalidClaimError: Invalid claims
            # ValueError: Invalid JWT format
            # TypeError: Invalid key type
            print(f"Error validating ID token: {e}")
            return False, {"error": "invalid_token", "error_description": str(e)}
    else:
        print("Error when validating auth callback")
        return False, resp


@cli_bp.cli.command()
@click.argument("url")
def exchange_auth_url(url):
    """
    Step 5b, Exchange an auth url for a token, from a redirect url
    """
    parts = urllib.parse.urlparse(url)
    query = urllib.parse.parse_qs(parts.query)
    if "iss" not in query or "code" not in query or "state" not in query:
        print("Missing iss, code, or state in query string")
        return
    provider = query["iss"][0]
    code = query["code"][0]
    state = query["state"][0]
    exchange_auth(provider, code, state)


@cli_bp.cli.command()
@click.argument("profile")
def refresh(profile):
    provider = solid.lookup_provider_from_profile(profile)
    backend = get_backend()

    keypair = solid.load_key(backend.get_relying_party_keys())
    provider_info = backend.get_resource_server_configuration(provider)

    configuration_token = backend.get_configuration_token(provider, profile)
    if not configuration_token.has_expired():
        print("Configuration token has not expired, skipping refresh")
        return
    always_use_client_url = current_app.config["ALWAYS_USE_CLIENT_URL"]
    base_url = current_app.config["BASE_URL"]
    client_id, client_secret = get_client_id_and_secret_for_provider(backend, provider, base_url, always_use_client_url)

    status, resp = solid.refresh_auth_token(keypair, provider_info, client_id, configuration_token)
    print(f"{status=}")
    print(resp)

    if status:
        backend.update_configuration_token(provider, profile, resp)
        print("Token updated")
    else:
        print(f"Failure updating token: {status}")
