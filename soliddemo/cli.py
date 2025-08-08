import json
import logging
import os
import urllib.parse

import click
import jwcrypto.jwk
import jwcrypto.jwt
import rdflib
import requests
from flask import Blueprint, current_app, url_for

from solidauth import client, solid
from solidauth.backend import SolidBackend
from solidauth.backend.db_backend import DBBackend
from solidauth.backend.redis_backend import RedisBackend
from solidauth.dpop import make_random_string
from soliddemo import extensions, get_sample_client_registration
from soliddemo.webserver import CLIENT_ID_DOCUMENT_SUFFIX

cli_bp = Blueprint("cli", __name__)
logger = logging.getLogger(__name__)


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


@cli_bp.cli.command("get-provider-configuration-from-profile")
@click.argument("profileurl")
def get_provider_configuration_from_profile(profileurl):
    """Step 2a, Look-up a user's vcard and find their OP (OpenID Provider).
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


@cli_bp.cli.command("get-provider-configuration")
@click.argument("provider")
def get_provider_configuration(provider):
    """Step 2b, if not using step 2a, just get the provider configuration without knowing the user's profile"""

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
@click.option("--use-client-id-document", is_flag=True, help="Use client ID document instead of dynamic registration")
def register(provider, use_client_id_document):
    """Step 3, Register with the OP.
    Pass in the provider url from `get-provider-configuration` or `get-provider-configuration-from-profile`

    This method is similar to `solidauth.authentication.generate_authentication_url`, but copied here so that we can
    add additional debugging output when testing.
    """

    provider_config = get_backend().get_resource_server_configuration(provider)

    if not provider_config:
        print("No configuration exists for this provider, use `lookup-op` or `get-provider-configuration` first")
        return

    existing_registration = get_backend().get_client_registration(provider)
    if existing_registration:
        print(f"Registration for {provider} already exists, skipping {existing_registration['client_id']}")
        return

    if not solid.op_can_do_dynamic_registration(provider_config):
        # Provider doesn't support dynamic registration - while solid allows us to use a
        # manually created client ("static registration"), we don't want to deal with this
        raise client.ClientDoesNotSupportDynamicRegistration(
            f"Provider {provider} does not support dynamic client registration. "
            f"Registration endpoint: {provider_config.get('registration_endpoint', 'not available')}"
        )

    if use_client_id_document:
        # Generate a client URL that points to our client metadata document
        # Section 5 of the Solid-OIDC spec (https://solidproject.org/TR/oidc#clientids) says
        # OAuth and OIDC require the Client application to identify itself to the OP and RS by presenting a client identifier (Client ID). Solid applications SHOULD use a URI that can be dereferenced as a Client ID Document.
        # this means that "token_endpoint_auth_methods_supported" should include "none", otherwise this is not supported
        # https://github.com/solid/solid-oidc/issues/78
        # If we want to use this, then there is no "registration" step, we just use the URL as the client_id
        # at the auth request step.
        base_url = current_app.config["BASE_URL"]
        client_id = base_url + url_for("register.client_id_url", suffix=CLIENT_ID_DOCUMENT_SUFFIX)
        print("App config requests what we use a client ID document, not dynamic registration")
        print("   (--use-client-id-document flag is set)")
        print("as a result, registration doesn't exist. Move directly to auth request")
        return
    else:
        print("Requested to do dynamic client registration")
        registration_request = get_sample_client_registration(
            current_app.config["BASE_URL"], [current_app.config["REDIRECT_URL"]]
        )
        # Set a different name so that we can differentiate between a client id documents and dynamic registration during testing
        registration_request["client_name"] = "Solid OIDC test app (dynamic registration)"
        client_registration = solid.dynamic_registration(registration_request, provider_config)
        get_backend().save_client_registration(provider, client_registration)

        print("Registered client with provider")
        client_id = client_registration["client_id"]
        print(f"Client ID is {client_id}")


@cli_bp.cli.command()
@click.argument("profileurl")
@click.option("--use-client-id-document", is_flag=True, help="Use client ID document instead of dynamic registration")
def auth_request(profileurl, use_client_id_document):
    """Step 4, Perform an authorization request.

    Provide a user's profile url
    """
    provider = solid.lookup_provider_from_profile(profileurl)

    base_url = current_app.config["BASE_URL"]

    provider_configuration = get_backend().get_resource_server_configuration(provider)

    if use_client_id_document:
        print("Using client_id as URL for auth request")
        base_url = current_app.config["BASE_URL"]
        url = f"/client/solid-oidc-client{CLIENT_ID_DOCUMENT_SUFFIX}.jsonld"
        client_id = base_url + url
    else:
        print("Using client from dynamic registration for auth request")
        client_registration = get_backend().get_client_registration(provider)
        if client_registration is None:
            print("No client registration, use `register` first")
            return

        client_id = client_registration["client_id"]

    print(f"Client ID is {client_id}")

    code_verifier, code_challenge = solid.make_verifier_challenge()
    state = make_random_string()

    assert get_backend().get_state_data(state) is None
    get_backend().set_state_data(state, code_verifier)

    auth_url = solid.generate_authorization_request(
        provider_configuration, current_app.config["REDIRECT_URL"], client_id, state, code_challenge
    )
    print(auth_url)


@cli_bp.cli.command()
@click.argument("code")
@click.argument("state")
@click.argument("provider", required=False)
@click.option("--use-client-id-document", is_flag=True, help="Use client ID document instead of dynamic registration")
def exchange_auth(code, state, provider, use_client_id_document):
    """Step 5, Exchange a code for a long-term token.

    Provide a provider url, and the code and state that were returned in the redirect by the provider
    Some providers don't include themselves in the &iss= parameter of the callback url, so if it's not
    available then you should store it in a client state at the previous step and retrieve it.

    This is the same code as `authentication_callback`, but copied here so that we can
    add additional debugging output when testing.
    """

    backend = get_backend()
    redirect_uri = current_app.config["REDIRECT_URL"]
    c = client.SolidClient(backend, use_client_id_document)

    if use_client_id_document:
        auth = None
        base_url = current_app.config["BASE_URL"]
        url = f"/client/solid-oidc-client{CLIENT_ID_DOCUMENT_SUFFIX}.jsonld"
        client_id = base_url + url
    else:
        client_id, client_secret = c.get_client_id_and_secret_for_provider(provider)
        auth = (client_id, client_secret)

    backend_state = backend.get_state_data(state)
    assert backend_state is not None, f"state {state} not in backend?"
    code_verifier = backend_state["code_verifier"]

    if provider is None:
        print(f"No provider provided, using issuer from state: {backend_state['issuer']}")
        provider = backend_state["issuer"]
    provider_config = backend.get_resource_server_configuration(provider)

    keypair = solid.load_key(backend.get_relying_party_keys())

    success, resp = solid.validate_auth_callback(
        keypair, code_verifier, code, provider_config, client_id, redirect_uri, auth
    )

    if success:
        id_token = resp["id_token"]
        server_jwks = backend.get_resource_server_keys(provider)

        # Extract the key ID from the JWT header
        kid = solid.get_jwt_kid(id_token)

        try:
            # Select the correct key based on the kid
            key = solid.select_jwk_by_kid(server_jwks, kid)

            # Validate and decode the ID token
            decoded_id_token = jwcrypto.jwt.JWT()
            decoded_id_token.deserialize(id_token, key=key)

            claims = json.loads(decoded_id_token.claims)

            # Validate ID token claims according to OpenID Connect Core 1.0
            try:
                solid.validate_id_token_claims(claims, provider, client_id)
            except solid.IDTokenValidationError as e:
                print(f"ID token validation failed: {e}")
                return False, {"error": "invalid_token", "error_description": str(e)}

            if "webid" in claims:
                # The user's web id should be in the 'webid' key, but this doesn't always exist
                # (used to be 'sub'). Node Solid Server still uses sub, but other services put a
                # different value in this field
                webid = claims["webid"]
            else:
                webid = claims["sub"]
            issuer = claims["iss"]
            sub = claims["sub"]
            backend.save_configuration_token(issuer, webid, sub, client_id, resp)
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
@click.option("--use-client-id-document", is_flag=True, help="Use client ID document instead of dynamic registration")
@click.pass_context
def exchange_auth_url(ctx, url, use_client_id_document):
    """
    Step 5b, Exchange an auth url for a token, from a redirect url
    """
    parts = urllib.parse.urlparse(url)
    query = urllib.parse.parse_qs(parts.query)
    if "code" not in query or "state" not in query:
        print("Missing code, or state in query string")
        return
    if "iss" in query:
        provider = query["iss"][0]
    else:
        print("No issuer in query string, will use provider from state")
        provider = None
    code = query["code"][0]
    state = query["state"][0]
    print(f"Provider: {provider}")
    print(f"Code: {code}")
    print(f"State: {state}")
    ctx.invoke(exchange_auth, code=code, state=state, provider=provider, use_client_id_document=use_client_id_document)


@cli_bp.cli.command()
@click.argument("profile")
@click.option("--use-client-id-document", is_flag=True, help="Use client ID document instead of dynamic registration")
def refresh(profile, use_client_id_document):
    provider = solid.lookup_provider_from_profile(profile)
    backend = get_backend()

    c = client.SolidClient(backend, use_client_id_document)
    keypair = solid.load_key(backend.get_relying_party_keys())
    provider_info = backend.get_resource_server_configuration(provider)

    # Use the same authentication method as during initial token exchange
    if use_client_id_document:
        auth = None
    else:
        client_id, client_secret = c.get_client_id_and_secret_for_provider(provider)
        auth = (client_id, client_secret)

    configuration_token = backend.get_configuration_token(provider, profile, use_client_id_document)
    client_id = configuration_token.client_id
    if not configuration_token.has_expired():
        print("Configuration token has not expired, skipping refresh")
        return

    status, resp = solid.refresh_auth_token(keypair, provider_info, client_id, configuration_token, auth)
    print(f"{status=}")
    print(resp)

    if status:
        backend.update_configuration_token(provider, profile, client_id, resp)
        print("Token updated")
    else:
        print(f"Failure updating token: {status}")


def get_uri_jsonld(uri, headers=None):
    if not headers:
        headers = {}
    headers.update({"Accept": "application/ld+json"})
    r = requests.get(uri, headers=headers)
    r.raise_for_status()
    logger.debug("Get json-ld from %s", uri)
    logger.debug("json-ld headers: %s", r.headers)
    logger.debug("json-ld content: %s", json.dumps(r.json(), indent=2))
    return r.json(), r.headers


def get_storage_from_profile_ttl(profile_uri):
    graph = rdflib.Graph()
    graph.parse(profile_uri)
    storage = graph.value(
        subject=rdflib.URIRef(profile_uri), predicate=rdflib.URIRef("http://www.w3.org/ns/pim/space#storage")
    )
    if storage is None:
        print("No storage found")
        return None
    return storage.toPython()


# File commands subcommand group
@cli_bp.cli.group()
def file():
    """File-related commands"""
    pass


@file.command()
@click.argument("profile")
def get_profile(profile):
    """Get a user's profile"""
    profile_json, headers = get_uri_jsonld(profile)
    print("Profile JSON:")
    print(json.dumps(profile_json, indent=2))
    print("Headers:", headers)


@file.command()
@click.argument("profile")
def get_storage(profile):
    """Get a user's storage"""
    storage = get_storage_from_profile_ttl(profile)
    print(f"storage: {storage}")


@file.command()
@click.argument("profile")
@click.argument("directory")
@click.argument("name")
@click.argument("contents")
@click.option("--use-client-id-document", is_flag=True, help="Use client ID document instead of dynamic registration")
def add_file(profile, directory, name, contents, use_client_id_document):
    """Add a file to a directory in the Solid pod"""
    print(f"Adding file to directory: {directory}/{name}")
    c = client.SolidClient(get_backend(), use_client_id_document)

    provider = solid.lookup_provider_from_profile(profile)
    if not provider:
        print("Cannot find provider, quitting")
        return
    storage = get_storage_from_profile_ttl(profile)
    if not storage:
        print("Cannot find storage, quitting")
        return

    file_path = os.path.join(storage, os.path.normpath(os.path.join(directory, name)))
    headers = c.get_bearer_for_user(provider, profile, file_path, "PUT")
    headers.update({"Content-Type": "text/plain"})
    print(f"Headers: {headers}")
    print(f"File path: {file_path}")
    print(f"Contents: {contents}")
    r = requests.put(file_path, data=contents, headers=headers)
    if r.status_code == 201:
        print("Successfully created")
    else:
        print(f"Unexpected status code: {r.status_code}: {r.text}")


@file.command()
@click.argument("profile")
@click.argument("directory")
@click.argument("name")
@click.option("--use-client-id-document", is_flag=True, help="Use client ID document instead of dynamic registration")
def delete_file(profile, directory, name, use_client_id_document):
    """Delete a file from a directory in the Solid pod"""
    print(f"Deleting file: {directory}/{name}")

    c = client.SolidClient(get_backend(), use_client_id_document)

    provider = solid.lookup_provider_from_profile(profile)
    if not provider:
        print("Cannot find provider, quitting")
        return
    storage = get_storage_from_profile_ttl(profile)
    if not storage:
        print("Cannot find storage, quitting")
        return

    file_path = os.path.join(storage, os.path.normpath(os.path.join(directory, name)))
    headers = c.get_bearer_for_user(provider, profile, file_path, "DELETE")
    r = requests.delete(file_path, headers=headers)
    if r.status_code == 205:
        print("Successfully deleted")
    else:
        print(f"Unexpected status code: {r.status_code}: {r.text}")


@file.command()
@click.argument("profile")
@click.argument("directory")
@click.argument("name")
@click.option("--use-client-id-document", is_flag=True, help="Use client ID document instead of dynamic registration")
def get_file(profile, directory, name, use_client_id_document):
    """Get information about a file in the Solid pod"""
    print(f"Getting info for file: {directory}/{name}")

    c = client.SolidClient(get_backend(), use_client_id_document)

    provider = solid.lookup_provider_from_profile(profile)
    if not provider:
        print("Cannot find provider, quitting")
        return
    storage = get_storage_from_profile_ttl(profile)
    if not storage:
        print("Cannot find storage, quitting")
        return

    file_path = os.path.join(storage, os.path.normpath(os.path.join(directory, name)))
    headers = c.get_bearer_for_user(provider, profile, file_path, "GET")
    r = requests.get(file_path, headers=headers)
    if r.status_code == 200:
        print("Successfully got file")
        print(r.text)
    else:
        print(f"Unexpected status code: {r.status_code}: {r.text}")
