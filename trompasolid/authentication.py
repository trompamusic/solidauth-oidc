import json
import zlib

import jwcrypto.jwt
import jwcrypto.jwk

from trompasolid import solid
from trompasolid.dpop import make_random_string


class NoProviderError(Exception):
    pass


def get_client_url_for_issuer(baseurl, issuer):
    if not baseurl.endswith("/"):
        baseurl += "/"
    issuer_hash = zlib.adler32(issuer.encode())
    client_url = baseurl + f"client/{issuer_hash}.jsonld"
    return client_url


def generate_authentication_url(backend, webid, redirect_url, always_use_client_url=False):
    log_messages = []

    if solid.is_webid(webid):
        provider = solid.lookup_provider_from_profile(webid)
    else:
        provider = webid

    if not provider:
        log_messages.append(f"Cannot find a provider for webid {webid}")
        raise NoProviderError(f"Cannot find a provider for webid {webid}")

    log_messages.append(f"Provider for this user is: {provider}")
    print(f"Provider for this user is: {provider}")

    provider_config = backend.get_resource_server_configuration(provider)
    provider_jwks = backend.get_resource_server_keys(provider)
    if provider_config and provider_jwks:
        log_messages.append(f"Configuration for {provider} already exists, skipping setup")
        print(f"Configuration for {provider} already exists, skipping")
    else:
        provider_config = solid.get_openid_configuration(provider)
        backend.save_resource_server_configuration(provider, provider_config)

        keys = solid.load_op_jwks(provider_config)
        backend.save_resource_server_keys(provider, keys)

        log_messages.append("Got configuration and jwks for provider")

    do_dynamic_registration = solid.op_can_do_dynamic_registration(provider_config) and not always_use_client_url
    log_messages.append(f"Can do dynamic: {solid.op_can_do_dynamic_registration(provider_config)}")

    # By default, try and do dynamic registration.
    # If the OP can't do it, send a client URL
    # If ALWAYS_USE_CLIENT_URL is True, send a client URL

    if do_dynamic_registration:
        log_messages.append("Requested to do dynamic client registration")
        client_registration = backend.get_client_registration(provider)
        if client_registration:
            # TODO: Check if redirect url is the same as the one configured here
            log_messages.append(f"Registration for {provider} already exists, skipping")
        else:
            client_registration = solid.dynamic_registration(provider, redirect_url, provider_config)
            backend.save_client_registration(provider, client_registration)

            log_messages.append("Registered client with provider")
        client_id = client_registration["client_id"]
    else:
        log_messages.append("Requested to use client URL for requests")

        # TODO: For now, generate a random URL based on the issuer + a basic hash.
        #  For testing this might need to be semi-random in case the provider caches it
        issuer = provider_config["issuer"]
        client_id = get_client_url_for_issuer(redirect_url, issuer)
        log_messages.append(f"client_id {client_id}")

    code_verifier, code_challenge = solid.make_verifier_challenge()
    state = make_random_string()

    assert backend.get_state_data(state) is None
    backend.set_state_data(state, code_verifier)

    auth_url = solid.generate_authorization_request(provider_config, redirect_url, client_id, state, code_challenge)
    log_messages.append(f"Got an auth url: {auth_url}")

    return {"provider": provider, "auth_url": auth_url, "log_messages": log_messages}


def authentication_callback(backend, auth_code, state, provider, redirect_uri, always_use_client_url=False):
    provider_config = backend.get_resource_server_configuration(provider)

    do_dynamic_registration = solid.op_can_do_dynamic_registration(provider_config) and not always_use_client_url
    if do_dynamic_registration:
        client_registration = backend.get_client_registration(provider)
        if not client_registration:
            raise Exception("Expected to find a registration for a backend but can't get one")
        client_id = client_registration["client_id"]
        client_secret = client_registration["client_secret"]
        auth = (client_id, client_secret)
    else:
        issuer = provider_config["issuer"]
        client_id = get_client_url_for_issuer(redirect_uri, issuer)
        auth = None

    code_verifier = backend.get_state_data(state)

    keypair = solid.load_key(backend.get_relying_party_keys())
    assert code_verifier is not None, f"state {state} not in backend?"

    success, resp = solid.validate_auth_callback(
        keypair, code_verifier, auth_code, provider_config, client_id, redirect_uri, auth
    )

    if success:
        id_token = resp["id_token"]
        server_key = backend.get_resource_server_keys(provider)
        # TODO: It seems like a server may give more than one key, is this the correct one?
        # TODO: We need to load the jwt, and from its header find the "kid" (key id) parameter
        #  from this, we can load through the list of server_key keys and find the key with this keyid
        #  and then use that key to validate the message
        key = server_key["keys"][0]
        key = jwcrypto.jwk.JWK.from_json(json.dumps(key))
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
        return True, resp
    else:
        print("Error when validating auth callback")
        return False, resp
