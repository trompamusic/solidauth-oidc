import json
import time
import zlib

import jwcrypto.jwk
import jwcrypto.jwt
import jwt

from trompasolid import solid
from trompasolid.dpop import make_random_string


class NoProviderError(Exception):
    pass


class ClientDoesNotSupportDynamicRegistration(Exception):
    """Raised when a client does not support dynamic registration."""

    pass


class IDTokenValidationError(Exception):
    """Raised when ID token validation fails."""

    pass


def validate_id_token_claims(claims, expected_issuer, client_id, max_age=None, nonce=None):
    """
    Validate ID token claims according to OpenID Connect Core 1.0 specification.

    Args:
        claims: JWT claims dictionary
        expected_issuer: Expected issuer (OP) URL
        client_id: Our client ID
        max_age: Maximum age of token in seconds (optional)
        nonce: Expected nonce value (optional)

    Raises:
        IDTokenValidationError: If any validation fails
    """
    # Validate issuer
    if claims.get("iss") != expected_issuer:
        raise IDTokenValidationError(f"Invalid issuer: expected {expected_issuer}, got {claims.get('iss')}")

    # Validate audience
    aud = claims.get("aud")
    if not aud:
        raise IDTokenValidationError("Missing 'aud' claim")

    # aud can be a string or list of strings
    if isinstance(aud, str):
        if aud != client_id:
            raise IDTokenValidationError(f"Invalid audience: expected {client_id}, got {aud}")
    elif isinstance(aud, list):
        if client_id not in aud:
            raise IDTokenValidationError(f"Client ID {client_id} not in audience list {aud}")
    else:
        raise IDTokenValidationError(f"Invalid 'aud' claim type: {type(aud)}")

    # Validate expiration time
    exp = claims.get("exp")
    if not exp:
        raise IDTokenValidationError("Missing 'exp' claim")

    current_time = int(time.time())
    if exp < current_time:
        raise IDTokenValidationError(f"Token has expired: exp={exp}, current_time={current_time}")

    # Validate issued at time
    iat = claims.get("iat")
    if not iat:
        raise IDTokenValidationError("Missing 'iat' claim")

    # iat should not be in the future (with small tolerance for clock skew)
    clock_skew = 300  # 5 minutes tolerance
    if iat > current_time + clock_skew:
        raise IDTokenValidationError(f"Token issued in the future: iat={iat}, current_time={current_time}")

    # Validate max_age if specified
    if max_age is not None:
        auth_time = claims.get("auth_time")
        if not auth_time:
            raise IDTokenValidationError("max_age specified but 'auth_time' claim missing")

        if auth_time + max_age < current_time:
            raise IDTokenValidationError(f"Token too old: auth_time={auth_time}, max_age={max_age}")

    # Validate nonce if specified
    if nonce is not None:
        token_nonce = claims.get("nonce")
        if not token_nonce:
            raise IDTokenValidationError("nonce expected but missing from token")
        if token_nonce != nonce:
            raise IDTokenValidationError(f"Invalid nonce: expected {nonce}, got {token_nonce}")


def get_client_url_for_issuer(baseurl, issuer):
    if not baseurl.endswith("/"):
        baseurl += "/"
    issuer_hash = zlib.adler32(issuer.encode())
    client_url = baseurl + f"client/{issuer_hash}.jsonld"
    return client_url


def select_jwk_by_kid(jwks, kid):
    """
    Select the correct JWK from a JWKS based on the key ID (kid).

    Args:
        jwks: JSON Web Key Set containing multiple keys
        kid: Key ID to match

    Returns:
        JWK object for the matching key

    Raises:
        ValueError: If no key with the specified kid is found
    """
    if "keys" not in jwks:
        raise ValueError("Invalid JWKS format: missing 'keys' field")

    for key_data in jwks["keys"]:
        if key_data.get("kid") == kid:
            return jwcrypto.jwk.JWK.from_json(json.dumps(key_data))

    # If no kid is specified in the JWT header, try the first key (fallback)
    if kid is None and jwks["keys"]:
        return jwcrypto.jwk.JWK.from_json(json.dumps(jwks["keys"][0]))

    raise ValueError(f"No key found with kid: {kid}")


def get_jwt_kid(token):
    """
    Extract the key ID (kid) from a JWT header without validating the signature.

    Args:
        token: JWT token string

    Returns:
        Key ID from the JWT header, or None if not present
    """
    try:
        header = jwt.get_unverified_header(token)
        return header.get("kid")
    except jwt.DecodeError as e:
        print(f"Error extracting kid from JWT: {e}")
        return None


def generate_authentication_url(
    backend, webid_or_provider, client_name, redirect_url, base_url, always_use_client_url=False
):
    log_messages = []

    if solid.is_webid(webid_or_provider):
        provider = solid.lookup_provider_from_profile(webid_or_provider)
    else:
        provider = webid_or_provider

    if not provider:
        log_messages.append(f"Cannot find a provider for webid {webid_or_provider}")
        raise NoProviderError(f"Cannot find a provider for webid {webid_or_provider}")

    log_messages.append(f"Provider for this user is: {provider}")
    print(f"Provider for this user is: {provider}")

    provider_config = backend.get_resource_server_configuration(provider)
    provider_jwks = backend.get_resource_server_keys(provider)
    if provider_config and provider_jwks:
        log_messages.append(f"Configuration for {provider} already exists, skipping setup")
        print(f"Configuration for {provider} already exists, skipping")
    else:
        provider_config = solid.get_openid_configuration(provider)
        # Get the canonical provider url from the openid configuration (e.g. https://solidcommunity.net vs https://solidcommunity.net/)
        provider = provider_config.get("issuer", provider)
        backend.save_resource_server_configuration(provider, provider_config)

        keys = solid.load_op_jwks(provider_config)
        backend.save_resource_server_keys(provider, keys)

        log_messages.append("Got configuration and jwks for provider")

    if not solid.op_can_do_dynamic_registration(provider_config):
        # Provider doesn't support dynamic registration - this is an error
        raise ClientDoesNotSupportDynamicRegistration(
            f"Provider {provider} does not support dynamic client registration. "
            f"Registration endpoint: {provider_config.get('registration_endpoint', 'not available')}"
        )

    if always_use_client_url:
        # Generate a client URL that points to our client metadata document
        # Section 5 of the Solid-OIDC spec (https://solidproject.org/TR/oidc#clientids) says
        # OAuth and OIDC require the Client application to identify itself to the OP and RS by presenting a client identifier (Client ID). Solid applications SHOULD use a URI that can be dereferenced as a Client ID Document.
        # this means that "token_endpoint_auth_methods_supported" should include "none", otherwise this is not supported
        issuer = provider_config["issuer"]
        client_id = get_client_url_for_issuer(base_url, issuer)
        log_messages.append(f"genererating a dereferenced URL for client_id: {client_id}")
        log_messages.append("Not performing dynamic registration, will use client_id as a URL")
    else:
        log_messages.append("Using dynamic client registration")
        client_registration = backend.get_client_registration(provider)
        if client_registration:
            # TODO: Check if redirect url is the same as the one configured here
            log_messages.append(f"Registration for {provider} already exists, skipping")
        else:
            client_registration = solid.dynamic_registration(provider, client_name, redirect_url, provider_config)
            backend.save_client_registration(provider, client_registration)
            log_messages.append("Registered client with provider")
        client_id = client_registration["client_id"]

    log_messages.append(f"client_id {client_id}")

    code_verifier, code_challenge = solid.make_verifier_challenge()
    state = make_random_string()

    assert backend.get_state_data(state) is None
    backend.set_state_data(state, code_verifier)

    auth_url = solid.generate_authorization_request(provider_config, redirect_url, client_id, state, code_challenge)
    log_messages.append(f"Got an auth url: {auth_url}")

    return {"provider": provider, "auth_url": auth_url, "log_messages": log_messages}


def get_client_id_and_secret_for_provider(backend, provider, base_url, always_use_client_url=False):
    provider_config = backend.get_resource_server_configuration(provider)

    if not always_use_client_url:
        client_registration = backend.get_client_registration(provider)
        if not client_registration:
            raise Exception("Expected to find a registration for a backend but can't get one")
        client_id = client_registration["client_id"]
        client_secret = client_registration["client_secret"]
    else:
        issuer = provider_config["issuer"]
        client_id = get_client_url_for_issuer(base_url, issuer)
        client_secret = None

    return client_id, client_secret


def authentication_callback(backend, auth_code, state, provider, redirect_uri, base_url, always_use_client_url=False):
    provider_config = backend.get_resource_server_configuration(provider)

    client_id, client_secret = get_client_id_and_secret_for_provider(backend, provider, base_url, always_use_client_url)
    auth = (client_id, client_secret) if client_secret else None

    code_verifier = backend.get_state_data(state)
    backend.delete_state_data(state)

    keypair = solid.load_key(backend.get_relying_party_keys())
    assert code_verifier is not None, f"state {state} not in backend?"

    success, resp = solid.validate_auth_callback(
        keypair, code_verifier, auth_code, provider_config, client_id, redirect_uri, auth
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

            # Validate ID token claims according to OpenID Connect Core 1.0
            try:
                validate_id_token_claims(claims, provider, client_id)
            except IDTokenValidationError as e:
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
            backend.save_configuration_token(issuer, webid, sub, resp)

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
