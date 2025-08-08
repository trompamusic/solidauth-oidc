import json
import logging

import jwcrypto.jwk
import jwcrypto.jwt

from solidauth import dpop, solid
from solidauth.backend import SolidBackend
from solidauth.dpop import make_token_for

logger = logging.getLogger(__name__)


class TokenRefreshFailed(Exception):
    pass


class NoProviderError(Exception):
    pass


class NoSuchAuthenticationError(Exception):
    """Raised if there is no authentication for a given provider and profile."""

    pass


class ClientDoesNotSupportDynamicRegistration(Exception):
    """Raised when a client does not support dynamic registration."""

    pass


class BadClientIdError(Exception):
    """Raised when client registration is missing or invalid."""

    pass


class ClientIDDocumentRegistrationNotSupportedError(Exception):
    """Raised when client ID document registration is not supported by the provider."""

    pass


class SolidClient:
    def __init__(self, backend: SolidBackend, use_client_id_document: bool):
        self.backend = backend
        self.use_client_id_document = use_client_id_document

    def get_bearer_for_user(self, provider, profile, url, method):
        """Given a solid provider, and a user vcard, get the bearer token needed
        to write to this provider as the user."""

        configuration_token = self.backend.get_configuration_token(provider, profile, self.use_client_id_document)
        if configuration_token is None:
            raise NoSuchAuthenticationError(f"No authentication found for {profile} and {provider}")

        client_id = configuration_token.client_id
        if configuration_token.has_expired():
            logger.debug(f"Token for {profile} has expired, refreshing")

            refresh_token = configuration_token.data["refresh_token"]
            keypair = solid.load_key(self.backend.get_relying_party_keys())
            provider_info = self.backend.get_resource_server_configuration(provider)

            if self.use_client_id_document:
                auth = None
            else:
                # TODO: This looks up registration data twice (above, and now)
                client_id, client_secret = self.get_client_id_and_secret_for_provider(provider)
                auth = (client_id, client_secret)

            status, resp = solid.refresh_auth_token(keypair, provider_info, client_id, configuration_token, auth)
            if status:
                if "refresh_token" not in resp:
                    resp.update({"refresh_token": refresh_token})
                access_token = resp["access_token"]
                self.backend.update_configuration_token(provider, profile, client_id, resp)
                logger.debug("... refreshed")
            else:
                logger.debug("... refresh failed")
                raise TokenRefreshFailed()

        key = self.backend.get_relying_party_keys()
        private_key = jwcrypto.jwk.JWK.from_json(key)
        # CSS Fails with a cryptic error if this field doesn't exist
        private_key["alg"] = "RS256"

        headers = {"Authorization": ("DPoP " + access_token), "DPoP": make_token_for(private_key, url, method)}

        return headers

    def generate_authentication_url(
        self, webid_or_provider, registration_request, redirect_url, client_id_document_url=None
    ):
        if client_id_document_url is None and self.use_client_id_document:
            raise ValueError("client_id_document_url is required when use_client_id_document is True")

        log_messages = []

        if solid.is_webid(webid_or_provider):
            provider = solid.lookup_provider_from_profile(webid_or_provider)
        else:
            provider = webid_or_provider

        if not provider:
            log_messages.append(f"Cannot find a provider for webid {webid_or_provider}")
            raise NoProviderError(f"Cannot find a provider for webid {webid_or_provider}")

        log_messages.append(f"Provider for this user is: {provider}")
        logger.debug(f"Provider for this user is: {provider}")

        provider_config = self.backend.get_resource_server_configuration(provider)
        provider_jwks = self.backend.get_resource_server_keys(provider)
        if provider_config and provider_jwks:
            log_messages.append(f"Configuration for {provider} already exists, skipping setup")
            logger.debug(f"Configuration for {provider} already exists, skipping")
        else:
            provider_config = solid.get_openid_configuration(provider)
            # Get the canonical provider url from the openid configuration (e.g. https://solidcommunity.net vs https://solidcommunity.net/)
            provider = provider_config.get("issuer", provider)
            self.backend.save_resource_server_configuration(provider, provider_config)

            keys = solid.load_op_jwks(provider_config)
            self.backend.save_resource_server_keys(provider, keys)

            log_messages.append("Got configuration and jwks for provider")

        if not solid.op_can_do_dynamic_registration(provider_config):
            # Provider doesn't support dynamic registration - this is an error
            raise ClientDoesNotSupportDynamicRegistration(
                f"Provider {provider} does not support dynamic client registration. "
                f"Registration endpoint: {provider_config.get('registration_endpoint', 'not available')}"
            )

        if client_id_document_url:
            # Check if the provider supports client ID document registration
            if not solid.op_supports_client_id_document_registration(provider_config):
                raise ClientIDDocumentRegistrationNotSupportedError(
                    f"Provider {provider} does not support client ID document registration. "
                    f"The provider must support the 'webid' scope and either have no registration endpoint "
                    f"auth methods or support the 'none' auth method."
                )
            client_id = client_id_document_url
            log_messages.append(f"Using a client id document: {client_id}")
            log_messages.append("Not performing dynamic registration, will use client_id as a URL")
        else:
            log_messages.append("Using dynamic client registration")
            client_registration = self.backend.get_client_registration(provider)
            if client_registration:
                # TODO: Check if redirect url is the same as the one configured here
                log_messages.append(f"Registration for {provider} already exists, skipping")
            else:
                client_registration = solid.dynamic_registration(registration_request, provider_config)
                self.backend.save_client_registration(provider, client_registration)
                log_messages.append("Registered client with provider")
            client_id = client_registration["client_id"]

        log_messages.append(f"client_id {client_id}")

        code_verifier, code_challenge = solid.make_verifier_challenge()
        state = dpop.make_random_string()

        assert self.backend.get_state_data(state) is None
        self.backend.set_state_data(state, code_verifier, provider)

        auth_url = solid.generate_authorization_request(provider_config, redirect_url, client_id, state, code_challenge)
        log_messages.append(f"Got an auth url: {auth_url}")

        return {"provider": provider, "auth_url": auth_url, "log_messages": log_messages}

    def get_client_id_and_secret_for_provider(self, provider):
        client_registration = self.backend.get_client_registration(provider)
        if not client_registration:
            raise BadClientIdError(f"No client registration found for provider {provider}")

        if "client_id" not in client_registration:
            raise BadClientIdError(f"Client registration for provider {provider} is missing client_id")

        if "client_secret" not in client_registration:
            raise BadClientIdError(f"Client registration for provider {provider} is missing client_secret")

        client_id = client_registration["client_id"]
        client_secret = client_registration["client_secret"]

        return client_id, client_secret

    def authentication_callback(self, auth_code, state, provider, redirect_uri, client_id_document_url=None):
        backend_state = self.backend.get_state_data(state)

        if backend_state is None:
            return False, {
                "error": "invalid_state",
                "error_description": f"State '{state}' not found or already used. Please start a new authentication flow.",
            }

        code_verifier = backend_state["code_verifier"]

        if provider is None:
            provider = backend_state["issuer"]
        self.backend.delete_state_data(state)

        provider_config = self.backend.get_resource_server_configuration(provider)

        if client_id_document_url:
            client_id = client_id_document_url
            auth = None
        else:
            client_id, client_secret = self.get_client_id_and_secret_for_provider(provider)
            auth = (client_id, client_secret)

        keypair = solid.load_key(self.backend.get_relying_party_keys())
        assert code_verifier is not None, f"state {state} not in backend?"

        success, resp = solid.validate_auth_callback(
            keypair, code_verifier, auth_code, provider_config, client_id, redirect_uri, auth
        )

        if success:
            id_token = resp["id_token"]
            server_jwks = self.backend.get_resource_server_keys(provider)

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
                    logger.debug("ID token validation failed", exc_info=e)
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
                self.backend.save_configuration_token(issuer, webid, sub, client_id, resp)

                return True, resp

            except ValueError as e:
                logger.debug("Error selecting JWK", exc_info=e)
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
                logger.debug("Error validating ID token", exc_info=e)
                return False, {"error": "invalid_token", "error_description": str(e)}
        else:
            logger.debug("Error when validating auth callback")
            return False, resp
