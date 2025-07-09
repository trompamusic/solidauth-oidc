import jwcrypto.jwk
import jwcrypto.jwt

from solidauth import solid
from solidauth.authentication import get_client_id_and_secret_for_provider
from solidauth.backend import SolidBackend
from solidauth.dpop import make_token_for

backend: SolidBackend = None


def set_backend(backend_):
    global backend
    backend = backend_


def get_bearer_for_user(provider, profile, url, method, client_id_document_url=None):
    """Given a solid provider, and a user vcard, get the bearer token needed
    to write to this provider as the user."""

    lookup_client_id_from_registration = True
    client_id = None
    if client_id_document_url:
        configuration_token = backend.get_configuration_token(provider, profile, client_id_document_url)
        if configuration_token:
            client_id = client_id_document_url
            lookup_client_id_from_registration = False

    if lookup_client_id_from_registration:
        # Either client_id_document_url was not provided, or it was provided but we didn't find a configuration token for it
        client_registration = backend.get_client_registration(provider)
        if client_registration:
            client_id = client_registration["client_id"]
            configuration_token = backend.get_configuration_token(provider, profile, client_id)
            if not configuration_token:
                raise ValueError("No configuration for this provider/user")
        else:
            raise ValueError("No client registration found and no client_id_document_url provided")

    access_token = configuration_token.data["access_token"]

    if configuration_token.has_expired():
        print(f"Token for {profile} has expired, refreshing")

        refresh_token = configuration_token.data["refresh_token"]
        keypair = solid.load_key(backend.get_relying_party_keys())
        provider_info = backend.get_resource_server_configuration(provider)

        if client_id_document_url is not None:
            auth = None
        else:
            # TODO: This looks up registration data twice (above, and now)
            client_id, client_secret = get_client_id_and_secret_for_provider(backend, provider)
            auth = (client_id, client_secret)

        status, resp = solid.refresh_auth_token(keypair, provider_info, client_id, configuration_token, auth)
        if status:
            if "refresh_token" not in resp:
                resp.update({"refresh_token": refresh_token})
            access_token = resp["access_token"]
            backend.update_configuration_token(provider, profile, client_id, resp)
            print("... refreshed")
        else:
            print("... refresh failed")

    key = backend.get_relying_party_keys()
    private_key = jwcrypto.jwk.JWK.from_json(key)
    # CSS Fails with a cryptic error if this field doesn't exist
    private_key["alg"] = "RS256"

    headers = {"Authorization": ("DPoP " + access_token), "DPoP": make_token_for(private_key, url, method)}

    return headers
