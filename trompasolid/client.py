import jwcrypto.jwk
import jwcrypto.jwt

from trompasolid.backend import SolidBackend
from trompasolid.dpop import make_token_for
from trompasolid import solid


backend: SolidBackend = None


def set_backend(backend_):
    global backend
    backend = backend_


def get_bearer_for_user(provider, profile, url, method):
    """Given a solid provider, and a user vcard, get the bearer token needed
    to write to this provider as the user."""

    configuration_token = backend.get_configuration_token(provider, profile)
    if not configuration_token:
        raise ValueError("No configuration for this provider/user")

    if configuration_token.has_expired():
        print(f"Token for {profile} has expired, refreshing")
        client_registration = backend.get_client_registration(provider)

        refresh_token = configuration_token.data["refresh_token"]
        token_data = configuration_token.data
        token_data.update({"refresh_token": refresh_token})
        keypair = solid.load_key(backend.get_relying_party_keys())
        provider_info = backend.get_resource_server_configuration(provider)
        resp = solid.refresh_auth_token(keypair, provider_info, client_registration["client_id"], token_data)

        backend.update_configuration_token(provider, profile, resp)
        print("... refreshed")

    key = backend.get_relying_party_keys()
    private_key = jwcrypto.jwk.JWK.from_json(key)
    # CSS Fails with a cryptic error if this field doesn't exist
    private_key['alg'] = "RS256"

    # TODO: Refresh token when it has expired
    access_keys = configuration_token.data
    access_token = access_keys['access_token']

    headers = {
        'Authorization': ('DPoP ' + access_token),
        'DPoP': make_token_for(private_key, url, method)
    }

    return headers
