import jwcrypto.jwk
import jwcrypto.jwt

from trompasolid.backend import SolidBackend
from trompasolid.dpop import make_token_for


backend: SolidBackend = None


def set_backend(backend_):
    global backend
    backend = backend_


def get_bearer_for_user(provider, user, url, method):
    """Given a solid provider, and a user vcard, get the bearer token needed
    to write to this provider as the user."""

    configuration_token = backend.get_configuration_token(provider, user)
    if not configuration_token:
        raise ValueError("No configuration for this provider/user")

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
