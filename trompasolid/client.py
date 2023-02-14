import jwcrypto.jwk
import jwcrypto.jwt
import requests
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

import solid
from trompasolid.backend.db_backend import DBBackend

engine = create_engine("postgresql+psycopg2://localhost/solid_oidc")
session = Session(engine)
backend = DBBackend(session)


def get_bearer_for_user(provider, user, url, method):
    """Given a solid provider, and a user vcard, get the bearer token needed
    to write to this provider as the user."""

    access_keys = backend.get_configuration_token(provider, user)
    if not access_keys:
        raise ValueError("No configuration for this provider/user")

    key = backend.get_relying_party_keys()
    private_key = jwcrypto.jwk.JWK.from_json(key)
    # CSS Fails with a cryptic error if this field doesn't exist
    private_key['alg'] = "RS256"

    # TODO: Refresh token when it has expired
    access_token = access_keys['access_token']

    headers = {
        'Authorization': ('DPoP ' + access_token),
        'DPoP': solid.make_token_for(private_key, url, method)
    }

    return headers
