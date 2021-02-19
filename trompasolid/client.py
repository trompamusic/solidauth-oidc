import time
import uuid

import jwt
import redis
from jwcrypto import jwk


_redis = None


def init_redis(host="localhost", port=6379):
    global _redis
    _redis = redis.Redis(host=host, port=port)


def get_bearer_for_user(provider, user):
    """Given a solid provider, and a user vcard, get the bearer token needed
    to write to this provider as the user."""
    if _redis is None:
        raise ValueError("Must call init_redis first")

    token_r_key = f"solidauth-rs-token-{provider}-{user}"
    id_token = _redis.get(token_r_key).decode("utf-8")
    jwk_r_key = "solidauth-local-key"
    local_jwk = _redis.get(jwk_r_key)
    private_key = jwk.JWK.from_json(local_jwk)

    # TODO: Check that the signature is signed with the pubkey of the above private key
    decoded_id_token = jwt.decode(id_token, algorithms=["RS256"], options={"verify_signature": False})

    now = time.time()
    # TODO: Expires in 1000 seconds from now. This could be configurable
    expires = now + 1000

    pop_token = {
        # The issuer of the pop is the audience of the auth token
        "iss": decoded_id_token['aud'],
        "aud": "https://trompa-solid.upf.edu",
        "exp": expires,
        "iat": now,
        "id_token": id_token,
        "token_type": "pop",
        "jti": str(uuid.uuid4())
    }

    bearer = jwt.encode(pop_token, key=private_key.export_to_pem(True, None), algorithm="RS256")

    return bearer
