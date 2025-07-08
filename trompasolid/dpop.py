import base64
import datetime
import os
import re

import jwcrypto.jwt


def make_token_for(keypair, uri, method):
    now = datetime.datetime.now()
    # DPoP tokens should have a short lifetime (5-10 minutes)
    exp_time = now + datetime.timedelta(minutes=10)

    jwt = jwcrypto.jwt.JWT(
        header={"typ": "dpop+jwt", "alg": "ES256", "jwk": keypair.export(private_key=False, as_dict=True)},
        claims={
            "jti": make_random_string(),
            "htm": method,
            "htu": uri,
            "iat": int(now.timestamp()),
            "exp": int(exp_time.timestamp()),
        },
    )
    jwt.make_signed_token(keypair)
    return jwt.serialize()


def make_random_string():
    x = base64.urlsafe_b64encode(os.urandom(40)).decode("utf-8")
    x = re.sub("[^a-zA-Z0-9]+", "", x)
    return x
