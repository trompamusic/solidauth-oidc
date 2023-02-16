import base64
import datetime
import os
import re

import jwcrypto.jwt


def make_token_for(keypair, uri, method):
    jwt = jwcrypto.jwt.JWT(
        header={
            "typ": "dpop+jwt",
            "alg": "ES256",
            "jwk": keypair.export(private_key=False, as_dict=True)
        },
        claims={
           "jti": make_random_string(),
           "htm": method,
           "htu": uri,
           "iat": int(datetime.datetime.now().timestamp())
        }
    )
    jwt.make_signed_token(keypair)
    return jwt.serialize()


def make_random_string():
    x = base64.urlsafe_b64encode(os.urandom(40)).decode('utf-8')
    x = re.sub('[^a-zA-Z0-9]+', '', x)
    return x
