import json
import secrets

import jwt
import requests
import requests.utils
from jwcrypto import jwk
from requests import Request


def lookup_provider_from_profile(profile_url: str):
    """

    :param profile_url: The profile of the user, e.g.  https://alice.coolpod.example/profile/card#me
    :return:
    """

    r = requests.options(profile_url)
    links = r.headers.get('Link')
    if links:
        parsed_links = requests.utils.parse_header_links(links)
        for l in parsed_links:
            if l.get('rel') == 'http://openid.net/specs/connect/1.0/issuer':
                return l['url']

    # If we get here, there was no rel in the options. Instead, try and get the card
    # and find its issuer
    # TODO: https://github.com/solid/webid-oidc-spec/blob/master/application-user-workflow.md#21-retrieve-profile
    #  says that we can find the OP url at :me -> solid:oidcIssuer
    #  DW suggests pim:storage, but this is unclear
    r = requests.get(profile_url,
                     headers={"Accept": "application/ld+json"})

    try:
        response = r.json()
        return None
    except json.decoder.JSONDecodeError:
        return None


def get_openid_configuration(op_url):
    """

    :param op_url:
    :return:
    """

    path = "/.well-known/openid-configuration"
    url = op_url + path

    r = requests.get(url, verify=False)
    configuration = r.json()
    return configuration


def load_op_jwks(op_config):
    """
    Download an OP's JSON Web Key Set (jwks) based on a well-known configuration
    :param op_config: a config from `get_openid_configuration`
    :return:
    """
    if "jwks_uri" not in op_config:
        raise ValueError("Cannot find 'jwks_uri'")
    r = requests.get(op_config["jwks_uri"], verify=False)
    return r.json()


def generate_keys():
    """Generate pub/private keys for the Relying Party

    Returns a string containing the json export of the private key
    """
    key = jwk.JWK.generate(kty='RSA', size=2048)
    return key.export_private()


def load_key(keydata):
    return jwk.JWK.from_json(keydata)


def dynamic_registration(provider, redirect_url, op_config):
    """Register an app with a provider"""
    if "registration_endpoint" not in op_config:
        raise ValueError("Cannot find 'registration_endpoint'")

    data = {
        "grant_types": ["implicit"],
        "issuer": provider,
        "redirect_uris": [redirect_url],
        "response_types": ["id_token token"],
        "scope": "openid profile",
        "application_type": "native"
    }

    r = requests.post(op_config["registration_endpoint"], json=data, verify=False)
    return r.json()


def generate_authorization_request(configuration, registration, redirect_url, key: jwk.JWK):
    auth_url = configuration["authorization_endpoint"]
    client_id = registration["client_id"]

    pubkey = key.export_public(as_dict=True)
    pubkey.update({"alg": "RS256", "ext": True, "key_ops": ["verify"]})

    nonce = secrets.token_urlsafe(24)
    request = {
        "redirect_uri": redirect_url,
        "display": "page",
        "nonce": nonce,
        "key": pubkey
    }
    print(request)
    # I can't seem to use jwcrypto to encode a jwt and sign it with the key, so let's just
    # install pyjwt and use that instead
    privatekey = key.export_to_pem(private_key=True, password=None)
    request_jwt = jwt.encode(request, key=None, algorithm=None)

    state = secrets.token_urlsafe(24)
    params = {
        "scope": "openid",
        "client_id": client_id,
        # TODO: This should be the values we added when registering
        "response_type": "id_token token",
        "request": request_jwt,
        "state": state,
    }

    p = Request('GET', auth_url, params=params).prepare()

    return p.url
