import base64
import datetime
import hashlib
import os
import re
import urllib.parse
from urllib.error import HTTPError

import rdflib
import requests
import requests.utils
from flask import request
from jwcrypto import jwk
import jwcrypto.jwt
from oic.oic import Client as OicClient
from oic.utils.authn.client import CLIENT_AUTHN_METHOD

# TODO: This should be in a flask session or in the DB
STATE_STORAGE = {}

def lookup_provider_from_profile(profile_url: str):
    """

    :param profile_url: The profile of the user, e.g.  https://alice.coolpod.example/profile/card#me
    :return:
    """

    r = requests.options(profile_url)
    r.raise_for_status()
    links = r.headers.get('Link')
    if links:
        parsed_links = requests.utils.parse_header_links(links)
        for l in parsed_links:
            if l.get('rel') == 'http://openid.net/specs/connect/1.0/issuer':
                return l['url']

    # If we get here, there was no rel in the options. Instead, try and get the card
    # and find its issuer
    graph = rdflib.Graph()
    try:
        graph.parse(profile_url)
        issuer = rdflib.URIRef("http://www.w3.org/ns/solid/terms#oidcIssuer")
        triples = list(graph.triples([None, issuer, None]))
        if triples:
            # first item in the response, 3rd item in the triple
            return triples[0][2].toPython()
    except HTTPError as e:
        if e.status == 404:
            print("Cannot find a profile at this url")
        else:
            raise e


def is_webid(url: str):
    """See if a URL is of a web id or a provider"""

    # TODO: Duplicates `lookup_provider_from_profile`
    # TODO: If we do this once, we can take advantage of it and also get the values
    r = requests.options(url)
    r.raise_for_status()
    links = r.headers.get('Link')
    if links:
        parsed_links = requests.utils.parse_header_links(links)
        for l in parsed_links:
            if l.get('rel') == 'http://openid.net/specs/connect/1.0/issuer':
                return True

    # If we get here, there was no rel in the options. Instead, try and get the card
    # and find its issuer
    graph = rdflib.Graph()
    try:
        graph.parse(url)
        issuer = rdflib.URIRef("http://www.w3.org/ns/solid/terms#oidcIssuer")
        triples = list(graph.triples([None, issuer, None]))
        if triples:
            return True
    except HTTPError:
        pass

    return False


def get_openid_configuration(op_url):
    """

    :param op_url:
    :return:
    """

    # https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationRequest
    # An issuer could contain a path component, the openid configuration location is appended to it.
    path = ".well-known/openid-configuration"
    if op_url.endswith("/"):
        url = op_url + path
    else:
        url = op_url + "/" + path

    r = requests.get(url, verify=False)
    r.raise_for_status()
    return r.json()


def load_op_jwks(op_config):
    """
    Download an OP's JSON Web Key Set (jwks) based on a well-known configuration
    :param op_config: a config from `get_openid_configuration`
    :return:
    """
    if "jwks_uri" not in op_config:
        raise ValueError("Cannot find 'jwks_uri'")
    r = requests.get(op_config["jwks_uri"], verify=False)
    r.raise_for_status()
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

    registration_response = OicClient(
        client_authn_method=CLIENT_AUTHN_METHOD).register(
            op_config['registration_endpoint'],
            redirect_uris=[redirect_url])
    print("Registration response:", registration_response)
    return registration_response.to_dict()


def make_random_string():
    x = base64.urlsafe_b64encode(os.urandom(40)).decode('utf-8')
    x = re.sub('[^a-zA-Z0-9]+', '', x)
    return x


def make_verifier_challenge():
    code_verifier = make_random_string()

    code_challenge = hashlib.sha256(code_verifier.encode('utf-8')).digest()
    code_challenge = base64.urlsafe_b64encode(code_challenge).decode('utf-8')
    code_challenge = code_challenge.replace('=', '')

    return code_verifier, code_challenge


def generate_authorization_request_external_id(configuration, redirect_url, client_id):
    auth_url = configuration["authorization_endpoint"]


    code_verifier, code_challenge = make_verifier_challenge()
    state = make_random_string()
    assert state not in STATE_STORAGE
    STATE_STORAGE[state] = {
        'code_verifier': code_verifier,
        'redirect_url': request.url
    }

    query = urllib.parse.urlencode({
        "response_type": "code",
        "redirect_uri": redirect_url,
        "code_challenge": code_challenge,
        "state": state,
        "code_challenge_method": "S256",
        "client_id": client_id,
        # offline_access: also asks for refresh token
        "scope": "openid webid offline_access",
    })

    url = auth_url + '?' + query
    return url



def generate_authorization_request(configuration, registration, redirect_url, key: jwk.JWK):
    auth_url = configuration["authorization_endpoint"]
    client_id = registration["client_id"]

    pubkey = key.export_public(as_dict=True)
    pubkey.update({"alg": "RS256", "ext": True, "key_ops": ["verify"]})

    code_verifier, code_challenge = make_verifier_challenge()
    state = make_random_string()
    assert state not in STATE_STORAGE
    STATE_STORAGE[state] = {
        'code_verifier': code_verifier,
        'redirect_url': request.url
    }

    query = urllib.parse.urlencode({
        "code_challenge": code_challenge,
        "state": state,
        "response_type": "code",
        "redirect_uri": redirect_url,
        "code_challenge_method": "S256",
        "client_id": client_id,
        # offline_access: also asks for refresh token
        "scope": "openid offline_access",
    })
    url = auth_url + '?' + query
    return url

    """
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
        "response_type": "id_token",
        "request": request_jwt,
        "state": state,
    }

    p = Request('GET', auth_url, params=params).prepare()

    return p.url
    """

def make_token_for(keypair, uri, method):
    jwt = jwcrypto.jwt.JWT(header={
        "typ":
        "dpop+jwt",
        "alg":
        "ES256",
        "jwk":
        keypair.export(private_key=False, as_dict=True)
    },
                           claims={
                               "jti": make_random_string(),
                               "htm": method,
                               "htu": uri,
                               "iat": int(datetime.datetime.now().timestamp())
                           })
    jwt.make_signed_token(keypair)
    return jwt.serialize()


def validate_auth_callback(auth_code, state, provider_info, client_id, redirect_uri):
    assert state in STATE_STORAGE, f"state {state} not in STATE_STORAGE?"


    # Generate a key-pair.
    keypair = jwcrypto.jwk.JWK.generate(kty='EC', crv='P-256')

    code_verifier = STATE_STORAGE[state].pop('code_verifier')
    print(f"Code verifier: {code_verifier}")
    print(f"{client_id=}")
    print(f"{redirect_uri=}")
    print(f"{auth_code=}")
    print(f"{provider_info['token_endpoint']=}")

    # Exchange auth code for access token
    resp = requests.post(url=provider_info['token_endpoint'],
                         data={
                             "grant_type": "authorization_code",
                             "client_id": client_id,
                             "redirect_uri": redirect_uri,
                             "code": auth_code,
                             "code_verifier": code_verifier,
                         },
                         headers={
                             'DPoP':
                                 make_token_for(
                                     keypair, provider_info['token_endpoint'],
                                     'POST')
                         },
                         allow_redirects=False)
    result = resp.json()
    print("exchange result", result)

    return {
        "key": keypair.export(),
        "result": result
    }