import base64
import hashlib
import urllib.parse
from urllib.error import HTTPError

import rdflib
import requests
import requests.utils
import jwcrypto.jwk
import jwcrypto.jwt
from oic.oic import Client as OicClient
from oic.utils.authn.client import CLIENT_AUTHN_METHOD

from trompasolid.dpop import make_random_string, make_token_for


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
    key = jwcrypto.jwk.JWK.generate(kty='EC', crv='P-256')
    return key.export_private()


def load_key(keydata):
    return jwcrypto.jwk.JWK.from_json(keydata)


def op_can_do_dynamic_registration(op_config):
    return "registration_endpoint" in op_config


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


def make_verifier_challenge():
    code_verifier = make_random_string()

    code_challenge = hashlib.sha256(code_verifier.encode('utf-8')).digest()
    code_challenge = base64.urlsafe_b64encode(code_challenge).decode('utf-8')
    code_challenge = code_challenge.replace('=', '')

    return code_verifier, code_challenge


def generate_authorization_request(configuration, redirect_url, client_id, state, code_challenge):
    auth_url = configuration["authorization_endpoint"]

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


def validate_auth_callback(keypair, code_verifier, auth_code, provider_info, client_id, redirect_uri, auth=None):
    # Exchange auth code for access token
    resp = requests.post(
        url=provider_info['token_endpoint'],
        data={
            "grant_type": "authorization_code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "code": auth_code,
            "code_verifier": code_verifier,
        },
        headers={
            "DPoP": make_token_for(keypair, provider_info["token_endpoint"], "POST")
        },
        # TODO: Community Solid Server seems to think that we're doing Basic Auth with the client id
        #  and secret, even though with my understanding, PKCE means that it's unnecessary. Unsure of if
        #  this is due to CSS or something during dynamic registration
        #  NSS doesn't seem to have this problem
        auth=auth,
        allow_redirects=False)
    try:
        resp.raise_for_status()
        result = resp.json()
        return result
    except requests.exceptions.HTTPError:
        print(resp.text)
        return None
