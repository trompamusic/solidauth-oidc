import base64
import hashlib
import logging
import urllib.parse
from urllib.error import HTTPError

import jwcrypto.jwk
import jwcrypto.jwt
import rdflib
import requests
import requests.utils
from oic.oic import Client as OicClient
from oic.utils.authn.client import CLIENT_AUTHN_METHOD

from solidauth.dpop import make_random_string, make_token_for

logger = logging.getLogger(__name__)


def lookup_provider_from_profile(profile_url: str):
    """

    :param profile_url: The profile of the user, e.g.  https://alice.coolpod.example/profile/card#me
    :return:
    """

    r = requests.options(profile_url, timeout=10)
    r.raise_for_status()
    links = r.headers.get("Link")
    if links:
        parsed_links = requests.utils.parse_header_links(links)
        for l in parsed_links:
            if l.get("rel") == "http://openid.net/specs/connect/1.0/issuer":
                return l["url"]

    # If we get here, there was no rel in the options. Instead, try and get the card
    # and find its issuer
    graph = rdflib.Graph()
    try:
        graph.parse(profile_url)
        issuer = rdflib.URIRef("http://www.w3.org/ns/solid/terms#oidcIssuer")
        triples = list(graph.triples((None, issuer, None)))
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
    try:
        provider = lookup_provider_from_profile(url)
        return provider is not None
    except HTTPError:
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

    r = requests.get(url, timeout=10)
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
    r = requests.get(op_config["jwks_uri"], timeout=10)
    r.raise_for_status()
    return r.json()


def generate_keys():
    """Generate pub/private keys for the Relying Party

    Returns a string containing the json export of the private key
    """
    key = jwcrypto.jwk.JWK.generate(kty="EC", crv="P-256")
    return key.export_private()


def load_key(keydata):
    return jwcrypto.jwk.JWK.from_json(keydata)


def op_can_do_dynamic_registration(op_config):
    return "registration_endpoint" in op_config


def op_supports_client_id_document_registration(op_config):
    """
    Check if a Solid Provider supports client ID document registration.

    According to the Solid-OIDC specification, this is becoming the preferred way to identify a client:
    https://solidproject.org/TR/oidc#clientids
    > Solid applications SHOULD use a URI that can be dereferenced as a [Client ID Document](https://solidproject.org/TR/oidc#clientids-document).

    The linked Github issue at https://github.com/solid/solid-oidc/issues/78 seems to indicate that the "token endpoint authentication" value of "none"
    indicates that this is how to specify that a server can support it (https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication),
    the field in the well-known RS configuration is "token_endpoint_auth_methods_supported".
    However inrupt pod spaces (ESS) and trinpod do not report "none" in this endpoint but do allow authentication with a client id document.

    Inrupt has some documentation about this: https://docs.inrupt.com/developer-tools/javascript/client-libraries/tutorial/authenticate-client/
    > A Client ID can be:
    > - a URL that dereferences to a [Client ID Document](https://solid.github.io/solid-oidc/#clientids-document).
    > - a value that has been registered using either [OIDC dynamic or static registration](https://solid.github.io/solid-oidc/#clientids-oidc).

    Looking through the source of inrupt solid-client-authn with the help of cursor, it seems that the library checks that
    "scopes_supported" includes "webid".

    This is reported in the solid-oidc spec as:
    > An OpenID Provider that conforms to the Solid-OIDC specification MUST advertise it in the OpenID Connect Discovery 1.0 [OIDC.Discovery](https://solidproject.org/TR/oidc#biblio-oidcdiscovery) resource by including `webid` in its `scopes_supported` metadata property.

    in Testing, only solidweb.org (NSS) didn't support a client id document, and in fact it doesn't include "webid" in the supported scopes.
    It seems that if a provider app fully supports the solid spec then it will both include webid, and will support client id documents

    Therefore we only test that the provider supports "webid" in its scopes_supported.

    Args:
        op_config: OpenID Provider configuration dictionary

    Returns:
        bool: True if client ID document registration is supported, False otherwise
    """
    # Check if the provider supports the 'webid' scope
    scopes_supported = op_config.get("scopes_supported", [])
    if "webid" not in scopes_supported:
        return False

    return True


def dynamic_registration(registration_request, op_config):
    """Register an app with a provider"""
    if "registration_endpoint" not in op_config:
        raise ValueError("Cannot find 'registration_endpoint'")

    client = OicClient(client_authn_method=CLIENT_AUTHN_METHOD)
    registration_response = client.register(op_config["registration_endpoint"], **registration_request)
    print("Registration response:", registration_response)
    return registration_response.to_dict()


def make_verifier_challenge():
    code_verifier = make_random_string()

    code_challenge = hashlib.sha256(code_verifier.encode("utf-8")).digest()
    code_challenge = base64.urlsafe_b64encode(code_challenge).decode("utf-8")
    code_challenge = code_challenge.replace("=", "")

    return code_verifier, code_challenge


def generate_authorization_request(configuration, redirect_url, client_id, state, code_challenge):
    auth_url = configuration["authorization_endpoint"]

    query = urllib.parse.urlencode(
        {
            "response_type": "code",
            "redirect_uri": redirect_url,
            "code_challenge": code_challenge,
            "state": state,
            "code_challenge_method": "S256",
            "client_id": client_id,
            # offline_access: also asks for refresh token
            "scope": "openid webid offline_access",
            "prompt": "consent",
        }
    )

    url = auth_url + "?" + query
    return url


def validate_auth_callback(keypair, code_verifier, auth_code, provider_info, client_id, redirect_uri, auth=None):
    # Exchange auth code for access token
    resp = requests.post(
        url=provider_info["token_endpoint"],
        data={
            "grant_type": "authorization_code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "code": auth_code,
            "code_verifier": code_verifier,
        },
        headers={"DPoP": make_token_for(keypair, provider_info["token_endpoint"], "POST")},
        # This is `client_secret_basic` Client authentication method:https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication
        # and is one of the options reported by the RS in token_endpoint_auth_methods_supported
        auth=auth,
        allow_redirects=False,
        timeout=10,
    )
    try:
        resp.raise_for_status()
        result = resp.json()
        return True, result
    except requests.exceptions.HTTPError:
        try:
            data = resp.json()
        except ValueError:
            data = resp.text
        return False, data


def refresh_auth_token(keypair, provider_info, client_id, configuration_token, auth=None):
    refresh_token = configuration_token.data["refresh_token"]
    resp = requests.post(
        url=provider_info["token_endpoint"],
        data={
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": client_id,
        },
        headers={"DPoP": make_token_for(keypair, provider_info["token_endpoint"], "POST")},
        auth=auth,
        allow_redirects=False,
        timeout=10,
    )
    try:
        resp.raise_for_status()
        result = resp.json()
        return True, result
    except requests.exceptions.HTTPError:
        print(f"Error refreshing token: HTTP {resp.status_code}")
        print(f"Response headers: {dict(resp.headers)}")
        print(f"Response body: {resp.text}")
        try:
            data = resp.json()
        except ValueError:
            data = resp.text
        return False, data
