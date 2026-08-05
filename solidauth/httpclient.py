from importlib.metadata import PackageNotFoundError, version

import requests
from requests.structures import CaseInsensitiveDict

try:
    DEFAULT_USER_AGENT = f"solidauth/{version('solidauth-oidc')}"
except PackageNotFoundError:
    DEFAULT_USER_AGENT = "solidauth/dev"

DEFAULT_TIMEOUT = 10

_user_agent = DEFAULT_USER_AGENT


def set_user_agent(user_agent: str) -> None:
    """Set the User-Agent used by subsequent solidauth requests."""
    global _user_agent
    _user_agent = user_agent


def get_user_agent() -> str:
    return _user_agent


def request(method: str, url: str, **kwargs) -> requests.Response:
    """Send a request with requests with the configured User-Agent and a default timeout."""
    headers = CaseInsensitiveDict({"User-Agent": _user_agent})
    headers.update(kwargs.pop("headers", None) or {})
    kwargs.setdefault("timeout", DEFAULT_TIMEOUT)
    return requests.request(method, url, headers=headers, **kwargs)
