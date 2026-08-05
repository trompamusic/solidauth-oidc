import pytest

from solidauth import httpclient


@pytest.fixture(autouse=True)
def reset_user_agent():
    """Reset the user agent after each test."""
    original = httpclient.get_user_agent()
    yield
    httpclient.set_user_agent(original)
