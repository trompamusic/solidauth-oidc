from unittest.mock import patch

from solidauth import httpclient


@patch("solidauth.httpclient.requests.request")
def test_request_adds_configured_user_agent_and_default_timeout(mock_request):
    httpclient.set_user_agent("CLARA/1.0")

    httpclient.request("POST", "https://example.com/token", headers={"DPoP": "a-dpop-token"})

    mock_request.assert_called_once_with(
        "POST",
        "https://example.com/token",
        headers={"DPoP": "a-dpop-token", "User-Agent": "CLARA/1.0"},
        timeout=httpclient.DEFAULT_TIMEOUT,
    )


@patch("solidauth.httpclient.requests.request")
def test_request_preserves_user_agent_and_timeout_overrides(mock_request):
    httpclient.request(
        "GET",
        "https://example.com",
        headers={"user-agent": "Caller/2.0"},
        timeout=(10, 60),
    )

    headers = mock_request.call_args.kwargs["headers"]
    assert headers["User-Agent"] == "Caller/2.0"
    assert len(headers) == 1
    assert mock_request.call_args.kwargs["timeout"] == (10, 60)
