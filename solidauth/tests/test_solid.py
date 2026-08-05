from unittest.mock import Mock, patch

import pytest
import requests

from solidauth import httpclient, solid


class TestLookupProviderFromProfile:
    """Test cases for the lookup_provider_from_profile function."""

    @patch("solidauth.solid.httpclient.request")
    def test_lookup_provider_from_profile_with_link_header(self, mock_request):
        """Test that provider is found via Link header."""
        mock_response = Mock()
        mock_response.headers = {"Link": '<https://example.com>; rel="http://openid.net/specs/connect/1.0/issuer"'}
        mock_request.return_value = mock_response

        result = solid.lookup_provider_from_profile("https://alice.example.com/profile/card#me")

        assert result == "https://example.com"
        mock_request.assert_called_once_with("OPTIONS", "https://alice.example.com/profile/card#me")

    @patch("solidauth.solid.httpclient.request")
    def test_lookup_provider_from_profile_with_rdf_data(self, mock_request):
        """Provider is found in the profile card when there is no Link header."""
        options_response = Mock()
        options_response.headers = {}
        card_response = Mock()
        card_response.headers = {"Content-Type": "text/turtle"}
        card_response.text = (
            "<https://alice.example.com/profile/card#me> "
            "<http://www.w3.org/ns/solid/terms#oidcIssuer> <https://op.example.com> ."
        )
        # First call is the OPTIONS probe, second is fetch_graph's GET for the card.
        mock_request.side_effect = [options_response, card_response]

        result = solid.lookup_provider_from_profile("https://alice.example.com/profile/card#me")

        assert result == "https://op.example.com"

    @patch("solidauth.solid.fetch_graph")
    @patch("solidauth.solid.httpclient.request")
    def test_lookup_provider_from_profile_no_provider_found(self, mock_request, mock_fetch_graph):
        """Test that None is returned when the card has no issuer triple."""
        mock_response = Mock()
        mock_response.headers = {}
        mock_request.return_value = mock_response

        mock_graph = Mock()
        mock_graph.triples.return_value = []
        mock_fetch_graph.return_value = mock_graph

        result = solid.lookup_provider_from_profile("https://alice.example.com/profile/card#me")

        assert result is None

    @patch("solidauth.solid.httpclient.request")
    def test_lookup_provider_from_profile_falls_back_to_card_when_options_fails(self, mock_request):
        """An OPTIONS failure is non-fatal: fall back to the card GET, which finds the issuer."""
        card_response = Mock()
        card_response.headers = {"Content-Type": "text/turtle"}
        card_response.text = (
            "<https://alice.example.com/profile/card#me> "
            "<http://www.w3.org/ns/solid/terms#oidcIssuer> <https://op.example.com> ."
        )
        # OPTIONS raises; the following card GET succeeds.
        mock_request.side_effect = [requests.exceptions.ConnectionError("boom"), card_response]

        result = solid.lookup_provider_from_profile("https://alice.example.com/profile/card#me")

        assert result == "https://op.example.com"

    @patch("solidauth.solid.httpclient.request")
    def test_lookup_provider_from_profile_returns_none_when_options_and_card_both_fail(self, mock_request):
        """None only when both the OPTIONS probe and the card GET fail."""
        mock_request.side_effect = requests.exceptions.ConnectionError("boom")

        result = solid.lookup_provider_from_profile("https://alice.example.com/profile/card#me")

        assert result is None

    @patch("solidauth.solid.fetch_graph")
    @patch("solidauth.solid.httpclient.request")
    def test_lookup_provider_from_profile_card_fetch_error_returns_none(self, mock_request, mock_fetch_graph):
        """A failure fetching/parsing the card flattens to None."""
        mock_response = Mock()
        mock_response.headers = {}
        mock_request.return_value = mock_response
        mock_fetch_graph.side_effect = solid.RdfTransportError("could not fetch")

        result = solid.lookup_provider_from_profile("https://alice.example.com/profile/card#me")

        assert result is None


class TestFetchGraph:
    """Test cases for the fetch_graph helper."""

    TURTLE = (
        "<https://alice.example.com/profile/card#me> "
        "<http://www.w3.org/ns/solid/terms#oidcIssuer> <https://op.example.com> ."
    )

    @patch("solidauth.solid.httpclient.request")
    def test_fetch_graph_strips_content_type_parameters(self, mock_request):
        """A Content-Type with a charset parameter is reduced to the media type rdflib accepts."""
        mock_response = Mock()
        mock_response.text = self.TURTLE
        mock_response.headers = {"Content-Type": "text/turtle; charset=utf-8"}
        mock_request.return_value = mock_response

        graph = solid.fetch_graph("https://alice.example.com/profile/card#me")

        issuer = solid.rdflib.URIRef("http://www.w3.org/ns/solid/terms#oidcIssuer")
        assert list(graph.triples((None, issuer, None)))
        mock_request.assert_called_once_with(
            "GET",
            "https://alice.example.com/profile/card#me",
            headers={"Accept": solid.RDF_ACCEPT},
        )

    @patch("solidauth.solid.httpclient.request")
    def test_fetch_graph_defaults_to_turtle_without_content_type(self, mock_request):
        """No Content-Type header falls back to rdflib's Turtle default."""
        mock_response = Mock()
        mock_response.text = self.TURTLE
        mock_response.headers = {}
        mock_request.return_value = mock_response

        graph = solid.fetch_graph("https://alice.example.com/profile/card#me")

        assert len(graph) == 1

    @patch("solidauth.solid.httpclient.request")
    def test_fetch_graph_wraps_transport_errors(self, mock_request):
        """Transport failures are re-raised as RdfTransportError with the cause chained."""
        cause = requests.exceptions.ConnectionError("boom")
        mock_request.side_effect = cause

        with pytest.raises(solid.RdfTransportError) as exc_info:
            solid.fetch_graph("https://alice.example.com/profile/card#me")

        assert exc_info.value.__cause__ is cause

    @patch("solidauth.solid.httpclient.request")
    def test_fetch_graph_wraps_parse_errors(self, mock_request):
        """A body that isn't valid RDF is re-raised as RdfParseError."""
        mock_response = Mock()
        mock_response.text = "<html>not rdf</html>"
        mock_response.headers = {"Content-Type": "text/turtle"}
        mock_request.return_value = mock_response

        with pytest.raises(solid.RdfParseError):
            solid.fetch_graph("https://alice.example.com/profile/card#me")


class TestOpCanDoDynamicRegistration:
    """Test cases for the op_can_do_dynamic_registration function."""

    def test_op_can_do_dynamic_registration_with_endpoint(self):
        """Test that function returns True when registration_endpoint is present."""
        op_config = {"registration_endpoint": "https://example.com/register"}

        result = solid.op_can_do_dynamic_registration(op_config)

        assert result is True

    def test_op_can_do_dynamic_registration_without_endpoint(self):
        """Test that function returns False when registration_endpoint is missing."""
        op_config = {"authorization_endpoint": "https://example.com/authorize"}

        result = solid.op_can_do_dynamic_registration(op_config)

        assert result is False


class TestOpSupportsClientIDDocumentRegistration:
    """Test cases for the op_supports_client_id_document_registration function."""

    def test_op_does_not_support_client_id_document_registration_missing_webid_scope(self):
        """Test that function returns False when webid scope is not supported."""
        op_config = {
            "registration_endpoint": "https://example.com/register",
            "registration_endpoint_auth_methods_supported": ["none"],
            "scopes_supported": ["openid", "offline_access"],
        }

        result = solid.op_supports_client_id_document_registration(op_config)

        assert result is False

    def test_op_does_not_support_client_id_document_registration_missing_scopes_supported_field(self):
        """Test that function returns False when scopes_supported field is missing."""
        op_config = {
            "registration_endpoint": "https://example.com/register",
            "registration_endpoint_auth_methods_supported": ["none"],
        }

        result = solid.op_supports_client_id_document_registration(op_config)

        assert result is False


class TestDynamicRegistration:
    """pyoidc makes its own request; it gets our User-Agent through a Session."""

    @patch("solidauth.solid.OicClient")
    def test_registration_uses_session_with_configured_user_agent(self, mock_client_class):
        httpclient.set_user_agent("CLARA/1.0")

        solid.dynamic_registration({"client_name": "app"}, {"registration_endpoint": "https://example.com/register"})

        settings = mock_client_class.call_args.kwargs["settings"]
        assert settings.requests_session.headers["User-Agent"] == "CLARA/1.0"
        mock_client_class.return_value.register.assert_called_once_with(
            "https://example.com/register", client_name="app"
        )
