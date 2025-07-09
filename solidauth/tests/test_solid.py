from unittest.mock import Mock, patch
from urllib.error import HTTPError

import pytest

from solidauth import solid


class TestIsWebID:
    """Test cases for the is_webid function."""

    @patch("solidauth.solid.lookup_provider_from_profile")
    def test_is_webid_with_valid_provider(self, mock_lookup):
        """Test that is_webid returns True when lookup_provider_from_profile returns a provider."""
        mock_lookup.return_value = "https://example.com"

        result = solid.is_webid("https://alice.example.com/profile/card#me")

        assert result is True
        mock_lookup.assert_called_once_with("https://alice.example.com/profile/card#me")

    @patch("solidauth.solid.lookup_provider_from_profile")
    def test_is_webid_with_no_provider(self, mock_lookup):
        """Test that is_webid returns False when lookup_provider_from_profile returns None."""
        mock_lookup.return_value = None

        result = solid.is_webid("https://alice.example.com/profile/card#me")

        assert result is False
        mock_lookup.assert_called_once_with("https://alice.example.com/profile/card#me")

    @patch("solidauth.solid.lookup_provider_from_profile")
    def test_is_webid_with_http_error(self, mock_lookup):
        """Test that is_webid returns False when lookup_provider_from_profile raises HTTPError."""
        mock_lookup.side_effect = HTTPError("https://example.com", 404, "Not Found", {}, None)

        result = solid.is_webid("https://alice.example.com/profile/card#me")

        assert result is False
        mock_lookup.assert_called_once_with("https://alice.example.com/profile/card#me")


class TestLookupProviderFromProfile:
    """Test cases for the lookup_provider_from_profile function."""

    @patch("requests.options")
    def test_lookup_provider_from_profile_with_link_header(self, mock_options):
        """Test that provider is found via Link header."""
        mock_response = Mock()
        mock_response.headers = {"Link": '<https://example.com>; rel="http://openid.net/specs/connect/1.0/issuer"'}
        mock_options.return_value = mock_response

        result = solid.lookup_provider_from_profile("https://alice.example.com/profile/card#me")

        assert result == "https://example.com"
        mock_options.assert_called_once_with("https://alice.example.com/profile/card#me", timeout=10)

    @patch("requests.options")
    @patch("rdflib.Graph")
    def test_lookup_provider_from_profile_with_rdf_data(self, mock_graph_class, mock_options):
        """Test that provider is found via RDF data when Link header is not available."""
        # Mock the options request to not have Link header
        mock_response = Mock()
        mock_response.headers = {}
        mock_options.return_value = mock_response

        # Mock the RDF graph
        mock_graph = Mock()
        mock_graph_class.return_value = mock_graph

        # Mock the URIRef object with toPython method
        mock_uriref = Mock()
        mock_uriref.toPython.return_value = "https://example.com"
        mock_graph.triples.return_value = [("subject", "predicate", mock_uriref)]

        result = solid.lookup_provider_from_profile("https://alice.example.com/profile/card#me")

        assert result == "https://example.com"
        mock_graph.parse.assert_called_once_with("https://alice.example.com/profile/card#me")

    @patch("requests.options")
    @patch("rdflib.Graph")
    def test_lookup_provider_from_profile_no_provider_found(self, mock_graph_class, mock_options):
        """Test that None is returned when no provider is found."""
        # Mock the options request to not have Link header
        mock_response = Mock()
        mock_response.headers = {}
        mock_options.return_value = mock_response

        # Mock the RDF graph to not find any triples
        mock_graph = Mock()
        mock_graph_class.return_value = mock_graph
        mock_graph.triples.return_value = []

        result = solid.lookup_provider_from_profile("https://alice.example.com/profile/card#me")

        assert result is None

    @patch("requests.options")
    def test_lookup_provider_from_profile_404_error(self, mock_options):
        """Test that HTTPError is raised when profile returns 404."""
        mock_options.side_effect = HTTPError("https://example.com", 404, "Not Found", {}, None)

        with pytest.raises(HTTPError):
            solid.lookup_provider_from_profile("https://alice.example.com/profile/card#me")


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
