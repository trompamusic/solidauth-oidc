"""
Tests for authentication functionality in the trompasolid package.
"""

import time
from unittest.mock import Mock, patch

import jwcrypto.jwk
import jwcrypto.jwt
import pytest

from trompasolid import solid
from trompasolid.authentication import (
    IDTokenValidationError,
    authentication_callback,
    get_jwt_kid,
    select_jwk_by_kid,
    validate_id_token_claims,
)


class TestJWTKeySelection:
    """Test cases for JWT key selection functionality."""

    @pytest.fixture
    def sample_jwks(self):
        """Sample JWKS with multiple keys for testing."""
        return {
            "keys": [
                {"kty": "EC", "crv": "P-256", "kid": "key1", "x": "test_x_1", "y": "test_y_1"},
                {"kty": "EC", "crv": "P-256", "kid": "key2", "x": "test_x_2", "y": "test_y_2"},
            ]
        }

    def test_select_jwk_by_kid_success(self, sample_jwks):
        """Test successful key selection with specific kid."""
        key = select_jwk_by_kid(sample_jwks, "key1")
        assert key is not None
        assert isinstance(key, jwcrypto.jwk.JWK)

    def test_select_jwk_by_kid_different_key(self, sample_jwks):
        """Test selecting a different key with different kid."""
        key = select_jwk_by_kid(sample_jwks, "key2")
        assert key is not None
        assert isinstance(key, jwcrypto.jwk.JWK)

    def test_select_jwk_by_kid_nonexistent(self, sample_jwks):
        """Test that selecting non-existent kid raises ValueError."""
        with pytest.raises(ValueError, match="No key found with kid: nonexistent"):
            select_jwk_by_kid(sample_jwks, "nonexistent")

    def test_select_jwk_by_kid_none_fallback(self, sample_jwks):
        """Test fallback to first key when kid is None."""
        key = select_jwk_by_kid(sample_jwks, None)
        assert key is not None
        assert isinstance(key, jwcrypto.jwk.JWK)

    def test_select_jwk_by_kid_invalid_jwks_format(self):
        """Test that invalid JWKS format raises ValueError."""
        invalid_jwks = {"invalid": "format"}
        with pytest.raises(ValueError, match="Invalid JWKS format: missing 'keys' field"):
            select_jwk_by_kid(invalid_jwks, "key1")

    def test_select_jwk_by_kid_empty_keys(self):
        """Test that empty keys list raises ValueError."""
        empty_jwks = {"keys": []}
        with pytest.raises(ValueError, match="No key found with kid: key1"):
            select_jwk_by_kid(empty_jwks, "key1")


class TestJWTKidExtraction:
    """Test cases for JWT kid extraction functionality."""

    @pytest.fixture
    def test_key(self):
        """Create a test key for JWT signing."""
        return jwcrypto.jwk.JWK.generate(kty="EC", crv="P-256")

    def test_get_jwt_kid_with_kid(self, test_key):
        """Test extracting kid from JWT that has kid in header."""
        # Create a JWT with kid in header
        jwt_with_kid = jwcrypto.jwt.JWT(
            header={"alg": "ES256", "typ": "JWT", "kid": "test_key_id"},
            claims={"sub": "test_user", "iss": "test_issuer"},
        )
        jwt_with_kid.make_signed_token(test_key)
        token_with_kid = jwt_with_kid.serialize()

        # Extract kid
        kid = get_jwt_kid(token_with_kid)
        assert kid == "test_key_id"

    def test_get_jwt_kid_without_kid(self, test_key):
        """Test extracting kid from JWT that doesn't have kid in header."""
        # Create a JWT without kid in header
        jwt_without_kid = jwcrypto.jwt.JWT(
            header={"alg": "ES256", "typ": "JWT"}, claims={"sub": "test_user", "iss": "test_issuer"}
        )
        jwt_without_kid.make_signed_token(test_key)
        token_without_kid = jwt_without_kid.serialize()

        # Extract kid
        kid = get_jwt_kid(token_without_kid)
        assert kid is None

    def test_get_jwt_kid_invalid_token(self):
        """Test handling of invalid JWT tokens."""
        # Test with malformed token
        kid = get_jwt_kid("invalid.jwt.token")
        assert kid is None

    def test_get_jwt_kid_none_token(self):
        """Test handling of None token."""
        kid = get_jwt_kid(None)
        assert kid is None

    def test_get_jwt_kid_empty_token(self):
        """Test handling of empty token."""
        kid = get_jwt_kid("")
        assert kid is None


class TestIDTokenValidation:
    """Test cases for ID token validation functionality."""

    @pytest.fixture
    def valid_claims(self):
        """Valid ID token claims for testing."""
        current_time = int(time.time())
        return {
            "iss": "https://example.com",
            "aud": "test_client_id",
            "exp": current_time + 3600,  # 1 hour from now
            "iat": current_time,
            "sub": "test_user",
            "webid": "https://example.com/profile#me",
        }

    def test_validate_id_token_claims_success(self, valid_claims):
        """Test successful validation of valid claims."""
        # Should not raise any exception
        validate_id_token_claims(valid_claims, "https://example.com", "test_client_id")

    def test_validate_id_token_claims_invalid_issuer(self, valid_claims):
        """Test validation fails with invalid issuer."""
        with pytest.raises(IDTokenValidationError, match="Invalid issuer"):
            validate_id_token_claims(valid_claims, "https://different.com", "test_client_id")

    def test_validate_id_token_claims_missing_aud(self, valid_claims):
        """Test validation fails with missing audience."""
        claims = valid_claims.copy()
        del claims["aud"]
        with pytest.raises(IDTokenValidationError, match="Missing 'aud' claim"):
            validate_id_token_claims(claims, "https://example.com", "test_client_id")

    def test_validate_id_token_claims_invalid_aud_string(self, valid_claims):
        """Test validation fails with invalid audience string."""
        claims = valid_claims.copy()
        claims["aud"] = "wrong_client_id"
        with pytest.raises(IDTokenValidationError, match="Invalid audience"):
            validate_id_token_claims(claims, "https://example.com", "test_client_id")

    def test_validate_id_token_claims_aud_list_success(self, valid_claims):
        """Test validation succeeds with audience as list."""
        claims = valid_claims.copy()
        claims["aud"] = ["test_client_id", "other_client_id"]
        # Should not raise any exception
        validate_id_token_claims(claims, "https://example.com", "test_client_id")

    def test_validate_id_token_claims_aud_list_failure(self, valid_claims):
        """Test validation fails when client_id not in audience list."""
        claims = valid_claims.copy()
        claims["aud"] = ["other_client_id", "another_client_id"]
        with pytest.raises(IDTokenValidationError, match="Client ID test_client_id not in audience list"):
            validate_id_token_claims(claims, "https://example.com", "test_client_id")

    def test_validate_id_token_claims_missing_exp(self, valid_claims):
        """Test validation fails with missing expiration."""
        claims = valid_claims.copy()
        del claims["exp"]
        with pytest.raises(IDTokenValidationError, match="Missing 'exp' claim"):
            validate_id_token_claims(claims, "https://example.com", "test_client_id")

    def test_validate_id_token_claims_expired_token(self, valid_claims):
        """Test validation fails with expired token."""
        claims = valid_claims.copy()
        claims["exp"] = int(time.time()) - 3600  # 1 hour ago
        with pytest.raises(IDTokenValidationError, match="Token has expired"):
            validate_id_token_claims(claims, "https://example.com", "test_client_id")

    def test_validate_id_token_claims_missing_iat(self, valid_claims):
        """Test validation fails with missing issued at time."""
        claims = valid_claims.copy()
        del claims["iat"]
        with pytest.raises(IDTokenValidationError, match="Missing 'iat' claim"):
            validate_id_token_claims(claims, "https://example.com", "test_client_id")

    def test_validate_id_token_claims_future_iat(self, valid_claims):
        """Test validation fails with future issued at time."""
        claims = valid_claims.copy()
        claims["iat"] = int(time.time()) + 600  # 10 minutes in future
        with pytest.raises(IDTokenValidationError, match="Token issued in the future"):
            validate_id_token_claims(claims, "https://example.com", "test_client_id")

    def test_validate_id_token_claims_with_nonce_success(self, valid_claims):
        """Test validation succeeds with valid nonce."""
        claims = valid_claims.copy()
        claims["nonce"] = "test_nonce"
        # Should not raise any exception
        validate_id_token_claims(claims, "https://example.com", "test_client_id", nonce="test_nonce")

    def test_validate_id_token_claims_with_nonce_failure(self, valid_claims):
        """Test validation fails with invalid nonce."""
        claims = valid_claims.copy()
        claims["nonce"] = "wrong_nonce"
        with pytest.raises(IDTokenValidationError, match="Invalid nonce"):
            validate_id_token_claims(claims, "https://example.com", "test_client_id", nonce="test_nonce")

    def test_validate_id_token_claims_missing_nonce(self, valid_claims):
        """Test validation fails when nonce expected but missing."""
        with pytest.raises(IDTokenValidationError, match="nonce expected but missing"):
            validate_id_token_claims(valid_claims, "https://example.com", "test_client_id", nonce="test_nonce")

    def test_validate_id_token_claims_with_max_age_success(self, valid_claims):
        """Test validation succeeds with valid max_age."""
        claims = valid_claims.copy()
        claims["auth_time"] = int(time.time()) - 300  # 5 minutes ago
        # Should not raise any exception
        validate_id_token_claims(
            claims,
            "https://example.com",
            "test_client_id",
            max_age=600,  # 10 minutes
        )

    def test_validate_id_token_claims_with_max_age_failure(self, valid_claims):
        """Test validation fails when token too old for max_age."""
        claims = valid_claims.copy()
        claims["auth_time"] = int(time.time()) - 1200  # 20 minutes ago
        with pytest.raises(IDTokenValidationError, match="Token too old"):
            validate_id_token_claims(
                claims,
                "https://example.com",
                "test_client_id",
                max_age=600,  # 10 minutes
            )

    def test_validate_id_token_claims_missing_auth_time(self, valid_claims):
        """Test validation fails when max_age specified but auth_time missing."""
        with pytest.raises(IDTokenValidationError, match="max_age specified but 'auth_time' claim missing"):
            validate_id_token_claims(valid_claims, "https://example.com", "test_client_id", max_age=600)


class TestJWTKeySelectionIntegration:
    """Integration tests combining kid extraction and key selection."""

    @pytest.fixture
    def test_key(self):
        """Create a test key for JWT signing."""
        return jwcrypto.jwk.JWK.generate(kty="EC", crv="P-256")

    @pytest.fixture
    def sample_jwks(self):
        """Sample JWKS with multiple keys for testing."""
        return {
            "keys": [
                {"kty": "EC", "crv": "P-256", "kid": "key1", "x": "test_x_1", "y": "test_y_1"},
                {"kty": "EC", "crv": "P-256", "kid": "key2", "x": "test_x_2", "y": "test_y_2"},
            ]
        }

    def test_full_flow_with_kid(self, test_key, sample_jwks):
        """Test the complete flow: extract kid from JWT and select correct key."""
        # Create a JWT with specific kid
        jwt_obj = jwcrypto.jwt.JWT(
            header={"alg": "ES256", "typ": "JWT", "kid": "key1"}, claims={"sub": "test_user", "iss": "test_issuer"}
        )
        jwt_obj.make_signed_token(test_key)
        token = jwt_obj.serialize()

        # Extract kid and select key
        kid = get_jwt_kid(token)
        key = select_jwk_by_kid(sample_jwks, kid)

        assert kid == "key1"
        assert key is not None
        assert isinstance(key, jwcrypto.jwk.JWK)

    def test_full_flow_without_kid(self, test_key, sample_jwks):
        """Test the complete flow: extract kid from JWT without kid and fallback."""
        # Create a JWT without kid
        jwt_obj = jwcrypto.jwt.JWT(
            header={"alg": "ES256", "typ": "JWT"}, claims={"sub": "test_user", "iss": "test_issuer"}
        )
        jwt_obj.make_signed_token(test_key)
        token = jwt_obj.serialize()

        # Extract kid and select key
        kid = get_jwt_kid(token)
        key = select_jwk_by_kid(sample_jwks, kid)

        assert kid is None
        assert key is not None
        assert isinstance(key, jwcrypto.jwk.JWK)


class TestClientIDDocumentRegistration:
    """Test cases for client ID document registration checking."""

    def test_op_supports_client_id_document_registration_with_no_auth_methods(self):
        """Test that OP supports client ID document registration when no auth methods specified."""
        op_config = {
            "registration_endpoint": "https://example.com/register",
            "registration_endpoint_auth_methods_supported": [],
        }
        assert solid.op_supports_client_id_document_registration(op_config) is True

    def test_op_supports_client_id_document_registration_with_none_auth_method(self):
        """Test that OP supports client ID document registration when 'none' auth method is supported."""
        op_config = {
            "registration_endpoint": "https://example.com/register",
            "registration_endpoint_auth_methods_supported": ["none", "client_secret_basic"],
        }
        assert solid.op_supports_client_id_document_registration(op_config) is True

    def test_op_does_not_support_client_id_document_registration_with_auth_methods(self):
        """Test that OP does not support client ID document registration when auth methods are required."""
        op_config = {
            "registration_endpoint": "https://example.com/register",
            "registration_endpoint_auth_methods_supported": ["client_secret_basic", "private_key_jwt"],
        }
        assert solid.op_supports_client_id_document_registration(op_config) is False

    def test_op_does_not_support_client_id_document_registration_no_endpoint(self):
        """Test that OP does not support client ID document registration when no registration endpoint."""
        op_config = {
            "authorization_endpoint": "https://example.com/authorize",
            "token_endpoint": "https://example.com/token",
        }
        assert solid.op_supports_client_id_document_registration(op_config) is False

    def test_op_does_not_support_client_id_document_registration_missing_auth_methods_field(self):
        """Test that OP supports client ID document registration when auth methods field is missing."""
        op_config = {"registration_endpoint": "https://example.com/register"}
        assert solid.op_supports_client_id_document_registration(op_config) is True


class TestStateParameterSecurity:
    """Test that state parameter is deleted after use in authentication_callback."""

    @patch("trompasolid.authentication.get_jwt_kid", return_value="kid1")
    @patch("trompasolid.authentication.select_jwk_by_kid")
    @patch("trompasolid.authentication.jwcrypto.jwt.JWT")
    @patch("trompasolid.authentication.validate_id_token_claims")
    @patch("trompasolid.authentication.solid")
    def test_state_deleted_after_callback_success(
        self, mock_solid, mock_validate, mock_jwt, mock_select_jwk, mock_get_kid
    ):
        backend = Mock()
        backend.get_resource_server_configuration.return_value = {"issuer": "https://issuer.example"}
        backend.get_state_data.return_value = {"code_verifier": "verifier", "issuer": "https://issuer.example"}
        backend.get_resource_server_keys.return_value = {"keys": [{"kid": "kid1"}]}
        backend.get_relying_party_keys.return_value = "{}"
        backend.get_client_registration.return_value = {"client_id": "cid", "client_secret": "secret"}
        backend.get_client_id_and_secret_for_provider = Mock(return_value=("cid", "secret"))
        backend.save_configuration_token = Mock()
        backend.delete_state_data = Mock()

        # Simulate successful validate_auth_callback
        mock_solid.validate_auth_callback.return_value = (True, {"id_token": "token"})
        mock_jwt.return_value.claims = '{"iss": "https://issuer.example", "sub": "sub", "webid": "webid"}'

        authentication_callback(backend, "auth_code", "state123", "https://issuer.example", "redirect", "base", False)

        backend.delete_state_data.assert_called_once_with("state123")

    @patch("trompasolid.authentication.get_jwt_kid", return_value="kid1")
    @patch("trompasolid.authentication.select_jwk_by_kid")
    @patch("trompasolid.authentication.jwcrypto.jwt.JWT")
    @patch("trompasolid.authentication.validate_id_token_claims", side_effect=IDTokenValidationError("fail"))
    @patch("trompasolid.authentication.solid")
    def test_state_deleted_after_callback_failure(
        self, mock_solid, mock_validate, mock_jwt, mock_select_jwk, mock_get_kid
    ):
        backend = Mock()
        backend.get_resource_server_configuration.return_value = {"issuer": "https://issuer.example"}
        backend.get_state_data.return_value = {"code_verifier": "verifier", "issuer": None}
        backend.get_resource_server_keys.return_value = {"keys": [{"kid": "kid1"}]}
        backend.get_relying_party_keys.return_value = "{}"
        backend.get_client_registration.return_value = {"client_id": "cid", "client_secret": "secret"}
        backend.get_client_id_and_secret_for_provider = Mock(return_value=("cid", "secret"))
        backend.save_configuration_token = Mock()
        backend.delete_state_data = Mock()

        # Simulate successful validate_auth_callback
        mock_solid.validate_auth_callback.return_value = (True, {"id_token": "token"})
        mock_jwt.return_value.claims = '{"iss": "https://issuer.example", "sub": "sub", "webid": "webid"}'

        authentication_callback(backend, "auth_code", "state456", "https://issuer.example", "redirect", "base", False)

        backend.delete_state_data.assert_called_once_with("state456")
