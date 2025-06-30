"""
Tests for authentication functionality in the trompasolid package.
"""

import jwcrypto.jwk
import jwcrypto.jwt
import pytest

from trompasolid.authentication import get_jwt_kid, select_jwk_by_kid


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
