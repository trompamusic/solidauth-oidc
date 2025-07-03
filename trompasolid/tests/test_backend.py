import datetime
from unittest.mock import Mock

import pytest

from trompasolid.backend.db_backend import DBBackend
from trompasolid.backend.redis_backend import RedisBackend


class TestDBBackend:
    """Test the database backend with client_id functionality."""

    @pytest.fixture
    def mock_session(self):
        """Create a mock SQLAlchemy session."""
        session = Mock()
        session.query.return_value.filter_by.return_value.first.return_value = None
        session.add = Mock()
        session.commit = Mock()
        session.merge = Mock()
        return session

    @pytest.fixture
    def db_backend(self, mock_session):
        """Create a DBBackend instance with mock session."""
        return DBBackend(mock_session)

    def test_save_configuration_token_with_client_id(self, db_backend, mock_session):
        """Test saving a configuration token with client_id."""
        # Mock the database model
        from trompasolid import db

        Mock(spec=db.ConfigurationToken)
        mock_session.query.return_value.filter_by.return_value.first.return_value = None

        # Mock a client registration
        mock_registration = Mock(spec=db.ClientRegistration)
        mock_registration.id = 123
        mock_session.query.return_value.filter_by.return_value.first.side_effect = [None, mock_registration]

        # Call the method
        db_backend.save_configuration_token("https://issuer.example", "profile", "sub", "client123", {"token": "data"})

        # Verify that merge was called with the correct parameters
        mock_session.merge.assert_called_once()
        call_args = mock_session.merge.call_args[0][0]
        assert call_args.issuer == "https://issuer.example"
        assert call_args.profile == "profile"
        assert call_args.sub == "sub"
        assert call_args.client_id == "client123"
        assert call_args.data == {"token": "data"}
        assert call_args.client_registration_id == 123

    def test_save_configuration_token_without_client_registration(self, db_backend, mock_session):
        """Test saving a configuration token when no client registration exists."""
        # Mock the database model
        from trompasolid import db

        Mock(spec=db.ConfigurationToken)
        mock_session.query.return_value.filter_by.return_value.first.return_value = None

        # Call the method
        db_backend.save_configuration_token("https://issuer.example", "profile", "sub", "client123", {"token": "data"})

        # Verify that merge was called with the correct parameters
        mock_session.merge.assert_called_once()
        call_args = mock_session.merge.call_args[0][0]
        assert call_args.issuer == "https://issuer.example"
        assert call_args.profile == "profile"
        assert call_args.sub == "sub"
        assert call_args.client_id == "client123"
        assert call_args.data == {"token": "data"}
        assert call_args.client_registration_id is None

    def test_get_configuration_token_with_client_id(self, db_backend, mock_session):
        """Test getting a configuration token with specific client_id."""
        # Mock the database model and return value
        from trompasolid import db

        mock_db_token = Mock(spec=db.ConfigurationToken)
        mock_db_token.issuer = "https://issuer.example"
        mock_db_token.profile = "profile"
        mock_db_token.sub = "sub"
        mock_db_token.client_id = "client123"
        mock_db_token.added = datetime.datetime.now(tz=datetime.timezone.utc)
        mock_db_token.data = {"token": "data"}

        mock_session.query.return_value.filter_by.return_value.first.return_value = mock_db_token

        # Call the method
        result = db_backend.get_configuration_token("https://issuer.example", "profile", "client123")

        # Verify the result
        assert result is not None
        assert result.issuer == "https://issuer.example"
        assert result.profile == "profile"
        assert result.sub == "sub"
        assert result.client_id == "client123"
        assert result.data == {"token": "data"}

    def test_get_configuration_tokens(self, db_backend, mock_session):
        """Test getting all configuration tokens."""
        # Mock the database model and return values
        from trompasolid import db

        mock_db_token1 = Mock(spec=db.ConfigurationToken)
        mock_db_token1.issuer = "https://issuer1.example"
        mock_db_token1.profile = "profile1"
        mock_db_token1.sub = "sub1"
        mock_db_token1.client_id = "client1"
        mock_db_token1.added = datetime.datetime.now(tz=datetime.timezone.utc)
        mock_db_token1.data = {"token": "data1"}

        mock_db_token2 = Mock(spec=db.ConfigurationToken)
        mock_db_token2.issuer = "https://issuer2.example"
        mock_db_token2.profile = "profile2"
        mock_db_token2.sub = "sub2"
        mock_db_token2.client_id = "client2"
        mock_db_token2.added = datetime.datetime.now(tz=datetime.timezone.utc)
        mock_db_token2.data = {"token": "data2"}

        mock_session.query.return_value.all.return_value = [mock_db_token1, mock_db_token2]

        # Call the method
        result = db_backend.get_configuration_tokens()

        # Verify the result
        assert len(result) == 2
        assert result[0].issuer == "https://issuer1.example"
        assert result[0].client_id == "client1"
        assert result[1].issuer == "https://issuer2.example"
        assert result[1].client_id == "client2"

    def test_save_client_registration_with_client_id(self, db_backend, mock_session):
        """Test saving a client registration with client_id field."""
        # Call the method
        registration_data = {"client_id": "client123", "client_secret": "secret123"}
        db_backend.save_client_registration("https://provider.example", registration_data)

        # Verify that add was called with the correct parameters
        mock_session.add.assert_called_once()
        call_args = mock_session.add.call_args[0][0]
        assert call_args.provider == "https://provider.example"
        assert call_args.client_id == "client123"
        assert call_args.data == registration_data


class TestRedisBackend:
    """Test the Redis backend with client_id functionality."""

    @pytest.fixture
    def mock_redis_client(self):
        """Create a mock Redis client."""
        redis_client = Mock()
        redis_client.ping.return_value = True
        redis_client.get.return_value = None
        redis_client.set.return_value = True
        redis_client.delete.return_value = 1
        return redis_client

    @pytest.fixture
    def redis_backend(self, mock_redis_client):
        """Create a RedisBackend instance with mock Redis client."""
        return RedisBackend(mock_redis_client)

    def test_save_configuration_token_with_client_id(self, redis_backend, mock_redis_client):
        """Test saving a configuration token with client_id."""
        # Call the method
        redis_backend.save_configuration_token(
            "https://issuer.example", "profile", "sub", "client123", {"token": "data"}
        )

        # Verify that set was called with the correct key
        mock_redis_client.set.assert_called_once()
        call_args = mock_redis_client.set.call_args
        key = call_args[0][0]
        assert "solidauth-rs-token-https://issuer.example-profile-client123" in key

    def test_get_configuration_token_with_client_id(self, redis_backend, mock_redis_client):
        """Test getting a configuration token with specific client_id."""
        # Mock the Redis response
        mock_redis_client.get.return_value = '{"token": "data"}'

        # Call the method
        result = redis_backend.get_configuration_token("https://issuer.example", "profile", "client123")

        # Verify the result
        assert result == '{"token": "data"}'

        # Verify that get was called with the correct key
        mock_redis_client.get.assert_called_once()
        call_args = mock_redis_client.get.call_args
        key = call_args[0][0]
        assert "solidauth-rs-token-https://issuer.example-profile-client123" in key

    def test_get_configuration_tokens(self, redis_backend, mock_redis_client):
        """Test getting all configuration tokens from Redis."""
        # Mock the Redis responses
        mock_redis_client.smembers.return_value = [
            b"solidauth-rs-token-https://issuer1.example-profile1-client1",
            b"solidauth-rs-token-https://issuer2.example-profile2-client2",
        ]
        mock_redis_client.get.side_effect = ['{"token": "data1"}', '{"token": "data2"}']

        # Call the method
        result = redis_backend.get_configuration_tokens()

        # Verify the result - Redis returns raw strings
        assert len(result) == 2
        assert result[0] == '{"token": "data1"}'
        assert result[1] == '{"token": "data2"}'

    def test_save_configuration_token_adds_to_list(self, redis_backend, mock_redis_client):
        """Test that saving a configuration token adds it to the list."""
        # Call the method
        redis_backend.save_configuration_token(
            "https://issuer.example", "profile", "sub", "client123", {"token": "data"}
        )

        # Verify that set was called for the token
        mock_redis_client.set.assert_called_once()

        # Verify that sadd was called to add to the list
        mock_redis_client.sadd.assert_called_once()
        call_args = mock_redis_client.sadd.call_args
        list_key = call_args[0][0]
        token_key = call_args[0][1]
        assert "solidauth-rs-tokens-list" in list_key
        assert "rs-token-https://issuer.example-profile-client123" in token_key
