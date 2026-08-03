import datetime
from unittest.mock import Mock

import pytest

from solidauth.backend.db_backend import DBBackend


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
        from solidauth import db

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
        from solidauth import db

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
        from solidauth import db

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
        from solidauth import db

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
