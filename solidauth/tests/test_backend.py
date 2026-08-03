import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from solidauth import db
from solidauth.backend.db_backend import DBBackend


class TestDBBackend:
    """Test the database backend with client_id functionality."""

    @pytest.fixture
    def session(self):
        engine = create_engine("sqlite+pysqlite:///:memory:")
        db.Base.metadata.create_all(engine)
        with Session(engine) as session:
            yield session
        engine.dispose()

    @pytest.fixture
    def db_backend(self, session):
        return DBBackend(session)

    def test_save_configuration_token_with_client_registration(self, db_backend, session):
        db_backend.save_client_registration(
            "https://issuer.example",
            {"client_id": "client123", "client_secret": "secret123"},
        )
        db_backend.save_configuration_token("https://issuer.example", "profile", "sub", "client123", {"token": "data"})

        stored = session.scalar(select(db.ConfigurationToken))
        assert stored.issuer == "https://issuer.example"
        assert stored.profile == "profile"
        assert stored.sub == "sub"
        assert stored.client_id == "client123"
        assert stored.data == {"token": "data"}
        assert stored.client_registration.provider == "https://issuer.example"

    def test_save_configuration_token_without_client_registration(self, db_backend, session):
        db_backend.save_configuration_token("https://issuer.example", "profile", "sub", "client123", {"token": "data"})

        stored = session.scalar(select(db.ConfigurationToken))
        assert stored.data == {"token": "data"}
        assert stored.client_registration_id is None

    def test_get_configuration_token_with_client_id_document(self, db_backend):
        db_backend.save_configuration_token(
            "https://issuer.example",
            "profile",
            "sub",
            "https://client.example/solid-oidc.jsonld",
            {"token": "data"},
        )

        result = db_backend.get_configuration_token("https://issuer.example", "profile", True)

        assert result is not None
        assert result.issuer == "https://issuer.example"
        assert result.profile == "profile"
        assert result.sub == "sub"
        assert result.client_id == "https://client.example/solid-oidc.jsonld"
        assert result.data == {"token": "data"}
        assert result.client_registration is None

    def test_get_configuration_tokens(self, db_backend):
        db_backend.save_configuration_token(
            "https://issuer1.example", "profile1", "sub1", "client1", {"token": "data1"}
        )
        db_backend.save_configuration_token(
            "https://issuer2.example", "profile2", "sub2", "client2", {"token": "data2"}
        )

        result = db_backend.get_configuration_tokens()

        assert len(result) == 2
        assert result[0].issuer == "https://issuer1.example"
        assert result[0].client_id == "client1"
        assert result[1].issuer == "https://issuer2.example"
        assert result[1].client_id == "client2"

    def test_save_client_registration_with_client_id(self, db_backend, session):
        registration_data = {"client_id": "client123", "client_secret": "secret123"}
        db_backend.save_client_registration("https://provider.example", registration_data)

        stored = session.scalar(select(db.ClientRegistration))
        assert stored.provider == "https://provider.example"
        assert stored.client_id == "client123"
        assert stored.data == registration_data
