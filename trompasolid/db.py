import datetime

from sqlalchemy import TIMESTAMP, ForeignKey, Index, Text, func
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class RelyingPartyKey(Base):
    """Keys for the client, there should only be one of these"""

    __tablename__ = "relying_party"
    id: Mapped[int] = mapped_column(primary_key=True)
    data: Mapped[dict] = mapped_column(postgresql.JSONB)

    def __repr__(self):
        return f"<RelyingPartyKey {self.id}>"


class ResourceServerConfiguration(Base):
    __tablename__ = "resource_server_configuration"
    id: Mapped[int] = mapped_column(primary_key=True)
    provider: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    data: Mapped[dict] = mapped_column(postgresql.JSONB)

    def __repr__(self):
        return f"<ResourceServerConfiguration {self.id} ({self.provider})>"


class ResourceServerKeys(Base):
    __tablename__ = "resource_server_keys"
    id: Mapped[int] = mapped_column(primary_key=True)
    provider: Mapped[str] = mapped_column(Text, nullable=False, index=True, unique=True)
    data: Mapped[dict] = mapped_column(postgresql.JSONB)

    def __repr__(self):
        return f"<ResourceServerKeys {self.id} ({self.provider})>"


class ClientRegistration(Base):
    __tablename__ = "client_registration"
    id: Mapped[int] = mapped_column(primary_key=True)
    provider: Mapped[str] = mapped_column(Text, nullable=False, index=True, unique=True)
    client_id: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    data: Mapped[dict] = mapped_column(postgresql.JSONB)
    configuration_tokens: Mapped[list["ConfigurationToken"]] = relationship(
        "ConfigurationToken", back_populates="client_registration"
    )

    def __repr__(self):
        return f"<ClientRegistration {self.id} ({self.provider})>"


class ConfigurationToken(Base):
    __tablename__ = "configuration_token"
    id: Mapped[int] = mapped_column(primary_key=True)
    client_id: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    issuer: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    sub: Mapped[str] = mapped_column(Text, nullable=False)
    profile: Mapped[str] = mapped_column(Text, nullable=False)
    added: Mapped[datetime.datetime] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False, server_default=func.now()
    )
    data: Mapped[dict] = mapped_column(postgresql.JSONB)
    client_registration_id: Mapped[int] = mapped_column(ForeignKey("client_registration.id"), nullable=True)
    client_registration: Mapped["ClientRegistration"] = relationship(
        "ClientRegistration", back_populates="configuration_tokens"
    )
    __table_args__ = (
        Index("configuration_token_idx_issuer_sub", "issuer", "sub", "client_id", unique=True),
        Index("configuration_token_idx_issuer_profile", "issuer", "profile", "client_id", unique=True),
    )

    def __repr__(self):
        return f"<ConfigurationToken {self.id} ({self.issuer}, {self.sub}, {self.client_id})>"


class State(Base):
    __tablename__ = "pkce_state"
    id: Mapped[int] = mapped_column(primary_key=True)
    state: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    code_verifier: Mapped[str] = mapped_column(Text, nullable=False, index=False)
    issuer: Mapped[str] = mapped_column(Text, nullable=True, index=False)

    def __repr__(self):
        return f"<State {self.id} ({self.state}, {self.code_verifier})>"
