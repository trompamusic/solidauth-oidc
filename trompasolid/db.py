from sqlalchemy import Index, Text
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class RelyingPartyKey(Base):
    """Keys for the client, there should only be one of these"""
    __tablename__ = 'relying_party'
    id: Mapped[int] = mapped_column(primary_key=True)
    data: Mapped[dict] = mapped_column(postgresql.JSONB)

    def __repr__(self):
        return f'<RelyingPartyKey {self.id}>'


class ResourceServerConfiguration(Base):
    __tablename__ = 'resource_server_configuration'
    id: Mapped[int] = mapped_column(primary_key=True)
    provider: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    data: Mapped[dict] = mapped_column(postgresql.JSONB)

    def __repr__(self):
        return f'<ResourceServerConfiguration {self.id} ({self.provider})>'


class ResourceServerKeys(Base):
    __tablename__ = 'resource_server_keys'
    id: Mapped[int] = mapped_column(primary_key=True)
    provider: Mapped[str] = mapped_column(Text, nullable=False, index=True, unique=True)
    data: Mapped[dict] = mapped_column(postgresql.JSONB)

    def __repr__(self):
        return f'<ResourceServerKeys {self.id} ({self.provider})>'


class ClientRegistration(Base):
    __tablename__ = 'client_registration'
    id: Mapped[int] = mapped_column(primary_key=True)
    provider: Mapped[str] = mapped_column(Text, nullable=False, index=True, unique=True)
    data: Mapped[dict] = mapped_column(postgresql.JSONB)

    def __repr__(self):
        return f'<ClientRegistration {self.id} ({self.provider})>'


class ConfigurationToken(Base):
    __tablename__ = 'configuration_token'
    id: Mapped[int] = mapped_column(primary_key=True)
    issuer: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    sub: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    data: Mapped[dict] = mapped_column(postgresql.JSONB)
    __table_args__ = (Index('configuration_token_idx_issuer_sub', "issuer", "sub", unique=True), )

    def __repr__(self):
        return f'<ConfigurationToken {self.id} ({self.issuer}, {self.sub})>'
