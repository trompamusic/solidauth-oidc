import datetime
from dataclasses import dataclass


@dataclass
class ResourceServerConfiguration:
    pass


@dataclass
class ResourceServerKeys:
    pass


@dataclass
class ResourceServerClientRegistration:
    pass


@dataclass
class RelyingPartyKeys:
    pass


@dataclass
class ClientRegistration:
    provider: str
    client_id: str
    data: dict


@dataclass
class ConfigurationToken:
    issuer: str
    sub: str
    profile: str
    client_id: str
    added: datetime.datetime
    data: dict
    client_registration: ClientRegistration | None = None

    def has_expired(self):
        expires_in = self.data["expires_in"]
        now = datetime.datetime.now(tz=datetime.timezone.utc)
        if self.added + datetime.timedelta(seconds=expires_in) < now:
            return True
        else:
            return False
