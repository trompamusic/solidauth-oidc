from abc import ABC, abstractmethod


class SolidBackend(ABC):

    @abstractmethod
    def is_ready(self):
        pass

    @abstractmethod
    def get_relying_party_keys(self):
        pass

    @abstractmethod
    def save_relying_party_keys(self, keys):
        pass

    @abstractmethod
    def get_resource_server_configuration(self, provider):
        pass

    @abstractmethod
    def save_resource_server_configuration(self, provider, configuration):
        pass

    @abstractmethod
    def get_resource_server_keys(self, provider):
        pass

    @abstractmethod
    def save_resource_server_keys(self, provider, keys):
        pass

    @abstractmethod
    def get_client_registration(self, provider):
        pass

    @abstractmethod
    def save_client_registration(self, provider, registration):
        pass

    @abstractmethod
    def save_configuration_token(self, issuer, sub, token):
        pass
