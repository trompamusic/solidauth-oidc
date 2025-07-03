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
    def save_configuration_token(self, issuer, profile, sub, token):
        pass

    @abstractmethod
    def update_configuration_token(self, issuer, profile, token):
        pass

    @abstractmethod
    def get_configuration_token(self, issuer, profile):
        pass

    @abstractmethod
    def get_configuration_tokens(self):
        pass

    @abstractmethod
    def get_state_data(self, state):
        pass

    @abstractmethod
    def delete_state_data(self, state):
        pass

    @abstractmethod
    def set_state_data(self, state, code_verifier, issuer=None):
        pass
