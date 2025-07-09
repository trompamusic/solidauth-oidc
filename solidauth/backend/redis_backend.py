import json

from solidauth.backend import SolidBackend

REDIS_KEY_PREFIX = "solidauth-"

# Private key for this app
CONFIG_RP_KEYS = "local-key"
# Server configuration for a Resource Server (key has provider url as a suffix)
CONFIG_RS_CONFIGURATION = "rs-configuration-{}"
# JWKS (public keys) for a Resource Server (key has provider url as a suffix)
CONFIG_RS_JWKS = "rs-jwks-{}"
# Registration information for this app on a Resource Server (key has provider url as a suffix)
CONFIG_CLIENT_REGISTRATION = "rs-registration-{}"
# Auth tokens to act as a particular user on a Resource Server (key has providerurl-userid-clientid as a suffix)
CONFIG_TOKENS = "rs-token-{}-{}-{}"
# List of all configuration token keys
CONFIG_TOKENS_LIST = "rs-tokens-list"
# PKCE state
CONFIG_STATE = "state-{}"


def make_redis_key(key_template, *args):
    return key_template.format(*args)


class RedisBackend(SolidBackend):
    def __init__(self, redis_client):
        self.redis_client = redis_client

    def is_ready(self):
        return self.redis_client.ping()

    def get_redis_dict(self, key):
        """Load a dict from redis"""
        value = self.get_redis_str(key)
        if value:
            return json.loads(value)
        else:
            return value

    def store_redis_dict(self, key, value):
        """Store a dict in redis (stored as a json-dumped string)"""
        value = json.dumps(value)
        return self.store_redis_str(key, value)

    def get_redis_str(self, key):
        """Load a string value from redis"""
        key = REDIS_KEY_PREFIX + key
        return self.redis_client.get(key)

    def store_redis_str(self, key, value):
        key = REDIS_KEY_PREFIX + key
        return self.redis_client.set(key, value)

    def get_relying_party_keys(self):
        return self.get_redis_str(CONFIG_RP_KEYS)

    def save_relying_party_keys(self, keys):
        return self.store_redis_str(CONFIG_RP_KEYS, keys)

    def get_resource_server_configuration(self, provider):
        return self.get_redis_dict(make_redis_key(CONFIG_RS_CONFIGURATION, provider))

    def save_resource_server_configuration(self, provider, configuration):
        return self.store_redis_dict(make_redis_key(CONFIG_RS_CONFIGURATION, provider), configuration)

    def get_resource_server_keys(self, provider):
        return self.get_redis_dict(make_redis_key(CONFIG_RS_JWKS, provider))

    def save_resource_server_keys(self, provider, keys):
        return self.store_redis_dict(make_redis_key(CONFIG_RS_JWKS, provider), keys)

    def get_client_registration(self, provider):
        return self.get_redis_dict(make_redis_key(CONFIG_CLIENT_REGISTRATION, provider))

    def save_client_registration(self, provider, client_registration):
        return self.store_redis_dict(make_redis_key(CONFIG_CLIENT_REGISTRATION, provider), client_registration)

    def save_configuration_token(self, issuer, profile, sub, client_id, token):
        token_key = make_redis_key(CONFIG_TOKENS, issuer, profile, client_id)
        result = self.store_redis_str(token_key, token)

        # Add to the list of all tokens for get_configuration_tokens
        list_key = REDIS_KEY_PREFIX + CONFIG_TOKENS_LIST
        self.redis_client.sadd(list_key, token_key)

        return result

    def get_configuration_token(self, issuer, profile, use_client_id_document):
        return self.get_redis_str(make_redis_key(CONFIG_TOKENS, issuer, profile, use_client_id_document))

    def update_configuration_token(self, issuer, profile, client_id, token):
        return self.store_redis_str(make_redis_key(CONFIG_TOKENS, issuer, profile, client_id), token)

    def get_configuration_tokens(self):
        list_key = REDIS_KEY_PREFIX + CONFIG_TOKENS_LIST
        token_keys = self.redis_client.smembers(list_key)
        tokens = []
        for key in token_keys:
            if isinstance(key, bytes):
                key = key.decode("utf-8")
            token_data = self.get_redis_str(key)
            if token_data:
                tokens.append(token_data)
        return tokens

    def get_state_data(self, state):
        return self.get_redis_dict(make_redis_key(CONFIG_STATE, state))

    def delete_state_data(self, state):
        key = make_redis_key(CONFIG_STATE, state)
        key = REDIS_KEY_PREFIX + key
        return self.redis_client.delete(key)

    def set_state_data(self, state, code_verifier, issuer=None):
        data = {
            "code_verifier": code_verifier,
            "issuer": issuer,
        }
        return self.store_redis_dict(make_redis_key(CONFIG_STATE, state), data)
