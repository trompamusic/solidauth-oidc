import json

from solid.backend import SolidBackend

REDIS_KEY_PREFIX = "solidauth-"

def make_redis_key(key_template, *args):
    return key_template.format(*args)

# Private key for this app
CONFIG_RP_KEYS = "local-key"
# Server configuration for a Resource Server (key has provider url as a suffix)
CONFIG_RS_CONFIGURATION = "rs-configuration-{}"
# JWKS (public keys) for a Resource Server (key has provider url as a suffix)
CONFIG_RS_JWKS = "rs-jwks-{}"
# Registration information for this app on a Resource Server (key has provider url as a suffix)
CONFIG_CLIENT_REGISTRATION = "rs-registration-{}"
# Auth tokens to act as a particular user on a Resource Server (key has providerurl-userid as a suffix)
CONFIG_TOKENS = "rs-token-{}-{}"

class RedisBackend(SolidBackend):
    def __init__(self, redis_client):
        self.redis_client = redis_client

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

    def save_configuration_token(self, issuer, sub, token):
        return self.store_redis_str(make_redis_key(CONFIG_TOKENS, issuer, sub), token)