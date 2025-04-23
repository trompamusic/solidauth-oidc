import os

REDIS_URL = os.getenv("CONFIG_REDIS_URL")
# redis://localhost:6379/0"

SECRET_KEY = os.getenv("CONFIG_SECRET_KEY")
SQLALCHEMY_DATABASE_URI = os.getenv("CONFIG_SQLALCHEMY_DATABASE_URI")

REDIRECT_URL = os.getenv("CONFIG_REDIRECT_URL")
# "http://localhost:5000/redirect"

BASE_URL = os.getenv("CONFIG_BASE_URL")

# When accessing an OP, should you register a client ID ahead of time, or submit a URL?
#  if the OP doesn't support client registration, it'll always submit a URL
ALWAYS_USE_CLIENT_URL = False
# ALWAYS_USE_CLIENT_URL = True

BACKEND = os.getenv("CONFIG_BACKEND")
if BACKEND not in ["redis", "db"]:
    raise ValueError("CONFIG_BACKEND must be 'redis' or 'db'")
