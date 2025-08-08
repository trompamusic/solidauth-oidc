import os
from urllib.parse import urlparse

REDIS_URL = os.getenv("CONFIG_REDIS_URL")
# redis://localhost:6379/0"

SECRET_KEY = os.getenv("CONFIG_SECRET_KEY")
SQLALCHEMY_DATABASE_URI = os.getenv("CONFIG_SQLALCHEMY_DATABASE_URI")

REDIRECT_URL = os.getenv("CONFIG_REDIRECT_URL")
# "http://localhost:5000/redirect"

BASE_URL = os.getenv("CONFIG_BASE_URL")
url_parts = urlparse(BASE_URL)
SERVER_NAME = url_parts.netloc
PREFERRED_URL_SCHEME = url_parts.scheme

BACKEND = os.getenv("CONFIG_BACKEND")
if BACKEND not in ["redis", "db"]:
    raise ValueError("CONFIG_BACKEND must be 'redis' or 'db'")

USE_CLIENT_ID_DOCUMENT = True
