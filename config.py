import os
from urllib.parse import urlparse

SECRET_KEY = os.getenv("CONFIG_SECRET_KEY")
SQLALCHEMY_DATABASE_URI = os.getenv("CONFIG_SQLALCHEMY_DATABASE_URI")

REDIRECT_URL = os.getenv("CONFIG_REDIRECT_URL")
# "http://localhost:5000/redirect"

BASE_URL = os.getenv("CONFIG_BASE_URL")
url_parts = urlparse(BASE_URL)
SERVER_NAME = url_parts.netloc
PREFERRED_URL_SCHEME = url_parts.scheme

USE_CLIENT_ID_DOCUMENT = True
