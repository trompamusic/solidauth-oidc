import os

REDIS_URL = os.getenv("CONFIG_REDIS_URL")
# redis://localhost:6379/0"

SECRET_KEY = os.getenv("CONFIG_SECRET_KEY")
SQLALCHEMY_DATABASE_URI = os.getenv("CONFIG_SQLALCHEMY_DATABASE_URI")

REDIRECT_URL = os.getenv("CONFIG_REDIRECT_URL")
# "http://localhost:5000/redirect"
