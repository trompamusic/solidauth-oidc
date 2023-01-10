from flask_redis import FlaskRedis
from flask_sqlalchemy import SQLAlchemy

redis_client = FlaskRedis()

db = SQLAlchemy()