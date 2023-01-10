from flask_admin import Admin
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_redis import FlaskRedis
from flask_sqlalchemy import SQLAlchemy

admin = Admin()
bcrypt = Bcrypt()
db = SQLAlchemy()
redis_client = FlaskRedis()
login_manager = LoginManager()
