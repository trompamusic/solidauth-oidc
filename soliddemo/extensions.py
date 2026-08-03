from flask_admin import Admin
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy

from soliddemo.admin import AuthIndexView

admin = Admin(index_view=AuthIndexView())
bcrypt = Bcrypt()
db = SQLAlchemy()
login_manager = LoginManager()
