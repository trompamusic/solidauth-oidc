from getpass import getpass

from flask.cli import with_appcontext

from solid.cli import cli_bp
from solid.db import User
from solid.extensions import db
from solid.webserver import webserver_bp, create_app
from trompasolid.db import Base

app = create_app()

app.register_blueprint(webserver_bp)
app.register_blueprint(cli_bp)


@app.cli.command("create-db")
def create_database():
    """Create database tables"""
    # This doesn't use the Flask-SQLAlchemy create_all method, as we have other
    # tables that aren't part of that extension's declarative base
    print("Creating database tables...")
    db.create_all()
    Base.metadata.create_all(db.engine)
    print("Done")


@app.cli.command("create-user")
@with_appcontext
def create_user():
    """Create an admin user account"""
    username = input("Username: ")
    pw = getpass("Password: ")
    pw2 = getpass("Again: ")
    if pw == pw2:
        user = User(username, pw, is_admin=True)
        db.session.add(user)
        db.session.commit()
        print(f"User {username} created")
    else:
        print("Passwords don't match")
