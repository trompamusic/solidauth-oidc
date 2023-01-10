from solid.cli import cli_bp
from solid.extensions import db
from solid.webserver import webserver_bp, create_app

app = create_app()

app.register_blueprint(webserver_bp)
app.register_blueprint(cli_bp)


@app.cli.command("create-db")
def create_database():
    """Create database tables"""
    print("Creating database tables...")
    db.create_all()
    print("Done")
