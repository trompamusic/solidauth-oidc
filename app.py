from solid.cli import cli_bp
from solid.webserver import webserver_bp, create_app

app = create_app()

app.register_blueprint(webserver_bp)
app.register_blueprint(cli_bp)
