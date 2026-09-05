"""Flask application factory."""
from flask import Flask

from app.config import FLASK_SECRET_KEY
from app.web import deps


def create_app():
    app = Flask(__name__,
                template_folder="../templates",
                static_folder="../static")
    app.secret_key = FLASK_SECRET_KEY
    app.teardown_appcontext(deps.close_conn)

    from app.web.auth_routes import bp as auth_bp
    from app.web.main_routes import bp as main_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)

    @app.context_processor
    def inject_user():
        return {"user": deps.current_user()}

    return app