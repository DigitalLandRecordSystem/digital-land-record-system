"""Flask application factory."""
from flask import Flask

from app.config import FLASK_SECRET_KEY, PROJECT_ROOT
from app.web import deps

FRONTEND_DIR = PROJECT_ROOT / "frontend"


def create_app():
    app = Flask(__name__,
                template_folder=str(FRONTEND_DIR / "templates"),
                static_folder=str(FRONTEND_DIR / "static"))
    app.secret_key = FLASK_SECRET_KEY
    app.teardown_appcontext(deps.close_conn)

    from app.web.auth_routes import bp as auth_bp
    from app.web.main_routes import bp as main_bp
    from app.web.deed_routes import bp as deed_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(deed_bp)

    @app.context_processor
    def inject_user():
        return {"user": deps.current_user()}

    return app