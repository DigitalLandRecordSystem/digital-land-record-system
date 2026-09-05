"""Flask application factory."""
from flask import Flask

from app.config import FLASK_SECRET_KEY, PROJECT_ROOT
from app.routes import deps

FRONTEND_DIR = PROJECT_ROOT / "frontend"


def create_app():
    app = Flask(__name__,
                template_folder=str(FRONTEND_DIR / "templates"),
                static_folder=str(FRONTEND_DIR / "static"))
    app.secret_key = FLASK_SECRET_KEY
    app.teardown_appcontext(deps.close_conn)

    from app.routes.auth_routes import bp as auth_bp
    from app.routes.main_routes import bp as main_bp
    from app.routes.deed_routes import bp as deed_bp
    from app.routes.profile_routes import bp as profile_bp
    from app.routes.transfer_routes import bp as transfer_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(deed_bp)
    app.register_blueprint(profile_bp)
    app.register_blueprint(transfer_bp)

    @app.context_processor
    def inject_user():
        return {"user": deps.current_user()}

    return app