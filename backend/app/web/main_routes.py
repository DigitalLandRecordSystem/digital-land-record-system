"""Landing page and dashboard."""
from flask import Blueprint, redirect, render_template, url_for

from app.web.deps import current_user, login_required

bp = Blueprint("main", __name__)


@bp.route("/")
def index():
    return redirect(url_for("main.dashboard") if current_user()
                    else url_for("auth.login"))


@bp.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")