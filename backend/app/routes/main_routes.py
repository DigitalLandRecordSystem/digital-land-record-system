"""Landing page and dashboard."""
from flask import Blueprint, redirect, render_template, url_for

from app.routes.deps import current_user, get_conn, login_required

bp = Blueprint("main", __name__)


@bp.route("/")
def index():
    return redirect(url_for("main.dashboard") if current_user()
                    else url_for("auth.login"))


@bp.route("/dashboard")
@login_required
def dashboard():
    from app.services import deed_service as ds
    from app.services import user_service as us

    conn, user = get_conn(), current_user()
    deeds = ds.list_deeds(conn, user)
    details = us.get_user_details(conn, user["user_id"])

    return render_template(
        "dashboard.html",
        details=details,
        deed_count=len(deeds),
        flagged=sum(1 for d in deeds if not d["intact"]),
    )