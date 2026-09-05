"""Profile viewing and editing."""
from flask import (Blueprint, flash, redirect, render_template, request,
                   url_for)

from app.services import profile_service as ps
from app.services import user_service as us
from app.routes.deps import current_user, get_conn, login_required

bp = Blueprint("profile", __name__, url_prefix="/profile")


@bp.route("/")
@login_required
def view():
    conn, user = get_conn(), current_user()
    try:
        profile = ps.get_profile(conn, user["user_id"])
    except ps.IntegrityFailure as exc:
        return render_template("profile_tampered.html", message=str(exc)), 409
    return render_template("profile.html", profile=profile,
                           details=us.get_user_details(conn, user["user_id"]))


@bp.route("/edit", methods=["GET", "POST"])
@login_required
def edit():
    conn, user = get_conn(), current_user()

    if request.method == "POST":
        values = {f: request.form.get(f, "").strip() for f in ps.FIELDS}
        try:
            ps.update_profile(conn, user["user_id"], **values)
        except ps.ProfileError as exc:
            flash(str(exc), "error")
            return render_template("profile_form.html", profile=values)
        flash("Profile updated and re-encrypted.", "success")
        return redirect(url_for("profile.view"))

    try:
        profile = ps.get_profile(conn, user["user_id"])
    except ps.IntegrityFailure as exc:
        return render_template("profile_tampered.html", message=str(exc)), 409
    return render_template("profile_form.html", profile=profile)