"""Deed management: list, create, view, edit."""
from flask import (Blueprint, abort, flash, redirect, render_template,
                   request, url_for)

from app.services import deed_service as ds
from app.routes.deps import current_user, get_conn, login_required

bp = Blueprint("deeds", __name__, url_prefix="/deeds")


@bp.route("/")
@login_required
def index():
    return render_template("deed_list.html",
                           deeds=ds.list_deeds(get_conn(), current_user()))


@bp.route("/new", methods=["GET", "POST"])
@login_required
def create():
    form = {}
    if request.method == "POST":
        form = {k: request.form.get(k, "").strip()
                for k in ("plot_no", "district", "area", "content")}
        try:
            deed_id = ds.create_deed(get_conn(), current_user()["user_id"],
                                     **form)
        except ds.DeedError as exc:
            flash(str(exc), "error")
        else:
            flash("Deed created and encrypted.", "success")
            return redirect(url_for("deeds.view", deed_id=deed_id))
    return render_template("deed_form.html", form=form, deed=None)


@bp.route("/<deed_id>")
@login_required
def view(deed_id):
    try:
        deed = ds.get_deed(get_conn(), deed_id, current_user())
    except LookupError:
        abort(404)
    except ds.AccessDenied as exc:
        flash(str(exc), "error")
        return redirect(url_for("deeds.index"))
    except ds.IntegrityFailure as exc:
        return render_template("deed_tampered.html",
                               deed_id=deed_id, message=str(exc)), 409
    return render_template("deed_view.html", deed=deed)


@bp.route("/<deed_id>/edit", methods=["GET", "POST"])
@login_required
def edit(deed_id):
    conn, user = get_conn(), current_user()
    try:
        deed = ds.get_deed(conn, deed_id, user)
    except LookupError:
        abort(404)
    except ds.AccessDenied as exc:
        flash(str(exc), "error")
        return redirect(url_for("deeds.index"))
    except ds.IntegrityFailure as exc:
        return render_template("deed_tampered.html",
                               deed_id=deed_id, message=str(exc)), 409

    if deed["owner_id"] != user["user_id"]:
        flash("Only the owner may edit a deed.", "error")
        return redirect(url_for("deeds.view", deed_id=deed_id))

    if request.method == "POST":
        form = {k: request.form.get(k, "").strip()
                for k in ("district", "area", "content")}
        try:
            ds.update_deed(conn, deed_id, user, **form)
        except ds.DeedError as exc:
            flash(str(exc), "error")
            return render_template("deed_form.html",
                                   form={**deed, **form}, deed=deed)
        flash("Deed updated and re-encrypted.", "success")
        return redirect(url_for("deeds.view", deed_id=deed_id))

    return render_template("deed_form.html", form=deed, deed=deed)