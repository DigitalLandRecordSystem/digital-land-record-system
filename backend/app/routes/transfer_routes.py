"""Ownership transfers: owners request, administrators decide."""
from flask import (Blueprint, flash, redirect, render_template, request,
                   url_for)

from app.services import message_service as ms
from app.services import transfer_service as ts
from app.routes.deps import admin_required, current_user, get_conn, login_required

bp = Blueprint("transfers", __name__, url_prefix="/transfers")


@bp.route("/")
@login_required
def index():
    return render_template(
        "transfer_list.html",
        transfers=ts.list_for_user(get_conn(), current_user()["user_id"]))


@bp.route("/request/<deed_id>", methods=["POST"])
@login_required
def create(deed_id):
    to_username = request.form.get("to_username", "").strip()
    message = request.form.get("message", "").strip()
    try:
        ts.request_transfer(get_conn(), deed_id, current_user(), to_username,
                            message=message or None)
    except LookupError:
        flash("No such deed.", "error")
    except (ts.TransferError, ts.AccessDenied, ms.MessageError) as exc:
        flash(str(exc), "error")
        return redirect(url_for("deeds.view", deed_id=deed_id))
    flash("Transfer requested. An administrator will review it.", "success")
    return redirect(url_for("transfers.index"))


@bp.route("/queue")
@admin_required
def queue():
    return render_template("transfer_queue.html",
                           transfers=ts.list_pending(get_conn()))


@bp.route("/queue/<request_id>/approve", methods=["POST"])
@admin_required
def approve(request_id):
    try:
        ts.approve(get_conn(), request_id, current_user())
    except (ts.TransferError, ts.AccessDenied) as exc:
        flash(str(exc), "error")
    else:
        flash("Transfer approved. The deed was re-encrypted under the new "
              "owner's key.", "success")
    return redirect(url_for("transfers.queue"))


@bp.route("/queue/<request_id>/reject", methods=["POST"])
@admin_required
def reject(request_id):
    reason = request.form.get("reason", "").strip()
    try:
        ts.reject(get_conn(), request_id, current_user(), reason)
    except (ts.TransferError, ts.AccessDenied) as exc:
        flash(str(exc), "error")
    else:
        flash("Transfer rejected. The reason was encrypted for the requester.",
              "success")
    return redirect(url_for("transfers.queue"))


@bp.route("/<request_id>/message", methods=["GET", "POST"])
@login_required
def message(request_id):
    """Unlock a message by re-deriving the reader's messaging key."""
    text = None
    if request.method == "POST":
        try:
            text = ts.read_message(get_conn(), request_id, current_user(),
                                   request.form.get("password", ""))
        except LookupError:
            flash("No such transfer request.", "error")
            return redirect(url_for("transfers.index"))
        except ts.AccessDenied as exc:
            flash(str(exc), "error")
            return redirect(url_for("transfers.index"))
        except (ts.TransferError, ms.MessageError) as exc:
            flash(str(exc), "error")

    return render_template("message_unlock.html", request_id=request_id,
                           message=text)