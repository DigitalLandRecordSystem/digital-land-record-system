"""Key management: inspect key versions and rotate them."""
from flask import Blueprint, flash, redirect, render_template, url_for
from app.crypto import key_manager as km
from app.services import deed_service as ds
from app.services import profile_service as ps
from app.services import user_service as us
from app.routes.deps import current_user, get_conn, login_required

bp = Blueprint("keys", __name__, url_prefix="/keys")


@bp.route("/")
@login_required
def index():
    conn, user = get_conn(), current_user()
    keys = km.list_keys(conn, user["user_id"])
    return render_template("keys.html", keys=keys)


@bp.route("/rotate/<algorithm>", methods=["POST"])
@login_required
def rotate(algorithm):
    algorithm = algorithm.upper()
    if algorithm not in (km.RSA, km.ECC):
        flash("Unknown algorithm.", "error")
        return redirect(url_for("keys.index"))

    conn, user = get_conn(), current_user()
    km.rotate_key(conn, user["user_id"], algorithm)
    flash(f"{algorithm} key rotated. The previous version was retired but "
          f"kept, so existing records remain readable.", "success")
    return redirect(url_for("keys.index"))


@bp.route("/migrate", methods=["POST"])
@login_required
def migrate():
    """Re-encrypt this user's records under their current active keys."""
    conn, user = get_conn(), current_user()
    us.reencrypt_account(conn, user["user_id"])
    deeds = ds.reencrypt_owned(conn, user["user_id"])
    had_profile = ps.reencrypt(conn, user["user_id"])

    parts = ["account", f"{deeds} deed(s)"]
    if had_profile:
        parts.append("profile")
    flash("Re-encrypted " + ", ".join(parts) + " under the current keys.",
          "success")
    return redirect(url_for("keys.index"))


@bp.route("/directory")
@login_required
def directory():
    return render_template("key_directory.html",
                           entries=km.public_directory(get_conn()))