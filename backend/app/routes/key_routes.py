"""Key management: inspect key versions and rotate them."""
from flask import (Blueprint, flash, make_response, redirect, render_template,
                   request, url_for)

from app.config import SESSION_LIFETIME_MINUTES
from app.crypto import key_manager as km
from app.services import deed_service as ds
from app.services import profile_service as ps
from app.services import session_service
from app.services import user_service as us
from app.routes.deps import (COOKIE_KW, SESSION_COOKIE, current_user, get_conn,
                             login_required)

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

    # Rotating a key is a security event, so every session issued under the
    # old key is revoked. The session doing the rotation is then re-issued as
    # a fresh token, which signs out every other device without signing this
    # one out mid-operation.
    session_service.revoke_all_for_user(conn, user["user_id"])
    replacement = session_service.create_session(
        conn, user["user_id"], mfa_verified=True,
        ip_address=request.remote_addr,
        user_agent=request.headers.get("User-Agent"))

    flash(f"{algorithm} key rotated. The previous version was retired but "
          f"kept, so existing records remain readable. All other sessions "
          f"were signed out.", "success")
    resp = make_response(redirect(url_for("keys.index")))
    resp.set_cookie(SESSION_COOKIE, replacement,
                    max_age=SESSION_LIFETIME_MINUTES * 60, **COOKIE_KW)
    return resp


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