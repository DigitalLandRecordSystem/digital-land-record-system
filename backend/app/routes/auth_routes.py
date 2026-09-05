"""Registration and two-step login."""
import sqlite3

from flask import (Blueprint, flash, make_response, redirect, render_template,
                   request, url_for)

from app.config import SESSION_LIFETIME_MINUTES
from app.crypto import totp
from app.services import auth_service, session_service, user_service
from app.routes.deps import (COOKIE_KW, PENDING_COOKIE, SESSION_COOKIE,
                          current_user, get_conn, login_required)

bp = Blueprint("auth", __name__)

PENDING_SECONDS = 300  # a pending session is short-lived by design


@bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user():
        return redirect(url_for("main.dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")

        if not (username and email and password):
            flash("All fields are required.", "error")
        elif password != confirm:
            flash("Passwords do not match.", "error")
        elif len(password) < 8:
            flash("Password must be at least 8 characters.", "error")
        else:
            conn = get_conn()
            try:
                user_id = user_service.register_user(conn, username, email, password)
            except sqlite3.IntegrityError:
                flash("That username or email is already registered.", "error")
            except ValueError as exc:
                flash(str(exc), "error")
            else:
                secret = auth_service.get_totp_secret(conn, user_id)
                return render_template("registered.html",
                                       username=username, secret=secret)

    return render_template("register.html")


@bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user():
        return redirect(url_for("main.dashboard"))

    if request.method == "POST":
        try:
            pending = auth_service.start_login(
                get_conn(),
                request.form.get("username", "").strip(),
                request.form.get("password", ""),
                ip_address=request.remote_addr,
                user_agent=request.headers.get("User-Agent"))
        except auth_service.AuthError:
            flash("Invalid username or password.", "error")
        else:
            resp = make_response(redirect(url_for("auth.verify")))
            resp.set_cookie(PENDING_COOKIE, pending,
                            max_age=PENDING_SECONDS, **COOKIE_KW)
            return resp

    return render_template("login.html")


@bp.route("/verify", methods=["GET", "POST"])
def verify():
    """Second factor. The pending session grants no access on its own."""
    pending = request.cookies.get(PENDING_COOKIE)
    if not pending:
        flash("Please sign in first.", "error")
        return redirect(url_for("auth.login"))

    conn = get_conn()
    row = session_service.validate_session(conn, pending, require_mfa=False)
    if row is None:
        flash("Your sign-in attempt expired. Please start again.", "error")
        resp = make_response(redirect(url_for("auth.login")))
        resp.delete_cookie(PENDING_COOKIE, path="/")
        return resp

    if request.method == "POST":
        code = request.form.get("code", "").strip()
        try:
            token = auth_service.complete_login(conn, pending, code)
        except auth_service.AuthError as exc:
            flash(str(exc), "error")
        else:
            resp = make_response(redirect(url_for("main.dashboard")))
            resp.set_cookie(SESSION_COOKIE, token,
                            max_age=SESSION_LIFETIME_MINUTES * 60, **COOKIE_KW)
            resp.delete_cookie(PENDING_COOKIE, path="/")
            return resp

    # This build uses HMAC-SHA256 rather than SHA-1, so codes do not pair with
    # standard authenticator apps. The current code is shown for demonstration.
    demo_code = totp.generate_code(auth_service.get_totp_secret(conn, row["user_id"]))
    return render_template("verify.html", demo_code=demo_code)


@bp.route("/logout", methods=["POST"])
@login_required
def logout():
    auth_service.logout(get_conn(), request.cookies.get(SESSION_COOKIE))
    resp = make_response(redirect(url_for("auth.login")))
    resp.delete_cookie(SESSION_COOKIE, path="/")
    flash("You have been signed out.", "success")
    return resp