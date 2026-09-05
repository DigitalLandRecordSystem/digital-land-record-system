"""Request-scoped database access and access-control decorators."""
from functools import wraps

from flask import flash, g, redirect, request, url_for

from app.database.db import get_connection
from app.services import auth_service

SESSION_COOKIE = "lr_session"
PENDING_COOKIE = "lr_pending"

# HttpOnly keeps the token out of reach of JavaScript; SameSite blocks it from
# being sent on cross-site requests. Secure stays off only because the demo
# runs over plain HTTP.
COOKIE_KW = dict(httponly=True, samesite="Lax", secure=False, path="/")


def get_conn():
    """One connection per request, closed by the teardown handler."""
    if "conn" not in g:
        g.conn = get_connection()
    return g.conn


def close_conn(exc=None):
    conn = g.pop("conn", None)
    if conn is not None:
        conn.close()


def current_user():
    """The fully authenticated user row for this request, or None."""
    if "user" not in g:
        token = request.cookies.get(SESSION_COOKIE)
        g.user = auth_service.current_user(get_conn(), token) if token else None
    return g.user


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if current_user() is None:
            flash("Please sign in to continue.", "error")
            return redirect(url_for("auth.login"))
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    """RBAC: administrator-only routes."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = current_user()
        if user is None:
            flash("Please sign in to continue.", "error")
            return redirect(url_for("auth.login"))
        if user["role"] != "ADMIN":
            flash("Administrator privileges are required.", "error")
            return redirect(url_for("main.dashboard"))
        return view(*args, **kwargs)
    return wrapped