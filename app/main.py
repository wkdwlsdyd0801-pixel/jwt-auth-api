"""
JWT authentication REST API.

  POST /auth/register  create an account
  POST /auth/login     password -> access + refresh token
  POST /auth/refresh   rotate: old refresh token -> new pair (single use)
  POST /auth/logout    revoke the whole login session
  GET  /me             example route protected by an access token

Run with:  flask --app app.main:create_app run
"""
import re
import sqlite3
import time
import uuid

from flask import Flask, g, jsonify, request

from . import db, security
from .config import Settings, load_settings

USERNAME_RE = re.compile(r"[A-Za-z0-9_.-]{3,32}")
MIN_PASSWORD = 12
# Hashing cost is paid on every attempt, so an unbounded password would be a cheap
# way to burn server CPU.
MAX_PASSWORD = 128


class ApiError(Exception):
    def __init__(self, status: int, message: str):
        self.status = status
        self.message = message


def _unauthorized(message: str = "Invalid or expired token") -> ApiError:
    # One message for every token failure: telling a caller "bad signature" versus
    # "expired" would help an attacker probing forged tokens.
    return ApiError(401, message)


def _json_field(*names: str) -> list[str]:
    """Return required string fields from the JSON body, or fail with 400."""
    body = request.get_json(silent=True)
    values = [body.get(name) if isinstance(body, dict) else None for name in names]
    # Type check: a list or number here would crash the code that follows.
    if not all(isinstance(value, str) for value in values):
        raise ApiError(400, f"JSON body must contain string fields: {', '.join(names)}")
    return values


def _issue_pair(conn: sqlite3.Connection, settings: Settings, user_id: int, family_id: str):
    """Create an access and a refresh token, record the refresh token and commit."""
    access, _ = security.create_token(settings, user_id, security.ACCESS)
    refresh, claims = security.create_token(settings, user_id, security.REFRESH, family_id)
    conn.execute(
        "INSERT INTO refresh_tokens (jti, family_id, user_id, expires_at) VALUES (?, ?, ?, ?)",
        (claims["jti"], family_id, user_id, claims["exp"]),
    )
    conn.commit()
    return jsonify(
        access_token=access,
        refresh_token=refresh,
        token_type="bearer",
        expires_in=settings.access_ttl_seconds,
    )


def create_app(settings: Settings | None = None) -> Flask:
    settings = settings or load_settings()
    db.init_db(settings.db_path)
    app = Flask(__name__)

    def get_conn() -> sqlite3.Connection:
        # One connection per request, closed in the teardown below.
        if "conn" not in g:
            g.conn = db.connect(settings.db_path)
        return g.conn

    @app.teardown_appcontext
    def close_conn(_exc):
        conn = g.pop("conn", None)
        if conn is not None:
            conn.close()

    @app.errorhandler(ApiError)
    def handle_api_error(error: ApiError):
        response = jsonify(error=error.message)
        response.status_code = error.status
        if error.status == 401:
            response.headers["WWW-Authenticate"] = "Bearer"
        return response

    def refresh_claims() -> dict:
        """Verify the refresh token from the request body and return its claims."""
        token, = _json_field("refresh_token")
        try:
            claims = security.decode_token(settings, token, security.REFRESH)
        except security.TokenError:
            raise _unauthorized() from None
        if "family_id" not in claims:
            raise _unauthorized()
        return claims

    @app.post("/auth/register")
    def register():
        username, password = _json_field("username", "password")
        if not USERNAME_RE.fullmatch(username):
            raise ApiError(400, "Username must be 3-32 characters: letters, digits, _ . -")
        if not MIN_PASSWORD <= len(password) <= MAX_PASSWORD:
            raise ApiError(400, f"Password must be {MIN_PASSWORD}-{MAX_PASSWORD} characters")
        conn = get_conn()
        try:
            # Parameter binding, and only the hash is ever stored.
            cur = conn.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, security.hash_password(password)),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            raise ApiError(409, "Username already taken") from None
        return jsonify(id=cur.lastrowid, username=username), 201

    @app.post("/auth/login")
    def login():
        username, password = _json_field("username", "password")
        if len(password) > MAX_PASSWORD:
            raise _unauthorized("Invalid username or password")
        conn = get_conn()
        row = conn.execute(
            "SELECT id, password_hash FROM users WHERE username = ?", (username,)
        ).fetchone()
        # Always verify, even with no such user, and answer identically either way.
        if not security.verify_password(row["password_hash"] if row else None, password):
            raise _unauthorized("Invalid username or password")
        # Expired rows can no longer be replayed, so this is a safe time to clean up.
        conn.execute("DELETE FROM refresh_tokens WHERE expires_at < ?", (int(time.time()),))
        return _issue_pair(conn, settings, row["id"], family_id=uuid.uuid4().hex)

    @app.post("/auth/refresh")
    def refresh():
        claims = refresh_claims()
        conn = get_conn()
        # One atomic UPDATE claims the token. A read-then-write would let two
        # concurrent requests both spend the same token. The write lock it takes is
        # held until _issue_pair commits, so a concurrent replay (below) cannot run
        # in between and miss the new token.
        claimed = conn.execute(
            "UPDATE refresh_tokens SET used_at = ? WHERE jti = ? AND used_at IS NULL AND revoked = 0",
            (int(time.time()), claims["jti"]),
        ).rowcount
        if not claimed:
            # A correctly signed token that was already spent means two parties hold
            # it: one is a thief, and we cannot tell which. Kill the whole session,
            # so the thief's newest token dies too and the real user logs in again.
            conn.execute("UPDATE refresh_tokens SET revoked = 1 WHERE family_id = ?", (claims["family_id"],))
            conn.commit()
            raise _unauthorized()
        return _issue_pair(conn, settings, int(claims["sub"]), claims["family_id"])

    @app.post("/auth/logout")
    def logout():
        claims = refresh_claims()
        conn = get_conn()
        conn.execute("UPDATE refresh_tokens SET revoked = 1 WHERE family_id = ?", (claims["family_id"],))
        conn.commit()
        return "", 204

    @app.get("/me")
    def me():
        scheme, _, token = request.headers.get("Authorization", "").partition(" ")
        if scheme.lower() != "bearer" or not token:
            raise _unauthorized("Missing bearer token")
        try:
            claims = security.decode_token(settings, token, security.ACCESS)
        except security.TokenError:
            raise _unauthorized() from None
        # A valid signature proves we issued it, not that the account still exists.
        user = get_conn().execute("SELECT id, username FROM users WHERE id = ?", (claims["sub"],)).fetchone()
        if user is None:
            raise _unauthorized()
        return jsonify(id=user["id"], username=user["username"])

    return app
