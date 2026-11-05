"""End-to-end tests: normal flows, then one forged or replayed token per attack."""
import sqlite3
import threading
import time

import jwt
import pytest

from app.config import Settings
from app.main import create_app

SECRET = "test-secret-" + "x" * 32
USER = {"username": "alice", "password": "correct-horse-battery"}


@pytest.fixture
def settings(tmp_path):
    return Settings(jwt_secret=SECRET, db_path=str(tmp_path / "test.db"))


@pytest.fixture
def client(settings):
    return create_app(settings).test_client()


@pytest.fixture
def tokens(client):
    assert client.post("/auth/register", json=USER).status_code == 201
    response = client.post("/auth/login", json=USER)
    assert response.status_code == 200
    return response.get_json()


def me(client, token):
    return client.get("/me", headers={"Authorization": f"Bearer {token}"})


def refresh(client, token):
    return client.post("/auth/refresh", json={"refresh_token": token})


def forge(settings, key=SECRET, algorithm="HS256", **overrides):
    """Build a token that is valid except for whatever the test overrides."""
    now = int(time.time())
    claims = {
        "iss": settings.issuer, "aud": settings.audience, "sub": "1", "iat": now,
        "exp": now + 600, "jti": "forged", "token_type": "access",
    }
    claims.update(overrides)
    return jwt.encode({k: v for k, v in claims.items() if v is not None}, key, algorithm=algorithm)


def test_login_then_access_protected_route(client, tokens):
    response = me(client, tokens["access_token"])
    assert response.status_code == 200
    assert response.get_json()["username"] == "alice"


def test_missing_token_is_rejected(client):
    assert client.get("/me").status_code == 401


def test_wrong_password_and_unknown_user_answer_identically(client, tokens):
    wrong = client.post("/auth/login", json={**USER, "password": "x" * 12})
    unknown = client.post("/auth/login", json={"username": "nobody", "password": "x" * 12})
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.get_json() == unknown.get_json()


def test_duplicate_username_and_short_password_are_rejected(client, tokens):
    assert client.post("/auth/register", json=USER).status_code == 409
    assert client.post("/auth/register", json={"username": "bob", "password": "short"}).status_code == 400


def test_password_is_stored_only_as_scrypt_hash(client, tokens, settings):
    stored = sqlite3.connect(settings.db_path).execute("SELECT password_hash FROM users").fetchone()[0]
    assert stored.startswith("scrypt:") and USER["password"] not in stored


def test_forge_helper_makes_accepted_tokens(client, tokens, settings):
    # Control case: proves the rejections below come from the one changed property.
    assert me(client, forge(settings)).status_code == 200


@pytest.mark.parametrize("attack", [
    pytest.param(dict(key="attacker-key-" + "y" * 32), id="wrong-signing-key"),
    pytest.param(dict(key=None, algorithm="none"), id="alg-none"),
    pytest.param(dict(algorithm="HS512"), id="algorithm-swap"),
    pytest.param(dict(exp=int(time.time()) - 10), id="expired"),
    pytest.param(dict(exp=None), id="no-exp-claim"),
    pytest.param(dict(iss="https://evil.example"), id="wrong-issuer"),
    pytest.param(dict(aud="another-api"), id="wrong-audience"),
    pytest.param(dict(sub="999"), id="deleted-or-unknown-user"),
])
def test_forged_access_tokens_are_rejected(client, tokens, settings, attack):
    assert me(client, forge(settings, **attack)).status_code == 401


def test_tampered_payload_breaks_signature(client, tokens, settings):
    header, _, signature = tokens["access_token"].split(".")
    _, other_payload, _ = forge(settings, sub="2").split(".")
    assert me(client, f"{header}.{other_payload}.{signature}").status_code == 401


def test_token_types_are_not_interchangeable(client, tokens):
    assert me(client, tokens["refresh_token"]).status_code == 401
    assert refresh(client, tokens["access_token"]).status_code == 401


def test_refresh_rotates_to_a_working_new_pair(client, tokens):
    response = refresh(client, tokens["refresh_token"])
    assert response.status_code == 200
    new = response.get_json()
    assert new["refresh_token"] != tokens["refresh_token"]
    assert me(client, new["access_token"]).status_code == 200


def test_refresh_reuse_revokes_the_whole_session(client, tokens):
    newest = refresh(client, tokens["refresh_token"]).get_json()["refresh_token"]
    # Replaying the spent token is the theft signal...
    assert refresh(client, tokens["refresh_token"]).status_code == 401
    # ...so the token issued from it must now be dead as well.
    assert refresh(client, newest).status_code == 401


def test_concurrent_refresh_lets_only_one_request_win(settings, tokens):
    app = create_app(settings)
    codes = []
    new_tokens = []

    def spend():
        response = refresh(app.test_client(), tokens["refresh_token"])
        codes.append(response.status_code)
        if response.status_code == 200:
            new_tokens.append(response.get_json()["refresh_token"])

    threads = [threading.Thread(target=spend) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sorted(codes) == [200] + [401] * 7
    # The losers count as replays, so even the winner's new token must be revoked.
    assert refresh(app.test_client(), new_tokens[0]).status_code == 401


def test_expired_refresh_token_is_rejected(tmp_path):
    settings = Settings(jwt_secret=SECRET, db_path=str(tmp_path / "t.db"), refresh_ttl_seconds=-1)
    client = create_app(settings).test_client()
    client.post("/auth/register", json=USER)
    assert refresh(client, client.post("/auth/login", json=USER).get_json()["refresh_token"]).status_code == 401


def test_logout_revokes_refresh_token(client, tokens):
    body = {"refresh_token": tokens["refresh_token"]}
    assert client.post("/auth/logout", json=body).status_code == 204
    assert refresh(client, tokens["refresh_token"]).status_code == 401


def test_malformed_request_bodies_are_rejected(client):
    assert client.post("/auth/login", data="not json").status_code == 400
    assert client.post("/auth/login", json={"username": ["a"], "password": 1}).status_code == 400
    assert client.post("/auth/refresh", json={}).status_code == 400


def test_weak_secret_refuses_to_start():
    with pytest.raises(ValueError):
        Settings(jwt_secret="secret")
