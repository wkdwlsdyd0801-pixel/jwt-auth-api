"""
Password hashing plus issuing and verifying JWTs.

Every check here exists to stop a specific attack; the comments name which one.
"""
import time
import uuid

import jwt
from werkzeug.security import check_password_hash, generate_password_hash

from .config import Settings

ACCESS = "access"
REFRESH = "refresh"

# The one accepted algorithm, fixed by the server. Trusting the token's own "alg"
# header would let an attacker choose "none" and skip the signature entirely.
ALGORITHM = "HS256"
REQUIRED_CLAIMS = ["exp", "iat", "iss", "aud", "sub", "jti", "token_type"]

# scrypt with the OWASP-recommended cost (N=2^17, r=8, p=1). It is memory-hard, so
# stolen hashes are expensive to crack even on GPUs; a random salt is added per
# password, so identical passwords do not produce identical hashes.
HASH_METHOD = "scrypt:131072:8:1"

# Verified when the username does not exist, so unknown and known users take the
# same time to answer. Otherwise response timing reveals which usernames are real.
_DUMMY_HASH = generate_password_hash("dummy-password-for-constant-work", method=HASH_METHOD)


class TokenError(Exception):
    """A token failed verification. Callers show one generic message for all causes."""


def hash_password(password: str) -> str:
    return generate_password_hash(password, method=HASH_METHOD)


def verify_password(stored_hash: str | None, password: str) -> bool:
    # Run the hash even for an unknown user, then still refuse that login.
    matches = check_password_hash(stored_hash or _DUMMY_HASH, password)
    return matches and stored_hash is not None


def create_token(settings: Settings, user_id: int, token_type: str, family_id: str | None = None) -> tuple[str, dict]:
    """Sign a token and return it with its claims (the caller may need jti and exp)."""
    now = int(time.time())
    ttl = settings.access_ttl_seconds if token_type == ACCESS else settings.refresh_ttl_seconds
    claims = {
        "iss": settings.issuer,
        "aud": settings.audience,
        "sub": str(user_id),
        "iat": now,
        "exp": now + ttl,
        "jti": uuid.uuid4().hex,
        "token_type": token_type,
    }
    if family_id:
        claims["family_id"] = family_id
    return jwt.encode(claims, settings.jwt_secret, algorithm=ALGORITHM), claims


def decode_token(settings: Settings, token: str, expected_type: str) -> dict:
    """Return the claims of a valid token, or raise TokenError."""
    try:
        claims = jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=[ALGORITHM],        # blocks alg=none and algorithm swaps
            issuer=settings.issuer,        # blocks tokens minted by another service
            audience=settings.audience,    # blocks tokens meant for another API
            # PyJWT only checks exp when present; requiring it stops a forged or
            # buggy token from never expiring just by leaving the claim out.
            options={"require": REQUIRED_CLAIMS},
        )
    except jwt.InvalidTokenError as exc:
        raise TokenError(str(exc)) from exc
    # Both types share a key, so without this a week-long refresh token would
    # also work as an access token and defeat the short access lifetime.
    if claims["token_type"] != expected_type:
        raise TokenError("wrong token type")
    return claims
