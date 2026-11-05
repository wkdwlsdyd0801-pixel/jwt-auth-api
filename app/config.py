"""Runtime settings, read from the environment and validated at startup."""
import os
from dataclasses import dataclass

MIN_SECRET_BYTES = 32


@dataclass(frozen=True)
class Settings:
    jwt_secret: str
    db_path: str = "auth.db"
    issuer: str = "jwt-auth-api"
    audience: str = "jwt-auth-api-clients"
    # Short access lifetime: access tokens are stateless and cannot be revoked,
    # so this value is the maximum time a stolen one stays useful.
    access_ttl_seconds: int = 15 * 60
    refresh_ttl_seconds: int = 7 * 24 * 60 * 60

    def __post_init__(self):
        # Fail at startup instead of silently signing with a guessable key:
        # anyone who can guess an HS256 secret can forge a token for any user.
        if len(self.jwt_secret.encode()) < MIN_SECRET_BYTES:
            raise ValueError(f"JWT_SECRET must be at least {MIN_SECRET_BYTES} bytes")


def load_settings() -> Settings:
    """Build settings from env vars. There is deliberately no default secret."""
    return Settings(
        jwt_secret=os.environ.get("JWT_SECRET", ""),
        db_path=os.environ.get("DB_PATH", "auth.db"),
        access_ttl_seconds=int(os.environ.get("ACCESS_TTL_SECONDS", 15 * 60)),
        refresh_ttl_seconds=int(os.environ.get("REFRESH_TTL_SECONDS", 7 * 24 * 60 * 60)),
    )
