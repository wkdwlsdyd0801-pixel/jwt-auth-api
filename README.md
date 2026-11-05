# jwt-auth-api

A Flask REST API with JWT authentication: short-lived access tokens, single-use rotating refresh tokens with reuse detection, and strict signature and claim verification.

## Run

```bash
pip install -r requirements.txt
cp .env.example .env    # then set JWT_SECRET (the command is in the file)
flask --app app.main:create_app run
```

The app refuses to start without a secret of at least 32 bytes. Endpoints: `POST /auth/register`, `/auth/login`, `/auth/refresh`, `/auth/logout` and `GET /me`.

## Test

```bash
pip install -r requirements-dev.txt
pytest
```

The tests forge a token for each attack: wrong key, `alg=none`, algorithm swap, expired, missing `exp`, wrong issuer or audience, tampered payload, token type confusion, and refresh token replay, including concurrent replay.

## Limitations

Access tokens stay valid after logout until they expire (15 minutes by default), the usual trade-off for stateless verification. In production this API also needs HTTPS and login rate limiting in front of it.
