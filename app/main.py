import hmac
import os
import time
from dataclasses import dataclass
from pathlib import Path

import jwt
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from jwt import PyJWKClient
from pydantic import BaseModel


@dataclass(frozen=True)
class Settings:
    allow_local: bool = False
    id_header: str = "X-Forwarded-Id-Token"
    google_client_id: str = ""
    logout_url: str = ""
    signing_key: str = ""
    issuer: str = "app-authorization-demo"
    audience: str = "app-authorization-demo"
    ttl: int = 43200

    @classmethod
    def from_env(cls):
        return cls(
            allow_local=os.getenv("APP_ALLOW_LOCAL_LOGIN", "false").lower() == "true",
            id_header=os.getenv("SSO_ID_TOKEN_HEADER", "X-Forwarded-Id-Token"),
            google_client_id=os.getenv("SSO_GOOGLE_CLIENT_ID", ""),
            logout_url=os.getenv("SSO_LOGOUT_URL", ""),
            signing_key=os.getenv("APP_ACCESS_TOKEN_SIGNING_KEY", ""),
            issuer=os.getenv("APP_ACCESS_TOKEN_ISSUER", "app-authorization-demo"),
            audience=os.getenv("APP_ACCESS_TOKEN_AUDIENCE", "app-authorization-demo"),
            ttl=int(os.getenv("APP_ACCESS_TOKEN_TTL_SECONDS", "43200")),
        )


class Login(BaseModel):
    username: str
    password: str


class Exchange(BaseModel):
    id_token: str | None = None


def create_app(settings=None, google_keys=None):
    cfg = settings or Settings.from_env()
    if len(cfg.signing_key.encode()) < 32:
        raise ValueError("APP_ACCESS_TOKEN_SIGNING_KEY must contain at least 32 bytes")
    if cfg.ttl <= 0 or (not cfg.allow_local and not cfg.google_client_id):
        raise ValueError("Positive token TTL and SSO_GOOGLE_CLIENT_ID (for SSO-only mode) are required")
    keys = google_keys or PyJWKClient("https://www.googleapis.com/oauth2/v3/certs")
    api = FastAPI(title="Authorization demo")

    @api.middleware("http")
    async def no_store(request, call_next):
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    def unauthorized():
        return HTTPException(401, "Invalid or missing token", headers={"WWW-Authenticate": "Bearer"})

    def mint(subject, kind, audience, ttl, **extra):
        now = int(time.time())
        return jwt.encode({"sub": subject, "iss": cfg.issuer, "aud": audience,
                           "iat": now, "exp": now + ttl, "token_use": kind, **extra},
                          cfg.signing_key, algorithm="HS256")

    def local_identity(token):
        claims = jwt.decode(token, cfg.signing_key, algorithms=["HS256"],
                            issuer=cfg.issuer, audience=cfg.issuer + ":local-login",
                            options={"require": ["sub", "iss", "aud", "iat", "exp", "token_use"]})
        if claims["token_use"] != "id" or not claims["sub"]:
            raise jwt.InvalidTokenError()
        return claims

    def identity(token, from_proxy=False):
        try:
            # Proxy headers always require a Google token, even when local login is enabled.
            if not from_proxy and cfg.allow_local:
                untrusted = jwt.decode(token, options={"verify_signature": False})
                if untrusted.get("iss") == cfg.issuer:
                    return local_identity(token)
            if not cfg.google_client_id:
                raise jwt.InvalidTokenError()
            key = keys.get_signing_key_from_jwt(token).key
            claims = jwt.decode(token, key, algorithms=["RS256"], audience=cfg.google_client_id,
                                issuer=["https://accounts.google.com", "accounts.google.com"],
                                options={"require": ["sub", "iss", "aud", "iat", "exp"]})
            if not claims["sub"]:
                raise jwt.InvalidTokenError()
            return claims
        except (jwt.PyJWTError, ValueError):
            raise unauthorized()

    @api.get("/")
    def index():
        return FileResponse(Path(__file__).with_name("index.html"))

    @api.get("/tokens")
    def tokens_page():
        return FileResponse(Path(__file__).with_name("tokens.html"))

    @api.get("/healthz")
    def health():
        return {"status": "ok"}

    @api.get("/api/session")
    def session(request: Request):
        if cfg.id_header in request.headers:
            token = request.headers[cfg.id_header]
            claims = identity(token, from_proxy=True)
            return {"authenticated": True, "user": claims["sub"], "id_token": token,
                    "local_login_allowed": False, "logout_url": cfg.logout_url}
        return {"authenticated": False, "local_login_allowed": cfg.allow_local,
                "logout_url": cfg.logout_url}

    @api.post("/api/login")
    def login(body: Login, request: Request):
        if cfg.id_header in request.headers:
            identity(request.headers[cfg.id_header], from_proxy=True)
            raise HTTPException(403, "Use your SSO session")
        if not cfg.allow_local:
            raise HTTPException(403, "Local login is disabled")
        if not (hmac.compare_digest(body.username, "demo") and hmac.compare_digest(body.password, "demo")):
            raise unauthorized()
        return {"id_token": mint("local:demo", "id", cfg.issuer + ":local-login", 300)}

    @api.post("/api/token")
    def exchange(body: Exchange, request: Request):
        proxy = cfg.id_header in request.headers
        token = request.headers[cfg.id_header] if proxy else body.id_token
        if not token:
            raise unauthorized()
        claims = identity(token, from_proxy=proxy)
        # Bind application identities to the upstream issuer as well as its subject.
        subject = claims["sub"] if claims["iss"] == cfg.issuer else "google:" + claims["sub"]
        return {"access_token": mint(subject, "access", cfg.audience, cfg.ttl, scope="demo:read"),
                "token_type": "Bearer", "expires_in": cfg.ttl}

    @api.get("/api/resource")
    def resource(request: Request):
        auth = request.headers.get("authorization", "")
        scheme, _, token = auth.partition(" ")
        if scheme.lower() != "bearer" or not token:
            raise unauthorized()
        try:
            claims = jwt.decode(token, cfg.signing_key, algorithms=["HS256"],
                                issuer=cfg.issuer, audience=cfg.audience,
                                options={"require": ["sub", "iss", "aud", "iat", "exp", "token_use"]})
            if claims["token_use"] != "access" or not claims["sub"]:
                raise jwt.InvalidTokenError()
        except jwt.PyJWTError:
            raise unauthorized()
        if "demo:read" not in str(claims.get("scope", "")).split():
            raise HTTPException(403, "Required scope: demo:read")
        return {"message": "認可に成功しました", "user": claims["sub"], "scope": claims["scope"]}

    return api
