import hmac
import os
import time
from dataclasses import dataclass
from pathlib import Path

import jwt
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from jwt import PyJWKClient
from pydantic import BaseModel, Field


# Default name of the non-standard header the reverse proxy uses to hand the Google ID token to this app.
# (The standard "Authorization" header is reserved here for the app's own access tokens.)
ID_TOKEN_HEADER = "X-Forwarded-Id-Token"


@dataclass(frozen=True)
class Settings:
    allow_local: bool = False
    id_header: str = ID_TOKEN_HEADER
    google_client_id: str = ""
    logout_url: str = ""
    signing_key: str = ""
    issuer: str = "app-authorization-demo"
    audience: str = "app-authorization-demo"
    ttl: int = 43200
    max_ttl: int = 2592000

    @classmethod
    def from_env(cls, environ=None):
        os_getenv = (environ if environ is not None else os.environ).get
        return cls(
            allow_local=os_getenv("APP_ALLOW_LOCAL_LOGIN", "false").lower() == "true",
            id_header=os_getenv("SSO_ID_TOKEN_HEADER", ID_TOKEN_HEADER),
            google_client_id=os_getenv("SSO_GOOGLE_CLIENT_ID", ""),
            logout_url=os_getenv("SSO_LOGOUT_URL", ""),
            signing_key=os_getenv("APP_ACCESS_TOKEN_SIGNING_KEY", ""),
            issuer=os_getenv("APP_ACCESS_TOKEN_ISSUER", "app-authorization-demo"),
            audience=os_getenv("APP_ACCESS_TOKEN_AUDIENCE", "app-authorization-demo"),
            ttl=int(os_getenv("APP_ACCESS_TOKEN_TTL_SECONDS", "43200")),
            max_ttl=int(os_getenv("APP_ACCESS_TOKEN_MAX_TTL_SECONDS", "2592000")),
        )


class Login(BaseModel):
    username: str
    password: str


class Exchange(BaseModel):
    id_token: str | None = None
    ttl_seconds: int | None = Field(default=None, strict=True, gt=0)


@dataclass(frozen=True)
class Check:
    name: str
    ok: bool
    error: str = ""


def validate(cfg):
    """Check startup settings without exposing their values."""
    google_ok = cfg.allow_local or bool(cfg.google_client_id)
    return [
        Check("SSO_GOOGLE_CLIENT_ID", google_ok,
              "" if google_ok else "required when APP_ALLOW_LOCAL_LOGIN is not true (SSO-only mode)"),
        Check("APP_ACCESS_TOKEN_SIGNING_KEY", len(cfg.signing_key.encode()) >= 32,
              "must contain at least 32 bytes"),
        Check("APP_ACCESS_TOKEN_TTL_SECONDS", 0 < cfg.ttl <= cfg.max_ttl,
              "must be positive and no greater than APP_ACCESS_TOKEN_MAX_TTL_SECONDS"),
    ]


def check_env(environ=None):
    """Dry run: validate settings from the environment and report every problem."""
    env = os.environ if environ is None else environ
    bad = [Check(name, False, "must be an integer")
           for name in ("APP_ACCESS_TOKEN_TTL_SECONDS", "APP_ACCESS_TOKEN_MAX_TTL_SECONDS")
           if not env.get(name, "0").strip().lstrip("-").isdigit()]
    return bad or validate(Settings.from_env(env))


def create_app(settings=None, google_keys=None):
    cfg = settings or Settings.from_env()
    for check in validate(cfg):
        if not check.ok:
            raise ValueError(f"{check.name}: {check.error}")
    keys = google_keys or PyJWKClient("https://www.googleapis.com/oauth2/v3/certs")
    api = FastAPI(title="Authorization demo")

    @api.middleware("http")
    async def no_store(request, call_next):
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    def proxy_token(request):
        # The proxy may forward the ID token as "Bearer <token>" (Authorization style) or bare.
        value = request.headers[cfg.id_header].strip()
        scheme, _, rest = value.partition(" ")
        return rest.strip() if scheme.lower() == "bearer" and rest.strip() else value

    def unauthorized(detail="Invalid or missing token"):
        return HTTPException(401, detail, headers={"WWW-Authenticate": "Bearer"})

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

    def identity(token, from_proxy=False, explain=False):
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
        except (jwt.PyJWTError, ValueError) as exc:
            # Only /api/session explains the reason, to help debug the proxy setup.
            if explain:
                raise unauthorized(f"{cfg.id_header} was received but is not valid: {exc}") from exc
            raise unauthorized() from exc

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
            token = proxy_token(request)
            claims = identity(token, from_proxy=True, explain=True)
            return {"authenticated": True, "user": claims["sub"], "id_token": token,
                    "id_token_header": {"name": cfg.id_header, "received": True},
                    "local_login_allowed": False, "logout_url": cfg.logout_url}
        return {"authenticated": False, "local_login_allowed": cfg.allow_local,
                "id_token_header": {"name": cfg.id_header, "received": False},
                "logout_url": cfg.logout_url}

    @api.get("/api/token-policy")
    def token_policy():
        return {"default_ttl_seconds": cfg.ttl, "max_ttl_seconds": cfg.max_ttl}

    @api.post("/api/login")
    def login(body: Login, request: Request):
        if cfg.id_header in request.headers:
            identity(proxy_token(request), from_proxy=True)
            raise HTTPException(403, "Use your SSO session")
        if not cfg.allow_local:
            raise HTTPException(403, "Local login is disabled")
        if not (hmac.compare_digest(body.username, "demo") and hmac.compare_digest(body.password, "demo")):
            raise unauthorized()
        return {"id_token": mint("local:demo", "id", cfg.issuer + ":local-login", 300)}

    @api.post("/api/token")
    def exchange(body: Exchange, request: Request):
        proxy = cfg.id_header in request.headers
        token = proxy_token(request) if proxy else body.id_token
        if not token:
            raise unauthorized()
        claims = identity(token, from_proxy=proxy)
        ttl = cfg.ttl if body.ttl_seconds is None else body.ttl_seconds
        if ttl > cfg.max_ttl:
            raise HTTPException(422, f"ttl_seconds must be at most {cfg.max_ttl}")
        # Bind application identities to the upstream issuer as well as its subject.
        subject = claims["sub"] if claims["iss"] == cfg.issuer else "google:" + claims["sub"]
        return {"access_token": mint(subject, "access", cfg.audience, ttl, scope="demo:read"),
                "token_type": "Bearer", "expires_in": ttl}

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
