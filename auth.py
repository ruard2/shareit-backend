# auth.py
import os
from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from fastapi import HTTPException, Depends, Cookie, Request
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from starlette.status import HTTP_401_UNAUTHORIZED
from dotenv import load_dotenv
from database import get_db
from models import User
from session_store import SESSION_STORE

load_dotenv()

# ── JWT secret — MUST come from environment ──────────────────────────────────
_UNSAFE_DEFAULTS = {"je-super-geheime-key", "secret", "changeme", ""}
SECRET_KEY = os.getenv("SECRET_KEY", "")
if SECRET_KEY in _UNSAFE_DEFAULTS:
    raise RuntimeError(
        "❌ SECRET_KEY is niet ingesteld of gebruikt een onveilige standaardwaarde. "
        "Stel SECRET_KEY in via de omgevingsvariabelen of het .env-bestand."
    )

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")

# 🔐 Maak JWT-token
def create_access_token(data: dict, expires_delta: timedelta = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    print(f"[JWT] gegenereerd voor user_id={data.get('sub')}, exp={expire}")
    return encoded_jwt


def _resolve_token(token: str, db: Session) -> User:
    """
    Gegeven een raw JWT-string: valideer en geef de bijbehorende User terug.
    Gooit HTTPException 401 als de token ongeldig/verlopen is.
    """
    # 1) Check in-memory store (fast path)
    user_id = SESSION_STORE.get(token)

    # 2) Fallback: verify as JWT directly (covers server-restart scenario)
    if not user_id:
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            sub = payload.get("sub")
            if sub:
                user_id = int(sub)
                SESSION_STORE[token] = user_id
        except JWTError:
            raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="Ongeldige sessie")

    if not user_id:
        raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="Ongeldige sessie")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="Gebruiker niet gevonden")

    return user


# ✅ Authenticatie: accepteert ZOWEL cookie ALS Authorization: Bearer header.
# Werkt daarmee op mobiel (cookie) én web (Authorization header).
def get_current_user_token(
    request: Request,
    session_id: str = Cookie(None),
    db: Session = Depends(get_db),
) -> User:
    # Probeer eerst Authorization: Bearer <token>
    auth_header = request.headers.get("authorization") or request.headers.get("Authorization")
    bearer_token: Optional[str] = None
    if auth_header and auth_header.lower().startswith("bearer "):
        bearer_token = auth_header[7:].strip()

    token = bearer_token or session_id

    # 🔍 DEBUG
    print(f"[AUTH] {request.method} {request.url.path}")
    print(f"[AUTH]   auth_header  = {repr(auth_header)}")
    print(f"[AUTH]   cookie       = {repr(session_id)}")
    print(f"[AUTH]   token found  = {bool(token)}")

    if not token:
        raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="Geen sessie gevonden")

    return _resolve_token(token, db)
