from fastapi import FastAPI, Depends, HTTPException, Request, Cookie, Header, File, UploadFile, Body, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

import os
import json
import time
import threading
from collections import defaultdict
from dotenv import load_dotenv

load_dotenv()  # laad .env vóór alles

# ── Rate-limiting voor /login ─────────────────────────────────────────────
_LOGIN_ATTEMPTS: dict = defaultdict(list)
_LOGIN_MAX_ATTEMPTS = 5
_LOGIN_WINDOW_SECONDS = 300  # 5 minuten

def _check_login_rate(ip: str):
    now = time.time()
    cutoff = now - _LOGIN_WINDOW_SECONDS
    _LOGIN_ATTEMPTS[ip] = [t for t in _LOGIN_ATTEMPTS[ip] if t > cutoff]
    if len(_LOGIN_ATTEMPTS[ip]) >= _LOGIN_MAX_ATTEMPTS:
        raise HTTPException(
            status_code=429,
            detail="Te veel inlogpogingen. Probeer het over 5 minuten opnieuw."
        )
    _LOGIN_ATTEMPTS[ip].append(now)

# ── Upload-validatie ──────────────────────────────────────────────────────
_ALLOWED_IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif", ".webp"}
_MAX_UPLOAD_BYTES = 5 * 1024 * 1024  # 5 MB

# ── Cloudinary (optioneel, aanbevolen voor productie) ─────────────────────
# Zet CLOUDINARY_URL in de omgeving (cloudinary://<key>:<secret>@<cloud_name>).
# Zonder die variabele vallen we terug op lokale opslag in ./static
# (let op: op Railway is dat tijdelijk en verdwijnt bij elke nieuwe deploy).
_CLOUDINARY_ENABLED = False
try:
    if os.getenv("CLOUDINARY_URL"):
        import cloudinary  # noqa: F401
        import cloudinary.uploader  # noqa: F401
        cloudinary.config(secure=True)  # leest CLOUDINARY_URL automatisch
        _CLOUDINARY_ENABLED = True
        print("[OK] Cloudinary actief — foto's worden in de cloud opgeslagen.")
    else:
        print("[INFO] CLOUDINARY_URL niet gezet — foto's lokaal in ./static "
              "(tijdelijk op Railway).")
except Exception as e:
    print(f"[WAARSCHUWING] Cloudinary niet geconfigureerd: {e}")

from uuid import uuid4
from datetime import datetime, timedelta
from typing import Optional, List, Set, Literal

from sqlalchemy import and_, func, not_, text
from sqlalchemy.orm import Session

from session_store import SESSION_STORE
from messaging import router as messaging_router

# 📦 Database & modellen
from database import SessionLocal, engine
import models
from models import User as Gebruiker
from models import User, Sessie, UserGroup, Item

from push_service import send_fcm_to_token

# 📦 Schema's
import schemas
from schemas import (
    UserCreate,
    UserResponse,
    UserLogin,
    GroupCreate,
    Membership,
    BorrowRequestCreate,
    BorrowRequestOut,
    ItemRequestCreate,
    ItemRequestOut,
)

# 📦 CRUD & Auth
import crud
from crud import (
    get_user_by_email,
    create_user,
    authenticate_user,
    verify_password,
    create_group,
    assign_admin_to_group,
    get_dashboard_info,
)
from auth import create_access_token, get_current_user_token


# ✅ Tabellen aanmaken
models.Base.metadata.create_all(bind=engine)

# ✅ Migraties uitvoeren (voegt nieuwe kolommen toe aan bestaande tabellen)
from migration import run_migrations
run_migrations(engine)

CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS, PATCH",
    # LET OP: de wildcard "*" dekt de Authorization-header NIET (CORS-spec).
    # Bij cross-origin (GitHub Pages -> Railway) moet Authorization expliciet
    # worden genoemd, anders blokkeert de browser elk geauthenticeerd verzoek.
    "Access-Control-Allow-Headers": "Authorization, Content-Type, Accept, Origin, X-Requested-With",
    "Access-Control-Max-Age": "600",
}

app = FastAPI()

# ✅ SessionMiddleware
_SESSION_SECRET = os.getenv("SESSION_SECRET", "")
if not _SESSION_SECRET:
    raise RuntimeError(
        "❌ SESSION_SECRET is niet ingesteld. "
        "Stel SESSION_SECRET in via de omgevingsvariabelen of het .env-bestand."
    )
app.add_middleware(SessionMiddleware, secret_key=_SESSION_SECRET)

app.include_router(messaging_router)

# make sure the folder exists
if not os.path.isdir("static"):
    os.makedirs("static")

# serve files out of ./static under the /static URL path
app.mount("/static", StaticFiles(directory="static"), name="static")

# ✅ Dependency voor DB
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ✅ CORS — twee-laags aanpak:
# 1) Middleware voegt headers toe aan elke response
# 2) Expliciete OPTIONS-route beantwoordt preflight gegarandeerd

@app.middleware("http")
async def add_cors_headers(request: Request, call_next):
    origin = request.headers.get("origin", "NO-ORIGIN")
    print(f"[CORS-MW] {request.method} {request.url.path}  origin={origin}")
    if request.method == "OPTIONS":
        print(f"[CORS-MW] >> Preflight! Returning 200 with CORS headers")
        return JSONResponse(status_code=200, content={}, headers=CORS_HEADERS)
    response = await call_next(request)
    for key, value in CORS_HEADERS.items():
        response.headers[key] = value
    print(f"[CORS-MW] << Response {response.status_code} with CORS headers added")
    return response

@app.options("/{rest_of_path:path}")
async def handle_options(rest_of_path: str):
    print(f"[OPTIONS-ROUTE] preflight for /{rest_of_path}")
    return JSONResponse(status_code=200, content={}, headers=CORS_HEADERS)

def _migrate_plain_pins():
    """
    Eenmalig: hash alle PIN-codes die nog in plain-text zijn opgeslagen.
    Bcrypt-hashes beginnen altijd met '$2b$', dus bestaande hashes worden
    overgeslagen. Veilig om bij elke herstart uit te voeren.
    """
    db = SessionLocal()
    try:
        users = db.query(User).all()
        migrated = 0
        for u in users:
            if u.pin_code and not u.pin_code.startswith("$2b$"):
                u.pin_code = crud.pwd_context.hash(u.pin_code)
                migrated += 1
        if migrated:
            db.commit()
            print(f"[PIN] PIN-migratie: {migrated} account(s) gehashed")
        else:
            print("[PIN] PIN-migratie: alle PINs zijn al veilig opgeslagen")
    finally:
        db.close()


def _overdue_check_loop():
    """Dagelijkse achtergrondtaak: overdue-notificaties + gratis-item-expiry."""
    import time
    while True:
        try:
            db = SessionLocal()
            crud.check_and_send_overdue_notifications(db)
            crud.check_and_expire_free_items(db)
            db.close()
        except Exception as e:
            print(f"[DAILY-CHECK] Fout: {e}")
        time.sleep(86400)  # 24 uur wachten


# ✅ Superuser wordt één keer automatisch aangemaakt
@app.on_event("startup")
def on_startup():
    # ── Kolom-migraties worden nu volledig afgehandeld door migration.py ──
    # (run_migrations wordt net boven on_startup aangeroepen, dus hier niets meer nodig)

    # ── Eenmalige migratie: hash plain-text PINs in bestaande database ──
    _migrate_plain_pins()

    # ── Start dagelijkse overdue-check ──
    threading.Thread(target=_overdue_check_loop, daemon=True).start()
    print("[OK] Overdue-checker gestart")

    db = SessionLocal()
    email = "admin@local.com"
    pin_code = "0000"

    # Check if superuser exists
    user = get_user_by_email(db, email)
    if not user:
        # Create admin's group (skip if it already exists)
        existing_group = db.query(models.Group).filter(models.Group.name == "Groep van Beheerder").first()
        if existing_group:
            group = existing_group
        else:
            group = create_group(db, GroupCreate(name="Groep van Beheerder"))

        # Create superuser (without direct group_id)
        superuser = User(
            name="Beheerder",
            email=email,
            phone_number="0000000000",
            address="Adminstraat 1",
            pin_code=crud.pwd_context.hash(pin_code),
            is_admin=True,
            is_approved=True,
            invited_by=None,
            role="superuser"
        )
        db.add(superuser)
        db.commit()
        db.refresh(superuser)

        # Assign superuser membership with superuser role
        membership = UserGroup(
            user_id=superuser.id,
            group_id=group.id,
            role="superuser"
        )
        db.add(membership)
        db.commit()

        print(f"[OK] Superuser en groep aangemaakt: {email} / {pin_code}")
    else:
        print(f"[INFO] Superuser '{email}' bestaat al.")

    # ── SMTP-waarschuwing ──
    if not os.getenv("SMTP_HOST"):
        print("[WAARSCHUWING] SMTP_HOST is niet geconfigureerd — PIN-reset e-mails worden alleen "
              "gelogd naar de console. Configureer SMTP via .env voor productie.")

    db.close()


@app.post("/devices/register")
def register_device(
    token: str = Body(...),
    platform: Literal["android","ios","web"] | None = Body(None),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user_token),
):
    crud.register_device_token(db, current_user.id, token, platform)
    return {"detail": "ok"}

@app.post("/devices/unregister")
def unregister_device(
    token: str = Body(...),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user_token),
):
    ok = crud.unregister_device_token(db, token, user_id=current_user.id)
    return {"detail": "ok" if ok else "not-found"}

# ✅ Helpers

def get_user_id_from_cookie(
    session_id: Optional[str] = Cookie(None),
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db)
) -> int:
    sessie = None

    if session_id:
        sessie = db.query(models.Sessie).filter(models.Sessie.session_id == session_id).first()
    elif authorization and authorization.startswith("Bearer "):
        token = authorization.split(" ")[1]
        sessie = db.query(models.Sessie).filter(models.Sessie.session_id == token).first()

    if not sessie:
        raise HTTPException(status_code=401, detail="Geen geldige sessie of token")

    return sessie.gebruiker_id

def is_admin_in_group(user: User, group_id: int) -> bool:
    return any(m.group_id == group_id and m.role == "admin" for m in user.memberships) or user.role == "superuser"


# ✅ ENDPOINTS

@app.post("/register")
def register(user: schemas.UserCreate, db: Session = Depends(get_db)):
    if user.invite_code:
        # Feature 3: Probeer eerst een groeps-invite_code op te zoeken
        group_by_code = crud.get_group_by_invite_code(db, user.invite_code)
        if group_by_code:
            user.group_id = group_by_code.id
        else:
            # Achterwaartse compat: zoek op gebruikers invite_code
            inviter = db.query(models.User).filter(models.User.invite_code == user.invite_code).first()
            if inviter:
                user.invited_by = inviter.id
                user.group_id = inviter.group_id
            else:
                raise HTTPException(status_code=400, detail="Ongeldige uitnodigingscode")

    # ✅ Voeg dit toe zodat groepskeuze in dropdown goed doorkomt
    if not user.group_id:
        raise HTTPException(status_code=400, detail="Geen groep geselecteerd")

    db_user = crud.get_user_by_email(db, user.email)
    if db_user:
        raise HTTPException(status_code=400, detail="E-mailadres al geregistreerd")

    created_user = crud.create_user(db=db, user=user)

    # Token maken en opslaan
    access_token = create_access_token(data={"sub": str(created_user.id)})
    SESSION_STORE[access_token] = created_user.id

    # Reageer met session cookie
    response = JSONResponse(content={
        "access_token": access_token,
        "token_type": "bearer",
        "user_id": created_user.id,
        "role": created_user.role,
        "is_admin": created_user.is_admin
    })

    response.set_cookie(key="session_id", value=access_token, httponly=True)
    return response



@app.post("/login")
async def login(request: Request, user_login: UserLogin, db: Session = Depends(get_db)):
    # Rate-limit op IP-adres: max 5 pogingen per 5 minuten
    client_ip = request.client.host if request.client else "unknown"
    _check_login_rate(client_ip)

    user = crud.authenticate_user(db, user_login.email, user_login.pin_code)

    if not user:
        raise HTTPException(status_code=401, detail="Incorrect email or password")

    access_token = create_access_token(data={"sub": str(user.id)})

    # Zet deze regel hier, binnen de functie:
    SESSION_STORE[access_token] = user.id

    response = JSONResponse(content={
        "access_token": access_token,
        "token_type": "bearer",
        "user_id": user.id,
        "role": user.role,
        "is_admin": user.is_admin,  # als je dit tijdelijk nog wil laten meelopen
        "is_approved": user.is_approved
    })

    response.set_cookie(key="session_id", value=access_token, httponly=True)
    return response

@app.post("/users/role/{user_id}", response_model=schemas.UserOut)
def update_user_role(
    user_id: int,
    new_role: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user_token)
):
    if current_user.role != "superuser":
        raise HTTPException(status_code=403, detail="Alleen superusers mogen rollen aanpassen")

    _ = crud.change_user_role(db, user_id, new_role)
    u = crud.get_user_by_id(db, user_id)
    return _user_to_out_with_privacy(u, current_user, u.group_id, db)


@app.post("/groups/{group_id}/admins/{user_id}", response_model=schemas.UserOut)
def add_admin_to_group(
    group_id: int,
    user_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user_token),
):
    # superusers can manage anywhere
    if current_user.role == "superuser":
        pass
    # group-admins only in groups where they actually are admin
    elif any(m.group_id == group_id and m.role == "admin" for m in current_user.memberships):
        pass
    else:
        raise HTTPException(
            status_code=403,
            detail="Alleen admins in je eigen groep (of superusers) mogen admins toewijzen"
        )

    crud.assign_admin_to_group(db, user_id, group_id)
    u = crud.get_user_by_id(db, user_id)
    return _user_to_out_with_privacy(u, current_user, group_id, db)



# Helper so you can inject the current User under the name "get_huidige_gebruiker"
def get_huidige_gebruiker(
    current_user: User = Depends(get_current_user_token)
) -> User:
    return current_user


@app.get("/gebruikers/dashboard")
def get_dashboard_data(
    current_user: User = Depends(get_huidige_gebruiker),
    db: Session = Depends(get_db)
):
    data = get_dashboard_info(db, current_user.id)
    if not data:
        raise HTTPException(status_code=404, detail="Gebruiker niet gevonden")
    return data


@app.post("/groepen/goedkeuren/{groep_id}")
def groep_goedkeuren(
    groep_id: int,
    db: Session = Depends(get_db),
    beheerder: Gebruiker = Depends(get_huidige_gebruiker)
):
    if beheerder.role not in ["admin", "superuser"]:
        raise HTTPException(status_code=403, detail="Alleen beheerders mogen goedkeuren")

    groep = db.query(models.Group).filter(models.Group.id == groep_id, models.Group.status == "pending").first()
    if not groep:
        raise HTTPException(status_code=404, detail="Groep niet gevonden of al actief")

    aanvrager_id = groep.aangemaakt_door
    gebruiker = db.query(Gebruiker).filter(Gebruiker.id == aanvrager_id).first()
    if not gebruiker:
        raise HTTPException(status_code=404, detail="Aanvrager niet gevonden")

    # 1) Zet groep actief
    groep.status = "active"

    # 2) Zet aanvrager als global admin
    gebruiker.role = "admin"

    # 3) Zorg dat de UserGroup.membership ook op 'admin' staat
    membership = (
        db.query(UserGroup)
          .filter_by(user_id=gebruiker.id, group_id=groep.id)
          .one_or_none()
    )
    if membership:
        membership.role = "admin"
    else:
        membership = UserGroup(user_id=gebruiker.id, group_id=groep.id, role="admin")
        db.add(membership)

    db.commit()
    return {"message": "Groep goedgekeurd en gebruiker hebt admin-rechten gekregen"}


@app.post("/groepen/nieuw", response_model=schemas.GroupOut)
def maak_groep_aan(
    group: schemas.GroupCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user_token)
):
    # mag maken als superuser óf als admin in één van je groepen
    is_group_admin = any(m.role == "admin" for m in current_user.memberships)
    if not (current_user.role == "superuser" or is_group_admin):
        raise HTTPException(status_code=403, detail="Geen rechten om een groep aan te maken")

    # 1) Prepare group data
    group_data = schemas.GroupCreate(
        name=group.name,
        status=group.status or "pending",
        aangemaakt_door=current_user.id
    )

    # 2) Create de groep
    nieuwe_groep = crud.create_group(db, group_data)

    # 3) Alleen de maker wordt admin in de nieuwe groep
    crud.assign_admin_to_group(db, current_user.id, nieuwe_groep.id)

    # 4) Return de juiste response
    return schemas.GroupOut(
        id=nieuwe_groep.id,
        name=nieuwe_groep.name,
        status=nieuwe_groep.status,
        aangemaakt_door=nieuwe_groep.aangemaakt_door,
        admins=[current_user.id]
    )


@app.get("/groep/invite_code")
def genereer_invite_code_met_user(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user_token)
):
    """Feature 3: geeft de invite_code van de eerste groep van de gebruiker.
    Genereert er één als die nog niet bestaat."""
    if current_user.memberships:
        group = db.query(models.Group).get(current_user.memberships[0].group_id)
        if group:
            if not group.invite_code:
                group = crud.assign_group_invite_code(db, group.id)
            print(f"[OK] Groep invite code: {group.invite_code}")
            return {"invite_code": group.invite_code, "group_name": group.name}
    # Fallback: gebruikers-niveau invite code (achterwaartse compatibiliteit)
    updated_user = crud.assign_invite_code(db, current_user.id)
    print(f"[OK] Gebruiker invite code (fallback): {updated_user.invite_code}")
    return {"invite_code": updated_user.invite_code}



@app.get("/users/pending", response_model=List[schemas.UserOut])
def get_pending_users(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user_token),
):
    # verzamel groepen waar current_user admin van is (of alle als superuser)
    if current_user.role == "superuser":
        group_ids = {g.id for g in crud.get_all_groups(db)}
    else:
        group_ids = {m.group_id for m in current_user.memberships if m.role == "admin"}

    if not group_ids:
        raise HTTPException(status_code=403, detail="Geen toegang")

    pendings: List[schemas.UserOut] = []
    for gid in group_ids:
        users = (
            db.query(models.User)
              .join(models.UserGroup,
                    and_(models.User.id == models.UserGroup.user_id,
                         models.UserGroup.group_id == gid))
              .filter(models.User.is_approved == False)
              .all()
        )
        for u in users:
            # privacy per user t.o.v. current_user in context van deze group
            item = _user_to_out_with_privacy(u, current_user, gid, db)
            pendings.append(item)
    return pendings


@app.post("/requests/{req_id}/returned")
def mark_returned(req_id: int, db: Session = Depends(get_db), current_user=Depends(get_current_user_token)):
    br = crud.get_request(db, req_id)
    # only the owner of the item can mark returned
    if br.item.owner_id != current_user.id:
        raise HTTPException(403)
    br.item.status = "free"
    br.status = "returned"
    db.commit()
    return {"detail": "Item marked as returned"}


@app.delete("/requests/{req_id}", status_code=status.HTTP_204_NO_CONTENT)
def cancel_borrow_request(
    req_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user_token),
):
    """
    Annuleer een eigen leenverzoek (alleen als status == 'pending').
    Zet het item terug op 'free' zodat anderen het kunnen aanvragen.
    """
    br = crud.get_request(db, req_id)
    if not br:
        raise HTTPException(status_code=404, detail="Verzoek niet gevonden")
    if br.requester_id != current_user.id:
        raise HTTPException(status_code=403, detail="Niet jouw verzoek")
    if br.status != "pending":
        raise HTTPException(
            status_code=400,
            detail="Alleen verzoeken met status 'in behandeling' kunnen worden geannuleerd"
        )
    # Zet item vrij
    if br.item and br.item.status == "reserved":
        br.item.status = "free"
    db.delete(br)
    db.commit()
    return None


@app.post("/requests/{req_id}/return", response_model=schemas.BorrowRequestOut)
def request_return(
    req_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user_token)
):
    br = crud.get_request(db, req_id)
    if br.requester_id != current_user.id:
        raise HTTPException(status_code=403, detail="Niet jouw verzoek")
    br.status = "return_requested"
    db.commit()
    db.refresh(br)
    return br

@app.get("/requests/return/pending", response_model=List[schemas.BorrowRequestOut])
def list_return_requests(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user_token)
):
    # owner or group-admin should see these
    admin_group_ids = [m.group_id for m in current_user.memberships if m.role=="admin"]
    q = (
      db.query(models.BorrowRequest)
        .filter(models.BorrowRequest.status == "return_requested")
        .filter(
          (models.BorrowRequest.item.has(owner_id=current_user.id)) |
          (models.BorrowRequest.group_id.in_(admin_group_ids))
        )
        .all()
    )
    return q
    

@app.post("/groups/{group_id}/join-request/decision")
def decide_join_request(
    group_id: int,
    requester_id: int = Body(..., embed=True),
    approve: bool = Body(..., embed=True),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user_token),
):
    # alleen superuser of admin van deze groep
    is_admin = current_user.role == "superuser" or any(
        m.group_id == group_id and m.role == "admin" for m in current_user.memberships
    )
    if not is_admin:
        raise HTTPException(403, "Geen toegang")

    user = crud.get_user_by_id(db, requester_id)
    if not user:
        raise HTTPException(404, "Gebruiker niet gevonden")

    if not approve:
        # optioneel: stuur notificatie 'join_request_denied'
        return {"detail": "Join-verzoek geweigerd"}

    # membership aanmaken (rol 'user') als die nog niet bestaat
    exists = db.query(models.UserGroup).filter_by(
        user_id=requester_id, group_id=group_id
    ).first()
    if not exists:
        db.add(models.UserGroup(user_id=requester_id, group_id=group_id, role="user"))

    # markeer goedgekeurd
    user.is_approved = True
    db.commit()
    return {"detail": "Lidmaatschap toegevoegd en gebruiker goedgekeurd"}

# --- USERS: deny (verwijderen/weigeren) --------------------------------------
from fastapi import HTTPException, Depends
from sqlalchemy.orm import Session
from typing import Optional



@app.delete("/users/me")
def delete_me(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user_token)
):
    crud.delete_user(db, current_user.id)
    return {"detail": "deleted"}

@app.post("/users/deny/{user_id}")
def deny_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user_token)
):
    # Alleen superuser of admin die recht heeft
    if current_user.role != "superuser":
        # is admin in dezelfde groep als de pending user?
        ug = db.query(models.UserGroup).filter_by(user_id=user_id).first()
        if not ug or not any(m.group_id == ug.group_id and m.role=="admin" for m in current_user.memberships):
            raise HTTPException(status_code=403, detail="Geen toegang")

    u = crud.get_user_by_id(db, user_id)
    if not u:
        raise HTTPException(status_code=404, detail="User niet gevonden")

    # simpele strategie: membership laten bestaan maar user niet approven, of user verwijderen
    # hier: verwijderen
    crud.delete_user(db, user_id)
    return {"detail": "User geweigerd en verwijderd"}


# --- Preferences: GET + POST (robust & consistent) --------------------------
# --- Preferences: GET + POST (robuust & consistent) --------------------------

# --- Preferences: get + save (robust) ----------------------------------------

@app.get("/users/me/preferences", response_model=schemas.PreferencesOut)
def get_my_preferences(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user_token),
):
    """
    Return user prefs + a 'profile' block (name/email/phone) taken from User.
    """
    base = crud.get_user_prefs_as_dict(db, current_user.id)
    profile = {
        "name": current_user.name,
        "email": current_user.email,
        "phone": current_user.phone_number,   # <- always map to 'phone'
    }
    return {**base, "profile": profile}


@app.post("/users/me/preferences", response_model=dict)
def save_my_preferences(
    payload: dict = Body(...),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user_token),
):
    # 1) Upsert prefs (notifications/privacy/ui)
    crud.update_user_prefs(db, current_user.id, payload or {})

    # 2) Profile fields (use SAME SESSION as `db`)
    prof = (payload or {}).get("profile") or {}
    if hasattr(prof, "dict"):       # tolerate pydantic-like
        prof = prof.dict()
    elif hasattr(prof, "model_dump"):
        prof = prof.model_dump()

    # Re-load the user in this session
    user = db.query(models.User).filter(models.User.id == current_user.id).first()
    if user and isinstance(prof, dict):
        dirty = False
        name  = prof.get("name")
        email = prof.get("email")
        phone = prof.get("phone")

        if name is not None and name != user.name:
            user.name = name; dirty = True
        if email is not None and email != user.email:
            user.email = email; dirty = True
        if phone is not None and phone != user.phone_number:
            user.phone_number = phone; dirty = True

        if dirty:
            db.commit()
            db.refresh(user)

    return {"detail": "ok"}



@app.post("/users/change_pin")
def change_pin(
    data: dict = Body(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user_token)
):
    old = data.get("old"); new = data.get("new")
    if not old or not new:
        raise HTTPException(400, "Oude en nieuwe pincode zijn verplicht")
    if not crud.pwd_context.verify(old, current_user.pin_code):
        raise HTTPException(400, "Oude pincode onjuist")
    current_user.pin_code = crud.pwd_context.hash(new)
    db.commit()
    return {"detail": "pin changed"}

@app.post("/users/change_password")
def change_password(
    data: dict = Body(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user_token)
):
    # Als je wachtwoord-hash gebruikt, check/zet hier
    # verify_password(data["old"], current_user.password_hash) ...
    return {"detail": "password changed"}


@app.post("/auth/logout")
def logout(
    request: Request,
    session_id: str | None = Cookie(None),
    db: Session = Depends(get_db)
):
    # Verwijder sessie uit DB als je die bewaart (jij gebruikt Sessie-tabel + SESSION_STORE)
    if session_id:
        try:
            s = db.query(models.Sessie).filter(models.Sessie.session_id == session_id).first()
            if s:
                db.delete(s); db.commit()
        except Exception:
            pass
        # Ook uit in-memory store
        SESSION_STORE.pop(session_id, None)
    resp = JSONResponse({"detail": "logged out"})
    resp.delete_cookie("session_id")
    return resp


@app.post("/requests/{req_id}/return/decision", response_model=schemas.BorrowRequestOut)
def decide_return(
    req_id: int,
    approve: bool = Body(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user_token)
):
    br = crud.get_request(db, req_id)
    # only item-owner or group-admin may decide
    is_owner = br.item.owner_id == current_user.id
    is_group_admin = any(m.group_id == br.group_id and m.role=="admin" for m in current_user.memberships)
    if not (is_owner or is_group_admin or current_user.role=="superuser"):
        raise HTTPException(status_code=403, detail="Geen toegang")
    if approve:
        br.status = "returned"
        br.item.status = "free"
        br.item.lender_id = None
        br.item.reserved_at = None
    else:
        # leave as loaned
        br.status = "approved"
    db.commit()
    db.refresh(br)
    return br


@app.post("/users/approve/{user_id}", response_model=schemas.UserOut)
def approve_user(user_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user_token)):
    u = crud.approve_user(db, user_id)
    # gebruik group-context van de user zelf
    return _user_to_out_with_privacy(u, current_user, u.group_id, db)


@app.get("/gebruikers/groep/{group_id}", response_model=List[schemas.UserOut])
def get_gebruikers_in_groep(
    group_id: int,
    current_user: models.User = Depends(get_current_user_token),
    db: Session = Depends(get_db),
):
    # membership check blijft gelijk
    is_member = any(m.group_id == group_id for m in current_user.memberships)
    if current_user.role != "superuser" and not is_member:
        raise HTTPException(status_code=403, detail="Geen toegang tot deze groep")

    users = crud.get_users_by_group(db, group_id)
    return [_user_to_out_with_privacy(u, current_user, group_id, db) for u in users]



def _user_to_out_with_privacy(u: models.User, viewer: models.User, group_id: int, db: Session) -> schemas.UserOut:
    # defaults
    email_out = u.email
    phone_out = u.phone_number

    prefs = crud.get_user_prefs(db, u.id)
    if prefs:
        if not prefs.priv_show_email and viewer.id != u.id and viewer.role != "superuser":
            email_out = None
        if not prefs.priv_show_phone and viewer.id != u.id and viewer.role != "superuser":
            phone_out = None

    return schemas.UserOut(
        id=u.id,
        name=u.name,
        email=email_out,                         # kan None zijn
        phone_number=phone_out,                  # kan None zijn
        is_admin=u.is_admin,
        is_approved=u.is_approved,
        group_id=group_id,
        invited_by=u.invited_by,
        role=next((m.role for m in u.memberships if m.group_id == group_id), "user"),
        admin_of_groups=[m.group_id for m in u.memberships if m.role == "admin"]
    )


@app.get("/groups/{group_id}/pending", response_model=list[schemas.UserOut])
def get_pending_by_group(
    group_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user_token),
):
    # alleen superuser of admin van deze groep
    is_group_admin = any(
        m.group_id == group_id and m.role == "admin"
        for m in current_user.memberships
    )
    if current_user.role != "superuser" and not is_group_admin:
        raise HTTPException(403, "Geen toegang tot deze groep")

    ugs = (
        db.query(models.UserGroup)
          .filter(models.UserGroup.group_id == group_id)
          .all()
    )

    pendings = []
    for ug in ugs:
        user = ug.user
        if not user.is_approved:
            pendings.append(_user_to_out_with_privacy(user, current_user, group_id, db))
    return pendings




@app.get("/users/group/{group_id}", response_model=List[schemas.UserOut])
def get_users_by_group(
    group_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user_token),
):
    is_group_admin = any(
        m.group_id == group_id and m.role == "admin"
        for m in current_user.memberships
    )
    if current_user.role != "superuser" and not is_group_admin:
        raise HTTPException(status_code=403, detail="Geen toegang tot deze groep")

    ugs: List[models.UserGroup] = (
        db.query(models.UserGroup)
          .filter(models.UserGroup.group_id == group_id)
          .all()
    )
    return [
        _user_to_out_with_privacy(ug.user, current_user, group_id, db)
        for ug in ugs
    ]


@app.post("/items/{item_id}/upload-photo", response_model=schemas.ItemOut)
async def upload_item_photo(
    item_id: int,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user_token),
):
    item = crud.get_item_by_id(db, item_id)
    if not item:
        raise HTTPException(404, "Item not found")

    # Valideer bestandstype
    original_name = file.filename or ""
    ext = os.path.splitext(original_name)[1].lower()
    if ext not in _ALLOWED_IMAGE_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Alleen afbeeldingen toegestaan: {', '.join(_ALLOWED_IMAGE_EXTENSIONS)}"
        )

    # Lees + valideer bestandsgrootte
    contents = await file.read()
    if len(contents) > _MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=400,
            detail=f"Bestand is te groot. Maximaal {_MAX_UPLOAD_BYTES // (1024*1024)} MB toegestaan."
        )

    if _CLOUDINARY_ENABLED:
        # Upload naar Cloudinary → permanente, CDN-versnelde URL.
        import cloudinary.uploader
        result = cloudinary.uploader.upload(
            contents,
            folder="shareit/items",
            public_id=f"item_{item_id}_{int(datetime.utcnow().timestamp())}",
            overwrite=True,
            resource_type="image",
        )
        item.image_path = result["secure_url"]
    else:
        # Lokale opslag (alleen geschikt voor lokale ontwikkeling).
        filename = f"{item_id}_{int(datetime.utcnow().timestamp())}{ext}"
        dest = os.path.join("static", filename)
        with open(dest, "wb") as f:
            f.write(contents)
        item.image_path = f"/static/{filename}"

    db.commit()
    db.refresh(item)
    return _wrap_item(item)




@app.post(
    "/items/",
    response_model=schemas.ItemOut,
    status_code=status.HTTP_201_CREATED,
)
def create_item(
    item: schemas.ItemCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user_token),
):
    # Altijd de owner_id van de ingelogde gebruiker gebruiken — nooit vertrouwen op de client
    item.owner_id = current_user.id
    db_item = crud.create_item(db, item)
    db.refresh(db_item)
    return _wrap_item(db_item)

@app.get("/requests/pending", response_model=List[schemas.BorrowRequestOut])
def list_pending(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user_token),
):
    # gather all group‐IDs the current_user administers (or all, if superuser)
    if current_user.role == "superuser":
        group_ids = {g.id for g in crud.get_all_groups(db)}
    else:
        group_ids = {m.group_id for m in current_user.memberships if m.role == "admin"}

    if not group_ids:
        raise HTTPException(status_code=403, detail="Geen toegang")

    results: List[models.BorrowRequest] = []
    for gid in group_ids:
        results.extend(crud.get_pending_requests_for_group(db, gid))
    return results


@app.get("/requests/mine", response_model=List[schemas.BorrowRequestOut])
def my_requests(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user_token),
):
    """Feature 4: eigen leenverzoeken met item_name en requester_name."""
    reqs = crud.get_my_borrow_requests(db, current_user.id)
    result = []
    for br in reqs:
        item_name = br.item.name if br.item else None
        requester_name = br.requester.name if br.requester else None
        result.append(schemas.BorrowRequestOut(
            id=br.id,
            item_id=br.item_id,
            requester_id=br.requester_id,
            group_id=br.group_id,
            status=br.status,
            created_at=br.created_at,
            message=br.message,
            pick_up_by=br.pick_up_by,
            duration_days=br.duration_days,
            return_by=br.return_by,
            has_damage=br.has_damage,
            damage_note=br.damage_note,
            item_name=item_name,
            requester_name=requester_name,
        ))
    return result


@app.post("/requests/{req_id}/decision", response_model=schemas.BorrowRequestOut)
def decide_request(
    req_id: int,
    approved: bool = Body(...),
    pick_up_by: Optional[datetime] = Body(None),
    duration_days: Optional[int] = Body(None),
    return_by: Optional[datetime] = Body(None),   # Feature 1: terugbrengdatum
    message: Optional[str] = Body(None),
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user_token)
):
    br = crud.get_request(db, req_id)
    # permission checks…

    if approved:
        br.status = "approved"
        br.pick_up_by = pick_up_by
        br.duration_days = duration_days
        # Auto-bereken return_by vanuit max_borrow_days als niet expliciet meegegeven
        if return_by:
            br.return_by = return_by
        elif br.item and br.item.max_borrow_days:
            br.return_by = datetime.utcnow() + timedelta(days=br.item.max_borrow_days)
        item = br.item
        item.status = "loaned"
        item.lender_id = current_user.id
        item.reserved_at = datetime.utcnow()
    else:
        br.status = "denied"
        br.message = message
        br.item.status = "free"

    db.commit()

    # Laat de aanvrager weten of het verzoek is goedgekeurd of afgewezen
    # (in-app notificatie + e-mail via create_notification).
    if br.requester_id:
        try:
            crud.create_notification(
                db,
                user_id=br.requester_id,
                type="request_decision",
                payload={
                    "item_name": br.item.name if br.item else "een item",
                    "status": br.status,
                },
            )
        except Exception as e:
            print(f"[NOTIF] kon beslissing-notificatie niet maken: {e}")

    return br


@app.post("/requests/{req_id}/extend")
def extend_loan(
    req_id: int,
    extra_days: int = Body(...),
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user_token),
):
    """Eigenaar verlengt de uitleentermijn met extra_days dagen."""
    br = crud.get_request(db, req_id)
    if not br:
        raise HTTPException(status_code=404, detail="Verzoek niet gevonden")
    if br.item.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Alleen de eigenaar mag verlengen")
    base = br.return_by if br.return_by else datetime.utcnow()
    br.return_by = base + timedelta(days=extra_days)
    br.overdue_notif_days = 0  # reset dagenteller
    db.commit()
    # Stuur notificatie naar lener
    if br.requester_id:
        crud.create_notification(db, user_id=br.requester_id, type="loan_extended", payload={
            "item_name": br.item.name,
            "extra_days": extra_days,
            "new_return_by": br.return_by.isoformat(),
        })
    return {"detail": "Verlengd", "new_return_by": br.return_by.isoformat()}




@app.get("/notifications/count", response_model=int)
def notification_count(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user_token),
):
    total = 0

    # 1) Gratis-ophaalverzoeken (ItemRequest) voor items van current_user
    try:
        total += crud.count_pending_item_requests(db, current_user.id)
    except Exception:
        pass

    # Verzamel admin-groepen van de gebruiker
    admin_group_ids = [m.group_id for m in current_user.memberships if m.role == "admin"]

    # Helper: aantal return_requests per groep (admin-scope)
    def count_return_requests_for_groups(group_ids: list[int]) -> int:
        if not group_ids:
            return 0
        return (
            db.query(func.count(models.BorrowRequest.id))
            .filter(
                models.BorrowRequest.group_id.in_(group_ids),
                models.BorrowRequest.status == "return_requested",
            )
            .scalar()
            or 0
        )

    # 2) Borrow- & return-requests + pending users in admin-groepen
    # 2a) Borrow-requests per admin-groep
    for gid in admin_group_ids:
        try:
            total += crud.count_pending_requests(db, gid)  # pending borrow requests
        except Exception:
            pass

        # 2b) Pending users per admin-groep
        try:
            pending_users_cnt = (
                db.query(func.count(models.User.id))
                .join(
                    models.UserGroup,
                    and_(
                        models.User.id == models.UserGroup.user_id,
                        models.UserGroup.group_id == gid,
                    ),
                )
                .filter(models.User.is_approved == False)
                .scalar()
                or 0
            )
            total += pending_users_cnt
        except Exception:
            pass

    # 2c) Return-requests in admin-groepen
    try:
        total += count_return_requests_for_groups(admin_group_ids)
    except Exception:
        pass

    # 2d) **NIÉUW**: Owner-based return-requests buiten admin-groepen (geen dubbel)
    # Let op: alleen voor niet-superusers, want de superuser-loop hieronder telt al "alle overige groepen".
    if current_user.role != "superuser":
        try:
            owner_returns_outside_admin = (
                db.query(func.count(models.BorrowRequest.id))
                .join(models.Item, models.Item.id == models.BorrowRequest.item_id)
                .filter(
                    models.BorrowRequest.status == "return_requested",
                    models.Item.owner_id == current_user.id,
                    # buiten admin-groepen om dubbel te voorkomen
                    not_(models.BorrowRequest.group_id.in_(admin_group_ids)) if admin_group_ids else True,
                )
                .scalar()
                or 0
            )
            total += owner_returns_outside_admin
        except Exception:
            pass

    # 3) Superuser telt ook alle overige groepen (excl. admin-groepen)
    if current_user.role == "superuser":
        try:
            all_gids = [g.id for g in db.query(models.Group).all()]
            other_gids = [gid for gid in all_gids if gid not in admin_group_ids]

            # 3a) Borrow-requests per overige groep
            for gid in other_gids:
                try:
                    total += crud.count_pending_requests(db, gid)
                except Exception:
                    pass

                # 3b) Pending users per overige groep
                try:
                    pending_users_cnt = (
                        db.query(func.count(models.User.id))
                        .join(
                            models.UserGroup,
                            and_(
                                models.User.id == models.UserGroup.user_id,
                                models.UserGroup.group_id == gid,
                            ),
                        )
                        .filter(models.User.is_approved == False)
                        .scalar()
                        or 0
                    )
                    total += pending_users_cnt
                except Exception:
                    pass

            # 3c) Return-requests in overige groepen (dekt óók owner-cases daar)
            try:
                total += count_return_requests_for_groups(other_gids)
            except Exception:
                pass

        except Exception:
            pass

    # 4) Ongelezen bel-notificaties (ongewijzigd)
    try:
        total += crud.count_unread_notifications(db, current_user.id)
    except Exception:
        pass

    return total

@app.get("/groepen/mijn", response_model=List[schemas.GroupOut])
def get_my_groups(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user_token),
):
    """
    Return the list of groups the current user belongs to,
    so the frontend can let them choose which group(s) to share an item with.
    """
    result: List[schemas.GroupOut] = []
    for ug in current_user.memberships:
        g = ug.group
        result.append(
            schemas.GroupOut(
                id=g.id,
                name=g.name,
                status=g.status,
                aangemaakt_door=g.aangemaakt_door,
                admins=[m.user_id for m in g.memberships if m.role == "admin"],
                invite_code=g.invite_code,  # Feature 3
            )
        )
    return result


@app.post("/items/{item_id}/borrow", response_model=schemas.BorrowRequestOut)
def borrow_item(
    item_id: int,
    return_by: Optional[datetime] = Body(None),  # Feature 1: gewenste terugbrengdatum
    message: Optional[str] = Body(None),
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user_token)
):
    item = crud.get_item_by_id(db, item_id)
    if item.owner_id == current_user.id:
        raise HTTPException(400, "Cannot borrow your own item")
    if item.status != "free":
        raise HTTPException(400, "Item not available")

    # ── Borrow blocking: controleer verlopen leningen ──
    overdue_count = crud.count_overdue_borrows(db, current_user.id)
    user_limit = crud.get_overdue_limit(current_user)
    if overdue_count >= user_limit:
        admin_names: List[str] = []
        for ug in current_user.memberships:
            grp = db.query(models.Group).filter(models.Group.id == ug.group_id).first()
            if grp:
                for m in grp.memberships:
                    if m.role == "admin" and m.user_id != current_user.id:
                        adm = crud.get_user_by_id(db, m.user_id)
                        if adm and adm.name not in admin_names:
                            admin_names.append(adm.name)
        beheerders = ", ".join(admin_names) if admin_names else "een beheerder"
        raise HTTPException(
            status_code=400,
            detail=(
                f"Je hebt {overdue_count} verlopen lening(en) en mag niet meer lenen. "
                f"Breng eerst je items terug of neem contact op met: {beheerders}."
            ),
        )

    # Bepaal de groepscontext: gebruik de eerste gemeenschappelijke groep als fallback
    borrower_group_ids = {m.group_id for m in current_user.memberships}
    owner_group_ids = {m.group_id for m in item.owner.memberships} if item.owner else set()
    shared_groups = borrower_group_ids & owner_group_ids
    group_id = next(iter(shared_groups), None) or current_user.group_id

    if not group_id:
        raise HTTPException(
            status_code=400,
            detail="Je bent nog geen lid van een groep. Sluit je aan bij een groep om items te lenen."
        )

    br = crud.create_borrow_request(db, item_id, current_user.id, group_id)
    br.return_by = return_by   # Feature 1
    br.message = message
    # mark item as "reserved" so nobody else can request
    item.status = "reserved"
    db.commit()
    return br


def _wrap_item(it: Item) -> schemas.ItemOut:
    owner = it.owner
    lender = it.lender
    group_ids = [m.group_id for m in owner.memberships] if owner else []
    return schemas.ItemOut(
        id=it.id,
        name=it.name,
        info=it.info,
        image_path=it.image_path,
        leenkosten=it.leenkosten,
        category=it.category,
        condition=it.condition,
        max_borrow_days=it.max_borrow_days,
        owner_id=it.owner_id,
        group_id=owner.group_id if owner else None,
        status=it.status,
        lender_id=it.lender_id,
        reserved_at=it.reserved_at,
        listed_at=it.listed_at,
        available_group_ids=group_ids,
        owner_name=owner.name if owner else None,
        lender_name=lender.name if lender else None,
    )


@app.get("/items/user/{user_id}", response_model=list[schemas.ItemOut])
def get_items_by_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user_token),
):
    # Groepslidmaatschap vereist: alleen zichtbaar als je in dezelfde groep zit,
    # of je bekijkt je eigen items, of je bent superuser.
    target = crud.get_user_by_id(db, user_id)
    if not target:
        raise HTTPException(status_code=404, detail="Gebruiker niet gevonden")
    if current_user.id != user_id and current_user.role != "superuser":
        target_group_ids = {m.group_id for m in target.memberships}
        my_group_ids = {m.group_id for m in current_user.memberships}
        if not (target_group_ids & my_group_ids):
            raise HTTPException(status_code=403, detail="Geen toegang")
    items = crud.get_items_for_user(db, user_id)
    return [_wrap_item(it) for it in items]



@app.get("/items/", response_model=list[schemas.ItemOut])
def get_all_items(
    skip: int = 0,
    limit: int = 50,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user_token),
):
    items = crud.get_items_for_user_groups(db, current_user)
    others = [it for it in items if it.owner_id != current_user.id]
    page = others[skip: skip + limit]
    return [_wrap_item(it) for it in page]


@app.post("/items/{item_id}/mark_returned", response_model=schemas.BorrowRequestOut)
def mark_item_returned(
    item_id: int,
    has_damage: Optional[bool] = Body(None),    # Feature 6: schademelding
    damage_note: Optional[str] = Body(None),    # Feature 6: schademelding
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user_token),
):
    item = crud.get_item_by_id(db, item_id)
    if not item:
        raise HTTPException(status_code=404, detail="Item niet gevonden")
    br = (
        db.query(models.BorrowRequest)
          .filter(
              models.BorrowRequest.item_id == item_id,
              models.BorrowRequest.requester_id == current_user.id,
              models.BorrowRequest.status.in_(["approved", "return_requested"]),
          )
          .order_by(models.BorrowRequest.created_at.desc())
          .first()
    )
    if not br:
        raise HTTPException(status_code=404, detail="Geen actief leenverzoek gevonden")
    br.status = "returned"
    br.has_damage = has_damage or False    # Feature 6
    br.damage_note = damage_note          # Feature 6
    item.status = "free"
    item.lender_id = None
    item.reserved_at = None
    db.commit()
    db.refresh(br)
    return br


@app.post("/items/{item_id}/mark_given", status_code=status.HTTP_204_NO_CONTENT)
def mark_free_item_given(
    item_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user_token),
):
    """
    Eigenaar bevestigt dat een gratis item is opgehaald door de reserveerder.
    Verwijdert het item definitief (weggegeven = weg).
    """
    item = crud.get_item_by_id(db, item_id)
    if not item:
        raise HTTPException(status_code=404, detail="Item niet gevonden")
    if item.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Alleen de eigenaar mag dit bevestigen")
    if item.leenkosten is not None:
        raise HTTPException(status_code=400, detail="Dit is geen gratis item")
    if item.status not in ("reserved", "free"):
        raise HTTPException(status_code=400, detail="Item heeft geen actieve reservering")

    # Stuur notificatie naar de ontvanger als er een reserveerder is
    if item.lender_id:
        crud.create_notification(db, user_id=item.lender_id, type="item_given", payload={
            "item_name": item.name,
            "owner_name": current_user.name,
        })

    crud.delete_item(db, item_id)
    return None


@app.delete("/items/{item_id}")
def delete_item(
    item_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user_token),
):
    item = crud.get_item_by_id(db, item_id)
    if not item:
        raise HTTPException(status_code=404, detail="Item niet gevonden")
    if item.owner_id != current_user.id and current_user.role != "superuser":
        raise HTTPException(status_code=403, detail="Alleen de eigenaar mag dit item verwijderen")
    return crud.delete_item(db, item_id)

@app.put("/items/{item_id}", response_model=schemas.ItemOut)
def update_item(
    item_id: int,
    item: schemas.ItemCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user_token),
):
    db_item = crud.get_item_by_id(db, item_id)
    if not db_item:
        raise HTTPException(404, "Item niet gevonden")
    if db_item.owner_id != current_user.id and current_user.role != "superuser":
        raise HTTPException(403, "Alleen de eigenaar mag dit item bewerken")

    # Basisvelden
    db_item.name = item.name
    db_item.info = item.info
    db_item.leenkosten = item.leenkosten
    db_item.category = item.category
    db_item.condition = item.condition
    db_item.max_borrow_days = item.max_borrow_days

    # Gratis → update listed_at only if still free/expired (re-listing resets it)
    if item.leenkosten is None:
        if db_item.status == "expired":
            # owner edits an expired item → re-list it
            db_item.status = "free"
            db_item.listed_at = datetime.utcnow()
        elif db_item.listed_at is None:
            db_item.listed_at = datetime.utcnow()
    else:
        db_item.listed_at = None  # lendable items don't expire

    # Status/lender overrides (e.g. mark returned via put)
    if item.status is not None:
        db_item.status = item.status
        db_item.lender_id = item.lender_id
        db_item.reserved_at = item.reserved_at

    # Groepsbeschikbaarheid
    if item.available_group_ids is not None:
        if item.available_group_ids:
            groups = db.query(models.Group).filter(
                models.Group.id.in_(item.available_group_ids)
            ).all()
            db_item.available_groups = groups
        else:
            db_item.available_groups = []

    db.commit()
    db.refresh(db_item)
    return _wrap_item(db_item)



@app.delete("/users/{user_id}")
def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user_token)
):
    # Haal doelgebruiker op
    target_user = crud.get_user_by_id(db, user_id)

    if not target_user:
        raise HTTPException(status_code=404, detail="Gebruiker niet gevonden")

    # Alleen superuser of admin mag verwijderen
    if current_user.role == "superuser":
        pass  # mag altijd
    elif current_user.role == "admin":
        if target_user.group_id != current_user.group_id:
            raise HTTPException(status_code=403, detail="Je mag alleen gebruikers uit je eigen groep verwijderen")
    else:
        raise HTTPException(status_code=403, detail="Geen toegang tot verwijderen van gebruikers")

    return crud.delete_user(db, user_id)

@app.delete("/groups/{group_id}/admins/{user_id}", response_model=schemas.UserOut)
def remove_admin_from_group(
    group_id: int,
    user_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user_token),
):
    if current_user.role == "superuser":
        pass
    elif current_user.role == "admin":
        if current_user.group_id != group_id:
            raise HTTPException(status_code=403, detail="Alleen admins in je eigen groep mogen admins verwijderen")
    else:
        raise HTTPException(status_code=403, detail="Alleen admins of superusers mogen admins verwijderen")

    user_out = crud.remove_admin_from_group(db, user_id, group_id)
    # return consistent met privacy
    u = crud.get_user_by_id(db, user_id)
    return _user_to_out_with_privacy(u, current_user, group_id, db)



@app.get("/gebruikers/mij", response_model=schemas.UserResponse)
def get_me(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user_token),
):
    # memberships → schemas.Membership
    memberships = []
    for ug in current_user.memberships:
        memberships.append(schemas.Membership(
            group_id=ug.group_id,
            name=ug.group.name if ug.group else f"Groep {ug.group_id}",
            info=None,
            role=ug.role
        ))

    # Let op: phone → 'phone' key (frontend verwacht dit)
    return {
        "id": current_user.id,
        "name": current_user.name,
        "email": current_user.email,
        "phone": current_user.phone_number,
        "is_admin": current_user.is_admin,
        "is_approved": current_user.is_approved,
        "role": current_user.role,
        "group_id": current_user.group_id,
        "invited_by": current_user.invited_by,
        "admin_of_groups": [m.group_id for m in current_user.memberships if m.role == "admin"],
        "memberships": memberships,
    }


@app.get("/items/search", response_model=list[schemas.ItemOut])
def search_items(
    q: str,
    skip: int = 0,
    limit: int = 50,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user_token),
):
    items = crud.search_items_for_user_groups(db, current_user, q)
    others = [it for it in items if it.owner_id != current_user.id]
    page = others[skip: skip + limit]
    return [_wrap_item(it) for it in page]


@app.get("/gebruikers/alle", response_model=list[schemas.UserOut])
def get_all_users(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user_token)
):
    if current_user.role != "superuser":
        raise HTTPException(status_code=403, detail="Alleen superusers mogen alle gebruikers bekijken")

    users = db.query(User).all()
    out: list[schemas.UserOut] = []
    for u in users:
        # gebruik de 'primaire' group context van de user (zoals bestaande code deed)
        gid = u.group_id
        out.append(_user_to_out_with_privacy(u, current_user, gid, db))
    return out




@app.get("/groups/all", response_model=List[schemas.GroupOut])
def get_all_groups(db: Session = Depends(get_db)):
    groepen = crud.get_all_groups(db)
    return [{
        "id": groep.id,
        "name": groep.name,
        "status": groep.status,
        "aangemaakt_door": groep.aangemaakt_door,
        "admins": [admin.id for admin in groep.admins]  # handmatig ids extraheren
    } for groep in groepen]

@app.delete("/groep/verwijder_lid/{gebruiker_id}")
def verwijder_lid_uit_groep(
    gebruiker_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user_token)  # ← was get_current_user
):
    target_user = crud.get_user_by_id(db, gebruiker_id)

    if not target_user:
        raise HTTPException(status_code=404, detail="Gebruiker niet gevonden")

    if current_user.role == "superuser":
        pass
    elif current_user.role == "admin":
        if target_user.group_id != current_user.group_id:
            raise HTTPException(status_code=403, detail="Alleen leden uit eigen groep mogen worden verwijderd")
    else:
        raise HTTPException(status_code=403, detail="Geen toestemming")

    crud.remove_user_from_all_groups(db, gebruiker_id)

    return {"detail": f"Gebruiker {gebruiker_id} is succesvol uit de groep verwijderd"}



# ---- Item Request

@app.delete("/gebruiker/verzoeken/{request_id}", status_code=status.HTTP_204_NO_CONTENT)
def remove_item_request(
    request_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user_token)
):
    """
    Verwijder een item request: alleen de maker of een admin mag dit.
    """
    req = db.query(models.ItemRequest).filter(models.ItemRequest.id == request_id).first()
    if not req:
        raise HTTPException(status_code=404, detail="Request niet gevonden")
    if req.requester_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Niet toegestaan")
    crud.delete_item_request(db, request_id)
    return None


@app.get("/spellcheck", response_model=List[str])
def spellcheck(
    term: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user_token),
):
    return crud.get_spell_suggestions(db, term)

# 2) Verzoek voor ontbrekend item
@app.post("/gebruiker/verzoeken", response_model=schemas.ItemRequestOut)
def user_request_item(
    payload: schemas.ItemRequestCreate = Body(...),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user_token),
):
    if not payload.term:
        raise HTTPException(status_code=400, detail="term is verplicht")
    return crud.create_item_request(db, current_user.id, payload)

@app.get("/gebruiker/verzoeken/incoming", response_model=List[schemas.ItemRequestOut])
def incoming_item_requests(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user_token)
):
    reqs = crud.get_incoming_item_requests(db, current_user.id)
    print(f"[NOTIF] /gebruiker/verzoeken/incoming returned {len(reqs)} requests for owner {current_user.id}")
    return reqs

@app.post("/gebruiker/verzoeken/{req_id}/respond", response_model=schemas.ItemRequestOut)
def respond_item_request_endpoint(
    req_id: int,
    body: dict = Body(...),  # { decision, pick_up_by?, contact_info?, reason? }
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user_token)
):
    resp = crud.respond_item_request(
      db, req_id, current_user.id,
      body["decision"],
      pick_up_by=body.get("pick_up_by"),
      contact_info=body.get("contact_info"),
      reason=body.get("reason")
    )
    if not resp:
        raise HTTPException(404, "Request niet gevonden")
    return resp

@app.post("/items/{item_id}/reserve", response_model=schemas.ItemOut, status_code=status.HTTP_200_OK)
def reserve_free_item(
    item_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user_token)
):
    """
    Reserveer een gratis item (leenkosten is None).
    Zet status op 'reserved', sla lender_id en reserved_at op.
    """
    # Check item existence first for a better error message
    db_item = crud.get_item_by_id(db, item_id)
    if not db_item:
        raise HTTPException(status_code=404, detail="Item niet gevonden")
    if db_item.leenkosten is not None:
        raise HTTPException(status_code=400, detail="Dit item is niet gratis")
    if db_item.status != "free":
        raise HTTPException(status_code=400, detail="Dit item is niet meer beschikbaar")
    if db_item.owner_id == current_user.id:
        raise HTTPException(status_code=400, detail="Je kunt je eigen item niet reserveren")

    item = crud.reserve_item(db, current_user.id, item_id)
    if not item:
        raise HTTPException(status_code=400, detail="Reservering mislukt")
    return _wrap_item(item)


@app.delete("/items/{item_id}/reserve", status_code=status.HTTP_204_NO_CONTENT)
def cancel_free_reservation(
    item_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user_token),
):
    """
    Annuleer je reservering van een gratis item.
    Zet item terug op 'free', verwijdert lender_id en reserved_at.
    """
    item = crud.get_item_by_id(db, item_id)
    if not item:
        raise HTTPException(status_code=404, detail="Item niet gevonden")
    if item.leenkosten is not None:
        raise HTTPException(status_code=400, detail="Dit is geen gratis item")
    if item.lender_id != current_user.id:
        raise HTTPException(status_code=403, detail="Jij hebt dit item niet gereserveerd")
    if item.status != "reserved":
        raise HTTPException(status_code=400, detail="Item is niet gereserveerd")

    item.status = "free"
    item.lender_id = None
    item.reserved_at = None
    db.commit()
    return None


@app.delete("/groups/{group_id}/members/{user_id}")
def remove_member_from_group(
    group_id: int,
    user_id: int,
    suppress_notify: int = 0,   # 1 = backend maakt geen bel-notificatie
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user_token),
):
    # permissie: superuser of admin van deze groep
    if current_user.role != "superuser":
        admin_membership = next(
            (m for m in current_user.memberships
             if m.group_id == group_id and m.role == "admin"),
            None
        )
        if not admin_membership:
            raise HTTPException(status_code=403, detail="Geen toestemming voor deze groep")

    # bestaat de membership?
    target_membership = (
        db.query(models.UserGroup)
          .filter(models.UserGroup.group_id == group_id,
                  models.UserGroup.user_id == user_id)
          .first()
    )
    if not target_membership:
        raise HTTPException(status_code=404, detail="Gebruiker zit niet in deze groep")

    # haal groepsnaam voor payload
    grp = db.query(models.Group).filter(models.Group.id == group_id).first()
    group_name = grp.name if grp else f"groep {group_id}"

    # uitvoeren
    ok = crud.remove_user_from_group(db, group_id, user_id)
    if not ok:
        raise HTTPException(status_code=500, detail="Verwijderen mislukt")

    # bel-notificatie aan de verwijderde gebruiker, tenzij onderdrukt
    if not suppress_notify:
        crud.create_notification(
            db,
            user_id=user_id,
            type="group_removal",
            payload={"group_id": group_id, "group_name": group_name}
        )

    return {"detail": "Member removed"}

@app.get("/notifications", response_model=list[schemas.NotificationOut])
def get_notifications(
    limit: int = 50,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user_token),
):
    notifs = crud.list_notifications(db, current_user.id, limit=limit)
    return notifs


@app.post("/notifications/{notif_id}/read")
def mark_notification_as_read(
    notif_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user_token),
):
    ok = crud.mark_notification_read(db, notif_id, current_user.id)
    if not ok:
        raise HTTPException(status_code=404, detail="Notificatie niet gevonden")
    return {"detail": "ok"}



@app.post("/groups/{group_id}/join-request")
def join_group_request(
    group_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user_token),
):
    # al lid?
    already = any(m.group_id == group_id for m in current_user.memberships)
    if already:
        raise HTTPException(status_code=400, detail="Je bent al lid van deze groep")

    # haal groep + admins op
    grp = db.query(models.Group).filter(models.Group.id == group_id).first()
    if not grp:
        raise HTTPException(status_code=404, detail="Groep niet gevonden")

    admin_user_ids = [m.user_id for m in grp.memberships if m.role == "admin"]
    if not admin_user_ids and current_user.role != "superuser":
        # geen admins (kan bijna niet), maar beschermend:
        raise HTTPException(status_code=400, detail="Geen administrators voor deze groep")

    # maak notificaties voor alle admins
    for admin_id in admin_user_ids:
        crud.create_notification(
            db,
            user_id=admin_id,
            type="group_join_request",
            payload=json.dumps({
                "group_id": group_id,
                "group_name": grp.name,
                "requester_id": current_user.id,
                "requester_name": current_user.name,
            })
        )

    return {"detail": "Verzoek verstuurd naar groepsbeheerders"}



@app.post("/items/{item_id}/request_return", response_model=schemas.BorrowRequestOut)
def owner_request_return(
    item_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user_token),
):
    # 1) Haal item op en controleer eigenaarschap
    item = crud.get_item_by_id(db, item_id)
    if not item:
        raise HTTPException(status_code=404, detail="Item niet gevonden")
    if item.owner_id != current_user.id and current_user.role != "superuser":
        raise HTTPException(status_code=403, detail="Alleen de eigenaar kan terugvragen")

    # 2) Bepaal (verwachte) lener
    if not item.lender_id:
        raise HTTPException(status_code=400, detail="Item heeft geen actieve lener")

    # 3) Zoek bestaande actieve BorrowRequest bij dit item (laatste eerst)
    br: Optional[models.BorrowRequest] = (
        db.query(models.BorrowRequest)
          .filter(models.BorrowRequest.item_id == item_id)
          .order_by(models.BorrowRequest.created_at.desc())
          .first()
    )

    # 4) Als er geen request is, maak er één namens de huidige lener
    if not br:
        br = crud.create_borrow_request(db, item_id=item.id,
                                        requester_id=item.lender_id,
                                        group_id=item.owner.group_id)  # owner.group_id beschikbaar via relaties
        # status wordt 'pending' gezet in create_borrow_request

    # 5) Zet status op 'return_requested'
    br.status = "return_requested"
    db.commit()
    db.refresh(br)
    return br

@app.post("/groups/{group_id}/leave")
def leave_group(
    group_id: int,
    reason: str | None = Body(default=None),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user_token),
):
    # check membership
    membership = (
        db.query(models.UserGroup)
          .filter(models.UserGroup.group_id == group_id,
                  models.UserGroup.user_id == current_user.id)
          .first()
    )
    if not membership:
        raise HTTPException(status_code=404, detail="Je zit niet in deze groep")

    # verwijder membership
    ok = crud.remove_user_from_group(db, group_id, current_user.id)
    if not ok:
        raise HTTPException(status_code=500, detail="Verlaten mislukt")

    # notify admins
    grp = db.query(models.Group).filter(models.Group.id == group_id).first()
    admin_user_ids = [m.user_id for m in grp.memberships if m.role == "admin"]
    payload = {
        "group_id": group_id,
        "group_name": grp.name if grp else f"groep {group_id}",
        "leaver_id": current_user.id,
        "leaver_name": current_user.name,
        "reason": reason
    }
    for admin_id in admin_user_ids:
        crud.create_notification(
            db,
            user_id=admin_id,
            type="group_leave",
            payload=json.dumps(payload)
        )

    return {"detail": "Groep verlaten"}



@app.get("/admin/blocked-borrowers")
def get_blocked_borrowers(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user_token),
):
    """
    Geeft een lijst van leners in de groepen van de beheerder die te veel verlopen leningen hebben.
    """
    if current_user.role == "superuser":
        group_ids = [g.id for g in crud.get_all_groups(db)]
    else:
        group_ids = [m.group_id for m in current_user.memberships if m.role == "admin"]
    if not group_ids:
        raise HTTPException(status_code=403, detail="Geen toegang")
    return crud.get_blocked_borrowers_for_admin(db, group_ids)


@app.post("/admin/users/{user_id}/overdue-action")
def admin_overdue_action(
    user_id: int,
    action: str = Body(...),           # "extend" | "clear" | "set_limit"
    days: Optional[int] = Body(None),         # voor "extend": aantal extra dagen
    new_limit: Optional[int] = Body(None),    # voor "set_limit": nieuwe limiet (None = systeem default)
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user_token),
):
    """
    Beheerder actie op verlopen leningen van een gebruiker:
    - extend: verleng alle verlopen met N dagen
    - clear: verwijder terugbrengdatum (onbeperkt)
    - set_limit: pas persoonlijk overdue-limiet aan
    """
    target = crud.get_user_by_id(db, user_id)
    if not target:
        raise HTTPException(status_code=404, detail="Gebruiker niet gevonden")

    # Permissie: superuser of admin in een gemeenschappelijke groep
    if current_user.role != "superuser":
        target_group_ids = {m.group_id for m in target.memberships}
        admin_group_ids = {m.group_id for m in current_user.memberships if m.role == "admin"}
        if not (target_group_ids & admin_group_ids):
            raise HTTPException(status_code=403, detail="Geen toegang tot deze gebruiker")

    if action == "extend":
        if not days or days <= 0:
            raise HTTPException(status_code=400, detail="Geef een geldig aantal dagen op")
        count = crud.extend_all_overdue_for_user(db, user_id, days)
        crud.create_notification(db, user_id=user_id, type="overdue_extended", payload={
            "extra_days": days,
            "admin_name": current_user.name,
        })
        return {"detail": f"{count} lening(en) verlengd met {days} dagen"}

    elif action == "clear":
        count = crud.clear_all_overdue_for_user(db, user_id)
        crud.create_notification(db, user_id=user_id, type="overdue_cleared", payload={
            "admin_name": current_user.name,
        })
        return {"detail": f"Terugbrengdatum verwijderd voor {count} lening(en)"}

    elif action == "set_limit":
        target.max_overdue_allowed = new_limit  # None = systeem default
        db.commit()
        limit_text = str(new_limit) if new_limit is not None else "systeem standaard (5)"
        return {"detail": f"Limiet voor {target.name} aangepast naar {limit_text}"}

    else:
        raise HTTPException(status_code=400, detail="Onbekende actie (gebruik: extend, clear of set_limit)")


@app.post("/push/token")
def register_push_token(
    body: dict = Body(...),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user_token),
):
    token = (body.get("token") or "").strip()
    platform = (body.get("platform") or "android").lower()
    if not token:
        raise HTTPException(status_code=400, detail="token is verplicht")
    crud.add_push_token(db, current_user.id, token, platform)
    return {"detail": "ok"}

@app.delete("/push/token")
def unregister_push_token(
    body: dict = Body(...),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user_token),
):
    token = (body.get("token") or "").strip()
    if not token:
        raise HTTPException(status_code=400, detail="token is verplicht")
    ok = crud.remove_push_token(db, current_user.id, token)
    return {"detail": "ok" if ok else "not found"}

@app.post("/push/test")
def push_test(
    body: dict = Body(default={"title": "Test", "body": "Hoi van FCM 👋"}),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user_token),
):
    tokens = crud.list_push_tokens_for_user(db, current_user.id)
    if not tokens:
        raise HTTPException(status_code=404, detail="Geen geregistreerde tokens")
    title = body.get("title") or "Test"
    text  = body.get("body")  or "Hoi!"
    results = []
    for t in tokens:
        ok, err = send_fcm_to_token(t, title, text, {"type": "test"})
        results.append({"token": t, "ok": ok, "err": err})
    sent = sum(1 for r in results if r["ok"])
    return {"sent": sent, "total": len(tokens), "results": results}


# ─── Feature 7: Vergeten PIN ────────────────────────────────────────────

@app.post("/auth/forgot-pin")
def forgot_pin(
    payload: schemas.ForgotPinRequest,
    db: Session = Depends(get_db),
):
    """
    Verzoek om PIN te resetten. Stuurt een resetcode via e-mail.
    Altijd 200 teruggeven (niet onthullen of het e-mailadres bestaat).
    """
    from email_service import send_pin_reset_email
    result = crud.create_pin_reset_token(db, payload.email)
    if result:
        user, token = result
        send_pin_reset_email(user.email, user.name, token)
    return {"detail": "Als dit e-mailadres bekend is, ontvang je een code."}


@app.post("/auth/reset-pin")
def reset_pin(
    payload: schemas.ResetPinRequest,
    db: Session = Depends(get_db),
):
    """
    Stel nieuwe PIN in met het reset-token uit de e-mail.
    """
    user = crud.reset_pin_with_token(db, payload.token, payload.new_pin)
    if not user:
        raise HTTPException(status_code=400, detail="Ongeldige of verlopen code")
    return {"detail": "Pincode succesvol opnieuw ingesteld"}


# ── Flutter web: serveer de build vanuit ./web/ ───────────────────────────
# Moet ALTIJD als laatste staan — API-routes hebben voorrang.
import pathlib
from fastapi.responses import FileResponse as _FileResponse

_WEB_DIR = pathlib.Path(os.getenv("WEB_DIR", "./web"))


@app.get("/{full_path:path}", include_in_schema=False)
async def serve_flutter_web(full_path: str):
    """
    Serveer de Flutter web-build.
    – Statische bestanden (JS, CSS, iconen …) worden direct teruggestuurd.
    – Elke andere route stuurt index.html terug (SPA-gedrag).
    Zet WEB_DIR in .env als de build ergens anders staat.
    """
    if not _WEB_DIR.exists():
        raise HTTPException(status_code=404, detail="Web-build niet gevonden. "
                            "Voer 'flutter build web' uit en kopieer build/web naar ./web/")
    candidate = _WEB_DIR / full_path
    if candidate.is_file():
        return _FileResponse(candidate)
    # SPA-fallback: stuur altijd index.html terug
    index = _WEB_DIR / "index.html"
    if not index.exists():
        raise HTTPException(status_code=404, detail="index.html niet gevonden in web-build")
    return _FileResponse(index)