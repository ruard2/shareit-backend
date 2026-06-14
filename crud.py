from sqlalchemy.orm import Session, aliased
from sqlalchemy import or_, and_, func, case
from fastapi import HTTPException
from spellchecker import SpellChecker
from typing import Optional, List, Union, Any

import random
import string
import time
from models import UserPreferences
from datetime import datetime

import json

from passlib.context import CryptContext
import models
import schemas
from models import User, Group, Item, Sessie, UserGroup, BorrowRequest
from schemas import UserCreate, ItemCreate, GroupCreate


spell = SpellChecker(language='nl')  # of geef eigen wordlist mee

# Password hashing context

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")



def get_dashboard_info(db: Session, user_id: int):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        return None

    # Alle groep-IDs waar de gebruiker lid van is
    group_ids = [m.group_id for m in user.memberships]  # User.memberships → UserGroup entries :contentReference[oaicite:2]{index=2}

    # 1) Jouw spullen (eigendom) — verlopenspullen niet meetellen
    owned_q = db.query(Item).filter(
        Item.owner_id == user.id,
        Item.status != "expired",
    )
    mijn_spullen = owned_q.count()

    # 2) Geleend door mij (maakt niet uit of reserved of loaned; zelfde als je had)
    geleend_door_mij = db.query(Item).filter(Item.lender_id == user.id).count()

    # 3) Beschikbaar in al jouw groepen, uitgesloten: je eigen items
    #    “beschikbaar” = status == 'free' (zowel gratis als te lenen, zolang vrij)
    beschikbaar = (
        db.query(Item)
          .join(UserGroup, Item.owner_id == UserGroup.user_id)
          .filter(UserGroup.group_id.in_(group_ids))
          .filter(Item.status == 'free')          # status-strings in jouw model :contentReference[oaicite:3]{index=3}
          .filter(Item.owner_id != user.id)
          .count()
    )

    # (optioneel) wat je al teruggaf
    requests = db.query(BorrowRequest).filter(BorrowRequest.requester_id == user.id).count()
    group_members = 0
    if user.group_id:
        group = db.query(Group).filter(Group.id == user.group_id).first()
        group_members = len(group.members) if group else 0

    return {
        "name": user.name,

        # oude keys (backwards compat, als je die elders gebruikt)
        "total_items": mijn_spullen,
        "borrowed_items": geleend_door_mij,
        "requests": requests,
        "group_members": group_members,

        # >>> keys die Home gebruikt <<<
        "mijn_spullen": mijn_spullen,
        "geleend_door_mij": geleend_door_mij,
        "beschikbaar": beschikbaar,

        # "uitgeleend" LATEN WE WEG — je wilde die tegel verwijderen
    }


# -------------------- Utility Functions --------------------

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def generate_invite_code(length: int = 6) -> str:
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))
# -------------------- NOtification helpers ----------
# ─── Membership gericht verwijderen ──────────────────────
def remove_user_from_group(db: Session, group_id: int, user_id: int) -> bool:
    ug = (
        db.query(models.UserGroup)
          .filter(models.UserGroup.group_id == group_id,
                  models.UserGroup.user_id == user_id)
          .first()
    )
    if not ug:
        return False
    db.delete(ug)
    db.commit()
    return True


# ─── Notifications CRUD ──────────────────────────────────
def create_notification(db: Session, user_id: int, type: str, payload: dict | None = None) -> models.Notification:
    # Normaliseer payload: sommige callers geven een dict, andere een JSON-string.
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except Exception:
            payload = {}
    if not isinstance(payload, dict):
        payload = {}

    notif = models.Notification(
        user_id=user_id,
        type=type,
        payload=json.dumps(payload)
    )
    db.add(notif)
    db.commit()
    db.refresh(notif)

    title, body, cat = _render_push_from_type(type, payload)

    # push (best-effort)
    try:
        import push
        push.notify_user(db, user_id, title, body, payload or {}, category=cat)
    except Exception:
        pass

    # e-mail (best-effort, asynchroon zodat de request niet op SMTP wacht)
    try:
        user = db.query(models.User).filter(models.User.id == user_id).first()
        if user and getattr(user, "email", None):
            _send_notification_email_async(user.email, user.name or "", title, body)
    except Exception:
        pass

    return notif


def _send_notification_email_async(to: str, name: str, title: str, body: str):
    """Verstuur een notificatie-mail in een achtergrond-thread (blokkeert de
    request niet). Doet niets schadelijks als SMTP niet is geconfigureerd —
    send_email logt dan alleen naar de console."""
    import threading

    def _run():
        try:
            from email_service import send_email
            subject = f"ShareIt — {title}"
            text = (
                f"Hoi {name},\n\n{body}\n\n"
                "Open ShareIt om te reageren.\n\n"
                "Groet,\nHet ShareIt team"
            )
            html = (
                f"<html><body>"
                f"<p>Hoi <strong>{name}</strong>,</p>"
                f"<p>{body}</p>"
                f"<p>Open ShareIt om te reageren.</p>"
                f"<br><p>Groet,<br>Het ShareIt team</p>"
                f"</body></html>"
            )
            send_email(to, subject, text, html)
        except Exception as e:
            print(f"[EMAIL] notificatie-mail mislukt: {e}")

    threading.Thread(target=_run, daemon=True).start()

def _render_push_from_type(type: str, p: dict):
    if not isinstance(p, dict):
        p = {}
    if type == "group_join_request":
        nm = p.get("requester_name", "Iemand")
        gn = p.get("group_name", "je groep")
        return ("Nieuw groepsverzoek", f"{nm} wil lid worden van {gn}", "join")
    if type == "group_removal":
        return ("Uit groep verwijderd", f"Je bent verwijderd uit {p.get('group_name','een groep')}", "join")
    if type == "item_request":
        return ("Nieuw itemverzoek", f"Iemand heeft een verzoek geplaatst", "borrow")
    if type == "item_reserved":
        nm = p.get("reserver_name", "Iemand")
        it = p.get("item_name", "je item")
        return ("Item gereserveerd", f"{nm} wil '{it}' ophalen", "borrow")
    if type == "item_expired":
        it = p.get("item_name", "een item")
        return ("Item verlopen", f"'{it}' is na 60 dagen niet opgehaald en verwijderd uit de lijst", None)
    if type == "item_given":
        it = p.get("item_name", "een item")
        return ("Item opgehaald", f"'{it}' is gemarkeerd als opgehaald", "borrow")
    if type == "loan_extended":
        it = p.get("item_name", "je lening")
        return ("Lening verlengd", f"De uitleentermijn van '{it}' is verlengd", "borrow")
    if type == "overdue_return":
        it = p.get("item_name", "een item")
        return ("Te laat terugbrengen", f"'{it}' had al teruggebracht moeten zijn", "borrow")
    if type == "overdue_owner":
        it = p.get("item_name", "je item")
        return ("Item nog niet terug", f"'{it}' is nog niet teruggebracht", "borrow")
    if type == "request_decision":
        it = p.get("item_name", "je verzoek")
        st = p.get("status", "")
        woord = "goedgekeurd" if st == "approved" else ("afgewezen" if st == "rejected" else "bijgewerkt")
        return ("Verzoek $woord".replace("$woord", woord), f"Je leenverzoek voor '{it}' is $woord".replace("$woord", woord), "borrow")
    if type == "user_approved":
        return ("Aanmelding goedgekeurd", "Je bent goedgekeurd — je kunt nu volledig meedoen", "join")
    # default
    return ("Melding", "Je hebt een nieuwe melding", None)


def list_notifications(db: Session, user_id: int, limit: int = 50):
    return (
        db.query(models.Notification)
          .filter(models.Notification.user_id == user_id)
          .order_by(models.Notification.created_at.desc())
          .limit(limit)
          .all()
    )


def count_unread_notifications(db: Session, user_id: int) -> int:
    return (
        db.query(func.count(models.Notification.id))
          .filter(models.Notification.user_id == user_id,
                  models.Notification.read_at.is_(None))
          .scalar()
        or 0
    )


def check_and_send_overdue_notifications(db: Session):
    """
    Run daily: zoek actieve leningen waarbij return_by is verstreken
    en stuur (als er een nieuwe "dag te laat" is) notificaties naar
    zowel de lener als de eigenaar.
    """
    now = datetime.utcnow()

    overdue_borrows = (
        db.query(models.BorrowRequest)
        .filter(
            models.BorrowRequest.status == "approved",
            models.BorrowRequest.return_by.isnot(None),
            models.BorrowRequest.return_by < now,
        )
        .all()
    )

    count = 0
    for br in overdue_borrows:
        days_late = max(1, (now - br.return_by).days + 1)
        prev = br.overdue_notif_days or 0
        if days_late <= prev:
            continue  # already notified for this day

        item = br.item
        borrower = br.requester
        if not item or not borrower or not item.owner:
            continue

        owner = item.owner

        # Verwijder vorige ongelezen overdue-notificaties voor deze lener/eigenaar
        # zodat de bel niet onnodig oploopt bij meerdere gemiste dagen.
        db.query(models.Notification).filter(
            models.Notification.user_id == borrower.id,
            models.Notification.type == "overdue_return",
            models.Notification.read_at.is_(None),
        ).update({"read_at": now})
        db.query(models.Notification).filter(
            models.Notification.user_id == owner.id,
            models.Notification.type == "overdue_owner",
            models.Notification.read_at.is_(None),
        ).update({"read_at": now})

        # Notificatie voor de lener
        create_notification(db, user_id=borrower.id, type="overdue_return", payload={
            "item_name": item.name,
            "days_late": days_late,
            "request_id": br.id,
            "owner_name": owner.name,
        })

        # Notificatie voor de eigenaar (met actieknoppen)
        create_notification(db, user_id=owner.id, type="overdue_owner", payload={
            "item_name": item.name,
            "days_late": days_late,
            "request_id": br.id,
            "borrower_name": borrower.name,
            "borrower_id": borrower.id,
        })

        br.overdue_notif_days = days_late
        count += 1

    db.commit()
    print(f"[OVERDUE] Check klaar: {len(overdue_borrows)} verlopen, {count} nieuwe notificaties verstuurd")


FREE_ITEM_EXPIRY_DAYS = 60


def check_and_expire_free_items(db: Session):
    """
    Dagelijkse check: gratis items (leenkosten IS NULL) die langer dan
    FREE_ITEM_EXPIRY_DAYS dagen geleden zijn geplaatst en nog steeds 'free'
    zijn, worden op 'expired' gezet. De eigenaar krijgt een notificatie.
    """
    from datetime import timedelta
    cutoff = datetime.utcnow() - timedelta(days=FREE_ITEM_EXPIRY_DAYS)

    expired_items = (
        db.query(models.Item)
        .filter(
            models.Item.leenkosten.is_(None),
            models.Item.status == "free",
            models.Item.listed_at.isnot(None),
            models.Item.listed_at < cutoff,
        )
        .all()
    )

    count = 0
    for item in expired_items:
        item.status = "expired"
        create_notification(db, user_id=item.owner_id, type="item_expired", payload={
            "item_name": item.name,
            "item_id": item.id,
            "listed_days": FREE_ITEM_EXPIRY_DAYS,
        })
        count += 1

    db.commit()
    print(f"[EXPIRY] {count} gratis item(s) verlopen na {FREE_ITEM_EXPIRY_DAYS} dagen")


def mark_notification_read(db: Session, notif_id: int, user_id: int) -> bool:
    notif = (
        db.query(models.Notification)
          .filter(models.Notification.id == notif_id,
                  models.Notification.user_id == user_id)
          .first()
    )
    if not notif:
        return False
    notif.read_at = datetime.utcnow()
    db.commit()
    return True


# -------------------- User CRUD --------------------

def create_user(db: Session, user: UserCreate) -> User:
    # Determine invited_by from group_code if provided
    invited_by_id = None
    group = None
    if user.group_code:
        group = db.query(Group).filter(Group.code == user.group_code).first()
        if not group:
            raise HTTPException(status_code=400, detail="Ongeldige groepscode")
        invited_by_id = group.owner_id
    elif user.group_id:
        group = db.query(Group).filter(Group.id == user.group_id).first()
        if not group:
            raise HTTPException(status_code=400, detail="Ongeldige groep-ID")

    # Create the user record
    db_user = User(
        name=user.name,
        email=user.email,
        phone_number=user.phone_number,
        address=user.address,
        pin_code=pwd_context.hash(user.pin_code),
        is_admin=False,
        is_approved=False,
        invited_by=invited_by_id,
        role=user.role or "user"
    )
    db.add(db_user)
    db.flush()

    # Assign initial membership if a group was specified
    if group:
        membership = UserGroup(
            user_id=db_user.id,
            group_id=group.id,
            role="user"
        )
        db.add(membership)

    db.commit()
    db.refresh(db_user)
    return db_user



# -------------------- Preferences helpers (single source of truth) --------------------
from typing import Optional, Any
from models import UserPreferences

def get_user_prefs(db: Session, user_id: int) -> Optional[UserPreferences]:
    """Lees preferences, of None als ze nog niet bestaan."""
    return (
        db.query(UserPreferences)
          .filter(UserPreferences.user_id == user_id)
          .first()
    )

def get_or_create_user_prefs(db: Session, user_id: int) -> UserPreferences:
    """Zorg dat er preferences bestaan (met defaults) en geef ze terug."""
    prefs = get_user_prefs(db, user_id)
    if not prefs:
        prefs = UserPreferences(user_id=user_id)
        db.add(prefs)
        db.commit()
        db.refresh(prefs)
    return prefs

def get_user_prefs_as_dict(db: Session, user_id: int) -> dict:
    """Handig voor GET /users/me/preferences."""
    prefs = get_or_create_user_prefs(db, user_id)
    return {
        "notifications": {
            "messages": prefs.notif_messages,
            "borrow": prefs.notif_borrow,
            "join_requests": prefs.notif_join_requests,
        },
        "privacy": {
            "show_email": prefs.priv_show_email,
            "show_phone": prefs.priv_show_phone,
        },
        "ui": {
            "theme": prefs.ui_theme,
            "language": prefs.ui_language,
        },
    }

def update_user_prefs(db: Session, user_id: int, payload: dict) -> UserPreferences:
    prefs = get_or_create_user_prefs(db, user_id)

    notif = payload.get("notifications", {})
    priv  = payload.get("privacy", {})
    ui    = payload.get("ui", {})

    # notifications
    if "messages" in notif:
        prefs.notif_messages = bool(notif["messages"])
    if "borrow" in notif:
        prefs.notif_borrow = bool(notif["borrow"])
    if "join_requests" in notif:
        prefs.notif_join_requests = bool(notif["join_requests"])

    # privacy
    if "show_email" in priv:
        prefs.priv_show_email = bool(priv["show_email"])
    if "show_phone" in priv:
        prefs.priv_show_phone = bool(priv["show_phone"])

    # ui
    if "theme" in ui and ui["theme"] in ("system", "light", "dark"):
        prefs.ui_theme = ui["theme"]
    if "language" in ui and ui["language"] in ("nl", "en"):
        prefs.ui_language = ui["language"]

    db.commit()
    db.refresh(prefs)
    return prefs






def serialize_user_for(requester_id: int, user: User, prefs: UserPreferences | None) -> dict:
    """
    Serieel user met respect voor privacy settings t.o.v. requester.
    Voor nu: e-mail/telefoon alleen tonen als prefs.* aan staat,
    of als requester==user, of requester is superuser.
    """
    show_email = user.email
    show_phone = user.phone_number

    if requester_id != user.id:
        # haal prefs op van target-user
        if not prefs:
            # geen prefs -> standaard niks tonen
            show_email = None
            show_phone = None
        else:
            if not prefs.priv_show_email:
                show_email = None
            if not prefs.priv_show_phone:
                show_phone = None

    # basisoutput (compat met bestaande front-ends die 'phone' verwachten)
    return {
        "id": user.id,
        "name": user.name,
        "email": show_email,
        "phone": show_phone,
        "is_admin": user.is_admin,
        "is_approved": user.is_approved,
        "role": user.role,
        "group_id": user.group_id,
        "invited_by": user.invited_by,
        "admin_of_groups": [m.group_id for m in user.memberships if m.role == "admin"],
    }


def get_user_by_email(db: Session, email: str) -> Optional[User]:
    return db.query(User).filter(User.email == email).first()


def get_user_by_id(db: Session, user_id: int) -> Optional[User]:
    return db.query(User).filter(User.id == user_id).first()


def get_user_by_session_id(db: Session, session_id: str) -> Optional[User]:
    sessie = db.query(Sessie).filter(Sessie.session_id == session_id).first()
    return get_user_by_id(db, sessie.gebruiker_id) if sessie else None


def authenticate_user(db: Session, email: str, pin_code: str) -> Optional[User]:
    user = get_user_by_email(db, email)
    if not user:
        return None
    if not pwd_context.verify(pin_code, user.pin_code):
        return None
    return user


def get_users_by_group(db: Session, group_id: int) -> List[User]:
    return (
        db.query(User)
        .join(UserGroup, and_(User.id == UserGroup.user_id, UserGroup.group_id == group_id))
        .all()
    )


def get_pending_users_by_group(db: Session, current_user: User) -> List[User]:
    # legacy signature: use current_user.group_id
    group_id = current_user.group_id
    return (
        db.query(User)
        .join(UserGroup, and_(User.id == UserGroup.user_id, UserGroup.group_id == group_id))
        .filter(User.is_approved == False)
        .all()
    )




def approve_user(db: Session, user_id: int) -> Optional[User]:
    user = get_user_by_id(db, user_id)
    if not user:
        return None
    user.is_approved = True
    db.commit()
    db.refresh(user)

    # If all members of their primary group are approved, activate the group
    primary_group_id = user.group_id
    if primary_group_id:
        pending = (
            db.query(User)
            .join(UserGroup, and_(User.id == UserGroup.user_id, UserGroup.group_id == primary_group_id))
            .filter(User.is_approved == False)
            .all()
        )
        if not pending:
            groep = db.query(Group).get(primary_group_id)
            if groep and groep.status != "active":
                groep.status = "active"
                db.commit()
    return user


def assign_group(db: Session, user_id: int, group_id: int) -> User:
    # Remove existing memberships, then add new one as 'user'
    db.query(UserGroup).filter(UserGroup.user_id == user_id).delete()
    membership = UserGroup(user_id=user_id, group_id=group_id, role="user")
    db.add(membership)
    db.commit()
    return get_user_by_id(db, user_id)


def remove_user_from_all_groups(db: Session, user_id: int) -> User:
    user = get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="Gebruiker niet gevonden")
    db.query(UserGroup).filter(UserGroup.user_id == user_id).delete()
    user.invited_by = None
    user.is_admin = False
    user.is_approved = False
    db.commit()
    db.refresh(user)
    return user


def delete_user(db: Session, user_id: int) -> dict:
    user = get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="Gebruiker niet gevonden")
    db.delete(user)
    db.commit()
    return {"detail": "Gebruiker verwijderd"}


def assign_invite_code(db: Session, user_id: int) -> User:
    code = generate_invite_code()
    user = get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="Gebruiker niet gevonden")
    user.invite_code = code
    db.commit()
    db.refresh(user)
    return user


def change_user_role(db: Session, user_id: int, new_role: str) -> User:
    user = get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="Gebruiker niet gevonden")
    if new_role not in ["user", "admin", "superuser"]:
        raise HTTPException(status_code=400, detail="Ongeldige rol")
    user.role = new_role
    db.commit()
    db.refresh(user)
    return user


def assign_admin_to_group(db: Session, user_id: int, group_id: int) -> User:
    user = get_user_by_id(db, user_id)
    group = db.query(Group).get(group_id)
    if not user or not group:
        raise HTTPException(status_code=404, detail="Gebruiker of groep niet gevonden")
    # Update existing membership or create a new one with role 'admin'
    membership = (
        db.query(UserGroup)
          .filter_by(user_id=user_id, group_id=group_id)
          .one_or_none()
    )
    if membership:
        membership.role = "admin"
    else:
        membership = UserGroup(user_id=user_id, group_id=group_id, role="admin")
        db.add(membership)
    db.commit()
    return get_user_by_id(db, user_id)

# -------------------- Item CRUD --------------------

def get_spell_suggestions(db: Session, term: str) -> List[str]:
    # eerste, haal je eigen item-namen op
    names = [i.name for i in db.query(models.Item).all()]
    # voeg die toe aan de NL-wordlist, zodat eigen namen ook onthouden worden
    for name in names:
        spell.word_frequency.add(name.lower())

    # haal kandidaten uit de algemene NL-dictionary
    suggestions = list(spell.candidates(term.lower()))
    # beperk tot maximaal 5
    return suggestions[:5]

def create_item_request(db: Session, requester_id: int, req_in: schemas.ItemRequestCreate):
    obj = models.ItemRequest(
        requester_id=requester_id,
        item_id=req_in.item_id,      # ← sla gekoppeld item op als meegegeven
        term=req_in.term,
        comment=req_in.comment,
    )
    db.add(obj)
    db.commit()
    db.refresh(obj)
    return obj



def reserve_item(db: Session, user_id: int, item_id: int):
    """
    Reserveer een gratis item (leenkosten == None), zet status op 'reserved',
    sla lender_id en reserved_at op. Stuurt notificatie naar eigenaar.
    """
    item = db.query(models.Item).filter(models.Item.id == item_id).first()
    if not item:
        return None
    if item.leenkosten is not None:
        return None   # alleen gratis items
    if item.status != "free":
        return None   # al gereserveerd/uitgeleend/verlopen

    reserver = db.query(models.User).filter(models.User.id == user_id).first()
    item.status = 'reserved'
    item.lender_id = user_id
    item.reserved_at = datetime.utcnow()
    db.commit()
    db.refresh(item)

    # Notificeer de eigenaar
    if item.owner_id and item.owner_id != user_id:
        create_notification(db, user_id=item.owner_id, type="item_reserved", payload={
            "item_name": item.name,
            "item_id": item.id,
            "reserver_name": reserver.name if reserver else "Iemand",
            "reserver_id": user_id,
        })

    return item


def delete_item_request(db: Session, request_id: int) -> None:
    """
    Verwijder een ItemRequest uit de database.
    """
    obj = db.query(models.ItemRequest).filter(models.ItemRequest.id == request_id).first()
    if not obj:
        return
    db.delete(obj)
    db.commit()


def get_incoming_item_requests(db: Session, owner_id: int):
    """
    Haal alle pending ItemRequest op voor items die door owner_id zijn aangeboden.
    Alleen verzoeken die aan een bestaand item gekoppeld zijn.
    """
    return (
        db.query(models.ItemRequest)
          .join(models.Item, models.Item.id == models.ItemRequest.item_id)
          .filter(
              models.ItemRequest.status == "pending",
              models.ItemRequest.item_id.isnot(None),
              models.Item.owner_id == owner_id,
          )
          .all()
    )

def respond_item_request(db: Session, req_id: int, responder_id: int,
                         decision: str, pick_up_by=None,
                         contact_info=None, reason=None):
    req = db.query(models.ItemRequest).get(req_id)
    if not req:
        return None
    req.status = "accepted" if decision=="accept" else "denied"
    req.pick_up_by = pick_up_by
    req.contact_info = contact_info
    req.reason = reason
    db.commit()
    db.refresh(req)
    return req

def delete_conversation(db: Session, user_id: int, peer_id: int) -> int:
    """
    Verwijder ALLE berichten tussen user_id en peer_id (beide richtingen).
    Retourneert het aantal verwijderde berichten.
    LET OP: hard delete voor beide kanten.
    """
    q = db.query(models.Message).filter(
        or_(
            and_(models.Message.sender_id == user_id, models.Message.recipient_id == peer_id),
            and_(models.Message.sender_id == peer_id, models.Message.recipient_id == user_id),
        )
    )
    deleted_count = q.count()
    q.delete(synchronize_session=False)
    db.commit()
    return deleted_count

def create_item(db: Session, item_in: schemas.ItemCreate) -> models.Item:
    is_free = item_in.leenkosten is None
    db_item = models.Item(
        name=item_in.name,
        info=item_in.info,
        leenkosten=item_in.leenkosten,
        owner_id=item_in.owner_id,
        category=item_in.category,
        condition=item_in.condition,
        max_borrow_days=item_in.max_borrow_days,
        listed_at=datetime.utcnow() if is_free else None,  # expiry tracking for gratis items
    )
    db.add(db_item)
    db.commit()
    # handle group availability
    if item_in.available_group_ids:
        groups = db.query(models.Group).filter(
            models.Group.id.in_(item_in.available_group_ids)
        ).all()
        db_item.available_groups = groups
        db.commit()
    db.refresh(db_item)
    return db_item

def update_item(db: Session, item_id: int, item: ItemCreate) -> Item:
    db_item = db.query(Item).get(item_id)
    if not db_item:
        raise HTTPException(status_code=404, detail="Item niet gevonden")
    db_item.name = item.name
    db_item.info = item.info
    db_item.image_path = item.image_path
    db_item.leenkosten = item.leenkosten
    db_item.owner_id = item.owner_id
    db_item.category = item.category    # Feature 5
    db_item.condition = item.condition  # Feature 5
    db.commit()
    db.refresh(db_item)
    return db_item


def delete_item(db: Session, item_id: int) -> Optional[Item]:
    item = db.query(Item).get(item_id)
    if item:
        db.delete(item)
        db.commit()
    return item


def get_items_for_user(db: Session, user_id: int) -> List[Item]:
    """
    Return all items owned by a single user.
    Used by GET /items/user/{user_id}
    """
    return db.query(Item).filter(Item.owner_id == user_id).all()

def search_items_for_user_groups(db: Session, current_user: models.User, zoekterm: str) -> List[models.Item]:
    group_ids = [m.group_id for m in current_user.memberships]
    return (
        db.query(Item)
          .join(UserGroup, Item.owner_id == UserGroup.user_id)
          .filter(UserGroup.group_id.in_(group_ids))
          .filter(Item.name.ilike(f"%{zoekterm}%"))
          .filter(Item.status != "expired")
          .all()
    )


def get_items_for_user_groups(db: Session, current_user) -> List[Item]:
    group_ids = [m.group_id for m in current_user.memberships]
    return (
        db.query(Item)
          .join(UserGroup, Item.owner_id == UserGroup.user_id)
          .filter(UserGroup.group_id.in_(group_ids))
          .filter(Item.status != "expired")
          .all()
    )

def get_item_by_id(db: Session, item_id: int) -> Optional[Item]:
    return db.query(Item).filter(Item.id == item_id).first()


# -------------------- Group CRUD --------------------

def create_group(db: Session, group: GroupCreate) -> Group:
    invite_code = generate_invite_code(8)   # Feature 3: unieke groepscode
    db_group = Group(
        name=group.name,
        status=group.status or "pending",
        aangemaakt_door=group.aangemaakt_door,
        invite_code=invite_code,
    )
    db.add(db_group)
    db.commit()
    db.refresh(db_group)
    return db_group


def get_group_by_invite_code(db: Session, code: str):
    """Feature 3: zoek een groep op invite_code."""
    return db.query(Group).filter(Group.invite_code == code).first()


def assign_group_invite_code(db: Session, group_id: int) -> Group:
    """Feature 3: genereer een nieuwe invite_code voor een groep."""
    group = db.query(Group).get(group_id)
    if not group:
        raise HTTPException(status_code=404, detail="Groep niet gevonden")
    group.invite_code = generate_invite_code(8)
    db.commit()
    db.refresh(group)
    return group


def get_all_groups(db: Session) -> List[Group]:
    return db.query(Group).all()



# -------------------- Borrow-Request CRUD --------------------

def get_pending_requests_for_group(db: Session, group_id: int) -> List[models.BorrowRequest]:
    """
    Return all BorrowRequest objects in this group whose status is still 'pending'.
    """
    return (
        db.query(models.BorrowRequest)
          .filter(
              models.BorrowRequest.group_id == group_id,
              models.BorrowRequest.status == "pending"
          )
          .all()
    )

def create_borrow_request(db: Session, item_id: int, requester_id: int, group_id: int) -> models.BorrowRequest:
    """
    Create a new BorrowRequest in status 'pending'.
    """
    br = models.BorrowRequest(
        item_id=item_id,
        requester_id=requester_id,
        group_id=group_id
    )
    db.add(br)
    db.commit()
    db.refresh(br)
    return br

def get_request(db: Session, req_id: int) -> models.BorrowRequest:
    """
    Fetch a single BorrowRequest by its ID, or raise 404.
    """
    br = db.query(models.BorrowRequest).filter(models.BorrowRequest.id == req_id).first()
    if not br:
        raise HTTPException(status_code=404, detail="Borrow request not found")
    return br

def get_my_borrow_requests(db: Session, user_id: int) -> List[models.BorrowRequest]:
    """Feature 4: alle leenverzoeken van de ingelogde gebruiker."""
    return (
        db.query(models.BorrowRequest)
          .filter(models.BorrowRequest.requester_id == user_id)
          .order_by(models.BorrowRequest.created_at.desc())
          .all()
    )

def count_pending_requests(db: Session, group_id: int) -> int:
    """
    Count how many pending borrow-requests exist for this group.
    """
    return (
        db.query(models.BorrowRequest)
          .filter(
              models.BorrowRequest.group_id == group_id,
              models.BorrowRequest.status == "pending"
          )
          .count()
    )

def count_pending_item_requests(db: Session, owner_id: int) -> int:
    """
    Tel het aantal pending ItemRequest voor items die door owner_id zijn aangeboden.
    """
    return (
        db.query(func.count(models.ItemRequest.id))
          .join(models.Item, models.Item.id == models.ItemRequest.item_id)
          .filter(
              models.Item.owner_id == owner_id,
              models.ItemRequest.status == 'pending'
          )
          .scalar()
        or 0
    )

# ─── Borrow blocking helpers ──────────────────────────────────────────────────

SYSTEM_OVERDUE_LIMIT = 5


def count_overdue_borrows(db: Session, user_id: int) -> int:
    """Tel hoeveel actieve leningen van deze gebruiker momenteel te laat zijn."""
    now = datetime.utcnow()
    return (
        db.query(func.count(models.BorrowRequest.id))
        .filter(
            models.BorrowRequest.requester_id == user_id,
            models.BorrowRequest.status == "approved",
            models.BorrowRequest.return_by.isnot(None),
            models.BorrowRequest.return_by < now,
        )
        .scalar()
        or 0
    )


def get_overdue_limit(user: models.User) -> int:
    """Geef de maximale toegestane verlopen leningen voor deze gebruiker."""
    return user.max_overdue_allowed if user.max_overdue_allowed is not None else SYSTEM_OVERDUE_LIMIT


def extend_all_overdue_for_user(db: Session, user_id: int, extra_days: int) -> int:
    """Verleng alle verlopen leningen van user_id met extra_days dagen."""
    from datetime import timedelta
    now = datetime.utcnow()
    overdue = (
        db.query(models.BorrowRequest)
        .filter(
            models.BorrowRequest.requester_id == user_id,
            models.BorrowRequest.status == "approved",
            models.BorrowRequest.return_by.isnot(None),
            models.BorrowRequest.return_by < now,
        )
        .all()
    )
    for br in overdue:
        br.return_by = (br.return_by or now) + timedelta(days=extra_days)
        br.overdue_notif_days = 0
    db.commit()
    return len(overdue)


def clear_all_overdue_for_user(db: Session, user_id: int) -> int:
    """Verwijder de terugbrengdatum van alle verlopen leningen van user_id (onbeperkt uitlenen)."""
    now = datetime.utcnow()
    overdue = (
        db.query(models.BorrowRequest)
        .filter(
            models.BorrowRequest.requester_id == user_id,
            models.BorrowRequest.status == "approved",
            models.BorrowRequest.return_by.isnot(None),
            models.BorrowRequest.return_by < now,
        )
        .all()
    )
    for br in overdue:
        br.return_by = None
        br.overdue_notif_days = 0
    db.commit()
    return len(overdue)


def get_blocked_borrowers_for_admin(db: Session, group_ids: list) -> list:
    """
    Vind alle gebruikers in de gegeven groepen die >= hun limiet verlopen leningen hebben.
    Geeft een lijst van dicts terug met user_id, user_name, overdue_count, limit.
    """
    user_ids_in_groups = (
        db.query(models.UserGroup.user_id)
        .filter(models.UserGroup.group_id.in_(group_ids))
        .distinct()
        .all()
    )
    result = []
    for (uid,) in user_ids_in_groups:
        user = db.query(models.User).filter(models.User.id == uid).first()
        if not user:
            continue
        limit = get_overdue_limit(user)
        overdue_count = count_overdue_borrows(db, uid)
        if overdue_count >= limit:
            result.append({
                "user_id": uid,
                "user_name": user.name,
                "overdue_count": overdue_count,
                "limit": limit,
            })
    return result


def count_global_pending_item_requests(db: Session) -> int:
    """
    Tel alle pending ItemRequest records (globaal).
    Gebruik deze alleen als je echt een globale teller wilt.
    """
    return (
        db.query(func.count(models.ItemRequest.id))
          .filter(models.ItemRequest.status == 'pending')
          .scalar()
        or 0
    )



# ------------- Mesaging logic --------------------

# -------------------- Messaging CRUD --------------------

def create_message(
    db: Session,
    sender_id: int,
    msg_in: schemas.MessageCreate
) -> Union[models.Message, List[models.Message]]:
    """
    If msg_in.recipient_id is None and msg_in.group_id is None and
    sender.role == "superuser", broadcast to all users.
    Else if msg_in.group_id is set, broadcast to that group.
    Otherwise send a 1:1 message.
    """
    # load sender record
    sender = db.query(models.User).get(sender_id)

    # 1) superuser → everyone
    if msg_in.recipient_id is None and msg_in.group_id is None and sender.role == "superuser":
        all_ids = [u.id for u in db.query(models.User.id).all()]
        objs = [
            models.Message(
                sender_id=sender_id,
                recipient_id=uid,
                content=msg_in.content,
                group_broadcast=True
            )
            for uid in all_ids
        ]
        db.bulk_save_objects(objs)
        db.commit()
        return objs

    # 2) group broadcast
    if msg_in.group_id is not None:
        member_ids = [
            ug.user_id
            for ug in db.query(models.UserGroup)
                        .filter(models.UserGroup.group_id == msg_in.group_id)
                        .all()
        ]
        objs = [
            models.Message(
                sender_id=sender_id,
                recipient_id=uid,
                content=msg_in.content,
                group_broadcast=True
            )
            for uid in member_ids
        ]
        db.bulk_save_objects(objs)
        db.commit()
        return objs

    # 3) direct 1:1
    obj = models.Message(
        sender_id=sender_id,
        recipient_id=msg_in.recipient_id,
        content=msg_in.content,
        group_broadcast=False
    )
    db.add(obj)
    db.commit()
    db.refresh(obj)

    try:
        import push
        if isinstance(obj, models.Message) and obj.recipient_id:
            sender_name = sender.name if sender else "Iemand"
            push.notify_user(
                db, obj.recipient_id,
                title=f"Nieuw bericht van {sender_name}",
                body=obj.content[:120],
                data={"type": "message", "peer_id": obj.sender_id},
                category="message"
            )
        elif isinstance(objs, list):  # broadcasts
            sender_name = sender.name if sender else "Beheerder"
            for o in objs:
                push.notify_user(
                    db, o.recipient_id,
                    title=f"Bericht van {sender_name}",
                    body=o.content[:120],
                    data={"type": "message", "peer_id": sender_id},
                    category="message"
                )
    except Exception:
        pass


    return obj

def count_unread_messages(db: Session, user_id: int) -> int:
    """
    Return how many unread messages this user has.
    """
    return (
        db.query(func.count(models.Message.id))
          .filter(
              models.Message.recipient_id == user_id,
              models.Message.read_at == None
          )
          .scalar()
        or 0
    )


def list_inbox(db: Session, user_id: int) -> list[dict]:
    Sender = aliased(models.User)

    subq = (
        db.query(
            models.Message.sender_id.label("peer_id"),
            func.max(models.Message.created_at).label("latest_at")
        )
        .filter(models.Message.recipient_id == user_id)
        .group_by(models.Message.sender_id)
        .subquery()
    )

    rows = (
        db.query(
            subq.c.peer_id,
            Sender.name.label("peer_name"),
            models.Message.content.label("latest_message"),
            subq.c.latest_at,


            # ...
            func.sum(
                case(
                    (
                        (models.Message.recipient_id == user_id) &
                        (models.Message.read_at == None) &
                        (models.Message.sender_id == subq.c.peer_id),
                        1
                    ),
                    else_=0
                )
            ).label("unread_count")

        )
        .join(
            models.Message,
            and_(
                models.Message.sender_id == subq.c.peer_id,
                models.Message.created_at == subq.c.latest_at
            )
        )
        .join(Sender, Sender.id == subq.c.peer_id)
        .group_by(
            subq.c.peer_id,
            Sender.name,
            models.Message.content,
            subq.c.latest_at
        )
        .order_by(subq.c.latest_at.desc())
        .all()
    )

    return [
        {
            "peer_id":        peer_id,
            "peer_name":      peer_name,
            "latest_message": latest_message,
            "latest_at":      latest_at,
            "unread_count":   unread_count,
        }
        for peer_id, peer_name, latest_message, latest_at, unread_count in rows
    ]

def get_conversation(db: Session, user1: int, user2: int) -> List[models.Message]:
    """
    Fetch the full two‐way thread between user1 and user2, ordered by time.
    """
    return (
        db.query(models.Message)
          .filter(
              or_(
                  and_(
                    models.Message.sender_id == user1,
                    models.Message.recipient_id == user2
                  ),
                  and_(
                    models.Message.sender_id == user2,
                    models.Message.recipient_id == user1
                  )
              )
          )
          .order_by(models.Message.created_at)
          .all()
    )


def get_message(db: Session, msg_id: int) -> models.Message:
    """
    Fetch a single message by its primary key.
    """
    return db.query(models.Message).get(msg_id)


def mark_message_read(db: Session, msg_id: int, user_id: int) -> models.Message:
    """
    Mark one message as read, if the authenticated user is the recipient.
    """
    msg = db.query(models.Message).get(msg_id)
    if msg and msg.recipient_id == user_id and msg.read_at is None:
        msg.read_at = datetime.utcnow()
        db.commit()
        db.refresh(msg)
    return msg


def delete_message(db: Session, msg_id: int, user_id: int) -> bool:
    """
    Delete a message if the user is either the sender or the recipient.
    Returns True if deleted, False otherwise.
    """
    msg = db.query(models.Message).get(msg_id)
    if not msg or user_id not in (msg.sender_id, msg.recipient_id):
        return False
    db.delete(msg)
    db.commit()
    return True




def register_device_token(db: Session, user_id: int, token: str, platform: str | None = None):
    tok = db.query(models.DeviceToken).filter(models.DeviceToken.token == token).first()
    if tok:
        tok.user_id = user_id
        tok.platform = platform or tok.platform
        tok.is_active = True
        tok.last_seen = datetime.utcnow()
    else:
        tok = models.DeviceToken(user_id=user_id, token=token, platform=platform or "android")
        db.add(tok)
    db.commit()
    db.refresh(tok)
    return tok

def unregister_device_token(db: Session, token: str, user_id: int | None = None) -> bool:
    q = db.query(models.DeviceToken).filter(models.DeviceToken.token == token)
    if user_id:
        q = q.filter(models.DeviceToken.user_id == user_id)
    tok = q.first()
    if not tok:
        return False
    db.delete(tok)
    db.commit()
    return True

def list_active_tokens(db: Session, user_id: int) -> list[str]:
    return [
        t.token
        for t in db.query(models.DeviceToken)
                   .filter(models.DeviceToken.user_id == user_id,
                           models.DeviceToken.is_active == True)
                   .all()
    ]

def add_push_token(db: Session, user_id: int, token: str, platform: str = "android"):
    existing = db.query(models.DeviceToken).filter(models.DeviceToken.token == token).first()
    if existing:
        existing.user_id = user_id
        existing.platform = platform or existing.platform
        existing.is_active = True
        existing.last_seen = datetime.utcnow()
    else:
        db.add(models.DeviceToken(user_id=user_id, token=token, platform=platform))
    db.commit()

def remove_push_token(db: Session, user_id: int, token: str) -> bool:
    pt = (
        db.query(models.DeviceToken)
          .filter(models.DeviceToken.user_id == user_id,
                  models.DeviceToken.token == token)
          .first()
    )
    if not pt:
        return False
    db.delete(pt)
    db.commit()
    return True

def list_push_tokens_for_user(db: Session, user_id: int) -> list[str]:
    return [t.token for t in db.query(models.DeviceToken).filter_by(user_id=user_id, is_active=True).all()]


# ─── Feature 7: PIN-reset ─────────────────────────────────

def create_pin_reset_token(db: Session, email: str) -> Optional[tuple]:
    """
    Zoek de gebruiker op email, genereer een reset-token, sla op en geef
    (user, token) terug. Geeft None terug als email niet bestaat.
    """
    from datetime import timedelta
    user = get_user_by_email(db, email)
    if not user:
        return None
    token = generate_invite_code(8)   # 8-tekens alfanumeriek
    user.reset_token = token
    user.reset_token_expires = datetime.utcnow() + timedelta(minutes=30)
    db.commit()
    db.refresh(user)
    return user, token


def reset_pin_with_token(db: Session, token: str, new_pin: str) -> Optional[User]:
    """
    Valideer het token, stel de nieuwe PIN in en wis het token.
    Geeft None terug bij ongeldig/verlopen token.
    """
    user = (
        db.query(User)
          .filter(User.reset_token == token)
          .first()
    )
    if not user:
        return None
    if user.reset_token_expires is None or datetime.utcnow() > user.reset_token_expires:
        return None  # token verlopen
    user.pin_code = pwd_context.hash(new_pin)
    user.reset_token = None
    user.reset_token_expires = None
    db.commit()
    db.refresh(user)
    return user
