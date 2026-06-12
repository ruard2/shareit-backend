# push.py
import os
from typing import Optional
from sqlalchemy.orm import Session

import crud
import models

# Optional Firebase import – keep the app running even if missing
_fire_ok = False
try:
    import firebase_admin
    from firebase_admin import credentials, messaging
    _fire_ok = True
except Exception:
    _fire_ok = False

_app_inited = False

def _ensure_firebase():
    global _app_inited
    if not _fire_ok or _app_inited:
        return _fire_ok and _app_inited
    path = os.getenv("FIREBASE_CREDENTIALS")  # path to service-account JSON
    if not path or not os.path.exists(path):
        return False
    cred = credentials.Certificate(path)
    firebase_admin.initialize_app(cred)
    _app_inited = True
    return True

def _allowed_by_prefs(db: Session, user_id: int, category: Optional[str]) -> bool:
    # category: "message" | "borrow" | "join" | None
    prefs = crud.get_user_prefs(db, user_id)
    if not prefs:
        return True  # default on if no prefs set
    if category == "message":
        return bool(prefs.notif_messages)
    if category == "borrow":
        return bool(prefs.notif_borrow)
    if category == "join":
        return bool(prefs.notif_join_requests)
    return True

def notify_user(db: Session, user_id: int, title: str, body: str,
                data: dict | None = None, category: str | None = None):
    if not _ensure_firebase():
        return
    if not _allowed_by_prefs(db, user_id, category):
        return

    tokens = crud.list_active_tokens(db, user_id)
    if not tokens:
        return

    msg = messaging.MulticastMessage(
        notification=messaging.Notification(title=title, body=body),
        data={**{k: str(v) for k, v in (data or {}).items()},
              "category": category or ""},
        tokens=tokens,
    )
    resp = messaging.send_multicast(msg)

    # prune invalid tokens
    bad = []
    for i, r in enumerate(resp.responses):
        if not r.success:
            code = getattr(r.exception, "code", "")
            if code in ("messaging/registration-token-not-registered",
                        "messaging/invalid-registration-token"):
                bad.append(tokens[i])
    for t in bad:
        try:
            crud.unregister_device_token(db, t, user_id)
        except Exception:
            pass
