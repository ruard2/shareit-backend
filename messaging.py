from fastapi import APIRouter, Depends, HTTPException, Body
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from typing import List, Union
from datetime import datetime

import models, crud, schemas
from database import get_db
from auth import get_current_user_token

router = APIRouter(prefix="/messages", tags=["messages"])

@router.post("/", response_model=schemas.MessageOut)
@router.post("/send", response_model=schemas.MessageOut)
def send_message(
    payload: schemas.MessageCreate = Body(...),
    db: Session = Depends(get_db),
    me: models.User = Depends(get_current_user_token),
):
    """
    Send a single message (direct or broadcast).
    POST /messages and POST /messages/send
    """
    result = crud.create_message(db, me.id, payload)
    # Broadcast returns a list; return a minimal JSON rather than failing schema validation
    if isinstance(result, list):
        return JSONResponse(
            status_code=200,
            content={"detail": "verzonden", "count": len(result)},
        )
    return result


@router.get("/count", response_model=int)
def unread_count(
    db: Session = Depends(get_db),
    me: models.User = Depends(get_current_user_token)
):
    """
    Count unread messages (direct + any group broadcasts not yet read) for me.
    """
    return crud.count_unread_messages(db, user_id=me.id)


@router.get("/inbox", response_model=List[schemas.InboxEntry])
def inbox(
    db: Session = Depends(get_db),
    me: models.User = Depends(get_current_user_token)
):
    return crud.list_inbox(db, me.id)

@router.get("/conversation/{other_id}", response_model=List[schemas.MessageOut])
def get_conversation_with(
    other_id: int,
    db: Session = Depends(get_db),
    me: models.User = Depends(get_current_user_token)
):
    """
    Two‐way conversation with another user; any unread messages from them get marked read.
    """
    conv = crud.get_conversation(db, me.id, other_id)
    for m in conv:
        if m.recipient_id == me.id and m.read_at is None:
            crud.mark_message_read(db, m.id, user_id=me.id)
    return conv

@router.get("/{id}", response_model=schemas.MessageOut)
def fetch_message(
    id: int,
    db: Session = Depends(get_db),
    me: models.User = Depends(get_current_user_token)
):
    """
    Fetch one message by ID, only if I'm sender or recipient.
    """
    msg = crud.get_message(db, id)
    if not msg or (me.id not in {msg.sender_id, msg.recipient_id}):
        raise HTTPException(404)
    return msg

@router.delete("/conversation/{peer_id}")
def delete_conversation_endpoint(
    peer_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user_token),
):
    deleted = crud.delete_conversation(db, current_user.id, peer_id)
    # Niet "404" gooien als er niets te verwijderen is; gewoon netjes antwoorden:
    return {"deleted": deleted}


@router.put("/{id}/read", response_model=schemas.MessageOut)
def read_message(
    id: int,
    db: Session = Depends(get_db),
    me: models.User = Depends(get_current_user_token)
):
    """
    Explicitly mark *this* message as read (even if it's a broadcast).
    """
    msg = crud.mark_message_read(db, id, user_id=me.id)
    if not msg:
        raise HTTPException(404)
    return msg

@router.delete("/{id}", status_code=204)
def remove_message(
    id: int,
    db: Session = Depends(get_db),
    me: models.User = Depends(get_current_user_token)
):
    """
    Delete a message (if I'm sender or recipient).
    """
    success = crud.delete_message(db, id, user_id=me.id)
    if not success:
        raise HTTPException(404)
    return None
