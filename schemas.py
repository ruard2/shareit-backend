from pydantic import BaseModel, EmailStr, ConfigDict
from typing import Optional, List
from datetime import datetime

# -------------------- Gebruiker --------------------

class UserBase(BaseModel):
    name: str
    email: EmailStr
    phone_number: Optional[str] = None
    address: Optional[str] = None

class UserCreate(UserBase):
    pin_code: str
    invited_by: Optional[int] = None
    invite_code: Optional[str] = None
    group_id: Optional[int] = None
    role: Optional[str] = "user"
    group_code: Optional[str] = None

class UserOut(UserBase):
    id: int
    # email mag verborgen worden o.b.v. privacy → Optional
    email: Optional[EmailStr] = None
    is_admin: bool
    is_approved: bool
    group_id: Optional[int]
    invited_by: Optional[int] = None
    role: str
    admin_of_groups: Optional[List[int]] = []
    # optioneel telefoonnummer in responses
    phone_number: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)

class UserLogin(BaseModel):
    email: EmailStr
    pin_code: str

class Membership(BaseModel):
    group_id: int
    name: str
    info: Optional[str] = None
    role: str

class UserResponse(BaseModel):
    id: int
    name: str
    email: Optional[EmailStr] = None
    phone: Optional[str] = None          # <-- optioneel toegevoegd
    is_admin: bool
    is_approved: bool
    role: str
    group_id: Optional[int]
    invited_by: Optional[int]
    admin_of_groups: List[int]
    memberships: List[Membership]

    model_config = ConfigDict(from_attributes=True)

# -------------------- Item --------------------

class ItemBase(BaseModel):
    name: str
    info: Optional[str] = None
    image_path: Optional[str] = None
    leenkosten: Optional[float] = None
    category: Optional[str] = None        # Feature 5
    condition: Optional[str] = None       # Feature 5
    max_borrow_days: Optional[int] = None # max uitleentermijn in dagen

class ItemCreate(ItemBase):
    owner_id: Optional[int] = None   # server overschrijft altijd met authenticated user
    available_group_ids: List[int] = []
    status: Optional[str] = None
    lender_id: Optional[int] = None
    reserved_at: Optional[datetime] = None


class ItemOut(ItemBase):
    id: int
    owner_id: int
    group_id: int
    status: str
    lender_id: Optional[int] = None
    reserved_at: Optional[datetime] = None
    listed_at: Optional[datetime] = None   # gratis-item expiry
    owner_name: Optional[str] = None   # Feature 2: naam eigenaar
    lender_name: Optional[str] = None  # Feature 2: naam lener

    max_borrow_days: Optional[int] = None
    available_group_ids: List[int]

    model_config = ConfigDict(from_attributes=True)


# -------------------- BorrowRequest --------------------

class BorrowRequestBase(BaseModel):
    message: Optional[str] = None
    pick_up_by: Optional[datetime] = None
    duration_days: Optional[int] = None
    return_by: Optional[datetime] = None  # Feature 1: terugbrengdatum

class BorrowRequestCreate(BorrowRequestBase):
    item_id: int
    requester_id: int
    group_id: int

class BorrowRequestOut(BaseModel):
    id: int
    item_id: Optional[int]
    requester_id: Optional[int]
    group_id: int
    status: str
    created_at: datetime
    message: Optional[str]
    pick_up_by: Optional[datetime]
    duration_days: Optional[int]
    return_by: Optional[datetime] = None      # Feature 1
    has_damage: Optional[bool] = None         # Feature 6
    damage_note: Optional[str] = None         # Feature 6
    item_name: Optional[str] = None           # Feature 4: naam item
    requester_name: Optional[str] = None      # Feature 4: naam aanvrager

    model_config = ConfigDict(from_attributes=True)


# -------------------- Groep --------------------

class GroupBase(BaseModel):
    name: str

class GroupCreate(GroupBase):
    aangemaakt_door: Optional[int] = None
    status: Optional[str] = "pending"

class GroupOut(GroupBase):
    id: int
    status: Optional[str]
    aangemaakt_door: Optional[int]
    admins: List[int] = []
    invite_code: Optional[str] = None  # Feature 3

    model_config = ConfigDict(from_attributes=True)

class GroupOutFull(GroupBase):
    id: int
    status: str
    aangemaakt_door: Optional[int]
    admins: List[int] = []
    invite_code: Optional[str] = None  # Feature 3

    model_config = ConfigDict(from_attributes=True)


#Item request

class ItemRequestBase(BaseModel):
    term: str
    comment: Optional[str] = None
    item_id: Optional[int] = None

class ItemRequestCreate(ItemRequestBase):
    pass

class ItemRequestOut(ItemRequestBase):
    id: int
    requester_id: int
    created_at: datetime
    status: str
    pick_up_by: Optional[datetime] = None
    contact_info: Optional[str] = None
    reason: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


# ─── Message Schemas ─────────────────────────────────────────────────

class InboxEntry(BaseModel):
    peer_id: int
    peer_name: str    
    latest_message: str
    latest_at: datetime
    unread_count: int

    model_config = ConfigDict(from_attributes=True)

class MessageBase(BaseModel):
    content: str

class MessageCreate(MessageBase):
    recipient_id: Optional[int] = None
    group_id:     Optional[int] = None
    # (superuser can omit both to broadcast to all)

class MessageOut(MessageBase):
    id: int
    sender_id:       int
    recipient_id:    Optional[int]
    group_broadcast: bool
    created_at:      datetime
    read_at:         Optional[datetime]

    model_config = ConfigDict(from_attributes=True)


# ─── Notifications ───────────────────────────────────────

class NotificationCreate(BaseModel):
    type: str
    payload: Optional[str] = None

class NotificationOut(BaseModel):
    id: int
    user_id: int
    type: str
    payload: Optional[str]
    created_at: datetime
    read_at: Optional[datetime]

    model_config = ConfigDict(from_attributes=True)


# -------------------- Preferences --------------------

class PreferencesNotifications(BaseModel):
    messages: bool = True
    borrow: bool = True
    join_requests: bool = True

class PreferencesPrivacy(BaseModel):
    show_email: bool = False
    show_phone: bool = False

class PreferencesUI(BaseModel):
    theme: str = "system"
    language: str = "nl"

class PreferencesProfile(BaseModel):
    name: str | None = None
    email: EmailStr | None = None
    phone: str | None = None

class PreferencesIn(BaseModel):
    notifications: PreferencesNotifications
    privacy: PreferencesPrivacy
    ui: PreferencesUI
    profile: PreferencesProfile | None = None

class PreferencesOut(BaseModel):
    notifications: PreferencesNotifications
    privacy: PreferencesPrivacy
    ui: PreferencesUI
    profile: PreferencesProfile

    model_config = ConfigDict(from_attributes=True)


# ─── PIN Reset (Feature 7) ─────────────────────────────────
class ForgotPinRequest(BaseModel):
    email: EmailStr

class ResetPinRequest(BaseModel):
    token: str
    new_pin: str
