from sqlalchemy import (
    Table, Column, Integer, String, Boolean, ForeignKey, Float,
    DateTime, Enum
)
from sqlalchemy.orm import relationship
from sqlalchemy.ext.hybrid import hybrid_property
from database import Base
from datetime import datetime


# ─────────────────── Device Tokens ───────────────────

class DeviceToken(Base):
    __tablename__ = "device_tokens"

    id         = Column(Integer, primary_key=True, index=True)
    user_id    = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    token      = Column(String(255), unique=True, nullable=False, index=True)
    platform   = Column(String(20))                  # 'android' | 'ios' | 'web'
    is_active  = Column(Boolean, default=True)
    last_seen  = Column(DateTime, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="device_tokens")


# ─────────────── Association: user ↔ group (with role) ───────────────

class UserGroup(Base):
    __tablename__ = "user_groups"
    user_id  = Column(Integer, ForeignKey("users.id"), primary_key=True)
    group_id = Column(Integer, ForeignKey("groups.id"), primary_key=True)
    role     = Column(Enum("user", "admin", "superuser", name="role_enum"), nullable=False)

    user  = relationship("User", back_populates="memberships")
    group = relationship("Group", back_populates="memberships")


# ─────────────────────────── User ───────────────────────────

class User(Base):
    __tablename__ = "users"

    id                  = Column(Integer, primary_key=True, index=True)
    name                = Column(String, nullable=False)
    email               = Column(String, unique=True, index=True, nullable=False)
    phone_number        = Column(String, nullable=True)
    address             = Column(String, nullable=True)
    pin_code            = Column(String, nullable=False)
    is_admin            = Column(Boolean, default=False)
    is_approved         = Column(Boolean, default=False)
    invited_by          = Column(Integer, ForeignKey("users.id"), nullable=True)
    invite_code         = Column(String(6), unique=True, nullable=True)
    role                = Column(String, default="user")  # Global role
    reset_token          = Column(String, nullable=True)         # Feature 7: vergeten PIN
    reset_token_expires  = Column(DateTime, nullable=True)       # Feature 7: vergeten PIN
    max_overdue_allowed  = Column(Integer, nullable=True)        # null = systeem default (5)

    # Relationships
    items = relationship(
        "Item",
        foreign_keys="[Item.owner_id]",
        back_populates="owner",
    )
    borrowed_items = relationship(
        "Item",
        foreign_keys="[Item.lender_id]",
        back_populates="lender",
    )
    outgoing_requests = relationship(
        "BorrowRequest",
        back_populates="requester",
        cascade="all, delete-orphan",
    )
    inviter = relationship("User", remote_side=[id], backref="invited_users")

    memberships = relationship("UserGroup", back_populates="user")

    # ✅ FIX: define on the User side so back_populates matches DeviceToken.user
    device_tokens = relationship(
        "DeviceToken",
        back_populates="user",
        cascade="all, delete-orphan"
    )

    @property
    def group_id(self):
        """
        Legacy single-group compatibility: returns the first group ID if any,
        else None.
        """
        return self.memberships[0].group_id if self.memberships else None


# ─────────────── Association: item ↔ group (availability) ───────────────

item_group = Table(
    "item_group",
    Base.metadata,
    Column("item_id", Integer, ForeignKey("items.id"), primary_key=True),
    Column("group_id", Integer, ForeignKey("groups.id"), primary_key=True),
)


# ─────────────────────────── Item ───────────────────────────

class Item(Base):
    __tablename__ = "items"

    id         = Column(Integer, primary_key=True, index=True)
    name       = Column(String, index=True)
    info       = Column(String, nullable=True)
    image_path = Column(String, nullable=True)
    leenkosten = Column(Float, nullable=True)
    category        = Column(String, nullable=True)   # Feature 5: categorie
    condition       = Column(String, nullable=True)   # Feature 5: toestand
    max_borrow_days = Column(Integer, nullable=True)  # max aantal dagen uitlenen

    owner_id   = Column(Integer, ForeignKey("users.id"))
    lender_id  = Column(Integer, ForeignKey("users.id"), nullable=True)
    status     = Column(
        Enum("free", "reserved", "loaned", "expired", name="item_status"),
        default="free", nullable=False
    )
    reserved_at = Column(DateTime, nullable=True)
    listed_at   = Column(DateTime, nullable=True)   # when gratis item was listed (voor expiry)

    owner = relationship(
        "User",
        foreign_keys=[owner_id],
        back_populates="items"
    )
    lender = relationship(
        "User",
        foreign_keys=[lender_id],
        back_populates="borrowed_items"
    )
    requests = relationship(
        "BorrowRequest",
        back_populates="item",
        cascade="all, delete-orphan"
    )

    # Many-to-many for group availability
    available_groups = relationship(
        "Group",
        secondary=item_group,
        back_populates="available_items",
    )

    @hybrid_property
    def group_id(self):
        """
        Expose owner's primary group directly on Item
        so Pydantic can serialize group_id.
        """
        return self.owner.group_id if self.owner else None

    @property
    def available_group_ids(self) -> list[int]:
        """
        All the group-IDs that the *owner* of this item belongs to.
        Pydantic will pick this up when serializing an ItemOut.
        """
        if self.owner is None:
            return []
        return [ug.group_id for ug in self.owner.memberships]


# ───────────────────── Borrow Requests ─────────────────────

class BorrowRequest(Base):
    __tablename__ = "borrow_requests"

    id           = Column(Integer, primary_key=True, index=True)
    item_id      = Column(Integer, ForeignKey("items.id"), nullable=True)
    requester_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    group_id     = Column(Integer, ForeignKey("groups.id"), nullable=False)
    status       = Column(
        Enum("pending", "approved", "denied", "return_requested", "returned", name="request_status"),
        default="pending",
    )

    created_at    = Column(DateTime, default=datetime.utcnow)
    message       = Column(String, nullable=True)
    pick_up_by    = Column(DateTime, nullable=True)
    duration_days = Column(Integer, nullable=True)
    return_by          = Column(DateTime, nullable=True)       # Feature 1: terugbrengdatum
    overdue_notif_days = Column(Integer, default=0, nullable=True) # hoeveel "X dagen te laat" notifs al verstuurd
    has_damage         = Column(Boolean, default=False, nullable=True)  # Feature 6: schademelding
    damage_note   = Column(String, nullable=True)         # Feature 6: schademelding

    item      = relationship("Item", back_populates="requests")
    requester = relationship("User", back_populates="outgoing_requests")


# ─────────────────────────── Group ───────────────────────────

class Group(Base):
    __tablename__ = "groups"

    id              = Column(Integer, primary_key=True, index=True)
    name            = Column(String, unique=True, nullable=False)
    status          = Column(String, default="pending")
    aangemaakt_door = Column(Integer, ForeignKey("users.id"), nullable=True)
    invite_code     = Column(String(8), unique=True, nullable=True)  # Feature 3: groepscode

    memberships = relationship("UserGroup", back_populates="group")
    members = relationship(
        "User",
        secondary="user_groups",
        primaryjoin="Group.id == UserGroup.group_id",
        secondaryjoin="User.id == UserGroup.user_id",
        viewonly=True
    )

    # back-populates for the Item.available_groups relationship
    available_items = relationship(
        "Item",
        secondary=item_group,
        back_populates="available_groups",
    )

    @property
    def admins(self):
        return [ug.user for ug in self.memberships if ug.role == "admin"]

    creator = relationship("User", foreign_keys=[aangemaakt_door])


# ─────────────────────────── Session ───────────────────────────

class Sessie(Base):
    __tablename__ = "sessies"

    id           = Column(Integer, primary_key=True, index=True)
    gebruiker_id = Column(Integer, ForeignKey("users.id"))
    session_id   = Column(String, unique=True, nullable=False)
    aangemaakt_op = Column(DateTime, default=datetime.utcnow)

    gebruiker = relationship("User")


# ─────────────────────────── Item Request ───────────────────────────

class ItemRequest(Base):
    __tablename__ = "item_requests"

    id          = Column(Integer, primary_key=True, index=True)
    requester_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    item_id     = Column(Integer, ForeignKey("items.id"), nullable=True)
    term        = Column(String, nullable=False)
    comment     = Column(String, nullable=True)
    created_at  = Column(DateTime, default=datetime.utcnow)
    status      = Column(Enum("pending", "accepted", "denied", name="itemreq_status"), default="pending")
    pick_up_by   = Column(DateTime, nullable=True)
    contact_info = Column(String, nullable=True)
    reason       = Column(String, nullable=True)

    requester = relationship("User")
    item      = relationship("Item")


# ─────────────────────────── Messaging ───────────────────────────

class Message(Base):
    __tablename__ = "messages"

    id              = Column(Integer, primary_key=True, index=True)
    sender_id       = Column(Integer, ForeignKey("users.id"), nullable=False)
    recipient_id    = Column(Integer, ForeignKey("users.id"), nullable=True)
    group_broadcast = Column(Boolean, default=False, nullable=False)
    content         = Column(String, nullable=False)
    created_at      = Column(DateTime, default=datetime.utcnow, nullable=False)
    read_at         = Column(DateTime, nullable=True)

    sender    = relationship("User", foreign_keys=[sender_id], backref="sent_messages")
    recipient = relationship("User", foreign_keys=[recipient_id], backref="received_messages")


# ───────────────────── Notifications ─────────────────────

class Notification(Base):
    __tablename__ = "notifications"

    id        = Column(Integer, primary_key=True, index=True)
    user_id   = Column(Integer, ForeignKey("users.id"), nullable=False)
    type      = Column(String, nullable=False)   # e.g. "group_removal"
    payload   = Column(String, nullable=True)    # optional JSON string
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    read_at    = Column(DateTime, nullable=True)

    user = relationship("User", backref="notifications")


# ───────────────────── User Preferences ─────────────────────

class UserPreferences(Base):
    __tablename__ = "user_preferences"

    user_id = Column(Integer, ForeignKey("users.id"), primary_key=True)

    # notifications
    notif_messages     = Column(Boolean, nullable=False, default=True)
    notif_borrow       = Column(Boolean, nullable=False, default=True)
    notif_join_requests = Column(Boolean, nullable=False, default=True)

    # privacy
    priv_show_email = Column(Boolean, nullable=False, default=True)
    priv_show_phone = Column(Boolean, nullable=False, default=True)

    # ui
    ui_theme    = Column(String, nullable=False, default="system")  # system|light|dark
    ui_language = Column(String, nullable=False, default="nl")      # nl|en

    user = relationship("User", backref="user_prefs", uselist=False)
