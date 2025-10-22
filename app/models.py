# app/models.py

from datetime import datetime, date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from app import db
from itsdangerous import URLSafeTimedSerializer as Serializer
from flask import current_app
# --- CORRECTED IMPORT ---
from sqlalchemy.orm import foreign, reconstructor
from sqlalchemy import and_, or_, CheckConstraint # Import CheckConstraint here

# ---------- USERS ----------
class User(UserMixin, db.Model):
    __tablename__ = "users"
    user_id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(255), nullable=False)
    last_name = db.Column(db.String(255))
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    phone = db.Column(db.String(50))
    location = db.Column(db.String(255))
    profile_picture = db.Column(db.String(255), nullable=True)
    status = db.Column(db.String(50), default="Active")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    fcm_token = db.Column(db.String(255), nullable=True)
    otp = db.Column(db.String(6), nullable=True)
    otp_expiry = db.Column(db.DateTime, nullable=True)
    is_verified = db.Column(db.Boolean, default=False)
    latitude = db.Column(db.Float, nullable=True)
    longitude = db.Column(db.Float, nullable=True)
    search_radius = db.Column(db.Integer, default=20)

    items = db.relationship("Item", backref="owner", lazy="dynamic")
    bookmarks = db.relationship("Bookmark", backref="user", lazy="dynamic")
    # Corrected relationships using backref names defined in ChatSession
    initiated_chats = db.relationship("ChatSession", foreign_keys="ChatSession.user_one_id", lazy="dynamic", back_populates="user_one")
    received_chats = db.relationship("ChatSession", foreign_keys="ChatSession.user_two_id", lazy="dynamic", back_populates="user_two")
    feedbacks = db.relationship("Feedback", backref="user", lazy="dynamic")
    reports = db.relationship("Report", backref="reporter", lazy="dynamic")
    category_follows = db.relationship("CategoryFollow", backref="user", lazy="dynamic")
    notifications = db.relationship("Notification", backref="user", lazy="dynamic")
    login_logs = db.relationship("LoginLog", backref="user", lazy="dynamic")
    trade_requests_made = db.relationship('TradeRequest', foreign_keys='TradeRequest.requester_id', backref='requester', lazy='dynamic')
    trade_requests_received = db.relationship('TradeRequest', foreign_keys='TradeRequest.owner_id', backref='owner', lazy='dynamic')
    donation_offers = db.relationship('DonationOffer', backref='user', lazy='dynamic')


    def set_password(self, raw_password):
        self.password = generate_password_hash(raw_password)

    def check_password(self, raw_password):
        return check_password_hash(self.password, raw_password)

    def get_id(self):
        return f"user:{self.user_id}"

    def get_reset_token(self, expires_sec=1800):
        s = Serializer(current_app.config['SECRET_KEY'])
        return s.dumps({'user_id': self.user_id})

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token, max_age=1800)['user_id']
        except:
            return None
        return User.query.get(user_id)


# ---------- ADMINS ----------
class Admin(UserMixin, db.Model):
    __tablename__ = "admins"
    admin_id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(255))
    last_name = db.Column(db.String(255))
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(50), default="Active")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, raw_password):
        self.password = generate_password_hash(raw_password)

    def check_password(self, raw_password):
        return check_password_hash(self.password, raw_password)

    def get_id(self):
        return f"admin:{self.admin_id}"


# ---------- ORGANIZATIONS ----------
class Organization(UserMixin, db.Model):
    __tablename__ = "organizations"
    org_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    phone = db.Column(db.String(100))
    location = db.Column(db.String(255))
    profile_picture = db.Column(db.String(255), nullable=True)
    status = db.Column(db.String(50), default="Pending")
    registered_at = db.Column(db.DateTime, default=datetime.utcnow)
    description = db.Column(db.Text, nullable=True)

    otp = db.Column(db.String(6), nullable=True)
    otp_expiry = db.Column(db.DateTime, nullable=True)
    is_verified = db.Column(db.Boolean, default=False)

    disaster_needs = db.relationship("DisasterNeed", backref="organization", lazy="dynamic")
    donation_offers = db.relationship('DonationOffer', backref='organization', lazy='dynamic') # Offers received
    chat_sessions = db.relationship("ChatSession", foreign_keys="ChatSession.participant_org_id", lazy="dynamic", back_populates="participant_org")
    bookmarks = db.relationship("Bookmark", foreign_keys="Bookmark.org_id", lazy="dynamic", cascade="all, delete-orphan")

    def set_password(self, raw_password):
        self.password = generate_password_hash(raw_password)

    def check_password(self, raw_password):
        return check_password_hash(self.password, raw_password)

    def get_id(self):
        return f"org:{self.org_id}"

    def get_reset_token(self, expires_sec=1800):
        s = Serializer(current_app.config['SECRET_KEY'])
        return s.dumps({'org_id': self.org_id})

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            org_id = s.loads(token, max_age=1800)['org_id']
        except:
            return None
        return Organization.query.get(org_id)

# ---------- LOGIN LOG ----------
class LoginLog(db.Model):
    __tablename__ = "login_logs"
    log_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.user_id"), nullable=False)
    login_time = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(100))
    # user relationship defined via backref


# ---------- ITEMS ----------
class Item(db.Model):
    __tablename__ = "items"
    item_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.user_id"), nullable=False, index=True)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    category = db.Column(db.String(255), index=True)
    sub_category = db.Column(db.String(255), nullable=True, index=True)
    type = db.Column(db.String(50), index=True) # Trade or Share
    condition = db.Column(db.String(50))
    urgency_level = db.Column(db.String(50))
    expected_return_category = db.Column(db.String(255), nullable=True) # Category or 'Money' for Trade type
    expected_return_sub_category = db.Column(db.String(255), nullable=True)
    location = db.Column(db.String(255), index=True)
    status = db.Column(db.String(50), default="Active", index=True) # Active, Traded, Deleted, etc.
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    deal_finalized_at = db.Column(db.DateTime, nullable=True) # Time when deal was confirmed
    latitude = db.Column(db.Float, nullable=True)
    longitude = db.Column(db.Float, nullable=True)

    # owner relationship defined via backref
    histories = db.relationship("ItemHistory", backref="item", lazy="dynamic", cascade="all, delete-orphan")
    bookmarks = db.relationship("Bookmark", backref="item", lazy="dynamic", cascade="all, delete-orphan")
    reports = db.relationship("Report", backref="item", lazy="dynamic") # Keep reports even if item deleted? Check cascade
    images = db.relationship("ItemImage", backref="item", lazy="select", cascade="all, delete-orphan")
    notifications = db.relationship("Notification", backref="item", lazy="dynamic") # Notifications related to this item
    # Trade requests where this item is offered
    trade_requests_offered = db.relationship('TradeRequest', foreign_keys='TradeRequest.item_offered_id', backref='offered_item', lazy='dynamic')
    # Trade requests where this item is requested
    trade_requests_received = db.relationship('TradeRequest', foreign_keys='TradeRequest.item_requested_id', backref='requested_item', lazy='dynamic')
    # Relationship to ChatSession linked via trade_item_id
    chat_sessions = db.relationship("ChatSession", back_populates="trade_item", foreign_keys="ChatSession.trade_item_id")


class TradeRequest(db.Model):
    __tablename__ = 'trade_requests'
    id = db.Column(db.Integer, primary_key=True)
    item_offered_id = db.Column(db.Integer, db.ForeignKey('items.item_id'), nullable=True)
    item_requested_id = db.Column(db.Integer, db.ForeignKey('items.item_id'), nullable=False)
    requester_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False) # Owner of the requested_item
    status = db.Column(db.String(50), default='pending', index=True) # pending, accepted, rejected
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # relationships defined via backref


class DealProposal(db.Model):
    __tablename__ = "deal_proposals"
    id = db.Column(db.Integer, primary_key=True)
    chat_session_id = db.Column(db.Integer, db.ForeignKey("chat_sessions.session_id"), nullable=False, unique=True, index=True)

    proposer_status = db.Column(db.String(50), default='pending', nullable=False) # pending, confirmed, rejected
    owner_status = db.Column(db.String(50), default='pending', nullable=False) # pending, confirmed, rejected

    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationship with cascade rule
    session = db.relationship("ChatSession", backref=db.backref(
        "deal_proposal",
        uselist=False,
        cascade="all, delete-orphan" # Correctly added cascade
    ))


# ---------- ITEM IMAGES ----------
class ItemImage(db.Model):
    __tablename__ = "item_images"
    image_id = db.Column(db.Integer, primary_key=True)
    item_id = db.Column(db.Integer, db.ForeignKey("items.item_id"), nullable=False, index=True)
    image_url = db.Column(db.String(255), nullable=False) # Path relative to static folder
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    # item relationship defined via backref


# ---------- ITEM HISTORY ----------
class ItemHistory(db.Model):
    __tablename__ = "item_history"
    history_id = db.Column(db.Integer, primary_key=True)
    item_id = db.Column(db.Integer, db.ForeignKey("items.item_id"), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.user_id"), nullable=True) # User who performed action (if applicable)
    action = db.Column(db.String(255)) # e.g., "Created", "Edited", "Deleted", "Traded"
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    # item relationship defined via backref


# ---------- DISASTER NEEDS ----------
class DisasterNeed(db.Model):
    __tablename__ = "disaster_needs"
    need_id = db.Column(db.Integer, primary_key=True)
    org_id = db.Column(db.Integer, db.ForeignKey("organizations.org_id"), nullable=False, index=True)
    title = db.Column(db.String(255), nullable=True)
    categories = db.Column(db.Text, nullable=True) # Comma-separated string
    description = db.Column(db.Text, nullable=False)
    location = db.Column(db.String(255), index=True)
    posted_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    # organization relationship defined via backref
    # Relationship to DonationOffer
    donation_offers = db.relationship("DonationOffer", backref="need", lazy="dynamic")
    # Relationship to ChatSession linked via disaster_need_id
    chat_sessions = db.relationship("ChatSession", back_populates="disaster_need", foreign_keys="ChatSession.disaster_need_id")
    # ** Removed the incorrectly placed donation_offer relationship block **


# ---------- DISASTER DONATIONS ----------
class DonationOffer(db.Model):
    __tablename__ = 'donation_offers'
    offer_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False, index=True)
    need_id = db.Column(db.Integer, db.ForeignKey('disaster_needs.need_id'), nullable=False, index=True)
    org_id = db.Column(db.Integer, db.ForeignKey('organizations.org_id'), nullable=False, index=True)
    status = db.Column(db.String(50), default='Pending Review', index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    verified_at = db.Column(db.DateTime, nullable=True)
    picked_up_at = db.Column(db.DateTime, nullable=True)
    completed_at = db.Column(db.DateTime, nullable=True)
    pickup_retries = db.Column(db.Integer, default=0)
    proof_image_url = db.Column(db.String(255), nullable=True)

    # relationships defined via backref (user, organization, need)
    offered_items = db.relationship('OfferedItem', backref='offer', cascade="all, delete-orphan")

    # ** Correctly added relationship TO ChatSession with passive_deletes **
    chat_session = db.relationship(
    'ChatSession',
    back_populates='donation_offer',
    uselist=False,
    foreign_keys='ChatSession.donation_offer_id', # Reference the FK on ChatSession
    passive_deletes=True
    )

class OfferedItem(db.Model):
    __tablename__ = 'offered_items'
    offered_item_id = db.Column(db.Integer, primary_key=True)
    offer_id = db.Column(db.Integer, db.ForeignKey('donation_offers.offer_id'), nullable=False, index=True)
    title = db.Column(db.String(255), nullable=False)
    category = db.Column(db.String(255), nullable=True)
    description = db.Column(db.Text, nullable=True)
    quantity = db.Column(db.Integer, nullable=False, default=1)
    condition = db.Column(db.String(50))
    image_url = db.Column(db.String(255), nullable=True)
    manufacture_date = db.Column(db.Date, nullable=True)
    expiry_date = db.Column(db.Date, nullable=True, index=True)
    status = db.Column(db.String(50), default='Pending', index=True) # Pending, Accepted, Rejected
    # offer relationship defined via backref


# ---------- CHAT (MODIFIED) ----------
class ChatSession(db.Model):
    __tablename__ = "chat_sessions"
    session_id = db.Column(db.Integer, primary_key=True)

    # Subject of the chat (Only ONE should be non-NULL)
    trade_item_id = db.Column(db.Integer, db.ForeignKey("items.item_id"), nullable=True, index=True)
    disaster_need_id = db.Column(db.Integer, db.ForeignKey("disaster_needs.need_id"), nullable=True, index=True) # Kept for older chats

    # ** Corrected ForeignKey definition with ondelete **
    donation_offer_id = db.Column(db.Integer, db.ForeignKey('donation_offers.offer_id', ondelete='SET NULL'), nullable=True, unique=True, index=True)

    # Participants (Renamed for clarity)
    user_one_id = db.Column(db.Integer, db.ForeignKey("users.user_id"), nullable=False, index=True) # Always the User in User-Org chats
    user_two_id = db.Column(db.Integer, db.ForeignKey("users.user_id"), nullable=True, index=True) # Null for User-Org chats
    participant_org_id = db.Column(db.Integer, db.ForeignKey("organizations.org_id"), nullable=True, index=True) # Null for User-User chats

    status = db.Column(db.String(50), default="Active", index=True) # Active, Blocked, Confirmed (deal)
    started_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    messages = db.relationship("ChatMessage", backref="session", lazy="dynamic", cascade="all, delete-orphan")

    # Relationships to participants using back_populates
    user_one = db.relationship("User", foreign_keys=[user_one_id], back_populates="initiated_chats")
    user_two = db.relationship("User", foreign_keys=[user_two_id], back_populates="received_chats")
    participant_org = db.relationship("Organization", foreign_keys=[participant_org_id], back_populates="chat_sessions") # Use back_populates

    # Relationships to subject using back_populates
    trade_item = db.relationship("Item", back_populates="chat_sessions", foreign_keys=[trade_item_id])
    disaster_need = db.relationship("DisasterNeed", back_populates="chat_sessions", foreign_keys=[disaster_need_id])

    # ** Corrected relationship definition with back_populates and correct foreign_keys string **
    donation_offer = db.relationship(
    'DonationOffer',
    # Let SQLAlchemy infer join from ForeignKey and back_populates
    foreign_keys=[donation_offer_id], # Refer to the column object on this model
    back_populates='chat_session'
    )

    # Constraints (Ensure CheckConstraint is imported: from sqlalchemy import CheckConstraint)
    __table_args__ = (
        db.CheckConstraint('(participant_org_id IS NOT NULL AND user_two_id IS NULL) OR (participant_org_id IS NULL AND user_two_id IS NOT NULL)', name='chk_participant_type'),
        db.CheckConstraint(
            "(CASE WHEN trade_item_id IS NOT NULL THEN 1 ELSE 0 END + "
            " CASE WHEN donation_offer_id IS NOT NULL THEN 1 ELSE 0 END + "
            " CASE WHEN disaster_need_id IS NOT NULL THEN 1 ELSE 0 END) = 1",
            name='chk_chat_subject_exclusive'
        ),
    )

    @reconstructor
    def init_on_load(self):
        """Initializes instance variables on load from DB."""
        self._other_user_instance = None # Cache for get_other_user

    def get_other_user(self, current_user_id):
        """Returns the User object who is NOT the current_user_id in a user-user chat."""
        if not self.is_org_chat: # Only for user-user chats
            other_id = self.user_two_id if self.user_one_id == current_user_id else self.user_one_id
            if self._other_user_instance and self._other_user_instance.user_id == other_id: return self._other_user_instance
            self._other_user_instance = User.query.get(other_id)
            return self._other_user_instance
        return None

    @property
    def is_org_chat(self):
        """Helper property to check if the chat involves an organization."""
        return self.participant_org_id is not None

    @property
    def subject(self):
        """Helper property to get the item, offer, or need the chat is about."""
        if self.trade_item_id: return self.trade_item
        if self.donation_offer_id: return self.donation_offer
        if self.disaster_need_id: return self.disaster_need
        return None


class ChatMessage(db.Model):
    __tablename__ = "chat_messages"
    message_id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.Integer, db.ForeignKey("chat_sessions.session_id"), nullable=False, index=True)
    sender_type = db.Column(db.String(50), nullable=False) # 'user' or 'org'
    sender_id = db.Column(db.Integer, nullable=False, index=True) # user_id or org_id
    message = db.Column(db.Text, nullable=True)
    image_url = db.Column(db.String(255), nullable=True) # Path relative to static folder
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    is_read = db.Column(db.Boolean, default=False, nullable=True, index=True) # Default False is safer.
    deleted_at = db.Column(db.DateTime, nullable=True) # Timestamp for soft delete
    # session relationship defined via backref


# ---------- FEEDBACK ----------
class Feedback(db.Model):
    __tablename__ = "feedback"
    feedback_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.user_id"), nullable=False, index=True)
    message = db.Column(db.Text, nullable=False)
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    status = db.Column(db.String(50), default="Open", index=True) # Open, Responded
    # user relationship defined via backref


# ---------- REPORT ----------
class Report(db.Model):
    __tablename__ = "reports"
    report_id = db.Column(db.Integer, primary_key=True)
    reported_by = db.Column(db.Integer, db.ForeignKey("users.user_id"), nullable=False, index=True)
    item_id = db.Column(db.Integer, db.ForeignKey("items.item_id"), nullable=True, index=True)
    chat_session_id = db.Column(db.Integer, db.ForeignKey("chat_sessions.session_id"), nullable=True, index=True)
    reported_org_id = db.Column(db.Integer, db.ForeignKey("organizations.org_id"), nullable=True, index=True)
    donation_offer_id = db.Column(db.Integer, db.ForeignKey("donation_offers.offer_id"), nullable=True, index=True)

    reason = db.Column(db.Text, nullable=False)
    reported_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    status = db.Column(db.String(50), default="Pending", index=True) # Pending, Resolved

    # reporter relationship defined via backref
    # item relationship defined via backref
    reported_org = db.relationship("Organization", foreign_keys=[reported_org_id])


# ---------- BOOKMARK ----------
class Bookmark(db.Model):
    __tablename__ = "bookmarks"
    bookmark_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.user_id"), nullable=True, index=True)
    org_id = db.Column(db.Integer, db.ForeignKey("organizations.org_id"), nullable=True, index=True)
    item_id = db.Column(db.Integer, db.ForeignKey("items.item_id"), nullable=False, index=True)
    saved_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    __table_args__ = (
        CheckConstraint('(user_id IS NOT NULL AND org_id IS NULL) OR (user_id IS NULL AND org_id IS NOT NULL)', name='chk_bookmark_owner_type'),
        db.UniqueConstraint('user_id', 'item_id', name='uq_user_item_bookmark'),
        db.UniqueConstraint('org_id', 'item_id', name='uq_org_item_bookmark'),
    )
    # Relationships defined via backref in User/Organization


# ---------- CATEGORY FOLLOW ----------
class CategoryFollow(db.Model):
    __tablename__ = "category_follows"
    follow_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.user_id"), nullable=False, index=True)
    category = db.Column(db.String(255), index=True)
    followed_at = db.Column(db.DateTime, default=datetime.utcnow)
    __table_args__ = (db.UniqueConstraint('user_id', 'category', name='uq_user_category_follow'),)
    # user relationship defined via backref


# ---------- NOTIFICATION ----------
class Notification(db.Model):
    __tablename__ = "notifications"
    notification_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.user_id"), nullable=False, index=True)
    item_id = db.Column(db.Integer, db.ForeignKey("items.item_id"), nullable=True, index=True)
    message = db.Column(db.Text, nullable=False)
    sent_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    status = db.Column(db.String(50), default="Unread", index=True) # Unread, Read
    # user relationship defined via backref
    # item relationship defined via backref


# ---------- SYSTEM SETTINGS ----------
class SystemSetting(db.Model):
    __tablename__ = "system_settings"
    setting_id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(255), unique=True, nullable=False, index=True)
    value = db.Column(db.String(255))
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)