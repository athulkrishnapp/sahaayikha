# app/routes.py

from flask import (
    Blueprint, render_template, redirect, url_for,
    flash, request, abort, jsonify, session, send_from_directory, current_app
)
from flask_login import (
    login_user, logout_user, current_user,
    login_required
)
from werkzeug.utils import secure_filename
from sqlalchemy import or_, not_, and_, func
from sqlalchemy import orm
from datetime import datetime, timedelta, date # Ensure date is imported
from functools import wraps
import json
import os
import random
from sqlalchemy.orm import joinedload as orm_joinedload
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError, Optional # Make sure Optional is here too
from app.firebase_service import send_push_notification
from wtforms.validators import Optional
from flask_wtf import FlaskForm
from wtforms import FieldList, FormField
from app.models import User, Organization, Item, ChatSession # Ensure ChatSession is imported
from app import db, login_manager
from sqlalchemy import desc # <<< ADD THIS IMPORT AT THE TOP
import json # Ensure this is imported
from flask import jsonify

from app.models import (
    User, Admin, Organization, LoginLog,
    Item, ItemImage, ItemHistory,
    ChatSession, ChatMessage, DealProposal,
    DisasterNeed, DonationOffer, OfferedItem, # <-- Correctly imported here
    Feedback, Report, Bookmark,
    CategoryFollow, Notification, TradeRequest, SystemSetting
)

from app.forms import (
    RegistrationForm, OrganizationRegistrationForm, LoginForm,
    ItemForm, FeedbackForm, ReportForm, OrganizationReportForm,
    CategoryFollowForm, DisasterNeedForm, DonationOfferForm, ChatForm, # <<< CORRECTED THIS LINE
    SearchForm, OtpForm, ForgotPasswordForm, ResetPasswordForm,
    ProfileForm, OfferedItemForm,
    CATEGORIES, SUB_CATEGORIES
)

from flask import jsonify
from app.email import send_email
from app.firebase_service import send_push_notification

# --- CORRECTED IMPORT ---
from .utils import GEOCODE_DATA, geocode_location, haversine_distance # Ensure GEOCODE_DATA is imported
from app.utils import geocode_location, haversine_distance, get_keywords, GEOCODE_DATA
main = Blueprint("main", __name__)



from wtforms import (
    StringField, PasswordField, SubmitField, TextAreaField,
    SelectField, BooleanField, DateField, FileField,
    MultipleFileField, IntegerField, FormField, SelectMultipleField, FieldList # <-- ADD IntegerField HERE
)

# --- Upload Folders (Keep as is) ---
USER_UPLOAD_FOLDER = os.path.join("app", "static", "images", "profiles", "users")
ORG_UPLOAD_FOLDER = os.path.join("app", "static", "images", "profiles", "orgs")
ITEM_UPLOAD_FOLDER = os.path.join("app", "static", "images", "items")
CHAT_UPLOAD_FOLDER = os.path.join("app", "static", "images", "chat_uploads")
os.makedirs(USER_UPLOAD_FOLDER, exist_ok=True)
os.makedirs(ORG_UPLOAD_FOLDER, exist_ok=True)
os.makedirs(ITEM_UPLOAD_FOLDER, exist_ok=True)
os.makedirs(CHAT_UPLOAD_FOLDER, exist_ok=True)


@login_manager.user_loader
def load_user(user_id):
    """Loads user, admin, or organization based on prefixed ID."""
    try:
        prefix, id_str = user_id.split(":")
        id_val = int(id_str)
    except Exception:
        return None
    if prefix == "user":
        return User.query.get(id_val)
    if prefix == "admin":
        return Admin.query.get(id_val)
    if prefix == "org":
        return Organization.query.get(id_val)
    return None

# --- Merged Context Processors ---
@main.context_processor
def inject_globals():
    """Injects unread counts and global categories into all templates."""
    unread_notifications = 0
    has_unread_chats = False
    session_ids = [] # Initialize session_ids to an empty list

    if current_user.is_authenticated:
        # Get the actual user object type
        user_obj = current_user._get_current_object()

        if isinstance(user_obj, User):
            # --- User Specific Logic ---
            # Unread notifications for users
            unread_notifications = Notification.query.filter_by(
                user_id=user_obj.user_id, status="Unread"
            ).count()

            # Unread chats for users (User-User or User-Org)
            # Use the corrected attribute names user_one_id and user_two_id
            user_sessions = ChatSession.query.filter(
                or_(
                    ChatSession.user_one_id == user_obj.user_id, # <-- Corrected
                    ChatSession.user_two_id == user_obj.user_id  # <-- Corrected
                )
            ).all()
            session_ids = [s.session_id for s in user_sessions] # Assign session_ids here

            if session_ids:
                # Count unread messages *not* sent by this user
                unread_chat_count = db.session.query(ChatMessage.message_id).filter(
                    ChatMessage.session_id.in_(session_ids),
                    ChatMessage.is_read == False,
                    not_(and_(
                        ChatMessage.sender_id == user_obj.user_id,
                        ChatMessage.sender_type == 'user'
                    ))
                ).count()
                has_unread_chats = unread_chat_count > 0

        elif isinstance(user_obj, Organization):
            # --- Organization Specific Logic ---
            # Unread notifications (Organizations don't have this in the current model)
            unread_notifications = 0 # Explicitly set to 0 for Orgs

            # Unread chats for organizations (Org-User)
            org_sessions = ChatSession.query.filter(
                ChatSession.participant_org_id == user_obj.org_id # Corrected attribute
            ).all() # Filter by the participant_org_id column
            session_ids = [s.session_id for s in org_sessions] # Assign session_ids here

            if session_ids:
                 # Count unread messages sent *by users* to this organization
                unread_chat_count = db.session.query(ChatMessage.message_id).filter(
                    ChatMessage.session_id.in_(session_ids),
                    ChatMessage.is_read == False,
                    ChatMessage.sender_type == 'user' # Only count messages from users
                ).count()
                has_unread_chats = unread_chat_count > 0

        # Note: No specific logic needed for Admin regarding chat/notification counts here,
        # session_ids remains [] and has_unread_chats remains False, preventing errors.

    # --- Global Categories (Assuming CATEGORIES is defined in forms.py) ---
    try:
        from app.forms import CATEGORIES
        # Ensure CATEGORIES is a list of tuples like [('', 'Label'), ('Value', 'Label'), ...]
        category_suggestions = [c[0] for c in CATEGORIES if c[0]] # Get only the values, skip empty ''
    except ImportError:
        category_suggestions = [] # Fallback if forms.py or CATEGORIES is not found

    return dict(
        unread_count=unread_notifications,
        has_unread_chats=has_unread_chats,
        categories=category_suggestions
    )

# --- Role Check Decorator ---
def role_required(role):
    """Decorator to restrict access based on user role."""
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if not current_user.is_authenticated:
                return login_manager.unauthorized()
            obj = current_user._get_current_object()
            if role == "admin" and not isinstance(obj, Admin):
                abort(403)
            if role == "org" and not isinstance(obj, Organization):
                abort(403)
            if role == "user" and not isinstance(obj, User):
                abort(403)
            return f(*args, **kwargs)
        return wrapped
    return decorator


# -------------------------
# Local Date Filter
# -------------------------

@main.app_template_filter('localdatetime')
def localdatetime_filter(utc_dt):
    """Converts UTC datetime to local time (approximated as IST)."""
    # Assuming IST (UTC+5:30)
    if isinstance(utc_dt, datetime):
        return utc_dt + timedelta(hours=5, minutes=30)
    return utc_dt # Return original if not a datetime object

# =========================
# AUTH SELECTOR ROUTES
# =========================
@main.route("/auth/login")
def auth_login_selector():
    """Shows the page for selecting user/org/admin login."""
    return render_template("auth_login.html")

@main.route("/auth/register")
def auth_register_selector():
    """Shows the page for selecting user/org registration."""
    return render_template("auth_reg.html")

# =========================
# Scheduled Deletion (Placeholder - move to background task)
# =========================
def run_scheduled_deletions():
    """
    Placeholder: Simulates soft-deleting old/completed items.
    *** IMPORTANT: This should be moved to a background task runner
    (e.g., Celery, APScheduler, or a cron job) and NOT called directly
    within a web request in production. ***
    """
    try:
        now = datetime.utcnow()
        # Get expiry days from SystemSetting, fallback to config default
        setting = SystemSetting.query.filter_by(key='ITEM_EXPIRY_DAYS').first()
        expiry_days = int(setting.value) if setting else current_app.config.get('ITEM_EXPIRY_DAYS_DEFAULT', 30)
        expiry_threshold = now - timedelta(days=expiry_days)

        # Find items older than threshold OR finalized more than 24h ago
        finalized_threshold = now - timedelta(hours=24)

        items_to_delete = Item.query.filter(
            Item.status == 'Active',
            or_(
                Item.deal_finalized_at <= finalized_threshold, # Finalized deals older than 24h
                Item.created_at <= expiry_threshold             # Items older than expiry days
            )
        ).all()

        if items_to_delete:
            history_entries = []
            for item in items_to_delete:
                item.status = 'Deleted' # Soft delete
                history_entries.append(ItemHistory(item_id=item.item_id, action="Item automatically deleted due to age/completion."))
            db.session.add_all(history_entries)
            db.session.commit()
            current_app.logger.info(f"Soft-deleted {len(items_to_delete)} items.")
    except Exception as e:
        current_app.logger.error(f"Error during scheduled item deletion: {e}")
        db.session.rollback()


# =========================
# AI & NOTIFICATION HELPERS (MODIFIED)
# =========================

# --- MODIFIED: send_smart_notifications ---
def send_smart_notifications(new_item):
    """
    Finds users who might be interested in the new item based on category follows
    and keyword matches. Creates notifications and sends push notifications.
    """
    try:
        if not isinstance(new_item.owner, User): # Ensure item poster exists and is a user
            current_app.logger.warning(f"Item {new_item.item_id} has no valid owner, skipping notifications.")
            return

        users_to_notify = {} # Use a dictionary {user_id: user_object}
        item_poster_id = new_item.user_id

        # 1. Notify users following the item's category
        followers = CategoryFollow.query.filter(
            CategoryFollow.category == new_item.category,
            CategoryFollow.user_id != item_poster_id # Exclude the poster
        ).all()
        for follow in followers:
            users_to_notify[follow.user_id] = follow.user # Add user object

        # 2. Basic Keyword Match: Notify users following categories related to keywords
        if new_item.description or new_item.title:
            item_keywords = get_keywords((new_item.title or "") + " " + (new_item.description or ""))
            if item_keywords:
                # Find categories whose names contain any of the item's keywords
                # This is a very basic match, could be improved with better mapping
                potential_categories = {cat[0] for cat in CATEGORIES if cat[0] and any(keyword in cat[0].lower() for keyword in item_keywords)}

                if potential_categories:
                    keyword_followers = CategoryFollow.query.filter(
                        CategoryFollow.category.in_(potential_categories),
                        CategoryFollow.user_id != item_poster_id, # Exclude poster
                        CategoryFollow.user_id.notin_(users_to_notify.keys()) # Exclude already added users
                    ).all()
                    for follow in keyword_followers:
                        users_to_notify[follow.user_id] = follow.user # Add user object


        # Create and save notifications
        notifications_to_add = []
        fcm_notifications = []
        for user_id, user in users_to_notify.items():
            # Avoid duplicate notifications for the same item/user combo (though filter above helps)
            exists = Notification.query.filter_by(user_id=user_id, item_id=new_item.item_id).first()
            if not exists:
                # Determine reason (can be enhanced)
                reason = "category match" if user.category_follows.filter_by(category=new_item.category).first() else "keyword match"
                message_text = f"New Item ({reason}): '{new_item.title}' was posted."

                notifications_to_add.append(Notification(
                    user_id=user_id,
                    item_id=new_item.item_id,
                    message=message_text
                ))

                # Prepare push notification if the user has a token
                if user.fcm_token:
                    fcm_notifications.append({
                        'token': user.fcm_token,
                        'title': "New Item Match!",
                        'body': message_text,
                        'data': {'itemId': str(new_item.item_id)}
                    })

        if notifications_to_add:
            db.session.add_all(notifications_to_add)
            db.session.commit()
            current_app.logger.info(f"Created {len(notifications_to_add)} smart notifications for item {new_item.item_id}")


        # Send push notifications (consider moving to background task)
        for fcm_note in fcm_notifications:
            try:
                send_push_notification(
                    token=fcm_note['token'],
                    title=fcm_note['title'],
                    body=fcm_note['body'],
                    data=fcm_note['data']
                )
            except Exception as e:
                current_app.logger.error(f"Failed to send FCM notification to token {fcm_note['token']} for item {new_item.item_id}: {e}")

    except Exception as e:
        current_app.logger.error(f"Error sending smart notifications for item {new_item.item_id if new_item else 'N/A'}: {e}")
        db.session.rollback() # Rollback notification creation if error occurs


def send_disaster_notifications(new_need):
    """Sends notifications to users in the same location as a new disaster need."""
    try:
        users_in_location = User.query.filter(
            User.location == new_need.location,
            User.status == 'Active' # Only notify active users
            ).all()

        notifications_to_add = []
        fcm_notifications = []
        org_name = new_need.organization.name if new_need.organization else "an organization"

        for user in users_in_location:
            message_text = f"New Disaster Need in {new_need.location}: '{new_need.title}' posted by {org_name}."

            # Avoid duplicate notifications (though less likely for needs)
            # exists = Notification.query.filter_by(user_id=user.user_id, message=message_text).first() # Basic check
            # if not exists:

            notifications_to_add.append(Notification(
                user_id=user.user_id,
                # Link to the need could be done via data payload in FCM or a dedicated need_id field if added
                message=message_text
            ))

            # Send push notification
            if user.fcm_token:
                 fcm_notifications.append({
                    'token': user.fcm_token,
                    'title': "Disaster Need Alert!",
                    'body': message_text,
                    'data': {'needId': str(new_need.need_id), 'location': new_need.location} # Add need ID
                 })

        if notifications_to_add:
            db.session.add_all(notifications_to_add)
            db.session.commit()
            current_app.logger.info(f"Created {len(notifications_to_add)} disaster notifications for need {new_need.need_id}")

        # Send push notifications (consider moving to background task)
        for fcm_note in fcm_notifications:
             try:
                 send_push_notification(
                     token=fcm_note['token'],
                     title=fcm_note['title'],
                     body=fcm_note['body'],
                     data=fcm_note['data']
                 )
             except Exception as e:
                 current_app.logger.error(f"Failed to send FCM disaster notification to token {fcm_note['token']} for need {new_need.need_id}: {e}")

    except Exception as e:
        current_app.logger.error(f"Error sending disaster notifications for need {new_need.need_id if new_need else 'N/A'}: {e}")
        db.session.rollback()


# -------------------------
# HOME ROUTE
# -------------------------
@main.route("/")
def home():
    """Renders the home page."""
    # --- REMOVED THE CALL TO run_scheduled_deletions() ---
    # Fetch recent active items for the gallery
    items = Item.query.filter_by(status="Active").order_by(Item.created_at.desc()).limit(8).all()
    return render_template("home.html", title="Home", items=items)


# =========================
# USER AUTH ROUTES
# =========================
@main.route("/register", methods=["GET", "POST"])
def register():
    """Handles user registration."""
    if current_user.is_authenticated and isinstance(current_user._get_current_object(), User):
        return redirect(url_for("main.dashboard"))

    form = RegistrationForm()
    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data).first() or \
           Organization.query.filter_by(email=form.email.data).first() or \
           Admin.query.filter_by(email=form.email.data).first():
            flash("Email address is already registered.", "danger")
            return render_template("auth/user_register.html", form=form)

        otp = ''.join([str(random.randint(0, 9)) for _ in range(6)])
        otp_expiry = datetime.utcnow() + timedelta(minutes=10) # OTP valid for 10 mins

        lat, lon = geocode_location(form.location.data)

        user = User(
            first_name=form.first_name.data.strip(),
            last_name=form.last_name.data.strip() if form.last_name.data else None,
            email=form.email.data.lower().strip(),
            phone=form.phone.data.strip() if form.phone.data else None,
            location=form.location.data,
            status="Pending", # Status until OTP verified
            otp=otp,
            otp_expiry=otp_expiry,
            latitude=lat,
            longitude=lon,
            search_radius=int(form.search_radius.data)
        )
        user.set_password(form.password.data)

        # Handle profile picture upload
        if form.profile_picture.data:
            try:
                file = form.profile_picture.data
                filename = secure_filename(f"{user.email.split('@')[0]}_{file.filename}")
                filepath = os.path.join(USER_UPLOAD_FOLDER, filename)
                file.save(filepath)
                user.profile_picture = f"images/profiles/users/{filename}" # Store relative path
            except Exception as e:
                current_app.logger.error(f"Profile picture upload failed for {user.email}: {e}")
                flash("Profile picture upload failed, proceeding without it.", "warning")


        db.session.add(user)
        db.session.commit()

        # Send OTP email (Consider background task)
        try:
            send_email(user.email, 'Verify Your Sahaayikha Account', f'<h1>Your OTP is: {otp}</h1><p>This code expires in 10 minutes.</p>')
        except Exception as e:
             current_app.logger.error(f"Failed to send OTP email to {user.email}: {e}")
             flash("Registration successful, but failed to send OTP email. Please try resending.", "warning")
             # Keep user pending, allow login attempt to trigger resend/verify prompt

        session['email'] = user.email # Store email for OTP verification page
        flash("Registration successful! Please check your email for the OTP to verify your account.", "success")
        return redirect(url_for('main.verify_otp'))

    return render_template("auth/user_register.html", form=form)


@main.route("/login", methods=["GET", "POST"])
def login():
    """Handles user login."""
    if current_user.is_authenticated and isinstance(current_user._get_current_object(), User):
        return redirect(url_for("main.dashboard"))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter(func.lower(User.email) == form.email.data.lower().strip()).first()

        if user and user.check_password(form.password.data):
            if not user.is_verified:
                flash('Account not verified. Please check your email for the OTP or resend it.', 'warning')
                session['email'] = user.email # Set session for verify_otp page
                # Optionally resend OTP here automatically or let user click resend on next page
                return redirect(url_for('main.verify_otp'))

            if user.status == 'Blocked':
                flash('Your account has been blocked by an administrator.', 'danger')
                return render_template("auth/user_login.html", form=form)

            # Login successful
            login_user(user, remember=form.remember.data)
            try:
                # Log login event
                db.session.add(LoginLog(user_id=user.user_id, ip_address=request.remote_addr))
                db.session.commit()
            except Exception as e:
                 current_app.logger.error(f"Failed to record login log for user {user.user_id}: {e}")
                 db.session.rollback()

            flash("Logged in successfully.", "success")
            next_page = request.args.get('next')
            return redirect(next_page or url_for("main.dashboard"))
        else:
            flash("Invalid email or password.", "danger")

    return render_template("auth/user_login.html", form=form)


@main.route("/verify_otp", methods=["GET", "POST"])
def verify_otp():
    """Handles user OTP verification."""
    # Redirect if already logged in or no email in session
    if current_user.is_authenticated and isinstance(current_user._get_current_object(), User):
         return redirect(url_for('main.dashboard'))
    if 'email' not in session:
        flash("Verification session expired or invalid. Please try logging in or registering again.", "warning")
        return redirect(url_for('main.login'))

    user_email = session['email']
    form = OtpForm()

    if form.validate_on_submit():
        user = User.query.filter(func.lower(User.email) == user_email.lower()).first()

        if user and user.otp == form.otp.data:
            if user.otp_expiry > datetime.utcnow():
                user.is_verified = True
                user.status = "Active" # Set status to Active upon verification
                user.otp = None         # Clear OTP fields
                user.otp_expiry = None
                db.session.commit()
                session.pop('email', None) # Clear email from session
                flash('Your account has been verified successfully! Please log in.', 'success')
                return redirect(url_for('main.login'))
            else:
                flash('OTP has expired. Please request a new one.', 'danger')
        else:
            flash('Invalid OTP entered.', 'danger')

    return render_template('auth/verify_otp.html', form=form, email=user_email)


@main.route("/resend_otp", methods=["POST"])
def resend_otp():
    """Handles AJAX request to resend OTP for users."""
    email_from_session = session.get('email')
    email_from_json = request.json.get('email')

    email = email_from_session or email_from_json

    if not email:
        return jsonify({'success': False, 'error': 'Session invalid or email missing.'}), 400

    user = User.query.filter(func.lower(User.email) == email.lower()).first()
    if user:
        if user.is_verified:
             return jsonify({'success': False, 'error': 'Account already verified.'}), 400

        # Generate and save new OTP
        otp = ''.join([str(random.randint(0, 9)) for _ in range(6)])
        user.otp = otp
        user.otp_expiry = datetime.utcnow() + timedelta(minutes=10)
        db.session.commit()

        # Send email (Consider background task)
        try:
            send_email(user.email, 'Your New Sahaayikha OTP', f'<h1>Your new OTP is: {otp}</h1><p>This code expires in 10 minutes.</p>')
            return jsonify({'success': True, 'message': 'A new OTP has been sent to your email.'})
        except Exception as e:
            current_app.logger.error(f"Failed to resend OTP email to {user.email}: {e}")
            return jsonify({'success': False, 'error': 'Failed to send email. Please try again later.'}), 500
    else:
        return jsonify({'success': False, 'error': 'User not found.'}), 404


@main.route("/forgot_password", methods=['GET', 'POST'])
def forgot_password():
    """Handles the start of the password reset process for users."""
    if current_user.is_authenticated:
        return redirect(url_for('main.home')) # Redirect logged-in users away

    form = ForgotPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter(func.lower(User.email) == form.email.data.lower().strip()).first()
        if user:
            # Generate reset token (valid for 30 minutes by default)
            token = user.get_reset_token()
            reset_url = url_for('main.reset_token', token=token, _external=True)

            # Send password reset email (Consider background task)
            try:
                send_email(user.email, 'Sahaayikha Password Reset Request',
                           f'''<h1>Password Reset Request</h1>
                               <p>To reset your password, visit the following link within 30 minutes:</p>
                               <p><a href="{reset_url}">Reset Password</a></p>
                               <p>If you did not make this request, please ignore this email.</p>''')
                flash('An email has been sent with instructions to reset your password.', 'info')
            except Exception as e:
                current_app.logger.error(f"Failed to send password reset email to {user.email}: {e}")
                flash('Failed to send password reset email. Please try again later.', 'danger')
        else:
            # Still show success message to prevent email enumeration
             flash('If an account exists for that email, an email has been sent with instructions.', 'info')

        return redirect(url_for('main.login')) # Redirect back to login page

    return render_template('auth/forgot_password.html', title='Forgot Password', form=form)


@main.route("/reset_password/<token>", methods=['GET', 'POST'])
def reset_token(token):
    """Handles password reset using the token received via email."""
    if current_user.is_authenticated:
        return redirect(url_for('main.home'))

    user = User.verify_reset_token(token) # Verifies token and checks expiry (default 30 mins)

    if user is None:
        flash('The password reset link is invalid or has expired.', 'warning')
        return redirect(url_for('main.forgot_password'))

    form = ResetPasswordForm()
    if form.validate_on_submit():
        try:
            user.set_password(form.password.data) # Hash and set the new password
            db.session.commit()
            flash('Your password has been successfully updated! You can now log in.', 'success')
            return redirect(url_for('main.login'))
        except Exception as e:
            current_app.logger.error(f"Error resetting password for user {user.user_id}: {e}")
            db.session.rollback()
            flash('An error occurred while updating your password. Please try again.', 'danger')

    return render_template('auth/reset_password.html', title='Reset Password', form=form)


# =========================
# ORGANIZATION AUTH ROUTES
# =========================
@main.route("/org/register", methods=["GET", "POST"])
def org_register():
    """Handles organization registration."""
    if current_user.is_authenticated and isinstance(current_user._get_current_object(), Organization):
        return redirect(url_for("main.org_dashboard"))

    form = OrganizationRegistrationForm()
    if form.validate_on_submit():
        # Check if email is already used by any type of account
        if Organization.query.filter(func.lower(Organization.email) == form.email.data.lower().strip()).first() or \
           User.query.filter(func.lower(User.email) == form.email.data.lower().strip()).first() or \
           Admin.query.filter(func.lower(Admin.email) == form.email.data.lower().strip()).first():
            flash("Email address is already registered.", "danger")
            return render_template("auth/org_register.html", form=form)

        otp = ''.join([str(random.randint(0, 9)) for _ in range(6)])
        otp_expiry = datetime.utcnow() + timedelta(minutes=10)

        org = Organization(
            name=form.name.data.strip(),
            email=form.email.data.lower().strip(),
            phone=form.phone.data.strip() if form.phone.data else None,
            location=form.location.data,
            description=form.description.data.strip() if form.description.data else None,
            status="Pending",  # Status for admin approval, NOT email verification
            registered_at=datetime.utcnow(),
            otp=otp,
            otp_expiry=otp_expiry,
            is_verified=False # Email not verified yet
        )
        org.set_password(form.password.data)

        # Handle profile picture upload
        if form.profile_picture.data:
            try:
                file = form.profile_picture.data
                filename = secure_filename(f"{org.email.split('@')[0]}_{file.filename}")
                filepath = os.path.join(ORG_UPLOAD_FOLDER, filename)
                file.save(filepath)
                org.profile_picture = f"images/profiles/orgs/{filename}"
            except Exception as e:
                current_app.logger.error(f"Org profile picture upload failed for {org.email}: {e}")
                flash("Profile picture upload failed, proceeding without it.", "warning")

        db.session.add(org)
        db.session.commit()

        # Send OTP email (Consider background task)
        try:
            send_email(org.email, 'Verify Your Sahaayikha Organization Account', f'<h1>Your OTP is: {otp}</h1><p>This code expires in 10 minutes.</p>')
        except Exception as e:
            current_app.logger.error(f"Failed to send OTP email to org {org.email}: {e}")
            flash("Registration successful, but failed to send OTP email. Please try resending.", "warning")

        session['org_email'] = org.email # Store email for OTP verification
        flash("Registration successful! Please check your email for the OTP to verify your account.", "success")
        return redirect(url_for('main.org_verify_otp'))

    return render_template("auth/org_register.html", form=form)


@main.route("/org/verify_otp", methods=["GET", "POST"])
def org_verify_otp():
    """Handles organization OTP verification."""
    if current_user.is_authenticated and isinstance(current_user._get_current_object(), Organization):
         return redirect(url_for('main.org_dashboard'))
    if 'org_email' not in session:
        flash("Verification session expired or invalid. Please try registering again.", "warning")
        return redirect(url_for('main.org_register'))

    org_email = session['org_email']
    form = OtpForm()

    if form.validate_on_submit():
        org = Organization.query.filter(func.lower(Organization.email) == org_email.lower()).first()

        if org and org.otp == form.otp.data:
             if org.otp_expiry > datetime.utcnow():
                org.is_verified = True # Mark email as verified
                # Status remains "Pending" until admin approval
                org.otp = None
                org.otp_expiry = None
                db.session.commit()
                session.pop('org_email', None)
                flash('Your organization email has been verified! Your registration is now pending administrator approval.', 'success')
                return redirect(url_for('main.org_login')) # Redirect to login, they can't log in yet but shows success
             else:
                flash('OTP has expired. Please request a new one.', 'danger')
        else:
            flash('Invalid OTP entered.', 'danger')

    return render_template('auth/org_verify_otp.html', form=form, email=org_email)


@main.route("/org/resend_otp", methods=["POST"])
def org_resend_otp():
    """Handles AJAX request to resend OTP for organizations."""
    email_from_session = session.get('org_email')
    email_from_json = request.json.get('email')
    email = email_from_session or email_from_json

    if not email:
        return jsonify({'success': False, 'error': 'Session invalid or email missing.'}), 400

    org = Organization.query.filter(func.lower(Organization.email) == email.lower()).first()
    if org:
        if org.is_verified:
             return jsonify({'success': False, 'error': 'Account email already verified.'}), 400

        # Generate and save new OTP
        otp = ''.join([str(random.randint(0, 9)) for _ in range(6)])
        org.otp = otp
        org.otp_expiry = datetime.utcnow() + timedelta(minutes=10)
        db.session.commit()

        # Send email (Consider background task)
        try:
            send_email(org.email, 'Your New Sahaayikha Organization OTP', f'<h1>Your new OTP is: {otp}</h1><p>This code expires in 10 minutes.</p>')
            return jsonify({'success': True, 'message': 'A new OTP has been sent to your email.'})
        except Exception as e:
            current_app.logger.error(f"Failed to resend OTP email to org {org.email}: {e}")
            return jsonify({'success': False, 'error': 'Failed to send email. Please try again later.'}), 500
    else:
        return jsonify({'success': False, 'error': 'Organization not found.'}), 404


@main.route("/org/login", methods=["GET", "POST"])
def org_login():
    """Handles organization login."""
    if current_user.is_authenticated and isinstance(current_user._get_current_object(), Organization):
        return redirect(url_for("main.org_dashboard"))

    form = LoginForm()
    if form.validate_on_submit():
        org = Organization.query.filter(func.lower(Organization.email) == form.email.data.lower().strip()).first()

        if org and org.check_password(form.password.data):
            # Check 1: Email Verification
            if not org.is_verified:
                flash('Please verify your email with the OTP first.', 'warning')
                session['org_email'] = org.email
                return redirect(url_for('main.org_verify_otp'))

            # Check 2: Admin Approval Status
            if org.status != "Approved":
                flash(f"Your organization's status is '{org.status}'. Login requires 'Approved' status from an admin.", "warning")
                return render_template("auth/org_login.html", form=form)

            # Login successful
            login_user(org, remember=form.remember.data)
            # No login log for orgs currently, add if needed
            flash("Organization logged in successfully.", "success")
            next_page = request.args.get('next')
            return redirect(next_page or url_for("main.org_dashboard"))
        else:
             flash("Invalid email or password.", "danger")

    return render_template("auth/org_login.html", form=form)


@main.route("/org/forgot_password", methods=['GET', 'POST'])
def org_forgot_password():
    """Handles start of password reset process for organizations."""
    if current_user.is_authenticated:
        return redirect(url_for('main.home'))

    form = ForgotPasswordForm()
    if form.validate_on_submit():
        org = Organization.query.filter(func.lower(Organization.email) == form.email.data.lower().strip()).first()
        if org:
            token = org.get_reset_token() # Uses Organization's method
            reset_url = url_for('main.org_reset_token', token=token, _external=True)
            # Send email (Consider background task)
            try:
                send_email(org.email, 'Sahaayikha Organization Password Reset',
                           f'''<h1>Password Reset Request</h1>
                               <p>To reset your organization's password, visit the following link within 30 minutes:</p>
                               <p><a href="{reset_url}">Reset Password</a></p>
                               <p>If you did not make this request, please ignore this email.</p>''')
                flash('An email has been sent with instructions to reset the password.', 'info')
            except Exception as e:
                current_app.logger.error(f"Failed to send password reset email to org {org.email}: {e}")
                flash('Failed to send password reset email. Please try again later.', 'danger')
        else:
             flash('If an organization account exists for that email, an email has been sent.', 'info')

        return redirect(url_for('main.org_login'))

    return render_template('auth/org_forgot_password.html', title='Forgot Organization Password', form=form)


@main.route("/org/reset_password/<token>", methods=['GET', 'POST'])
def org_reset_token(token):
    """Handles organization password reset using the token."""
    if current_user.is_authenticated:
        return redirect(url_for('main.home'))

    org = Organization.verify_reset_token(token) # Uses Organization's method

    if org is None:
        flash('The password reset link is invalid or has expired.', 'warning')
        return redirect(url_for('main.org_forgot_password'))

    form = ResetPasswordForm()
    if form.validate_on_submit():
        try:
            org.set_password(form.password.data)
            db.session.commit()
            flash('Organization password updated successfully! You can now log in.', 'success')
            return redirect(url_for('main.org_login'))
        except Exception as e:
             current_app.logger.error(f"Error resetting password for org {org.org_id}: {e}")
             db.session.rollback()
             flash('An error occurred while updating the password. Please try again.', 'danger')

    return render_template('auth/org_reset_password.html', title='Reset Organization Password', form=form)



# =========================
# LOGOUT ROUTE
# =========================
@main.route("/logout")
@login_required # Requires user to be logged in to log out
def logout():
    """Logs out the current user, admin, or organization."""
    logout_user()
    flash("You have been logged out successfully.", "info")
    return redirect(url_for("main.home"))


# =========================
# PROFILE ROUTES
# =========================
@main.route('/organization/<int:org_id>')
def public_org_profile(org_id):
    """Displays the public profile page for an organization."""
    organization = Organization.query.get_or_404(org_id)
    # Fetch active disaster needs posted by this organization
    needs = DisasterNeed.query.filter_by(org_id=organization.org_id).order_by(DisasterNeed.posted_at.desc()).all()
    return render_template("public_org_profile.html", organization=organization, needs=needs)


@main.route('/user/<int:user_id>')
@login_required # Require login to view user profiles
def public_profile(user_id):
    """Displays the public profile page for a user."""
    # Redirect users viewing their own public profile to their editable one
    if isinstance(current_user._get_current_object(), User) and user_id == current_user.user_id:
        return redirect(url_for('main.profile'))

    user_profile = User.query.get_or_404(user_id)

    # Fetch only 'Active' items posted by that user
    items = Item.query.filter_by(user_id=user_profile.user_id, status='Active')\
                      .order_by(Item.created_at.desc()).all()

    return render_template("public_profile.html", user=user_profile, items=items)


# app/routes.py

# =========================
# PROFILE ROUTES (Consolidated for User/Org)
# =========================

@main.route("/profile/picture/delete", methods=["POST"]) # Define a URL and allow POST
@login_required # Ensure user is logged in
# Add @role_required if necessary (e.g., @role_required("user"))
def delete_profile_picture():
    """Deletes the user's or organization's profile picture."""
    actor = current_user._get_current_object() # User or Organization

    # Determine paths based on actor type
    is_user = isinstance(actor, User)
    folder_rel_path = "images/profiles/users/" if is_user else "images/profiles/orgs/"
    folder_abs_path = os.path.join(current_app.root_path, 'static', folder_rel_path)
    placeholder = f"{folder_rel_path}{'users' if is_user else 'orgs'}_placeholder.png"

    if actor.profile_picture and 'placeholder' not in actor.profile_picture:
        try:
            # Delete the file
            old_filename = os.path.basename(actor.profile_picture)
            old_filepath = os.path.join(folder_abs_path, old_filename)
            if os.path.exists(old_filepath):
                os.remove(old_filepath)

            # Update the database record
            actor.profile_picture = None # Or set to placeholder path if preferred
            db.session.commit()

            # Return success with the URL of the placeholder image
            placeholder_url = url_for('static', filename=placeholder)
            return jsonify({"success": True, "placeholder_url": placeholder_url})

        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Error deleting profile picture for {getattr(actor, 'email', 'ID: ' + str(getattr(actor, 'user_id', getattr(actor, 'org_id', 'N/A'))))}: {e}")
            return jsonify({"success": False, "error": "Server error deleting picture."}), 500
    else:
        # No picture to delete or already placeholder
        placeholder_url = url_for('static', filename=placeholder)
        return jsonify({"success": True, "placeholder_url": placeholder_url}) # Indicate success



@main.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    """Handles viewing and updating the profile for the logged-in user or org."""
    actor = current_user._get_current_object()
    blocked_chats = [] # Only relevant for users

    template = None
    form = None

    if isinstance(actor, User):
        template = "auth/user_profile.html"
        form = ProfileForm(obj=actor) # Use specific User profile form
        blocked_chats = ChatSession.query.filter(
             ChatSession.status == 'Blocked',
             ChatSession.participant_org_id == None,
             or_(ChatSession.user_one_id == actor.user_id, ChatSession.user_two_id == actor.user_id)
        ).all()
    elif isinstance(actor, Organization):
        template = "auth/org_profile.html"
        # Use OrganizationRegistrationForm for editing Org profile fields
        form = OrganizationRegistrationForm(obj=actor)
        # Make password fields optional for profile updates in this form instance
        form.password.validators = [Optional(), Length(min=6)]
        form.confirm_password.validators = [Optional(), EqualTo('password', message='Passwords must match')]
    elif isinstance(actor, Admin):
        return redirect(url_for('main.admin_profile'))
    else:
        flash("Profile not available for this account type.", "warning")
        return redirect(url_for("main.home"))

    if form.validate_on_submit():
        # Frontend JS should have handled password verification via modal if needed.
        # This block executes if verification passed OR wasn't required.

        # Email check (usually disabled, but kept for robustness)
        if hasattr(form, 'email') and form.email.data != actor.email:
             # Add uniqueness check across all models if email change is allowed
             pass # Currently email is disabled

        # Phone update - check handled by frontend JS + verify_profile_password
        if hasattr(form, 'phone') and hasattr(actor, 'phone'):
            new_phone = form.phone.data.strip() if form.phone.data else None
            actor.phone = new_phone

        # Other basic info updates
        if hasattr(form, 'first_name') and hasattr(actor, 'first_name'): actor.first_name = form.first_name.data.strip()
        if hasattr(form, 'last_name') and hasattr(actor, 'last_name'): actor.last_name = form.last_name.data.strip() if form.last_name.data else None
        if hasattr(form, 'name') and isinstance(actor, Organization): actor.name = form.name.data.strip()
        if hasattr(form, 'description') and isinstance(actor, Organization): actor.description = form.description.data.strip() if form.description.data else None
        if hasattr(form, 'search_radius') and isinstance(actor, User): actor.search_radius = int(form.search_radius.data)

        # Location update
        if hasattr(form, 'location') and hasattr(actor, 'location') and actor.location != form.location.data:
            actor.location = form.location.data
            if isinstance(actor, User): # Geocode only for Users currently
                lat, lon = geocode_location(form.location.data)
                actor.latitude = lat
                actor.longitude = lon

        # Profile picture update (remains same logic)
        if hasattr(form, 'profile_picture') and form.profile_picture.data:
            try:
                 file = form.profile_picture.data
                 folder_rel_path = "images/profiles/users/" if isinstance(actor, User) else "images/profiles/orgs/"
                 folder_abs_path = os.path.join(current_app.root_path, 'static', folder_rel_path)
                 os.makedirs(folder_abs_path, exist_ok=True)
                 base_name = actor.email.split('@')[0] if hasattr(actor, 'email') and actor.email else str(getattr(actor, 'user_id', getattr(actor, 'org_id', 'id')))
                 timestamp = datetime.utcnow().strftime('%Y%m%d%H%M%S%f')
                 _, f_ext = os.path.splitext(file.filename)
                 filename = secure_filename(f"{base_name}_{timestamp}{f_ext}")
                 filepath = os.path.join(folder_abs_path, filename)
                 # Delete old picture if exists and is not placeholder
                 if hasattr(actor, 'profile_picture') and actor.profile_picture and 'placeholder' not in actor.profile_picture:
                    old_filename = os.path.basename(actor.profile_picture)
                    old_filepath = os.path.join(folder_abs_path, old_filename)
                    if os.path.exists(old_filepath) and old_filename != filename:
                         try: os.remove(old_filepath)
                         except OSError as e: current_app.logger.warning(f"Could not delete old profile picture {old_filepath}: {e}")
                 file.save(filepath)
                 if hasattr(actor, 'profile_picture'): actor.profile_picture = f"{folder_rel_path}{filename}"
            except Exception as e:
                 current_app.logger.error(f"Profile picture update failed for actor ID {getattr(actor, 'user_id', getattr(actor, 'org_id', 'N/A'))}: {e}")
                 flash("Profile picture update failed.", "danger")


        try:
            db.session.commit()
            flash("Profile updated successfully.", "success")
            return redirect(url_for("main.profile")) # Redirect back to profile page
        except Exception as e:
             current_app.logger.error(f"Database error updating profile: {e}")
             db.session.rollback()
             flash("Error updating profile. Please try again.", "danger")

    elif request.method == 'POST':
        # Flash general form errors if validation fails
        for field, errors in form.errors.items():
             for error in errors:
                flash(f"Error in {getattr(form, field).label.text if hasattr(form, field) else field}: {error}", "danger")

    # Disable email editing for both user and org
    if hasattr(form, 'email'):
         form.email.render_kw = {'readonly': True, 'disabled': True, 'class': 'form-control form-control bg-light'} # Ensure styling

    # Pass initial values needed for JS check specifically for Org phone
    initial_org_phone = actor.phone if isinstance(actor, Organization) else None

    return render_template(template, form=form, blocked_chats=blocked_chats, initial_org_phone=initial_org_phone)



@main.route('/profile/verify_password', methods=['POST'])
@login_required
def verify_profile_password():
    """Verifies the current user's OR organization's password via AJAX."""
    password = request.json.get('password')
    actor = current_user._get_current_object() # Get the actual User or Organization object

    current_app.logger.debug(f"Verify Password Route Hit for Actor Type: {type(actor)}, Email: {getattr(actor, 'email', 'N/A')}")
    current_app.logger.debug(f"Received password via JSON: '{password}'")

    if not password:
        current_app.logger.warning("Password not found in JSON request.")
        return jsonify({'success': False, 'error': 'Password not provided.'}), 400

    # Check if the actor object has the check_password method
    if not hasattr(actor, 'check_password') or not callable(getattr(actor, 'check_password')):
        current_app.logger.error(f"Current actor object (type: {type(actor)}) lacks a callable check_password method.")
        return jsonify({'success': False, 'error': 'Internal server error.'}), 500

    try:
        is_correct = actor.check_password(password)
    except Exception as e:
        # Catch potential errors during password check (e.g., hashing issues)
        current_app.logger.error(f"Error during check_password for actor {getattr(actor, 'email', 'N/A')}: {e}")
        return jsonify({'success': False, 'error': 'Password verification failed.'}), 500


    current_app.logger.debug(f"Password check result: {is_correct}")

    if is_correct:
        return jsonify({'success': True})
    else:
        # Return 401 Unauthorized for incorrect password
        return jsonify({'success': False, 'error': 'Incorrect password.'}), 401
# =========================
# ADMIN ROUTES
# =========================
@main.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    """Handles admin login."""
    if current_user.is_authenticated and isinstance(current_user._get_current_object(), Admin):
        return redirect(url_for("main.admin_dashboard"))

    form = LoginForm()
    if form.validate_on_submit():
        admin = Admin.query.filter(func.lower(Admin.email) == form.email.data.lower().strip()).first()
        if admin and admin.check_password(form.password.data):
            login_user(admin, remember=form.remember.data)
            flash("Admin login successful.", "success")
            next_page = request.args.get('next')
            return redirect(next_page or url_for("main.admin_dashboard"))
        else:
            flash("Invalid admin email or password.", "danger")

    return render_template("auth/admin_login.html", title="Admin Login", form=form)


@main.route("/admin/dashboard")
@login_required
@role_required("admin")
def admin_dashboard():
    """Displays the main admin dashboard with statistics."""
    try:
        users_count = db.session.query(func.count(User.user_id)).scalar()
        orgs_count = db.session.query(func.count(Organization.org_id)).scalar()
        items_count = db.session.query(func.count(Item.item_id)).filter(Item.status != 'Deleted').scalar() # Count non-deleted items
        feedback_count = db.session.query(func.count(Feedback.feedback_id)).filter(Feedback.status == 'Open').scalar() # Count open feedback
        reports_count = db.session.query(func.count(Report.report_id)).filter(Report.status == 'Pending').scalar() # Count pending reports
    except Exception as e:
         current_app.logger.error(f"Error fetching admin dashboard counts: {e}")
         users_count, orgs_count, items_count, feedback_count, reports_count = 0, 0, 0, 0, 0
         flash("Error loading dashboard statistics.", "warning")

    return render_template(
        "dashboard/admin_dashboard.html",
        users_count=users_count,
        orgs_count=orgs_count,
        items_count=items_count,
        feedback_count=feedback_count,
        reports_count=reports_count
    )


@main.route("/admin/profile", methods=["GET", "POST"])
@login_required
@role_required("admin")
def admin_profile():
    """Handles viewing and updating the admin's own profile."""
    admin = current_user._get_current_object()
    # Using RegistrationForm is okay if fields match, but consider a dedicated AdminProfileForm
    form = RegistrationForm(obj=admin)

    # Make password optional for profile updates
    form.password.validators = [Optional(), Length(min=6)]
    form.confirm_password.validators = [Optional(), EqualTo('password', message='Passwords must match')]
    # Remove validators not relevant for Admin
    form.phone.validators = []
    form.location.validators = []
    form.profile_picture.validators = []
    form.search_radius.validators = []


    if form.validate_on_submit():
        admin.first_name = form.first_name.data.strip()
        admin.last_name = form.last_name.data.strip() if form.last_name.data else None
        admin.email = form.email.data.lower().strip() # Allow changing email? Ensure uniqueness check if so.

        # Update password only if provided
        if form.password.data:
            admin.set_password(form.password.data)

        try:
            db.session.commit()
            flash("Admin profile updated successfully.", "success")
        except Exception as e:
            # Handle potential unique constraint errors if email is changed and already exists
             current_app.logger.error(f"Error updating admin profile for {admin.admin_id}: {e}")
             db.session.rollback()
             flash("Error updating profile. The email might already be in use.", "danger")

        return redirect(url_for("main.admin_profile"))

    # Pre-populate form for GET request
    form.email.data = admin.email # Ensure current email is shown

    return render_template("dashboard/admin_profile.html", form=form)


@main.route("/admin/logs")
@login_required
@role_required("admin")
def login_logs():
    """Displays user login logs."""
    # Add pagination for large number of logs
    page = request.args.get('page', 1, type=int)
    logs_pagination = LoginLog.query.order_by(LoginLog.login_time.desc()).paginate(page=page, per_page=20)
    logs = logs_pagination.items
    return render_template("dashboard/login_logs.html", logs=logs, pagination=logs_pagination)


@main.route("/admin/feedbacks")
@login_required
@role_required("admin")
def admin_feedbacks():
    """Displays user feedback."""
    feedbacks = Feedback.query.order_by(Feedback.submitted_at.desc()).all()
    return render_template("admin/admin_feedback.html", feedbacks=feedbacks)


@main.route("/admin/reports")
@login_required
@role_required("admin")
def admin_reports():
    """Displays user and organization reports."""
    reports = Report.query.order_by(Report.reported_at.desc()).all()
    return render_template("admin/admin_reports.html", reports=reports)


@main.route("/admin/reports/<int:report_id>/resolve", methods=["POST"]) # Changed to POST
@login_required
@role_required("admin")
def resolve_report(report_id):
    """Marks a report as resolved."""
    report = Report.query.get_or_404(report_id)
    if report.status == 'Pending':
        report.status = "Resolved"
        db.session.commit()
        flash(f"Report ID {report_id} marked as resolved.", "success")
    else:
        flash(f"Report ID {report_id} was already {report.status}.", "info")
    return redirect(url_for("main.admin_reports"))


@main.route("/admin/reports/<int:report_id>/delete", methods=["POST"])
@login_required
@role_required("admin")
def admin_report_delete(report_id):
    """Deletes a report."""
    report = Report.query.get_or_404(report_id)
    try:
        db.session.delete(report)
        db.session.commit()
        flash(f"Report ID {report_id} deleted successfully.", "success")
    except Exception as e:
        current_app.logger.error(f"Error deleting report {report_id}: {e}")
        db.session.rollback()
        flash("Error deleting report.", "danger")
    return redirect(url_for("main.admin_reports"))


@main.route("/admin/feedbacks/<int:feedback_id>/reply", methods=["POST"])
@login_required
@role_required("admin")
def admin_feedback_reply(feedback_id):
    """Sends a notification reply to feedback and marks it as responded."""
    feedback = Feedback.query.get_or_404(feedback_id)
    if feedback.status == 'Open':
        notification = Notification(
            user_id=feedback.user_id,
            message="Thank you for your feedback! We appreciate you helping us improve Sahaayikha. - The Sahaayikha Team"
        )
        feedback.status = "Responded"
        db.session.add(notification)
        db.session.commit()
        flash("A 'thank you' notification has been sent to the user.", "success")
        # TODO: Consider sending push notification as well
    else:
        flash("Feedback has already been responded to.", "info")
    return redirect(url_for("main.admin_feedbacks"))


@main.route("/admin/feedbacks/<int:feedback_id>/delete", methods=["POST"])
@login_required
@role_required("admin")
def admin_feedback_delete(feedback_id):
    """Deletes a feedback entry."""
    feedback = Feedback.query.get_or_404(feedback_id)
    try:
        db.session.delete(feedback)
        db.session.commit()
        flash("Feedback deleted successfully.", "success")
    except Exception as e:
        current_app.logger.error(f"Error deleting feedback {feedback_id}: {e}")
        db.session.rollback()
        flash("Error deleting feedback.", "danger")
    return redirect(url_for("main.admin_feedbacks"))


# --- Admin - User/Org Management ---
@main.route("/admin/manage_users")
@login_required
@role_required("admin")
def admin_manage_users():
    """Displays lists of users and organizations for management."""
    search_query = request.args.get('search', '').strip()
    user_query = User.query
    org_query = Organization.query

    if search_query:
        search_term = f'%{search_query}%'
        user_query = user_query.filter(or_(
            User.first_name.ilike(search_term),
            User.last_name.ilike(search_term),
            User.email.ilike(search_term)
        ))
        org_query = org_query.filter(or_(
             Organization.name.ilike(search_term),
             Organization.email.ilike(search_term)
        ))

    users = user_query.order_by(User.first_name, User.last_name).all()
    organizations = org_query.order_by(Organization.name).all()

    return render_template("admin/manage_users.html", users=users, organizations=organizations, search_query=search_query)


@main.route("/admin/user/<int:user_id>/toggle_status", methods=["POST"])
@login_required
@role_required("admin")
def admin_toggle_user_status(user_id):
    """Blocks or unblocks a user."""
    user = User.query.get_or_404(user_id)
    if user.status == "Active":
        user.status = "Blocked"
        action = "blocked"
        category = "warning"
    elif user.status == "Blocked":
        user.status = "Active"
        action = "unblocked"
        category = "success"
    else: # Handle "Pending" or other statuses if necessary
         flash(f"User '{user.first_name}' has status '{user.status}', cannot toggle block.", "info")
         return redirect(url_for("main.admin_manage_users"))

    db.session.commit()
    flash(f"User '{user.first_name} {user.last_name or ''}' has been {action}.", category)
    return redirect(url_for("main.admin_manage_users"))


@main.route("/admin/org/<int:org_id>/toggle_status", methods=["POST"])
@login_required
@role_required("admin")
def admin_toggle_org_status(org_id):
    """Blocks or unblocks (re-approves) an organization."""
    org = Organization.query.get_or_404(org_id)
    # Allow toggling between Approved and Blocked
    if org.status == "Approved":
        org.status = "Blocked"
        action = "blocked"
        category = "warning"
    elif org.status == "Blocked":
        org.status = "Approved" # Unblocking means re-approving
        action = "unblocked"
        category = "success"
    else:
        # Don't toggle if Pending, Rejected, etc. Use approval screen for that.
         flash(f"Organization '{org.name}' has status '{org.status}'. Use approval screen or manage status directly.", "info")
         return redirect(url_for("main.admin_manage_users"))

    db.session.commit()
    flash(f"Organization '{org.name}' has been {action}.", category)
    return redirect(url_for("main.admin_manage_users"))


# --- Admin – Org Approval ---
@main.route("/admin/org-approvals")
@login_required
@role_required("admin")
def admin_org_approvals():
    """Displays organizations pending admin approval."""
    # Only show orgs that have verified their email but are still Pending admin review
    pending_orgs = Organization.query.filter_by(status="Pending", is_verified=True).order_by(Organization.registered_at).all()
    return render_template("admin/admin_org_approval.html", pending=pending_orgs)


@main.route("/admin/org-approve/<int:org_id>", methods=["POST"])
@login_required
@role_required("admin")
def approve_org(org_id):
    """Approves a pending organization."""
    org = Organization.query.get_or_404(org_id)
    if org.status == "Pending" and org.is_verified:
        org.status = "Approved"
        db.session.commit()
        flash(f"Organization '{org.name}' approved successfully.", "success")
        # TODO: Send email notification to organization
    else:
        flash(f"Organization '{org.name}' is not in a state to be approved (Status: {org.status}, Verified: {org.is_verified}).", "warning")
    return redirect(url_for("main.admin_org_approvals"))


@main.route("/admin/org-reject/<int:org_id>", methods=["POST"])
@login_required
@role_required("admin")
def reject_org(org_id):
    """Rejects a pending organization."""
    org = Organization.query.get_or_404(org_id)
    if org.status == "Pending" and org.is_verified:
        org.status = "Rejected"
        db.session.commit()
        flash(f"Organization '{org.name}' rejected.", "danger")
         # TODO: Send email notification to organization explaining rejection (optional)
    else:
        flash(f"Organization '{org.name}' is not in a state to be rejected (Status: {org.status}, Verified: {org.is_verified}).", "warning")
    return redirect(url_for("main.admin_org_approvals"))


# --- Admin – System Settings ---
@main.route("/admin/settings")
@login_required
@role_required("admin")
def system_settings():
    """Displays system settings for editing."""
    settings = SystemSetting.query.order_by(SystemSetting.key).all()
    return render_template("admin/system_settings.html", settings=settings)


@main.route("/admin/settings/update/<int:setting_id>", methods=["POST"])
@login_required
@role_required("admin")
def update_setting(setting_id):
    """Updates a system setting value."""
    setting = SystemSetting.query.get_or_404(setting_id)
    new_value = request.form.get("value", "").strip() # Get value and strip whitespace

    # Add validation based on key if needed (e.g., ITEM_EXPIRY_DAYS should be integer)
    if setting.key == 'ITEM_EXPIRY_DAYS':
        try:
            int_value = int(new_value)
            if int_value <= 0:
                 raise ValueError("Expiry days must be positive.")
            setting.value = str(int_value) # Store as string but validate as int
        except ValueError:
             flash("Invalid input: Item Expiry Days must be a positive number.", "danger")
             return redirect(url_for("main.system_settings"))
    elif setting.key == 'MAINTENANCE_MODE':
        if new_value.lower() not in ['true', 'false']:
             flash("Invalid input: Maintenance Mode must be 'true' or 'false'.", "danger")
             return redirect(url_for("main.system_settings"))
        setting.value = new_value.lower()
    else:
         # Generic update for other settings
         if not new_value: # Basic check for empty value
            flash(f"Value for '{setting.key}' cannot be empty.", "danger")
            return redirect(url_for("main.system_settings"))
         setting.value = new_value

    setting.updated_at = datetime.utcnow() # Update timestamp
    db.session.commit()
    flash(f"Setting '{setting.key}' updated successfully.", "success")
    return redirect(url_for("main.system_settings"))


# =========================
# ORGANIZATION DASHBOARD & ACTIONS
# =========================

@main.route("/org/dashboard", methods=['GET', 'POST'])
@login_required
@role_required("org")
def org_dashboard():
    """Displays the organization dashboard and handles posting new needs."""
    org = current_user._get_current_object()
    form = DisasterNeedForm()

    # --- Handle POST request (Form Submission) ---
    if form.validate_on_submit():
        new_need = DisasterNeed(
            title=form.title.data.strip(),
            categories=",".join(sorted(form.categories.data)) if form.categories.data else "",
            description=form.description.data.strip(),
            location=form.location.data,
            org_id=org.org_id
        )
        db.session.add(new_need)
        db.session.commit()
        try:
            send_disaster_notifications(new_need)
        except Exception as e:
            current_app.logger.error(f"Failed to send disaster notifications for need {new_need.need_id}: {e}")
            flash("Need posted, but failed to send notifications.", "warning")
        flash("New disaster need has been posted successfully.", "success")
        return redirect(url_for('main.org_dashboard', filter='needs'))

    # --- Handle GET request OR POST request where validation FAILED ---
    current_filter = request.args.get('filter', 'needs')
    my_needs, offers = [], []
    chat_sessions = [] # Will be populated by sorted list later
    has_unread_chats = False
    unread_session_ids = set()

    # --- *** MODIFICATION START: Query org's chat sessions, get latest messages, and sort *** ---
    org_sessions_query = ChatSession.query.filter(
        ChatSession.participant_org_id == org.org_id
    ).options(
        orm.joinedload(ChatSession.user_one), # Eager load user
        orm.joinedload(ChatSession.disaster_need) # Eager load subject (need)
    )

    sessions_with_latest_message = []
    all_org_sessions = org_sessions_query.all() # Fetch all sessions

    if all_org_sessions:
        session_ids = [s.session_id for s in all_org_sessions]

        # Query for unread messages *sent by users*
        unread_messages_query = ChatMessage.query.filter(
            ChatMessage.session_id.in_(session_ids),
            ChatMessage.is_read == False,
            ChatMessage.sender_type == 'user' # Only count messages from users
        ).options(orm.load_only(ChatMessage.session_id)) # Optimize query

        unread_session_ids = {msg.session_id for msg in unread_messages_query.all()}
        has_unread_chats = len(unread_session_ids) > 0

        # Query for the latest message timestamp in each session
        latest_messages_subquery = db.session.query(
            ChatMessage.session_id,
            func.max(ChatMessage.timestamp).label('latest_timestamp')
        ).filter(ChatMessage.session_id.in_(session_ids))\
         .group_by(ChatMessage.session_id)\
         .subquery()

        # Join sessions with their latest message timestamp
        sessions_with_time = db.session.query(
            ChatSession, latest_messages_subquery.c.latest_timestamp
        ).outerjoin(latest_messages_subquery, ChatSession.session_id == latest_messages_subquery.c.session_id)\
         .filter(ChatSession.session_id.in_(session_ids))\
         .all() # Returns list of tuples (ChatSession, latest_timestamp | None)

        # Create list of dictionaries for easier sorting
        for session, latest_timestamp in sessions_with_time:
            sessions_with_latest_message.append({
                'session': session,
                'latest_activity': latest_timestamp or session.started_at, # Fallback to start time
                'is_unread': session.session_id in unread_session_ids
            })

        # Sort: Unread first, then by latest activity timestamp descending
        sessions_with_latest_message.sort(key=lambda x: (not x['is_unread'], x['latest_activity']), reverse=True)

        # Assign the sorted sessions if the filter is 'chats'
        if current_filter == 'chats':
             chat_sessions = [s_data['session'] for s_data in sessions_with_latest_message]
    # --- *** MODIFICATION END *** ---


    # Fetch other data based on the selected filter
    if current_filter == 'needs':
        my_needs = DisasterNeed.query.filter_by(org_id=org.org_id).order_by(DisasterNeed.posted_at.desc()).all()
    elif current_filter in ['incoming', 'pickup', 'pending_donation', 'completed']:
        offer_query = DonationOffer.query.filter_by(org_id=org.org_id)
        offer_query = offer_query.options(
            orm.joinedload(DonationOffer.user),
            orm.joinedload(DonationOffer.need)
        )
        if current_filter == 'incoming':
            offer_query = offer_query.filter(DonationOffer.status == 'Pending Review')
        elif current_filter == 'pickup':
            offer_query = offer_query.filter(DonationOffer.status.in_(['Awaiting Pickup', 'Accepted', 'Partially Accepted']))
        elif current_filter == 'pending_donation':
            offer_query = offer_query.filter(DonationOffer.status == 'Donation Pending')
        elif current_filter == 'completed':
            offer_query = offer_query.filter(DonationOffer.status == 'Completed')
        offers = offer_query.order_by(DonationOffer.created_at.desc()).all()
    elif current_filter != 'chats': # Handle default or unknown filters (excluding 'chats' handled above)
        current_filter = 'needs' # Ensure filter reflects the default view
        my_needs = DisasterNeed.query.filter_by(org_id=org.org_id).order_by(DisasterNeed.posted_at.desc()).all()


    # --- Render the template ---
    return render_template(
        "dashboard/org_dashboard.html",
        org=org,
        my_items=my_needs, # Pass needs as my_items
        offers=offers,
        chat_sessions=chat_sessions, # Pass the sorted list
        form=form,
        current_filter=current_filter,
        unread_session_ids=unread_session_ids, # Pass the set of IDs
        has_unread_chats=has_unread_chats
    )

# =========================
# USER DASHBOARD
# =========================
@main.route("/dashboard")
@login_required
@role_required("user")
def dashboard():
    """Displays the user dashboard with different views and integrated search/filters."""
    view = request.args.get("view", "all")
    form_data = request.args.copy()
    if view == 'all' and 'location' not in form_data and current_user.location:
        form_data['location'] = current_user.location
    form = SearchForm(form_data)

    items, disaster_needs, my_offers = [], [], []
    regular_chats, disaster_chats = [], []
    unread_session_ids, has_unread_regular, has_unread_disaster = set(), False, False
    has_unread_chats = False
    items_json = "[]"
    map_center_coords = None
    map_radius_km = None
    current_location_filter = None
    active_search_term = request.args.get('search', '').strip()

    # --- Query User's Chats ---
    user_sessions_query = ChatSession.query.filter(
        or_(ChatSession.user_one_id == current_user.user_id, ChatSession.user_two_id == current_user.user_id)
    ).options(
        orm_joinedload(ChatSession.user_one),
        orm_joinedload(ChatSession.user_two),
        orm_joinedload(ChatSession.participant_org),
        orm_joinedload(ChatSession.trade_item),
        orm_joinedload(ChatSession.disaster_need)
    ) # Eager load participants and subjects

    # --- *** MODIFICATION START: Fetch latest message times and unread status *** ---
    sessions_with_latest_message = []
    unread_session_ids = set()
    all_user_sessions = user_sessions_query.all() # Fetch all sessions first

    if all_user_sessions:
        session_ids = [s.session_id for s in all_user_sessions]

        # Query for unread messages *not* sent by the current user
        unread_messages_query = ChatMessage.query.filter(
            ChatMessage.session_id.in_(session_ids),
            ChatMessage.is_read == False,
            not_(and_(ChatMessage.sender_id == current_user.user_id, ChatMessage.sender_type == 'user'))
        ).options(orm.load_only(ChatMessage.session_id)) # Optimize query
        
        unread_session_ids = {msg.session_id for msg in unread_messages_query.all()}
        has_unread_chats = len(unread_session_ids) > 0

        # Query for the latest message timestamp in each session
        latest_messages_subquery = db.session.query(
            ChatMessage.session_id,
            func.max(ChatMessage.timestamp).label('latest_timestamp')
        ).filter(ChatMessage.session_id.in_(session_ids))\
         .group_by(ChatMessage.session_id)\
         .subquery()

        # Join sessions with their latest message timestamp
        sessions_with_time = db.session.query(
            ChatSession, latest_messages_subquery.c.latest_timestamp
        ).outerjoin(latest_messages_subquery, ChatSession.session_id == latest_messages_subquery.c.session_id)\
         .filter(ChatSession.session_id.in_(session_ids))\
         .all() # Returns list of tuples (ChatSession, latest_timestamp | None)

        # Create list of dictionaries for easier sorting
        for session, latest_timestamp in sessions_with_time:
            sessions_with_latest_message.append({
                'session': session,
                'latest_activity': latest_timestamp or session.started_at, # Fallback to start time
                'is_unread': session.session_id in unread_session_ids
            })

        # Sort: Unread first, then by latest activity timestamp descending
        sessions_with_latest_message.sort(key=lambda x: (not x['is_unread'], x['latest_activity']), reverse=True)

    # --- *** MODIFICATION END *** ---


    # --- Fetch Data Based on View/Filter ---
    if view == "chats":
        # Use the sorted list
        all_sorted_sessions = [s_data['session'] for s_data in sessions_with_latest_message]
        regular_chats = [s for s in all_sorted_sessions if s.trade_item_id is not None]
        disaster_chats = [s for s in all_sorted_sessions if s.disaster_need_id is not None]
        # Unread flags are now based on the direct query result
        has_unread_regular = any(s.session_id in unread_session_ids for s in regular_chats)
        has_unread_disaster = any(s.session_id in unread_session_ids for s in disaster_chats)

    elif view == "mine":
        # ... (rest of the 'mine' view logic remains the same) ...
        query = Item.query.filter_by(user_id=current_user.user_id, status='Active')
        filter_type = request.args.get('filter')
        if filter_type in ["Trade", "Share"]:
            query = query.filter_by(type=filter_type)
        mine_categories = form.categories.data
        mine_urgency = form.urgency.data
        mine_condition = form.condition.data
        mine_sort_by = form.sort_by.data or 'newest'
        if mine_categories: query = query.filter(Item.category.in_(mine_categories))
        if mine_urgency: query = query.filter_by(urgency_level=mine_urgency)
        if mine_condition: query = query.filter_by(condition=mine_condition)
        if mine_sort_by == 'oldest':
            items = query.order_by(Item.created_at.asc()).all()
        else:
            items = query.order_by(Item.created_at.desc()).all()


    elif view == "bookmarks":
        items = Item.query.join(Bookmark, Item.item_id == Bookmark.item_id)\
                      .filter(Bookmark.user_id == current_user.user_id)\
                      .order_by(Bookmark.saved_at.desc()).all()
    elif view == "donations":
        my_offers = DonationOffer.query.filter_by(user_id=current_user.user_id).order_by(DonationOffer.created_at.desc()).all()

    else: # 'all' view
        # ... (rest of the 'all' view logic remains the same) ...
        query = Item.query.filter(Item.status == "Active", Item.user_id != current_user.user_id)
        current_location_filter = form.location.data
        search = active_search_term
        if search:
            search_term_like = f"%{search}%"
            query = query.filter(or_(Item.title.ilike(search_term_like), Item.description.ilike(search_term_like)))
        location_filter = form.location.data
        radius_str = form.radius.data
        categories = form.categories.data
        urgency = form.urgency.data
        condition = form.condition.data
        sort_by = form.sort_by.data or 'newest'
        active_categories = categories if categories else []
        if not active_categories and request.args.get('categories'):
             active_categories = [request.args.get('categories')]
        if active_categories:
            query = query.filter(Item.category.in_(active_categories))
        if urgency: query = query.filter_by(urgency_level=urgency)
        if condition: query = query.filter_by(condition=condition)
        filter_type = request.args.get('filter')
        if filter_type == 'Disaster':
            disaster_needs = DisasterNeed.query.order_by(DisasterNeed.posted_at.desc()).all()
            items = []
        else:
            if filter_type in ["Trade", "Share"]:
                query = query.filter_by(type=filter_type)
            all_items = query.order_by(Item.created_at.desc()).all()
            results = []
            user_lat, user_lon = None, None
            base_location_name = None
            items_with_distance = []
            if location_filter:
                base_location_name = location_filter
                map_center_coords = geocode_location(location_filter)
            else: map_center_coords = None
            if radius_str:
                try: map_radius_km = float(radius_str)
                except ValueError: map_radius_km = None
            else: map_radius_km = None
            radius_active = map_radius_km is not None
            sort_by_distance_active = sort_by == 'distance'
            center_coords_valid = map_center_coords and map_center_coords[0] is not None
            if (radius_active or sort_by_distance_active) and center_coords_valid:
                user_lat, user_lon = map_center_coords
                radius_km_filter = map_radius_km if radius_active else float('inf')
                for item in all_items:
                    item_lat, item_lon = item.latitude, item.longitude
                    if item_lat is None or item_lon is None:
                        coords = geocode_location(item.location)
                        if coords and coords[0] is not None:
                            item_lat, item_lon = coords
                    if item_lat is not None and item_lon is not None:
                         dist = haversine_distance(user_lat, user_lon, item_lat, item_lon)
                         if dist <= radius_km_filter: items_with_distance.append({'item': item, 'distance': dist})
                    elif not radius_active:
                        items_with_distance.append({'item': item, 'distance': float('inf')})
                if sort_by_distance_active: items_with_distance.sort(key=lambda x: x['distance'])
                results = [item_dist['item'] for item_dist in items_with_distance]
            else:
                 results = all_items
                 if radius_active and not center_coords_valid: flash(f"Could not find coordinates for '{base_location_name or 'selected location'}'. Cannot filter by radius.", "warning")
                 if sort_by_distance_active and not center_coords_valid: flash(f"Could not find coordinates for '{base_location_name or 'selected location'}'. Cannot sort by distance.", "warning"); sort_by = 'newest'
            if sort_by == 'oldest' and (not sort_by_distance_active or not center_coords_valid):
                 results.sort(key=lambda item: item.created_at)
            elif sort_by == 'newest' and (not sort_by_distance_active or not center_coords_valid):
                 results.sort(key=lambda item: item.created_at, reverse=True)
            items = results
            items_for_map = [
                {"item_id": item.item_id, "title": item.title, "latitude": item.latitude, "longitude": item.longitude}
                for item in items if item.latitude and item.longitude
            ]
            items_json = json.dumps(items_for_map)


    return render_template(
        "dashboard/user_dashboard.html",
        items=items,
        view=view,
        disaster_needs=disaster_needs,
        my_offers=my_offers,
        regular_chats=regular_chats,
        disaster_chats=disaster_chats,
        unread_session_ids=unread_session_ids, # Pass the set of IDs
        has_unread_regular=has_unread_regular,
        has_unread_disaster=has_unread_disaster,
        has_unread_chats=has_unread_chats,
        form=form,
        items_json=items_json,
        map_center_coords=map_center_coords,
        map_radius_km=map_radius_km,
        all_locations_coords=json.dumps(GEOCODE_DATA),
        current_location_filter=current_location_filter,
        active_search_term=active_search_term
    )

# =========================
# TRADE SESSION LOGIC (MODIFIED)
# =========================

@main.route("/trade/request/<int:item_id>", methods=['GET', 'POST'])
@login_required
@role_required("user")
def request_trade(item_id):
    item_to_get = Item.query.options(
        orm_joinedload(Item.images),
        orm_joinedload(Item.owner)
    ).get_or_404(item_id)
    form = FlaskForm() # Base form for CSRF

    # Validations (remain the same)
    if item_to_get.user_id == current_user.user_id:
        flash("You cannot request your own item.", "warning")
        return redirect(url_for('main.view_item', item_id=item_id))
    if item_to_get.status != 'Active':
        flash("This item is no longer available.", "info")
        return redirect(url_for('main.items_list'))
    if item_to_get.type != 'Trade':
        flash("Requests can only be made for 'Trade' items.", "info")
        return redirect(url_for('main.view_item', item_id=item_id))

    # --- Monetary Trade Offer Logic (Remains the same, check expected_return_category) ---
    if item_to_get.expected_return_category == 'Money':
        # ... (Monetary offer logic using expected_return_category) ...
        # Check if an active request already exists
        existing_request = TradeRequest.query.filter(
            TradeRequest.item_requested_id == item_id,
            TradeRequest.requester_id == current_user.user_id,
            TradeRequest.status.in_(['pending', 'accepted']) # Check for active states
        ).first()

        if existing_request:
            flash('You already have an active monetary offer/request for this item.', 'info')
            return redirect(url_for('main.view_item', item_id=item_id))

        # Find or create a user-user chat session
        session = ChatSession.query.filter(
            ChatSession.trade_item_id == item_id,
            ChatSession.participant_org_id == None, # Ensure user-user
            or_(
                (ChatSession.user_one_id == current_user.user_id) & (ChatSession.user_two_id == item_to_get.user_id),
                (ChatSession.user_one_id == item_to_get.user_id) & (ChatSession.user_two_id == current_user.user_id)
            )
        ).first()

        if not session:
            session = ChatSession(
                trade_item_id=item_id,
                user_one_id=current_user.user_id, # Requester is user_one
                user_two_id=item_to_get.user_id    # Owner is user_two
            )
            db.session.add(session)

        # Create a TradeRequest with no offered item
        new_request = TradeRequest(
            item_requested_id=item_to_get.item_id,
            owner_id=item_to_get.user_id,
            requester_id=current_user.user_id,
            item_offered_id=None  # <-- The 'null offer' for Money
        )
        db.session.add(new_request)

        # Create Notification
        notification_message = f"{current_user.first_name} sent a monetary offer request for your '{item_to_get.title}'."
        notification = Notification(
            user_id=item_to_get.user_id,
            message=notification_message,
            item_id=item_id
        )
        db.session.add(notification)

        try:
            db.session.commit()
            current_app.logger.info(f"Created money request {new_request.id} for item {item_id}")

            # Send Push Notification
            owner = item_to_get.owner
            if owner and owner.fcm_token:
                try:
                    send_push_notification(
                        token=owner.fcm_token,
                        title="New Monetary Offer!",
                        body=notification_message,
                        data={'itemId': str(item_id), 'type': 'trade_request'}
                    )
                except Exception as e:
                     current_app.logger.error(f"FCM failed for money request notification to user {owner.user_id}: {e}")

            flash('Your monetary offer request has been sent! You can discuss details in the chat.', 'success')
            # Redirect directly to chat for Money offers
            return redirect(url_for('main.chat', session_id=session.session_id))

        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Error creating money request for item {item_id}: {e}")
            flash("An error occurred while sending your request.", "danger")
            return redirect(url_for('main.view_item', item_id=item_id))
        # --- End Monetary Trade ---

    # --- Item-for-Item Trade Logic ---

    # Get expected categories from the item being requested
    suggested_main_cat = item_to_get.expected_return_category
    suggested_sub_cat = item_to_get.expected_return_sub_category

    # Base query for items the current user owns and can trade
    my_items_query = Item.query.filter_by(
        user_id=current_user.user_id,
        status='Active',
        type='Trade'
    )

    # Apply category filters based on owner's expectation
    if suggested_main_cat and suggested_main_cat != 'Money':
        my_items_query = my_items_query.filter(Item.category == suggested_main_cat)
        # --- *** ADD SUB-CATEGORY FILTER if specified *** ---
        if suggested_sub_cat:
            my_items_query = my_items_query.filter(Item.sub_category == suggested_sub_cat)
        # --- *** END SUB-CATEGORY FILTER *** ---

    # Exclude the item being requested itself (cannot offer item A for item A)
    my_items_query = my_items_query.filter(Item.item_id != item_id)

    # Fetch the filtered list of items the user can offer
    my_items_for_trade = my_items_query.order_by(Item.title).all()


    # --- Handle POST request (form submission) ---
    if request.method == 'POST':
        if not form.validate_on_submit(): # Basic CSRF check
            flash("Invalid form submission. Please try again.", "danger")
            # Re-render with the already filtered list
            return render_template("items/request_trade.html", item_to_get=item_to_get, my_items=my_items_for_trade,
                                   suggested_category=suggested_main_cat, suggested_sub_category=suggested_sub_cat, form=form)

        item_to_offer_id = request.form.get('item_to_offer')

        # Verify the selected item is in the *filtered* list the user was shown
        valid_offer_ids = {item.item_id for item in my_items_for_trade}
        try:
            selected_offer_id = int(item_to_offer_id)
        except (ValueError, TypeError):
             selected_offer_id = None

        if not selected_offer_id or selected_offer_id not in valid_offer_ids:
            flash("Please select a valid item from the suggested list to offer.", "warning")
            # Re-render with the filtered list
            return render_template("items/request_trade.html", item_to_get=item_to_get, my_items=my_items_for_trade,
                                   suggested_category=suggested_main_cat, suggested_sub_category=suggested_sub_cat, form=form)

        # Get the full object for the offered item (we know it's valid now)
        item_offered = Item.query.get(selected_offer_id)

        # Check for existing request (remains same)
        existing_request = TradeRequest.query.filter( TradeRequest.item_requested_id == item_id, TradeRequest.requester_id == current_user.user_id, TradeRequest.status.in_(['pending', 'accepted']) ).first()
        if existing_request:
             flash("You already have an active trade request for this item.", "info")
             return redirect(url_for('main.view_item', item_id=item_id))

        # Create request and notification (remains same)
        trade_request = TradeRequest(item_offered_id=selected_offer_id, item_requested_id=item_id, requester_id=current_user.user_id, owner_id=item_to_get.user_id, status='pending')
        db.session.add(trade_request)
        notification_message = f"{current_user.first_name} requested to trade their '{item_offered.title}' for your '{item_to_get.title}'."
        notification = Notification(user_id=item_to_get.user_id, message=notification_message, item_id=item_id)
        db.session.add(notification)

        try:
            db.session.commit()
            owner = item_to_get.owner
            if owner and owner.fcm_token:
                 # ...(Send Push Notification)...
                 try: send_push_notification( token=owner.fcm_token, title="New Trade Request!", body=notification_message, data={'itemId': str(item_id), 'type': 'trade_request'} )
                 except Exception as e: current_app.logger.error(f"FCM failed for trade request notification to user {owner.user_id}: {e}")

            flash("Trade request sent successfully!", "success")
            return redirect(url_for('main.view_item', item_id=item_id))
        except Exception as e:
            db.session.rollback(); current_app.logger.error(f"Error creating item trade request for item {item_id}: {e}")
            flash("An error occurred while sending your request.", "danger")
            return redirect(url_for('main.view_item', item_id=item_id))

    # --- GET Request ---
    # Render the page, passing the *filtered* list of items
    return render_template("items/request_trade.html",
                           item_to_get=item_to_get,
                           my_items=my_items_for_trade, # Pass the filtered list
                           suggested_category=suggested_main_cat,
                           suggested_sub_category=suggested_sub_cat,
                           form=form)


@main.route('/share/chat/<int:item_id>') # Define the URL
@login_required
@role_required("user") # Only users can initiate share chats
def start_share_chat(item_id):
    """Finds or creates a chat session for a 'Share' item and redirects to it."""
    item = Item.query.options(orm_joinedload(Item.owner)).get_or_404(item_id)

    # --- Security & Validation ---
    if item.user_id == current_user.user_id:
        flash("You cannot start a chat about your own item.", "warning")
        return redirect(url_for('main.view_item', item_id=item_id))
    if item.status != 'Active':
        flash("This item is no longer available.", "info")
        return redirect(url_for('main.items_list'))
    if item.type != 'Share':
        flash("This item is not listed for sharing.", "info")
        return redirect(url_for('main.view_item', item_id=item_id))
    if item.deal_finalized_at:
        flash("This item has already been shared.", "info")
        return redirect(url_for('main.view_item', item_id=item_id))

    owner = item.owner
    if not owner: # Should not happen with eager loading, but check anyway
        flash("Cannot start chat: Item owner not found.", "danger")
        return redirect(url_for('main.view_item', item_id=item_id))

    # --- Find or Create Chat Session ---
    session = ChatSession.query.filter(
        ChatSession.trade_item_id == item_id,
        ChatSession.participant_org_id == None, # Ensure user-user
        or_(
            (ChatSession.user_one_id == current_user.user_id) & (ChatSession.user_two_id == owner.user_id),
            (ChatSession.user_one_id == owner.user_id) & (ChatSession.user_two_id == current_user.user_id)
        )
    ).first()

    if not session:
        session = ChatSession(
            trade_item_id=item_id,          # Link session to the item
            user_one_id=current_user.user_id, # Initiator is user_one
            user_two_id=owner.user_id         # Owner is user_two
        )
        db.session.add(session)
        try:
            # Add notification for the owner (optional)
            notification_message = f"{current_user.first_name} started a chat to discuss receiving your shared item: '{item.title}'."
            notification = Notification(
                user_id=owner.user_id,
                message=notification_message,
                item_id=item_id
            )
            db.session.add(notification)

            db.session.commit() # Commit session and notification
            current_app.logger.info(f"Created share chat session {session.session_id} for item {item_id}")

            # Send Push Notification to owner (optional)
            if owner.fcm_token:
                try:
                    send_push_notification(
                        token=owner.fcm_token,
                        title="New Share Chat Started!",
                        body=f"{current_user.first_name} wants to chat about receiving '{item.title}'.",
                        data={'itemId': str(item_id), 'sessionId': str(session.session_id), 'type': 'share_chat_started'}
                    )
                except Exception as e:
                     current_app.logger.error(f"FCM failed for share chat start notification to user {owner.user_id}: {e}")

        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Error creating share chat session for item {item_id}: {e}")
            flash("An error occurred while trying to start the chat.", "danger")
            return redirect(url_for('main.view_item', item_id=item_id))

    elif session.status != 'Active':
        # Reactivate if blocked (owner might need to unblock from profile)
        flash("Cannot join chat. It might be blocked or inactive.", "warning")
        return redirect(url_for('main.view_item', item_id=item_id))


    # --- Redirect to the Chat ---
    return redirect(url_for('main.chat', session_id=session.session_id))



@main.route('/trade/accept/<int:request_id>', methods=['POST'])
@login_required
@role_required("user") # Only users accept item trades
def accept_trade(request_id):
    """Handles the item owner accepting a trade request."""
    trade_request = TradeRequest.query.get_or_404(request_id)

    # Security: Ensure current user is the owner and request is pending
    if trade_request.owner_id != current_user.user_id:
        abort(403)
    if trade_request.status != 'pending':
         flash("This trade request has already been actioned.", "info")
         return redirect(request.referrer or url_for('main.view_item', item_id=trade_request.item_requested_id))

    trade_request.status = 'accepted'

    # Find or create chat session
    chat_session = ChatSession.query.filter(
        ChatSession.trade_item_id == trade_request.item_requested_id,
        ChatSession.participant_org_id == None,
        or_(
            (ChatSession.user_one_id == trade_request.requester_id) & (ChatSession.user_two_id == trade_request.owner_id),
            (ChatSession.user_one_id == trade_request.owner_id) & (ChatSession.user_two_id == trade_request.requester_id)
        )
    ).first()

    if not chat_session:
        chat_session = ChatSession(
            trade_item_id=trade_request.item_requested_id,
            user_one_id=trade_request.owner_id, # Owner (accepter)
            user_two_id=trade_request.requester_id, # Requester
            status='Active'
        )
        db.session.add(chat_session)
        # Flush to get session_id before commit if needed immediately, though commit below is fine
        db.session.flush()
        current_app.logger.info(f"Created chat session {chat_session.session_id} upon accepting trade request {request_id}")
    else:
        # Ensure existing chat is active if it was somehow blocked/confirmed before
        chat_session.status = 'Active'


    # Notify the requester (in-app)
    notification_message = f"{current_user.first_name} accepted your trade request for '{trade_request.requested_item.title}'. You can now chat to arrange details."
    requester_notification = Notification(
        user_id=trade_request.requester_id,
        message=notification_message,
        item_id=trade_request.item_requested_id
    )
    db.session.add(requester_notification)
    db.session.commit() # Commit all changes together

    # --- ADD PUSH NOTIFICATION ---
    requester = trade_request.requester # Fetch the requester User object
    if requester and requester.fcm_token:
        try:
            send_push_notification(
                token=requester.fcm_token,
                title="Trade Accepted!",
                body=f"{current_user.first_name} accepted your trade for '{trade_request.requested_item.title}'.",
                # Include session_id to navigate user to chat
                data={'itemId': str(trade_request.item_requested_id), 'sessionId': str(chat_session.session_id), 'type': 'trade_accepted'}
            )
        except Exception as e:
            current_app.logger.error(f"FCM failed for trade accept notification to user {requester.user_id}: {e}")
    # --- END PUSH NOTIFICATION ---

    flash("Trade accepted! A chat has been started to finalize details.", "success")
    # Redirect directly to the chat session
    return redirect(url_for('main.chat', session_id=chat_session.session_id))

# ---

@main.route('/trade/reject/<int:request_id>', methods=['POST'])
@login_required
@role_required("user") # Only users reject item trades
def reject_trade(request_id):
    """Handles the item owner rejecting a trade request."""
    trade_request = TradeRequest.query.get_or_404(request_id)

    # Security: Ensure current user is the owner and request is pending
    if trade_request.owner_id != current_user.user_id:
        abort(403)
    if trade_request.status != 'pending':
        flash("This trade request has already been actioned.", "info")
        return redirect(request.referrer or url_for('main.view_item', item_id=trade_request.item_requested_id))

    trade_request.status = 'rejected'

     # Notify the requester (in-app)
    notification_message = f"Unfortunately, {current_user.first_name} rejected your trade request for '{trade_request.requested_item.title}'."
    requester_notification = Notification(
        user_id=trade_request.requester_id,
        message=notification_message,
        item_id=trade_request.item_requested_id # Link to item
    )
    db.session.add(requester_notification)
    db.session.commit() # Commit changes

    # --- ADD PUSH NOTIFICATION ---
    requester = trade_request.requester # Fetch the requester User object
    if requester and requester.fcm_token:
         try:
             send_push_notification(
                 token=requester.fcm_token,
                 title="Trade Rejected",
                 body=f"{current_user.first_name} rejected your trade request for '{trade_request.requested_item.title}'.",
                 data={'itemId': str(trade_request.item_requested_id), 'type': 'trade_rejected'}
             )
         except Exception as e:
             current_app.logger.error(f"FCM failed for trade reject notification to user {requester.user_id}: {e}")
    # --- END PUSH NOTIFICATION ---

    flash("Trade request rejected successfully.", "info")
    return redirect(request.referrer or url_for('main.view_item', item_id=trade_request.item_requested_id))

# ---

# =========================
# ITEM ROUTES
# =========================
@main.route("/item/new", methods=["GET", "POST"])
@login_required
@role_required("user")
def new_item():
    """Handles posting a new item."""
    form = ItemForm()
    submitted_item_sub = None
    submitted_expected_sub = None

    if request.method == 'POST':
        # --- *** Step 1: Populate choices BEFORE validation *** ---
        main_cat_submitted = request.form.get('category')
        expected_main_cat_submitted = request.form.get('expected_return_category')

        # Populate item sub_category choices
        if main_cat_submitted and main_cat_submitted in SUB_CATEGORIES:
            form.sub_category.choices = SUB_CATEGORIES[main_cat_submitted]
        else:
            form.sub_category.choices = [] # Ensure it's empty if no valid main cat

        # Populate expected_return_sub_category choices
        if expected_main_cat_submitted and expected_main_cat_submitted in SUB_CATEGORIES:
            form.expected_return_sub_category.choices = SUB_CATEGORIES[expected_main_cat_submitted]
        else:
            form.expected_return_sub_category.choices = []

        # Store submitted values for potential re-population if validation fails later
        submitted_item_sub = request.form.get('sub_category')
        submitted_expected_sub = request.form.get('expected_return_sub_category')
        # --- *** End Step 1 *** ---

    # --- *** Step 2: Run WTForms validation *** ---
    if form.validate_on_submit():
        # Validation passed, proceed to save
        lat, lon = geocode_location(getattr(current_user, "location", None))
        item = Item(
            title=form.title.data.strip(),
            description=form.description.data.strip() if form.description.data else None,
            category=form.category.data,
            # Use data from the validated form object
            sub_category=form.sub_category.data if form.sub_category.data else None,
            type=form.type.data,
            condition=form.condition.data,
            urgency_level=form.urgency_level.data,
            # --- *** Save split expected return fields *** ---
            expected_return_category=form.expected_return_category.data if form.type.data == 'Trade' else None,
            expected_return_sub_category=form.expected_return_sub_category.data if form.type.data == 'Trade' and form.expected_return_sub_category.data else None,
             # --- *** END CHANGE *** ---
            location=getattr(current_user, "location", None),
            status="Active",
            created_at=datetime.utcnow(),
            user_id=getattr(current_user, "user_id", None),
            latitude=lat,
            longitude=lon
        )
        db.session.add(item)
        db.session.flush()

        # ... (Image handling logic remains the same) ...
        images_added = []
        if form.images.data:
            files = form.images.data if isinstance(form.images.data, list) else [form.images.data]
            for f in files:
                 # ...(rest of image saving)...
                 if f and f.filename:
                    try:
                        filename = secure_filename(f"{item.item_id}_{datetime.utcnow().timestamp()}_{f.filename}")
                        filepath = os.path.join(ITEM_UPLOAD_FOLDER, filename)
                        f.save(filepath)
                        images_added.append(ItemImage(item_id=item.item_id, image_url=f"images/items/{filename}"))
                    except Exception as e:
                        current_app.logger.error(f"Failed to save image {f.filename} for item {item.item_id}: {e}")
                        flash(f"Could not save image: {f.filename}", "warning")
            if images_added:
                db.session.add_all(images_added)


        # Log creation history
        db.session.add(ItemHistory(
            item_id=item.item_id,
            user_id=getattr(current_user, "user_id", None),
            action="Item Created",
            timestamp=datetime.utcnow()
        ))
        db.session.commit()

        send_smart_notifications(item) # Trigger notifications

        flash("Item posted successfully!", "success")
        return redirect(url_for("main.dashboard", view="mine"))

    # --- *** Step 3: Handle Validation Errors (if POST and validate_on_submit failed) *** ---
    elif request.method == 'POST':
        # Flash WTForms errors (which now includes sub-category choice errors)
        validation_failed = False
        for fieldName, errorMessages in form.errors.items():
            fieldLabel = getattr(getattr(form, fieldName, None), 'label', None)
            display_name = fieldLabel.text if fieldLabel else fieldName.replace('_', ' ').title()
            for error in errorMessages:
                flash(f"Error in {display_name}: {error}", "danger")
                validation_failed = True

        # Restore submitted sub-category values if validation failed, so JS can re-select them
        if validation_failed:
             form.sub_category.data = submitted_item_sub
             form.expected_return_sub_category.data = submitted_expected_sub
             # Re-populate choices based on the *originally submitted* main categories
             # (Form object still holds these after failed validation)
             if form.category.data and form.category.data in SUB_CATEGORIES:
                 form.sub_category.choices = SUB_CATEGORIES[form.category.data]
             if form.expected_return_category.data and form.expected_return_category.data in SUB_CATEGORIES:
                 form.expected_return_sub_category.choices = SUB_CATEGORIES[form.expected_return_category.data]

    # --- *** Step 4: Render Template (for GET or failed POST) *** ---
    # Ensure choices are set for GET request display as well (though JS handles it mainly)
    if request.method == 'GET':
        form.sub_category.choices = []
        form.expected_return_sub_category.choices = []

    return render_template(
        "items/post_item.html",
        form=form,
        sub_categories_json=json.dumps(SUB_CATEGORIES)
    )

@main.route("/item/<int:item_id>")
def view_item(item_id):
    """Displays the details page for a specific item."""
    item = Item.query.options(
        orm_joinedload(Item.images),
        orm_joinedload(Item.owner)
    ).get_or_404(item_id)

    is_bookmarked = False
    chat_session = None
    deal = None
    trade_request = None
    context_trade_request = None
    proposer = None
    current_actor = current_user._get_current_object() if current_user.is_authenticated else None

    # Check for Trade Request Context
    context_trade_id = request.args.get('context_trade_id', type=int)
    if context_trade_id and current_actor and isinstance(current_actor, User):
        temp_trade_request = TradeRequest.query.options(
            orm_joinedload(TradeRequest.requested_item),
            orm_joinedload(TradeRequest.offered_item)
        ).get(context_trade_id)
        if (temp_trade_request and
                temp_trade_request.item_offered_id == item_id and
                temp_trade_request.owner_id == current_actor.user_id):
            context_trade_request = temp_trade_request
            proposer = temp_trade_request.requester

    # Fetch details relevant only if a user is logged in
    if current_actor and isinstance(current_actor, User):
        is_bookmarked = Bookmark.query.filter_by(user_id=current_actor.user_id, item_id=item.item_id).count() > 0
        chat_session = ChatSession.query.filter(
            ChatSession.trade_item_id == item.item_id,
            ChatSession.participant_org_id == None,
            or_(
                (ChatSession.user_one_id == current_actor.user_id) & (ChatSession.user_two_id == item.user_id),
                (ChatSession.user_one_id == item.user_id) & (ChatSession.user_two_id == current_actor.user_id)
            )
        ).first()

        if chat_session:
            deal = DealProposal.query.filter_by(chat_session_id=chat_session.session_id).first()
            if not proposer:
                other_user_obj = chat_session.get_other_user(current_actor.user_id)
                if other_user_obj: proposer = User.query.get(other_user_obj.user_id)

        if item.user_id != current_actor.user_id and item.type == 'Trade':
            trade_request = TradeRequest.query.filter(
                TradeRequest.item_requested_id == item.item_id,
                TradeRequest.requester_id == current_actor.user_id,
                TradeRequest.status.in_(['pending', 'accepted'])
            ).first()
        elif item.user_id == current_actor.user_id and not proposer:
             accepted_trade_request = TradeRequest.query.filter(
                 TradeRequest.item_requested_id == item.item_id,
                 TradeRequest.owner_id == current_actor.user_id,
                 TradeRequest.status == 'accepted'
             ).options(orm_joinedload(TradeRequest.requester)).first()
             if accepted_trade_request:
                 proposer = accepted_trade_request.requester
                 trade_request = accepted_trade_request

    # Fetch pending incoming trade requests if owner
    incoming_trade_requests = []
    # --- *** Check expected_return_category instead of expected_return *** ---
    if current_actor and isinstance(current_actor, User) and item.user_id == current_actor.user_id and item.type == 'Trade' and item.expected_return_category != 'Money':
    # --- *** END CHANGE *** ---
        incoming_trade_requests = TradeRequest.query.options(
            orm_joinedload(TradeRequest.requester),
            orm_joinedload(TradeRequest.offered_item).joinedload(Item.images)
        ).filter_by(
            item_requested_id=item.item_id,
            status='pending'
        ).order_by(TradeRequest.created_at.desc()).all()

    return render_template(
        "items/view_item.html",
        item=item,
        is_bookmarked=is_bookmarked,
        session=chat_session,
        deal=deal,
        proposer=proposer,
        trade_request=trade_request,
        context_trade_request=context_trade_request,
        incoming_trade_requests=incoming_trade_requests
    )


@main.route('/deal/<int:session_id>/propose', methods=['POST'])
@login_required
@role_required("user") # Deals/Shares are currently only between users
def propose_deal(session_id):
    decision = request.form.get('decision') # 'confirmed' or 'rejected'
    if decision not in ['confirmed', 'rejected']:
        flash("Invalid decision.", "danger")
        return redirect(request.referrer or url_for('main.chat', session_id=session_id))

    chat_session = ChatSession.query.get_or_404(session_id)
    # Use the subject property to get the item (works for Trade or Share)
    item = chat_session.subject

    # --- Security Checks ---
    # Ensure it's a user-user chat and the item exists
    if not item or chat_session.is_org_chat or not isinstance(item, Item):
         abort(404) # Or handle appropriately if item was deleted mid-chat
    if chat_session.user_one_id != current_user.user_id and chat_session.user_two_id != current_user.user_id:
         abort(403)
    # Check if item is still Active (relevant for both Trade and Share)
    if item.status != 'Active':
         flash(f"This item is no longer active (Status: {item.status}).", "warning")
         return redirect(url_for('main.chat', session_id=session_id))


    # --- Find or create the deal proposal ---
    deal = DealProposal.query.filter_by(chat_session_id=session_id).first()
    if not deal:
        deal = DealProposal(chat_session_id=session_id, owner_status='pending', proposer_status='pending')
        db.session.add(deal)

    # --- Update the status for the current user ---
    is_owner = item.user_id == current_user.user_id
    if is_owner:
        deal.owner_status = decision
    else:
        # Determine who the proposer is (the non-owner in the chat)
        # This logic assumes user_one is proposer if not owner, adjust if needed
        deal.proposer_status = decision

    deal.updated_at = datetime.utcnow()

    # --- Determine the other party to notify ---
    other_user = None
    other_user_id = chat_session.user_two_id if chat_session.user_one_id == current_user.user_id else chat_session.user_one_id
    if other_user_id:
        other_user = User.query.get(other_user_id) # Fetch the User object

    # --- Check Deal Outcome and Prepare Messages ---
    final_outcome = None
    flash_message = ""
    flash_category = "info"
    push_title = f"{item.type.capitalize()} Update" # Dynamic title
    push_body = f"{current_user.first_name} set their status to '{decision}' for the {item.type.lower()} of '{item.title}'."
    push_data = {'sessionId': str(session_id), 'itemId': str(item.item_id), 'type': 'deal_update'} # Keep type generic or split later

    # --- >>> MODIFIED LOGIC FOR CONFIRMATION <<< ---
    if deal.owner_status == 'confirmed' and deal.proposer_status == 'confirmed':
        item.deal_finalized_at = datetime.utcnow()
        # Set status based on item type
        if item.type == 'Share':
            item.status = 'Shared'
            flash_message = 'Share confirmed by both parties! The item is marked as shared.'
            push_title = "Item Shared!"
            push_body = f"The sharing arrangement for '{item.title}' is confirmed!"
            push_data['type'] = 'share_confirmed' # Specific type
        else: # Default to Trade
            item.status = 'Traded'
            flash_message = 'Deal confirmed by both parties! The item is marked as traded.'
            push_title = "Deal Confirmed!"
            push_body = f"The deal for '{item.title}' is confirmed! You can finalize details in the chat."
            push_data['type'] = 'trade_confirmed' # Specific type

        chat_session.status = 'Confirmed' # Use 'Confirmed' for both
        flash_category = 'success'
        final_outcome = 'confirmed'
    # --- >>> END MODIFICATION <<< ---

    # --- Rejection Logic (Remains largely the same) ---
    elif deal.owner_status == 'rejected' or deal.proposer_status == 'rejected':
        item.deal_finalized_at = None # Ensure it's not finalized
        chat_session.status = 'Active' # Keep chat active
        flash_message = f'Your decision ({decision}) has been recorded. The {item.type.lower()} cannot proceed due to a rejection.'
        flash_category = 'warning'
        final_outcome = 'rejected'
        rejected_by_role = "owner" if (is_owner and decision == 'rejected') or (not is_owner and deal.owner_status == 'rejected') else "other user"

        push_title = f"{item.type.capitalize()} Rejected"
        if decision == 'rejected': # If the current user just rejected
             push_body = f"{current_user.first_name} (the {('owner' if is_owner else 'other user')}) rejected the {item.type.lower()} proposal for '{item.title}'."
        else: # If the other user already rejected
             push_body = f"The {item.type.lower()} proposal for '{item.title}' was previously rejected by the {rejected_by_role}."
        push_data['type'] = f'{item.type.lower()}_rejected' # e.g., 'share_rejected'

    # --- Pending Logic (Remains the same) ---
    else:
        item.deal_finalized_at = None
        chat_session.status = 'Active'
        flash_message = f'Your decision has been recorded. Waiting for the other party to confirm the {item.type.lower()}.'
        flash_category = 'info'
        final_outcome = 'pending'
        push_body = f"{current_user.first_name} set their status to '{decision}' for the {item.type.lower()} of '{item.title}'. Waiting for your decision."


    # --- Commit Changes ---
    try:
        db.session.commit()
        flash(flash_message, flash_category)
    except Exception as e:
        # ... (error handling remains the same) ...
        db.session.rollback()
        current_app.logger.error(f"Error saving deal/share status for session {session_id}: {e}")
        flash("An error occurred while updating the status.", "danger")
        return redirect(request.referrer or url_for('main.chat', session_id=session_id))


    # --- Send Push Notification (after commit) ---
    if other_user and other_user.fcm_token:
        # ... (notification sending logic remains the same, using updated push_title, push_body, push_data) ...
        try:
            send_push_notification(
                token=other_user.fcm_token,
                title=push_title,
                body=push_body,
                data=push_data
            )
        except Exception as e:
            current_app.logger.error(f"FCM failed for {item.type.lower()} update notification to user {other_user.user_id}: {e}")


    return redirect(request.referrer or url_for('main.chat', session_id=session_id))


@main.route("/item/<int:item_id>/history")
@login_required # Only logged-in users? Or maybe only owner/admin?
def item_history(item_id):
    """Displays the history log for an item."""
    item = Item.query.get_or_404(item_id)
    # Optional: Add permission check (e.g., only owner or admin can view history)
    # if item.user_id != current_user.user_id and not isinstance(current_user._get_current_object(), Admin):
    #     abort(403)

    history = ItemHistory.query.filter_by(item_id=item_id).order_by(ItemHistory.timestamp.desc()).all()
    return render_template("items/item_history.html", history=history, item=item) # Pass item for context


@main.route("/item/image/<int:image_id>/delete", methods=["POST"])
@login_required
@role_required("user") # Only users own items with images
def delete_item_image(image_id):
    """Handles AJAX request to delete an item image."""
    image = ItemImage.query.get_or_404(image_id)
    item = image.item

    # Security check: Ensure the current user owns the item
    if item.user_id != current_user.user_id:
        return jsonify({"success": False, "error": "Permission denied."}), 403

    try:
        # Construct full path and delete file
        # Assumes image_url is relative path like "images/items/filename.jpg"
        file_path = os.path.join(current_app.static_folder, image.image_url)

        if os.path.exists(file_path):
            os.remove(file_path)

        # Delete database record
        db.session.delete(image)
        db.session.commit()

        return jsonify({"success": True})

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error deleting item image {image_id}: {e}")
        return jsonify({"success": False, "error": "Server error deleting image."}), 500


@main.route("/item/<int:item_id>/edit", methods=["GET", "POST"])
@login_required
@role_required("user")
def edit_item(item_id):
    item = Item.query.options(orm.joinedload(Item.images)).get_or_404(item_id)
    if item.user_id != current_user.user_id:
        abort(403)

    # Populate form from object on GET, leave empty on POST (WTForms handles POST data)
    form = ItemForm(obj=item if request.method == 'GET' else None)
    submitted_item_sub = None
    submitted_expected_sub = None

    if request.method == 'POST':
        # --- *** Step 1: Populate choices BEFORE validation *** ---
        main_cat_submitted = request.form.get('category')
        expected_main_cat_submitted = request.form.get('expected_return_category')

        if main_cat_submitted and main_cat_submitted in SUB_CATEGORIES:
            form.sub_category.choices = SUB_CATEGORIES[main_cat_submitted]
        else:
             form.sub_category.choices = []

        if expected_main_cat_submitted and expected_main_cat_submitted in SUB_CATEGORIES:
            form.expected_return_sub_category.choices = SUB_CATEGORIES[expected_main_cat_submitted]
        else:
            form.expected_return_sub_category.choices = []

        submitted_item_sub = request.form.get('sub_category')
        submitted_expected_sub = request.form.get('expected_return_sub_category')
        # --- *** End Step 1 *** ---

    # --- *** Step 2: Run WTForms validation *** ---
    if form.validate_on_submit():
        item.title = form.title.data.strip()
        item.description = form.description.data.strip() if form.description.data else None
        item.category = form.category.data
        item.sub_category = form.sub_category.data if form.sub_category.data else None
        item.type = form.type.data
        item.condition = form.condition.data
        item.urgency_level = form.urgency_level.data

        # --- *** Update split expected return fields *** ---
        if item.type == 'Trade':
            item.expected_return_category = form.expected_return_category.data
            item.expected_return_sub_category = form.expected_return_sub_category.data if form.expected_return_sub_category.data else None
        else:
             item.expected_return_category = None
             item.expected_return_sub_category = None
        # --- *** END CHANGE *** ---

        # ... (Image handling logic remains the same) ...
        images_added = []
        if form.images.data:
            files = form.images.data if isinstance(form.images.data, list) else [form.images.data]
            current_image_count = db.session.query(ItemImage).filter_by(item_id=item.item_id).count() # Query current count
            if current_image_count + len(files) > 8:
                 flash(f"Cannot upload more than 8 images in total. You have {current_image_count} existing images.", "warning")
            else:
                for f in files:
                     # ...(rest of image saving)...
                     if f and f.filename:
                        try:
                            filename = secure_filename(f"{item.item_id}_{datetime.utcnow().timestamp()}_{f.filename}")
                            filepath = os.path.join(ITEM_UPLOAD_FOLDER, filename)
                            f.save(filepath)
                            images_added.append(ItemImage(item_id=item.item_id, image_url=f"images/items/{filename}"))
                        except Exception as e:
                            current_app.logger.error(f"Failed to save image {f.filename} during edit for item {item.item_id}: {e}")
                            flash(f"Could not save image: {f.filename}", "warning")
                if images_added:
                    db.session.add_all(images_added)


        # Log edit history
        db.session.add(ItemHistory(item_id=item.item_id, user_id=current_user.user_id, action="Item Edited"))
        db.session.commit()
        flash("Item updated successfully.", "success")
        return redirect(url_for("main.view_item", item_id=item.item_id))

    # --- *** Step 3: Handle Validation Errors (if POST and validate_on_submit failed) *** ---
    elif request.method == 'POST':
        validation_failed = False
        for fieldName, errorMessages in form.errors.items():
            fieldLabel = getattr(getattr(form, fieldName, None), 'label', None)
            display_name = fieldLabel.text if fieldLabel else fieldName.replace('_', ' ').title()
            for error in errorMessages:
                flash(f"Error in {display_name}: {error}", "danger")
                validation_failed = True

        # Restore submitted sub-category values if validation failed
        if validation_failed:
             form.sub_category.data = submitted_item_sub
             form.expected_return_sub_category.data = submitted_expected_sub
             # Re-populate choices based on the *originally submitted* main categories
             if form.category.data and form.category.data in SUB_CATEGORIES:
                 form.sub_category.choices = SUB_CATEGORIES[form.category.data]
             if form.expected_return_category.data and form.expected_return_category.data in SUB_CATEGORIES:
                 form.expected_return_sub_category.choices = SUB_CATEGORIES[form.expected_return_category.data]

    # --- *** Step 4: Render Template (for GET or failed POST) *** ---
    # For GET, ensure form object data is set for JS (obj=item should handle this)
    # Also ensure choices are pre-populated for JS based on existing item data
    if request.method == 'GET':
        if item.category and item.category in SUB_CATEGORIES:
            form.sub_category.choices = SUB_CATEGORIES[item.category]
        else:
            form.sub_category.choices = [] # Set choices to empty list initially for GET

        if item.expected_return_category and item.expected_return_category in SUB_CATEGORIES:
            form.expected_return_sub_category.choices = SUB_CATEGORIES[item.expected_return_category]
        else:
             form.expected_return_sub_category.choices = []


    return render_template(
        "items/edit_item.html",
        form=form,
        item=item,
        sub_categories_json=json.dumps(SUB_CATEGORIES)
    )


@main.route("/item/<int:item_id>/delete", methods=["POST"])
@login_required
@role_required("user") # Only users delete items
def delete_item(item_id):
    """Handles deleting an item (soft delete recommended)."""
    item = Item.query.get_or_404(item_id)

    # Security check: Only owner can delete
    if item.user_id != current_user.user_id:
        abort(403)

    try:
        # --- Option 1: Soft Delete (Recommended) ---
        if item.status != 'Deleted':
            item.status = "Deleted"
            # Log deletion history
            db.session.add(ItemHistory(item_id=item.item_id, user_id=current_user.user_id, action="Item Deleted by User"))
            db.session.commit()
            flash("Item marked as deleted.", "success")
        else:
            flash("Item was already deleted.", "info")

        # --- Option 2: Hard Delete (Less Recommended - loses history, breaks relations if not careful) ---
        # # Delete associated images first (files and DB records)
        # for img in item.images:
        #     try:
        #         file_path = os.path.join(current_app.static_folder, img.image_url)
        #         if os.path.exists(file_path):
        #             os.remove(file_path)
        #     except Exception as e:
        #         current_app.logger.warning(f"Error deleting image file {img.image_url} for item {item_id}: {e}")
        #     db.session.delete(img)
        # # Delete history, bookmarks, reports, notifications related to this item? Or keep them?
        # # Delete trade requests involving this item?
        # # Delete chat sessions related to this item?
        # # ... Careful cascading needed ...
        # db.session.delete(item)
        # db.session.commit()
        # flash("Item permanently deleted.", "success")

    except Exception as e:
         current_app.logger.error(f"Error deleting item {item_id}: {e}")
         db.session.rollback()
         flash("An error occurred while deleting the item.", "danger")

    return redirect(url_for("main.dashboard", view="mine")) # Redirect to 'My Items'


# =========================
# BOOKMARKS
# =========================
@main.route("/bookmark/<int:item_id>", methods=['POST'])
@login_required # Allow both users and orgs TO HIT THE ROUTE initially
def add_or_remove_bookmark(item_id):
    """Adds or removes a bookmark for the current user OR organization and item."""
    actor = current_user._get_current_object()

    # <<< --- ADDED CHECK: Prevent Orgs --- >>>
    if isinstance(actor, Organization):
        flash("Bookmarking is not available for organizations.", "warning")
        return redirect(request.referrer or url_for("main.home"))
    # <<< --- END ADDED CHECK --- >>>

    # --- Existing User Logic ---
    if isinstance(actor, User):
        item = Item.query.get_or_404(item_id) # Ensure item exists
        bookmark = Bookmark.query.filter_by(user_id=actor.user_id, item_id=item_id).first()
        owner_kwargs = {'user_id': actor.user_id}
        actor_name = actor.first_name

        if bookmark:
            # Remove bookmark
            db.session.delete(bookmark)
            db.session.commit()
            flash(f"Removed '{item.title}' from bookmarks.", "info")
        else:
            # Add bookmark
            try:
                new_bookmark = Bookmark(item_id=item_id, **owner_kwargs)
                db.session.add(new_bookmark)
                db.session.commit()
                flash(f"Added '{item.title}' to bookmarks.", "success")
            except Exception as e: # Catch potential constraint violations
                 db.session.rollback()
                 current_app.logger.error(f"Error adding bookmark for item {item_id} by {actor_name}: {e}")
                 flash("Could not add bookmark. Please try again.", "danger")

        # Redirect back to the page the user was on
        return redirect(request.referrer or url_for("main.view_item", item_id=item_id))
    else:
        # Fallback for unexpected actor types (though covered by Org check above)
        flash("Invalid account type for bookmarking.", "warning")
        return redirect(request.referrer or url_for("main.home"))


@main.route("/bookmarks")
@login_required
@role_required("user")
def bookmarks():
    """Displays the user's bookmarked items (now handled by dashboard view)."""
    # This route might be redundant if dashboard handles it, but keep for direct access if needed
    # Fetch bookmarked items directly
    bookmarked_items = Item.query.join(Bookmark, Item.item_id == Bookmark.item_id)\
                        .filter(Bookmark.user_id == current_user.user_id)\
                        .order_by(Bookmark.saved_at.desc()).all()

    # Pass items directly to a template (or reuse dashboard template logic)
    return render_template("features/bookmarks.html", items=bookmarked_items)


# =========================
# CATEGORY FOLLOW
# =========================
@main.route('/follow', methods=['GET', 'POST'])
@login_required
@role_required("user")
def follow_category_page():
    """Page to manage followed categories and add new ones via form."""
    form = CategoryFollowForm()

    # --- Fetch followed categories for form choices BEFORE validation ---
    followed = CategoryFollow.query.filter_by(user_id=current_user.user_id).order_by(CategoryFollow.category).all()
    followed_names = {f.category for f in followed}

    # Prepare choices for the form, excluding already followed categories
    available_choices = [(c[0], c[1]) for c in CATEGORIES if c[0] and c[0] not in followed_names]
    form.category.choices = [('', 'Select Category to Follow...')] + available_choices


    # --- Handle POST request (form submission to follow a category) ---
    if form.validate_on_submit():
        category_to_follow = form.category.data

        # *** CORRECTION START ***
        # Perform the follow action directly here
        valid_categories = {c[0] for c in CATEGORIES if c[0]}
        if category_to_follow not in valid_categories:
            flash(f"'{category_to_follow}' is not a valid category.", "warning")
        elif category_to_follow in followed_names:
            flash(f"You are already following '{category_to_follow}'.", "info")
        else:
            try:
                new_follow = CategoryFollow(user_id=current_user.user_id, category=category_to_follow)
                db.session.add(new_follow)
                db.session.commit()
                flash(f"You are now following '{category_to_follow}'.", "success")
                # Redirect back to the same page using GET to refresh the lists
                return redirect(url_for('main.follow_category_page'))
            except Exception as e:
                db.session.rollback()
                current_app.logger.error(f"Error following category {category_to_follow} for user {current_user.user_id}: {e}")
                flash("An error occurred while trying to follow the category.", "danger")
        # *** CORRECTION END ***

        # No longer redirecting to the POST-only route:
        # return redirect(url_for('main.follow_unfollow_category', category_name=category)) # <-- REMOVE/COMMENT OUT THIS LINE

    # --- Handle GET request (display page) ---
    # Refresh followed list in case the POST request failed validation but didn't redirect
    followed = CategoryFollow.query.filter_by(user_id=current_user.user_id).order_by(CategoryFollow.category).all()

    return render_template('features/follow_category.html', form=form, followed_categories=followed)

# --- Keep the follow_unfollow_category function as is for the unfollow buttons ---
@main.route("/category/follow/<string:category_name>", methods=['POST']) # Still POST only
@login_required
@role_required("user")
def follow_unfollow_category(category_name):
    """Toggles following/unfollowing a specific category (Handles Unfollow button POST)."""
    valid_categories = {c[0] for c in CATEGORIES if c[0]}
    if category_name not in valid_categories:
        flash(f"'{category_name}' is not a valid category.", "warning")
        return redirect(request.referrer or url_for("main.follow_category_page"))

    follow = CategoryFollow.query.filter_by(user_id=current_user.user_id, category=category_name).first()

    if follow:
        # Unfollow
        db.session.delete(follow)
        db.session.commit()
        flash(f"You are no longer following '{category_name}'.", "info")
    else:
        # Follow (This case might not be hit often now, but keep for robustness)
        new_follow = CategoryFollow(user_id=current_user.user_id, category=category_name)
        db.session.add(new_follow)
        db.session.commit()
        flash(f"You are now following '{category_name}'.", "success")

    # Redirect back to the manage follow page after action
    return redirect(url_for("main.follow_category_page"))


@main.route('/category/<string:category_name>')
def category_items(category_name):
    """Displays items belonging to a specific category."""
     # Basic validation
    valid_categories = {c[0] for c in CATEGORIES if c[0]}
    if category_name not in valid_categories:
        abort(404) # Or redirect with a flash message

    items_in_category = Item.query.filter(
                            Item.category == category_name,
                            Item.status == 'Active'
                         ).order_by(Item.created_at.desc()).all()

    return render_template('items/category_items.html', items=items_in_category, category={'name': category_name})


# =========================
# DISASTER NEEDS & DONATIONS
# =========================

@main.route("/disaster-relief")
@login_required
@role_required("user") # Only users view the feed this way
def disaster_relief_feed():
    """Shows active disaster needs to users."""
    needs = DisasterNeed.query.order_by(DisasterNeed.posted_at.desc()).all()
    return render_template("features/disaster_relief_feed.html", needs=needs)


@main.route("/disaster-need/<int:need_id>/offer", methods=['GET', 'POST'])
@login_required
@role_required("user") # Only users make offers
def make_donation_offer(need_id):
    """Handles users submitting a donation offer for a disaster need."""
    need = DisasterNeed.query.get_or_404(need_id)
    form = DonationOfferForm()

    # --- *** THIS IS THE FIX *** ---
    # Get the specific item form from the field list (assuming JS adds at least one)
    # This logic applies *before* validation for GET and *during* validation for POST
    # We must set choices *before* validation is run on POST.
    # A better way might be to set this in the form's __init__ if we passed the need,
    # but for this route, we can set it dynamically.

    # Get categories from the specific DisasterNeed
    if need.categories:
        # Split the comma-separated string of categories into a list
        org_categories_list = [cat.strip() for cat in need.categories.split(',') if cat.strip()]
        # Create the (value, label) tuples for the form
        category_choices = [(cat, cat) for cat in org_categories_list]
    else:
        # Provide an empty list as a fallback if the need has no categories
        category_choices = []

    # Apply these choices to *all* item forms in the FieldList
    for item_form in form.offered_items.entries:
        item_form.category.choices = category_choices
    # --- *** END OF FIX *** ---


    if form.validate_on_submit():
        # --- Custom Validation for Critical Items ---
        critical_categories = ['Medicines', 'Food & Snacks', 'Baby Products', 'Health & Wellness']
        is_custom_valid = True
        for i, item_data in enumerate(form.offered_items.data):
            if item_data['category'] in critical_categories:
                # Check expiry date logic (e.g., must be in the future)
                if not item_data['expiry_date']:
                     flash(f"Error in Item #{i+1} ('{item_data['title']}'): Expiry date is required for the '{item_data['category']}' category.", 'danger')
                     is_custom_valid = False
                elif item_data['expiry_date'] < date.today():
                     flash(f"Error in Item #{i+1} ('{item_data['title']}'): Expiry date cannot be in the past.", 'danger')
                     is_custom_valid = False
                # Manufacture date optional unless specific logic requires it

        if not is_custom_valid:
            # Re-render form with errors if custom validation fails
            # We must re-apply choices on failure
            for item_form in form.offered_items.entries:
                item_form.category.choices = category_choices
            return render_template("features/make_offer.html", form=form, need=need)
        # --- End Custom Validation ---

        # Create the main offer record
        new_offer = DonationOffer(
            user_id=current_user.user_id,
            need_id=need.need_id,
            org_id=need.org_id,
            status='Pending Review' # Initial status
        )
        db.session.add(new_offer)
        db.session.flush() # Get new_offer.offer_id

        # Process each offered item
        items_to_add = []
        for item_form_data in form.offered_items.data:
            image_relative_path = None
            if item_form_data['image']:
                try:
                    file = item_form_data['image']
                    # Use offer_id and item title for a more unique filename
                    filename_base = secure_filename(f"offer_{new_offer.offer_id}_{item_form_data['title'][:20]}")
                    filename = f"{filename_base}_{datetime.utcnow().timestamp()}{os.path.splitext(file.filename)[1]}"
                    filepath = os.path.join(CHAT_UPLOAD_FOLDER, filename) # Using CHAT_UPLOAD for donation images too
                    file.save(filepath)
                    image_relative_path = f"images/chat_uploads/{filename}"
                except Exception as e:
                    current_app.logger.error(f"Failed saving image for offered item '{item_form_data['title']}': {e}")
                    flash(f"Could not save image for item: {item_form_data['title']}", "warning")

            offered_item = OfferedItem(
                offer_id=new_offer.offer_id, # Link using ID
                title=item_form_data['title'],
                category=item_form_data['category'],
                description=item_form_data['description'],
                quantity=item_form_data['quantity'],
                condition=item_form_data['condition'],
                image_url=image_relative_path,
                manufacture_date=item_form_data['manufacture_date'],
                expiry_date=item_form_data['expiry_date'],
                status='Pending' # Initial status for item
            )
            items_to_add.append(offered_item)

        if items_to_add:
            db.session.add_all(items_to_add)

        db.session.commit()
        flash('Your donation offer has been successfully sent for review!', 'success')
        # TODO: Notify organization about the new offer
        return redirect(url_for('main.dashboard', view='donations')) # Redirect to "My Donations" view

    elif request.method == 'POST': # Handle WTForms validation errors on POST
        # We must re-apply choices if validation fails
        for item_form in form.offered_items.entries:
            item_form.category.choices = category_choices

        for field, errors in form.errors.items():
             if field == 'offered_items': # Handle FieldList errors
                 for i, item_errors in enumerate(errors):
                     if item_errors:
                         flash(f"Error in Item #{i+1}:", 'danger')
                         for item_field, item_messages in item_errors.items():
                             flash(f"- {item_field.replace('_', ' ').title()}: {', '.join(item_messages)}", 'danger')
             else: # Handle top-level form errors
                 flash(f"Error in {getattr(form, field).label.text}: {', '.join(errors)}", "danger")


    return render_template("features/make_offer.html", form=form, need=need)


@main.route("/offer/<int:offer_id>/edit", methods=['GET', 'POST'])
@login_required
@role_required("user")
def edit_donation_offer(offer_id):
    """Handles editing a pending donation offer more efficiently."""
    offer = DonationOffer.query.options(orm.joinedload(DonationOffer.offered_items)).get_or_404(offer_id)

    # Security & Status Check
    if offer.user_id != current_user.user_id: abort(403)
    if offer.status != 'Pending Review':
        flash('This offer cannot be edited as it has already been reviewed or actioned.', 'warning')
        return redirect(url_for('main.view_my_offer', offer_id=offer_id))

    # Define inline forms to include the existing item ID for processing updates
    class EditOfferedItemForm(OfferedItemForm):
        offered_item_id = IntegerField('Existing ID', validators=[Optional()])

    class EditDonationOfferForm(DonationOfferForm):
        offered_items = FieldList(FormField(EditOfferedItemForm), min_entries=0)


    # Populate form based on request method
    if request.method == 'GET':
        prepared_data = {'offered_items': []}
        for item in offer.offered_items:
            item_dict = {k: v for k, v in item.__dict__.items() if not k.startswith('_')}
            item_dict['offered_item_id'] = item.offered_item_id
            item_dict['image_url'] = item.image_url # Used by template JS
            if isinstance(item_dict.get('manufacture_date'), date):
                item_dict['manufacture_date'] = item_dict['manufacture_date'].isoformat()
            if isinstance(item_dict.get('expiry_date'), date):
                item_dict['expiry_date'] = item_dict['expiry_date'].isoformat()
            prepared_data['offered_items'].append(item_dict)
        form = EditDonationOfferForm(data=prepared_data)
    else: # POST
        form = EditDonationOfferForm()


    if form.validate_on_submit():
        # --- Custom Validation for Critical Items ---
        critical_categories = ['Medicines', 'Food & Snacks', 'Baby Products', 'Health & Wellness']
        is_custom_valid = True
        for i, item_data in enumerate(form.offered_items.data):
             if item_data['category'] in critical_categories:
                if not item_data['expiry_date']:
                     flash(f"Error in Item #{i+1} ('{item_data['title']}'): Expiry date is required for the '{item_data['category']}' category.", 'danger')
                     is_custom_valid = False
                elif isinstance(item_data['expiry_date'], date) and item_data['expiry_date'] < date.today():
                     flash(f"Error in Item #{i+1} ('{item_data['title']}'): Expiry date cannot be in the past.", 'danger')
                     is_custom_valid = False

        if not is_custom_valid:
            return render_template("features/edit_offer.html", form=form, offer=offer)
        # --- End Custom Validation ---

        try:
            existing_items_map = {item.offered_item_id: item for item in offer.offered_items}
            submitted_item_ids = set()
            items_to_add = []
            files_to_delete = [] # Keep track of old image files to delete

            # --- Process submitted items ---
            for i, item_form_data in enumerate(form.offered_items.data):
                existing_item_id = item_form_data.get('offered_item_id')
                image_field_name = f'offered_items-{i}-image'
                image_file = request.files.get(image_field_name) if image_field_name in request.files else None
                # ## REMOVED remove_image_flag logic ##
                image_relative_path = None # Final path for DB
                old_image_to_delete = None # Path of file to delete if replaced

                item_being_updated = existing_items_map.get(existing_item_id) if existing_item_id else None
                current_image_url = item_being_updated.image_url if item_being_updated else None

                # --- Handle Image Logic ---
                if image_file and image_file.filename != '':
                    # User uploaded a new image, replacing the old one (if any)
                    try:
                        # Save new image
                        filename_base = secure_filename(f"offer_{offer.offer_id}_{item_form_data['title'][:20]}")
                        filename = f"{filename_base}_{datetime.utcnow().timestamp()}{os.path.splitext(image_file.filename)[1]}"
                        filepath = os.path.join(CHAT_UPLOAD_FOLDER, filename)
                        image_file.save(filepath)
                        image_relative_path = f"images/chat_uploads/{filename}" # Set DB value to new path

                        # If there was an old image, mark it for deletion
                        if current_image_url:
                            old_image_to_delete = current_image_url
                        current_app.logger.info(f"Uploaded new image {image_relative_path}, replacing {current_image_url or 'nothing'} (item ID: {existing_item_id}).")

                    except Exception as e:
                        current_app.logger.error(f"Failed saving image during edit for offered item '{item_form_data['title']}': {e}")
                        flash(f"Could not save updated image for item: {item_form_data['title']}", "warning")
                        image_relative_path = current_image_url # Fallback: Keep old URL if save failed
                else:
                    # No new upload: Keep the existing image URL
                    image_relative_path = current_image_url

                # Add the old file path to the list for deletion if needed
                if old_image_to_delete:
                    files_to_delete.append(old_image_to_delete)

                # --- Update existing or create new ---
                if item_being_updated:
                    # Update existing item
                    item_being_updated.title = item_form_data['title']
                    item_being_updated.category = item_form_data['category']
                    item_being_updated.description = item_form_data['description']
                    item_being_updated.quantity = item_form_data['quantity']
                    item_being_updated.condition = item_form_data['condition']
                    item_being_updated.manufacture_date = item_form_data['manufacture_date']
                    item_being_updated.expiry_date = item_form_data['expiry_date']
                    item_being_updated.image_url = image_relative_path # Update DB field with new path or keep old
                    item_being_updated.status = 'Pending' # Reset status
                    submitted_item_ids.add(existing_item_id)
                else:
                    # Add as a new item
                    new_offered_item = OfferedItem(
                        offer_id=offer.offer_id,
                        title=item_form_data['title'],
                        category=item_form_data['category'],
                        description=item_form_data['description'],
                        quantity=item_form_data['quantity'],
                        condition=item_form_data['condition'],
                        image_url=image_relative_path, # Path if uploaded, else None
                        manufacture_date=item_form_data['manufacture_date'],
                        expiry_date=item_form_data['expiry_date'],
                        status='Pending'
                    )
                    items_to_add.append(new_offered_item)

            # --- Delete items that were removed ---
            items_to_remove = []
            for item_id, item in existing_items_map.items():
                if item_id not in submitted_item_ids:
                    items_to_remove.append(item)
                    if item.image_url:
                        # Ensure removed item's image file is also marked for deletion
                        if item.image_url not in files_to_delete:
                            files_to_delete.append(item.image_url)

            # Perform database operations
            if items_to_remove:
                for item in items_to_remove:
                    db.session.delete(item)
            if items_to_add:
                db.session.add_all(items_to_add)

            offer.created_at = datetime.utcnow() # Update timestamp to reflect edit
            db.session.commit()

            # --- Delete old image files AFTER commit ---
            for image_path_rel in files_to_delete:
                try:
                    if image_path_rel and image_path_rel.startswith('images/'):
                         full_path = os.path.join(current_app.static_folder, image_path_rel)
                         if os.path.exists(full_path):
                             os.remove(full_path)
                             current_app.logger.info(f"Deleted old image file: {full_path}")
                    else:
                        current_app.logger.warning(f"Skipping deletion of potentially invalid path: {image_path_rel}")
                except Exception as e:
                    current_app.logger.error(f"Error deleting old image file {image_path_rel}: {e}")


            flash('Your donation offer has been updated successfully!', 'success')
            return redirect(url_for('main.view_my_offer', offer_id=offer_id))

        except Exception as e:
            current_app.logger.error(f"Error editing donation offer {offer_id}: {e}")
            db.session.rollback()
            flash("An error occurred while updating the offer.", "danger")

    elif request.method == 'POST' and form.errors: # Handle WTForms validation errors
         for field, errors in form.errors.items():
             if field == 'offered_items':
                 for i, item_errors in enumerate(errors):
                     if item_errors:
                         flash(f"Error in Item #{i+1}:", 'danger')
                         for item_field, item_messages in item_errors.items():
                             label = getattr(getattr(form.offered_items[i], item_field, None), 'label', None)
                             display_name = label.text if label else item_field.replace('_', ' ').title()
                             flash(f"- {display_name}: {', '.join(item_messages)}", 'danger')
             else:
                 flash(f"Error in {getattr(form, field).label.text}: {', '.join(errors)}", "danger")

    # Pass existing items data (for GET) or submitted data (on POST validation error)
    return render_template("features/edit_offer.html", form=form, offer=offer)


@main.route("/offer/<int:offer_id>/delete", methods=['POST'])
@login_required
@role_required("user")
def delete_donation_offer(offer_id):
    """Handles withdrawing (deleting) a user's donation offer."""
    offer = DonationOffer.query.options(orm.joinedload(DonationOffer.offered_items)).get_or_404(offer_id)

    # Security & Status Check
    if offer.user_id != current_user.user_id: abort(403)
    if offer.status != 'Pending Review':
         flash('This offer cannot be withdrawn as it has already been actioned.', 'warning')
         return redirect(url_for('main.view_my_offer', offer_id=offer_id))

    image_files_to_delete = [item.image_url for item in offer.offered_items if item.image_url]

    try:
        # Delete associated OfferedItem records first
        OfferedItem.query.filter_by(offer_id=offer.offer_id).delete()
        # Delete the DonationOffer record
        db.session.delete(offer)
        db.session.commit()

        # Delete associated image files AFTER successful DB commit
        for image_path_rel in image_files_to_delete:
             try:
                 if image_path_rel and image_path_rel.startswith('images/'):
                     full_path = os.path.join(current_app.static_folder, image_path_rel)
                     if os.path.exists(full_path):
                         os.remove(full_path)
                         current_app.logger.info(f"Deleted image file for withdrawn offer: {full_path}")
                 else:
                     current_app.logger.warning(f"Skipping deletion of potentially invalid path during offer withdrawal: {image_path_rel}")
             except Exception as e:
                 current_app.logger.error(f"Error deleting image file {image_path_rel} for withdrawn offer {offer_id}: {e}")

        flash('Your donation offer has been successfully withdrawn.', 'info')
    except Exception as e:
         current_app.logger.error(f"Error deleting donation offer {offer_id}: {e}")
         db.session.rollback()
         flash("An error occurred while withdrawing the offer.", "danger")
         return redirect(url_for('main.view_my_offer', offer_id=offer_id))

    return redirect(url_for('main.dashboard', view='donations'))

@main.route("/my-offer/<int:offer_id>")
@login_required
@role_required("user")
def view_my_offer(offer_id):
    """Displays the detailed status and items for a user's specific donation offer."""
    offer = DonationOffer.query.options(
        orm.joinedload(DonationOffer.offered_items), # Eager load items
        orm.joinedload(DonationOffer.need),          # Eager load need details
        orm.joinedload(DonationOffer.organization)   # Eager load org details
    ).get_or_404(offer_id)

    # Security check: ensure the current user owns this offer
    if offer.user_id != current_user.user_id: abort(403)

    # Form for reporting the organization related to this offer
    report_form = OrganizationReportForm() # Renamed form variable

    return render_template("features/view_my_offer.html", offer=offer, form=report_form)



@main.route('/user/chat/start/<int:offer_id>') # Define the URL for the user to click
@login_required
@role_required("user") # Ensure only users can access this
def start_chat_from_offer(offer_id):
    """Finds or creates a chat session between a user and an org regarding a donation offer."""
    # Eager load related objects to avoid multiple queries
    offer = DonationOffer.query.options(
        orm.joinedload(DonationOffer.need),
        orm.joinedload(DonationOffer.organization)
    ).get_or_404(offer_id) #

    # Security check: Ensure the current user made this offer
    if offer.user_id != current_user.user_id: #
        abort(403) # Forbidden access

    need = offer.need #
    organization = offer.organization #

    # Check if the need or organization associated with the offer still exists
    if not need:
        flash("Cannot start chat: the related disaster need has been deleted.", "danger")
        # Redirect back to where the user likely was (their donations list)
        return redirect(request.referrer or url_for('main.dashboard', view='donations'))
    if not organization:
        flash("Cannot start chat: the related organization no longer exists.", "danger")
        return redirect(request.referrer or url_for('main.dashboard', view='donations'))

    # --- FIX: Find existing chat based on OFFER ID ---
    chat_session = ChatSession.query.filter_by(
        donation_offer_id=offer.offer_id
    ).first()

    if not chat_session:
        # --- FIX: Create a new chat session linked to OFFER ID ---
        chat_session = ChatSession(
            donation_offer_id=offer.offer_id, # Link to the specific offer
            user_one_id=current_user.user_id, #
            participant_org_id=organization.org_id, #
            status='Active' # Ensure status is set
        )
        db.session.add(chat_session)
        try:
            db.session.commit()
            current_app.logger.info(f"Created user-initiated org chat session {chat_session.session_id} from offer {offer_id}") #
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Error creating chat session from offer {offer_id}: {e}")
            flash("Could not start chat session due to a database error.", "danger")
            return redirect(request.referrer or url_for('main.dashboard', view='donations'))

    elif chat_session.status != 'Active':
         # Reactivate chat if it was previously blocked or finalized
         chat_session.status = 'Active' #
         try:
            db.session.commit()
         except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Error reactivating chat session {chat_session.session_id}: {e}")
            flash("Could not reactivate chat session due to a database error.", "danger")
            return redirect(request.referrer or url_for('main.dashboard', view='donations'))


    # Redirect the user to the chat interface for the found/created session
    return redirect(url_for('main.chat', session_id=chat_session.session_id)) #




@main.route("/org/offer/<int:offer_id>/review", methods=['GET', 'POST'])
@login_required
@role_required("org")
def review_donation_offer(offer_id):
    """Handles an organization reviewing a specific donation offer."""
    offer = DonationOffer.query.options(orm.joinedload(DonationOffer.offered_items), orm.joinedload(DonationOffer.user)).get_or_404(offer_id) # Eager load user

    # Security Check
    if offer.org_id != current_user.org_id: abort(403)
    
    # --- LOGIC CHANGE START ---
    # Only check status if the request is POST (i.e., trying to submit a review)
    if request.method == 'POST':
        # Status Check: Can only POST to a pending review
        if offer.status != 'Pending Review':
             flash('This offer has already been reviewed or actioned and cannot be submitted again.', 'info')
             return redirect(url_for('main.org_dashboard', filter='incoming'))

        # --- Existing POST logic ---
        has_rejections = False
        has_acceptances = False
        item_decisions = {} # Store decisions {offered_item_id: 'Accepted'/'Rejected'}

        # Process decisions for each item
        for item in offer.offered_items:
            decision = request.form.get(f'item_decision_{item.offered_item_id}')
            if decision == 'accept':
                item_decisions[item.offered_item_id] = 'Accepted'
                has_acceptances = True
            elif decision == 'reject':
                item_decisions[item.offered_item_id] = 'Rejected'
                has_rejections = True
            else:
                flash(f"Invalid decision received for item ID {item.offered_item_id}.", "danger")
                return render_template('features/review_offer.html', offer=offer)

        if not has_acceptances and not has_rejections:
             flash('Please accept or reject at least one item to finalize the review.', 'warning')
             return render_template('features/review_offer.html', offer=offer)

        # Determine overall offer status and notification message
        notification_message = "" # Initialize
        if has_acceptances:
            offer.status = 'Awaiting Pickup'
            if has_rejections:
                 notification_message = f"Your offer for '{offer.need.title}' was partially accepted. Please prepare the accepted items for pickup within 2 days."
            else:
                 notification_message = f"Your offer for '{offer.need.title}' has been accepted! Please prepare the items for pickup within 2 days."
        else: # Only rejections
            offer.status = 'Rejected'
            notification_message = f"Unfortunately, your offer for '{offer.need.title}' was rejected by {current_user.name}."

        offer.verified_at = datetime.utcnow() # Timestamp the review action

        try:
            # Update individual item statuses
            for item_id, status in item_decisions.items():
                 item = next((i for i in offer.offered_items if i.offered_item_id == item_id), None)
                 if item: item.status = status

            # Create notification for the user
            new_notification = Notification(user_id=offer.user_id, message=notification_message)
            db.session.add(new_notification)

            db.session.commit() # Commit all changes

            # --- ADD PUSH NOTIFICATION ---
            user_to_notify = offer.user # Already eager loaded
            if user_to_notify and user_to_notify.fcm_token:
                push_title = "Donation Offer Update"
                if offer.status == 'Awaiting Pickup':
                    push_title = "Offer Accepted!" if not has_rejections else "Offer Partially Accepted!"
                elif offer.status == 'Rejected':
                    push_title = "Offer Rejected"

                try:
                    send_push_notification(
                        token=user_to_notify.fcm_token,
                        title=push_title,
                        body=notification_message, # Use the same message
                        data={'offerId': str(offer_id), 'type': 'offer_review'}
                    )
                except Exception as e:
                     current_app.logger.error(f"FCM failed for offer review notification to user {user_to_notify.user_id}: {e}")
            # --- END PUSH NOTIFICATION ---

            flash(f"Offer reviewed. Donor notified. Offer status: {offer.status}.", 'success')

            # Redirect based on new status
            redirect_filter = 'pickup' if offer.status == 'Awaiting Pickup' else 'incoming'
            return redirect(url_for('main.org_dashboard', filter=redirect_filter))

        except Exception as e:
            current_app.logger.error(f"Error finalizing offer review for {offer_id}: {e}")
            db.session.rollback()
            flash("An error occurred while saving the review.", "danger")
    # --- LOGIC CHANGE END ---

    # GET request: Render the review/view template regardless of status.
    # The template will use its {% if offer.status == 'Pending Review' %} logic.
    return render_template('features/review_offer.html', offer=offer)

@main.route('/org/offer/<int:offer_id>/pickup_status', methods=['POST'])
@login_required
@role_required('org')
def update_pickup_status(offer_id):
    """Handles organization updating the pickup status of an offer."""
    offer = DonationOffer.query.options(orm.joinedload(DonationOffer.user)).get_or_404(offer_id) # Eager load user

    # Security & Status Check
    if offer.org_id != current_user.org_id: abort(403)
    if offer.status not in ['Awaiting Pickup', 'Accepted', 'Partially Accepted']:
        flash(f'Cannot update pickup status for offer with status "{offer.status}".', 'warning')
        return redirect(request.referrer or url_for('main.org_dashboard'))

    new_status_action = request.form.get('status') # 'Pickup Completed' or 'Pickup Failed'
    notification_message = "" # Initialize
    flash_message = ""
    flash_category = "info"

    if new_status_action == 'Pickup Completed':
        offer.status = 'Donation Pending'
        offer.picked_up_at = datetime.utcnow()
        notification_message = f"Pickup completed for your offer regarding '{offer.need.title}'. Thank you! We'll update again once donated."
        flash_message = 'Offer marked as "Picked Up". Status is now "Donation Pending".'
        flash_category = 'success'

    elif new_status_action == 'Pickup Failed':
        offer.pickup_retries += 1
        if offer.pickup_retries >= 2:
            offer.status = 'Pickup Failed'
            notification_message = f"Pickup failed after a retry for your offer regarding '{offer.need.title}'. The offer has been cancelled."
            flash_message = 'Pickup failed after retry. Offer cancelled.'
            flash_category = 'danger'
        else:
            notification_message = f"Pickup attempt failed for your offer regarding '{offer.need.title}'. We will retry once more soon."
            flash_message = f'Pickup attempt #{offer.pickup_retries} failed. A final attempt will be scheduled. Status remains "Awaiting Pickup".'
            flash_category = 'warning'
    else:
        flash("Invalid pickup status action.", "danger")
        return redirect(request.referrer or url_for('main.org_dashboard'))

    # Send notification to user
    new_notification = Notification(user_id=offer.user_id, message=notification_message)
    db.session.add(new_notification)
    db.session.commit() # Commit changes

    # --- ADD PUSH NOTIFICATION ---
    user_to_notify = offer.user # Already eager loaded
    if user_to_notify and user_to_notify.fcm_token:
         push_title = "Pickup Update"
         if new_status_action == 'Pickup Completed': push_title = "Pickup Completed!"
         elif new_status_action == 'Pickup Failed': push_title = "Pickup Failed" if offer.status == 'Pickup Failed' else "Pickup Attempt Failed"

         try:
             send_push_notification(
                 token=user_to_notify.fcm_token,
                 title=push_title,
                 body=notification_message,
                 data={'offerId': str(offer_id), 'type': 'pickup_status'}
             )
         except Exception as e:
             current_app.logger.error(f"FCM failed for pickup status notification to user {user_to_notify.user_id}: {e}")
    # --- END PUSH NOTIFICATION ---

    flash(flash_message, flash_category)
    return redirect(url_for('main.org_dashboard', filter='pickup'))

# ---


@main.route('/org/need/<int:need_id>/edit', methods=['GET', 'POST'])
@login_required
@role_required('org')
def edit_disaster_need(need_id):
    """Handles editing an existing disaster need."""
    need = DisasterNeed.query.get_or_404(need_id)
    if need.org_id != current_user.org_id: abort(403)

    # Pre-populate form, splitting categories string into list for multi-select
    form = DisasterNeedForm(obj=need, categories=need.categories.split(',') if need.categories else [])

    if form.validate_on_submit():
        need.title = form.title.data.strip()
        need.categories = ",".join(sorted(form.categories.data)) # Store sorted categories
        need.description = form.description.data.strip()
        need.location = form.location.data
        # need.posted_at = datetime.utcnow() # Update timestamp? Or add updated_at field?
        db.session.commit()
        flash('Disaster need updated successfully.', 'success')
        return redirect(url_for('main.org_dashboard', filter='needs'))

    return render_template('features/edit_need.html', form=form, need=need)


@main.route('/org/need/<int:need_id>/delete', methods=['POST'])
@login_required
@role_required('org')
def delete_disaster_need(need_id):
    """Handles deleting a disaster need."""
    need = DisasterNeed.query.options(orm.joinedload(DisasterNeed.donation_offers)).get_or_404(need_id) # Eager load offers
    if need.org_id != current_user.org_id: abort(403)

    # Prevent deletion if there are active (non-final state) offers
    active_offer_statuses = ['Pending Review', 'Awaiting Pickup', 'Accepted', 'Partially Accepted', 'Donation Pending']
    active_offers = [offer for offer in need.donation_offers if offer.status in active_offer_statuses]

    if active_offers:
        flash(f'Cannot delete need "{need.title}" because it has {len(active_offers)} active donation offer(s). Please resolve or reject them first.', 'danger')
        return redirect(url_for('main.org_dashboard', filter='needs'))

    try:
        # If no active offers, proceed with deletion
        # Delete related chat sessions first? Or rely on cascade/set null? Check foreign key constraints.
        # ChatSession.query.filter_by(disaster_need_id=need_id).delete() # Example if needed

        # Delete associated offers (which should only be in final states like Completed, Rejected, Pickup Failed)
        for offer in need.donation_offers:
            # Delete offered items first (cascade should handle this if set up)
            OfferedItem.query.filter_by(offer_id=offer.offer_id).delete()
            db.session.delete(offer)

        # Delete the need itself
        db.session.delete(need)
        db.session.commit()
        flash(f'Disaster need "{need.title}" and its non-active offers have been deleted.', 'success')
    except Exception as e:
        current_app.logger.error(f"Error deleting disaster need {need_id}: {e}")
        db.session.rollback()
        flash("An error occurred while deleting the disaster need.", "danger")

    return redirect(url_for('main.org_dashboard', filter='needs'))


@main.route('/org/offer/<int:offer_id>/complete', methods=['POST'])
@login_required
@role_required('org')
def complete_donation(offer_id):
    """Marks a donation offer as completed, optionally uploading proof."""
    offer = DonationOffer.query.options(orm.joinedload(DonationOffer.user)).get_or_404(offer_id) # Eager load user

    # Security & Status Check
    if offer.org_id != current_user.org_id: abort(403)
    if offer.status != 'Donation Pending':
        flash(f'Cannot mark offer as complete. Current status is "{offer.status}".', 'warning')
        return redirect(request.referrer or url_for('main.org_dashboard'))

    proof_image = request.files.get('proof_image')
    image_relative_path = None
    if proof_image and proof_image.filename:
        try:
            filename_base = secure_filename(f"proof_{offer_id}")
            filename = f"{filename_base}_{datetime.utcnow().timestamp()}{os.path.splitext(proof_image.filename)[1]}"
            filepath = os.path.join(CHAT_UPLOAD_FOLDER, filename)
            proof_image.save(filepath)
            image_relative_path = f"images/chat_uploads/{filename}"
            offer.proof_image_url = image_relative_path
        except Exception as e:
            current_app.logger.error(f"Failed to save proof image for offer {offer_id}: {e}")
            flash("Failed to save proof image, completing without it.", "warning")

    offer.status = 'Completed'
    offer.completed_at = datetime.utcnow()

    # Notify user
    notification_message = f"Donation complete! Your offered items for '{offer.need.title}' have been successfully utilized. Thank you for your contribution!"
    new_notification = Notification(user_id=offer.user_id, message=notification_message)
    db.session.add(new_notification)
    db.session.commit() # Commit changes

    # --- ADD PUSH NOTIFICATION ---
    user_to_notify = offer.user # Already eager loaded
    if user_to_notify and user_to_notify.fcm_token:
         try:
             send_push_notification(
                 token=user_to_notify.fcm_token,
                 title="Donation Completed!",
                 body=notification_message,
                 data={'offerId': str(offer_id), 'type': 'donation_complete'}
             )
         except Exception as e:
             current_app.logger.error(f"FCM failed for donation complete notification to user {user_to_notify.user_id}: {e}")
    # --- END PUSH NOTIFICATION ---

    flash('Donation marked as completed successfully!', 'success')
    return redirect(url_for('main.org_dashboard', filter='completed'))

# ---


@main.route('/org/chat/start/<int:offer_id>')
@login_required
@role_required("org")
def start_org_chat(offer_id):
    """Finds or creates a chat session between an org and a user regarding a donation offer."""
    offer = DonationOffer.query.get_or_404(offer_id)
    if offer.org_id != current_user.org_id: abort(403)
    need = offer.need
    if not need:
        flash("Cannot start chat: the related disaster need has been deleted.", "danger")
        # Redirect based on where the org likely clicked from
        return redirect(request.referrer or url_for('main.org_dashboard'))

    # --- FIX: Find existing chat based on OFFER ID ---
    chat_session = ChatSession.query.filter_by(
        donation_offer_id=offer.offer_id
    ).first()

    if not chat_session:
        # --- FIX: Create a new chat session linked to OFFER ID ---
        chat_session = ChatSession(
            donation_offer_id=offer.offer_id, # Link to the specific offer
            user_one_id=offer.user_id,
            participant_org_id=current_user.org_id,
            status='Active' # Add status
        )
        db.session.add(chat_session)
        db.session.commit()
        current_app.logger.info(f"Created org chat session {chat_session.session_id} from offer {offer_id}")

    return redirect(url_for('main.chat', session_id=chat_session.session_id))


# =========================
# FEEDBACK & REPORTS
# =========================
@main.route("/feedback", methods=["GET", "POST"])
@login_required
@role_required("user") # Only users submit feedback this way
def feedback():
    """Handles user submitting feedback."""
    form = FeedbackForm()
    if form.validate_on_submit():
        new_feedback = Feedback(
            user_id=current_user.user_id,
            message=form.message.data.strip(),
            status="Open" # Initial status
        )
        db.session.add(new_feedback)
        db.session.commit()
        flash("Thank you! Your feedback has been submitted.", "success")
        return redirect(url_for("main.dashboard")) # Redirect user to their dashboard
    return render_template("features/feedback.html", form=form)


@main.route("/report", methods=["GET", "POST"])
@login_required
@role_required("user") # Only users submit general reports
def report_general():
    """Handles submitting a general report (not tied to specific item/org/chat)."""
    form = ReportForm()
    # You might want different forms/routes for different report types
    # For now, this is a generic one
    item_id = request.args.get('item_id', type=int)
    session_id = request.args.get('session_id', type=int)
    org_id = request.args.get('org_id', type=int)

    if form.validate_on_submit():
        new_report = Report(
            reported_by=current_user.user_id,
            reason=form.reason.data.strip(),
            item_id=item_id,
            chat_session_id=session_id,
            reported_org_id=org_id,
            status="Pending" # Initial status
        )
        db.session.add(new_report)
        db.session.commit()
        flash("Report submitted successfully. An administrator will review it.", "success")
        return redirect(url_for("main.dashboard")) # Redirect user to dashboard

    # Pre-fill context if available
    context = {}
    if item_id: context['item'] = Item.query.get(item_id)
    if session_id: context['session'] = ChatSession.query.get(session_id)
    if org_id: context['organization'] = Organization.query.get(org_id)

    return render_template("features/report.html", form=form, context=context)


@main.route('/report/organization/<int:offer_id>', methods=['POST']) # Changed from GET/POST to POST only via modal
@login_required
@role_required('user')
def report_organization(offer_id):
    """Handles user reporting an organization related to a specific donation offer."""
    offer = DonationOffer.query.get_or_404(offer_id)
    # Security check
    if offer.user_id != current_user.user_id: abort(403)

    form = OrganizationReportForm() # Form defined specifically for this modal/action
    if form.validate_on_submit():
        new_report = Report(
            reported_by=current_user.user_id,
            reported_org_id=offer.org_id,
            donation_offer_id=offer.offer_id, # Link report to the specific offer context
            reason=form.reason.data.strip(),
            status='Pending'
        )
        db.session.add(new_report)
        db.session.commit()
        flash('Organization reported successfully. An administrator will review your report.', 'success')
    else:
        # Handle form errors if submitted via non-modal GET (though unlikely now)
         for field, errors in form.errors.items():
            for error in errors:
                flash(f"Error in report reason: {error}", "danger")

    return redirect(url_for('main.view_my_offer', offer_id=offer_id)) # Redirect back to offer page


# =========================
# NOTIFICATIONS
# =========================
@main.route("/notifications")
@login_required
@role_required("user") # Only users have this notification view
def notifications():
    """Displays user notifications, filtering by read/unread status."""
    current_filter = request.args.get('filter', 'unread') # Default to 'unread'
    status_filter = 'Read' if current_filter == 'read' else 'Unread'

    # Fetch notifications based on filter
    user_notifications = Notification.query.filter_by(
        user_id=current_user.user_id,
        status=status_filter
    ).order_by(Notification.sent_at.desc()).all()

    # --- Mark Unread as Read ---
    # Only mark as read if viewing the 'unread' tab and there are notifications
    if current_filter == 'unread' and user_notifications:
        ids_to_mark = [n.notification_id for n in user_notifications] # Already filtered to Unread
        try:
            Notification.query.filter(Notification.notification_id.in_(ids_to_mark))\
                           .update({Notification.status: 'Read'}, synchronize_session=False)
            db.session.commit()
            # Optionally update unread_count here if needed immediately, though context processor handles next load
        except Exception as e:
            current_app.logger.error(f"Error marking notifications as read for user {current_user.user_id}: {e}")
            db.session.rollback()


    return render_template("features/notifications.html", notifications=user_notifications, current_filter=current_filter)


@main.route("/notification/<int:notification_id>/delete", methods=["POST"])
@login_required
@role_required("user") # Only users delete their notifications
def delete_notification(notification_id):
    """Deletes a specific notification."""
    notification = Notification.query.get_or_404(notification_id)
    # Security check
    if notification.user_id != current_user.user_id: abort(403)

    try:
        db.session.delete(notification)
        db.session.commit()
        flash("Notification deleted.", "info")
    except Exception as e:
         current_app.logger.error(f"Error deleting notification {notification_id} for user {current_user.user_id}: {e}")
         db.session.rollback()
         flash("Error deleting notification.", "danger")

    # Redirect back to the notifications page, preserving the filter if possible
    origin_filter = request.form.get('origin_filter', 'unread') # Get filter from hidden input if added
    return redirect(url_for("main.notifications", filter=origin_filter))


# =========================
# CHAT (Consolidated & Refactored)
# =========================

@main.route('/message/<int:message_id>/delete', methods=['POST'])
@login_required # Allow both users and orgs
def delete_message(message_id):
    """Soft deletes a chat message if the current actor is the sender."""
    msg = ChatMessage.query.get_or_404(message_id)
    current_actor = current_user._get_current_object()
    is_user = isinstance(current_actor, User)
    is_org = isinstance(current_actor, Organization)
    actor_id = current_actor.user_id if is_user else current_actor.org_id
    actor_type = 'user' if is_user else 'org'

    # Security Check: Ensure the current actor is the sender
    if msg.sender_id != actor_id or msg.sender_type != actor_type:
        return jsonify({'success': False, 'error': 'Permission denied.'}), 403

    # "Soft delete"
    msg.deleted_at = datetime.utcnow()
    # Optional: Clear content
    # msg.message = "[Message Deleted]"
    # msg.image_url = None
    db.session.commit()

    return jsonify({'success': True})


@main.route('/chat/<int:session_id>/block', methods=['POST'])
@login_required
@role_required("user") # Only users can block user-user chats currently
def block_chat(session_id):
    """Blocks a user-user chat session."""
    chat_session = ChatSession.query.get_or_404(session_id)
    # Ensure it's a user-user chat and the current user is part of it
    if chat_session.is_org_chat or \
       (chat_session.user_one_id != current_user.user_id and chat_session.user_two_id != current_user.user_id):
        abort(403)

    if chat_session.status != 'Blocked':
        chat_session.status = 'Blocked'
        db.session.commit()
        flash('Chat blocked. You can no longer send or receive messages in this conversation.', 'warning')
        # TODO: Notify the other user? Maybe not for blocking.
    else:
         flash('Chat is already blocked.', 'info')

    return redirect(url_for('main.chat', session_id=session_id))


@main.route('/chat/<int:session_id>/unblock', methods=['POST'])
@login_required
@role_required("user") # Only users can unblock
def unblock_chat(session_id):
    """Unblocks a previously blocked user-user chat session."""
    chat_session = ChatSession.query.get_or_404(session_id)
    # Security check
    if chat_session.is_org_chat or \
       (chat_session.user_one_id != current_user.user_id and chat_session.user_two_id != current_user.user_id):
        abort(403)

    if chat_session.status == 'Blocked':
        chat_session.status = 'Active'
        db.session.commit()
        flash('Chat has been unblocked. You can now send messages.', 'success')
    else:
        flash('Chat is not currently blocked.', 'info')

    # Redirect back to profile where the blocked list is managed
    return redirect(url_for('main.profile'))


@main.route('/chat/session/<int:session_id>/delete', methods=['POST'])
@login_required # Allow both users and orgs
def delete_chat_session(session_id):
    """Deletes an entire chat session history for the current actor."""
    # Note: This is a hard delete. Consider soft delete or archiving instead.
    session = ChatSession.query.get_or_404(session_id)
    current_actor = current_user._get_current_object()
    is_user = isinstance(current_actor, User)
    is_org = isinstance(current_actor, Organization)

    # Authorization check
    is_participant = False
    if is_user:
        is_participant = (session.user_one_id == current_actor.user_id or session.user_two_id == current_actor.user_id)
    elif is_org:
        is_participant = (session.participant_org_id == current_actor.org_id)

    if not is_participant: abort(403)

    try:
        # ---> ADD THIS BLOCK TO DELETE DealProposal FIRST <---
        # Find the associated DealProposal using the relationship or a direct query
        deal = DealProposal.query.filter_by(chat_session_id=session.session_id).first()
        if deal:
            current_app.logger.info(f"Deleting associated DealProposal (ID: {deal.id}) for ChatSession {session_id}")
            db.session.delete(deal)
        # ---> END ADDITION <---

        # Now delete the chat session (cascade should handle ChatMessages)
        current_app.logger.info(f"Deleting ChatSession {session_id}")
        db.session.delete(session)

        db.session.commit() # Commit both deletions
        flash('Chat session and all its messages have been permanently deleted.', 'success')
    except Exception as e:
        # Log the specific error including the traceback
        current_app.logger.error(f"Error deleting chat session {session_id}: {e}", exc_info=True) # Added exc_info=True
        db.session.rollback()
        flash("An error occurred while deleting the chat session.", "danger") # Generic message to user

    # Redirect to the appropriate dashboard chat list
    if is_org:
        return redirect(url_for('main.org_dashboard', filter='chats'))
    else:
        return redirect(url_for('main.dashboard', view='chats'))


@main.route("/chat/<int:session_id>", methods=["GET", "POST"])
@login_required # Allow both Users and Orgs
def chat(session_id):
    """Handles displaying and sending messages within a chat session."""
    chat_session = ChatSession.query.options(
        # Eager load related data - Load owner for items as well
        orm.joinedload(ChatSession.trade_item).options(
            orm.joinedload(Item.images),
            orm.joinedload(Item.owner) # <<< ADDED OWNER LOAD HERE
        ),
        orm.joinedload(ChatSession.disaster_need), # Eager load need (for old chats)
        # --- ADD THIS LINE to load the new relationship ---
        orm.joinedload(ChatSession.donation_offer).options(
            orm.joinedload(DonationOffer.need), # <<< Also load the need via the offer
            orm.joinedload(DonationOffer.offered_items) # <<< Load offered items for sidebar context if needed
        ),
        # Load fcm_token for push notifications
        orm.joinedload(ChatSession.user_one).load_only(User.user_id, User.first_name, User.last_name, User.profile_picture, User.fcm_token),
        orm.joinedload(ChatSession.user_two).load_only(User.user_id, User.first_name, User.last_name, User.profile_picture, User.fcm_token),
        # Load relevant org details
        orm.joinedload(ChatSession.participant_org).load_only(Organization.org_id, Organization.name, Organization.profile_picture),
    ).get_or_404(session_id)

    current_actor = current_user._get_current_object()
    is_user = isinstance(current_actor, User)
    is_org = isinstance(current_actor, Organization)
    actor_id = current_actor.user_id if is_user else current_actor.org_id
    actor_type = 'user' if is_user else 'org'

    # --- Authorization Check ---
    is_participant = False
    if is_user: is_participant = (chat_session.user_one_id == actor_id or chat_session.user_two_id == actor_id)
    elif is_org: is_participant = (chat_session.participant_org_id == actor_id)
    if not is_participant: abort(403)

    # --- Mark Messages as Read ---
    unread_messages = ChatMessage.query.filter(
        ChatMessage.session_id == session_id,
        ChatMessage.is_read == False,
        not_(and_(ChatMessage.sender_id == actor_id, ChatMessage.sender_type == actor_type))
    ).all()
    if unread_messages:
        try:
            for msg in unread_messages: msg.is_read = True
            db.session.commit()
        except Exception as e:
             current_app.logger.error(f"Error marking messages read for session {session_id}: {e}")
             db.session.rollback()

    # --- REVISED SUBJECT LOADING ---
    the_subject = None
    if chat_session.trade_item_id:
        # Explicitly load the item, even if status is not 'Active'
        the_subject = Item.query.options(orm.joinedload(Item.images), orm.joinedload(Item.owner)).get(chat_session.trade_item_id)
    elif chat_session.donation_offer_id:
        # Explicitly load the offer and its related need
        the_subject = DonationOffer.query.options(orm.joinedload(DonationOffer.need)).get(chat_session.donation_offer_id)
    elif chat_session.disaster_need_id: # Fallback for old chats
        the_subject = DisasterNeed.query.options(orm.joinedload(DisasterNeed.organization)).get(chat_session.disaster_need_id) # Load org too

    # Initialize variables
    the_item = None         # For user-user trade item context
    donation_offer = None # For user-org donation offer context
    disaster_need = None  # For subject display (often linked from donation_offer)
    trade_request = None  # For user-user trade logic

    other_user, organization_participant = None, None

    # Determine participants and specific context variables
    if chat_session.is_org_chat:
        # This is a User-Org chat
        organization_participant = chat_session.participant_org # Org is always participant_org
        other_user = chat_session.user_one                  # User is always user_one

        # Assign based on the explicitly loaded subject
        if isinstance(the_subject, DonationOffer):
            donation_offer = the_subject
            disaster_need = donation_offer.need # Get the need from the offer
        elif isinstance(the_subject, DisasterNeed): # Fallback
            disaster_need = the_subject
            # Try to find offer again if needed (less reliable)
            donation_offer = DonationOffer.query.filter_by(
                need_id=disaster_need.need_id,
                user_id=chat_session.user_one_id,
                org_id=chat_session.participant_org_id
            ).first()
        # Ensure org participant is loaded if only need was loaded (fallback)
        if not organization_participant and disaster_need and disaster_need.organization:
            organization_participant = disaster_need.organization


    else:
        # This is a User-User chat
        other_user = chat_session.get_other_user(actor_id) if is_user else None

        if isinstance(the_subject, Item):
            the_item = the_subject # Assign the explicitly loaded item
            # Find the trade request (if applicable)
            if other_user:
                trade_request = TradeRequest.query.filter(
                    TradeRequest.item_requested_id == the_item.item_id,
                    or_(
                        (TradeRequest.requester_id == actor_id and TradeRequest.owner_id == other_user.user_id),
                        (TradeRequest.requester_id == other_user.user_id and TradeRequest.owner_id == actor_id)
                    )
                ).options(
                    orm_joinedload(TradeRequest.offered_item).joinedload(Item.images), # Eager load offered item
                    orm_joinedload(TradeRequest.requester) # Load requester for sidebar
                ).first()
            # Ensure other_user is loaded if only item was loaded (fallback)
            if not other_user and the_item and the_item.owner:
                # Determine who the other user is based on who owns the item vs current user
                other_user_id_temp = the_item.user_id if chat_session.user_one_id == the_item.user_id else chat_session.user_two_id
                if other_user_id_temp != actor_id:
                     other_user = User.query.get(other_user_id_temp)


    # DealProposal logic only for user-user chats
    deal = DealProposal.query.filter_by(chat_session_id=session_id).first() if not chat_session.is_org_chat else None

    # Handle placeholder subject IF the explicit query failed to find the item/need/offer
    if not the_subject:
        # Define a simple placeholder class
        class DummySubject:
            def __init__(self):
                self.title = "[Details Unavailable]"
                self.images = []
                self.item_id = 0
                self.need_id = 0
                self.owner = None
                self.organization = None
                self.type = "Unknown"
                # Add any other attributes your template might expect
                self.status = "Unknown"
                self.description = ""
                self.expected_return_category = None
                self.need = None # Add need attribute for donation offer check

        the_subject = DummySubject() # Use the placeholder
        # Assign to specific vars if needed by template logic further down
        if chat_session.is_org_chat:
            disaster_need = the_subject
        else:
            the_item = the_subject
            
    # --- Make sure participant variables are set even if using placeholder ---
    # These might still be available from chat_session even if subject is gone
    if chat_session.is_org_chat:
        if not organization_participant: organization_participant = chat_session.participant_org
        if not other_user: other_user = chat_session.user_one
    else: # User-user
        if not other_user: other_user = chat_session.get_other_user(actor_id)


    # --- Handle Form Submission ---
    form = ChatForm()
    if form.validate_on_submit():
        if chat_session.status != 'Active':
            flash("Cannot send messages. This chat is currently " + chat_session.status.lower() + ".", "warning")
            return redirect(url_for("main.chat", session_id=session_id))
        if not form.message.data and not form.image.data:
            return redirect(url_for("main.chat", session_id=session_id)) # Just refresh if empty

        image_relative_path = None
        image_file = form.image.data
        if image_file and image_file.filename != '':
            try:
                # Save new image
                filename = secure_filename(f"chat_{session_id}_{actor_id}_{datetime.utcnow().timestamp()}{os.path.splitext(image_file.filename)[1]}")
                filepath = os.path.join(CHAT_UPLOAD_FOLDER, filename)
                image_file.save(filepath)
                image_relative_path = f"images/chat_uploads/{filename}"
            except Exception as e:
                current_app.logger.error(f"Failed to save chat image for session {session_id}: {e}")
                flash("Error uploading image.", "danger")
                image_relative_path = None

        # Create and save message
        msg = ChatMessage(
            session_id=chat_session.session_id,
            sender_id=actor_id,
            sender_type=actor_type,
            message=form.message.data.strip() if form.message.data else None,
            image_url=image_relative_path
        )
        db.session.add(msg)
        db.session.commit() # Commit message first

        # --- Push Notification Logic ---
        recipient_token = None
        recipient_id_log = "N/A"
        recipient_user = None # Can be User or Org (though Org FCM not implemented)

        if chat_session.is_org_chat:
            if is_user: # User sending to Org
                # recipient_user = organization_participant # Future: Get org token?
                pass # FCM for Orgs not implemented
            else: # Org sending to User
                recipient_user = other_user # User is always 'other_user' in org chat context here
                if recipient_user and recipient_user.fcm_token:
                   recipient_token = recipient_user.fcm_token
                   recipient_id_log = f"User {recipient_user.user_id}"
        else: # User-user chat
            recipient_user = other_user # 'other_user' is correct here
            if recipient_user and recipient_user.fcm_token:
               recipient_token = recipient_user.fcm_token
               recipient_id_log = f"User {recipient_user.user_id}"

        if recipient_token:
            sender_name = current_actor.first_name if is_user else current_actor.name
            push_body = msg.message if msg.message else f"{sender_name} sent an image"
            try:
                send_push_notification(
                    token=recipient_token,
                    title=f"New message from {sender_name}",
                    body=push_body,
                    data={'sessionId': str(session_id), 'type': 'new_message'}
                )
                current_app.logger.info(f"Sent FCM notification for session {session_id} to {recipient_id_log}")
            except Exception as e:
                 current_app.logger.error(f"FCM failed for new chat message notification to {recipient_id_log} in session {session_id}: {e}")
        else:
             current_app.logger.info(f"No FCM token found for recipient {recipient_id_log} in session {session_id}, skipping push notification.")
        # --- End Push Notification ---

        return redirect(url_for("main.chat", session_id=session_id)) # Refresh page after sending


    # --- Fetch Messages ---
    messages = ChatMessage.query.filter_by(session_id=session_id).order_by(ChatMessage.timestamp.asc()).all()

    # --- Render Template ---
    return render_template(
        "features/chat.html",
        messages=messages,
        form=form,
        session=chat_session,
        other_user=other_user,                # The User object (either other user or user in org chat)
        organization=organization_participant, # The Org object (only in org chats)
        deal=deal,
        donation_offer=donation_offer,        # Specific offer context (only in org chats)
        the_item=the_subject,                 # Pass the loaded subject (Item, Offer, Need, or Dummy)
        trade_request=trade_request           # Specific trade context (only in user-user trades)
    )


# =========================
# ITEM SEARCH / FILTER (MODIFIED)
# =========================
@main.route("/items", methods=['GET'])
def items_list():
    """Displays searchable and filterable list of active items."""
    form = SearchForm(request.args) # Populates form from query params
    query = Item.query.filter_by(status="Active")

    # Exclude own items if logged in as a user
    if current_user.is_authenticated and isinstance(current_user._get_current_object(), User):
        query = query.filter(Item.user_id != current_user.user_id)

    # --- Apply Filters from Form Data ---
    search = form.search.data.strip() if form.search.data else None
    location_filter = form.location.data # Single location for distance sort base
    radius_str = form.radius.data # String: '', '5', '10', etc.

    # Get categories from the form (which is populated by request.args)
    categories = form.categories.data # This handles the multi-select filter
    # If the form field is empty, check for a single 'category' param from the navbar link
    if not categories and request.args.get('category'):
        categories = [request.args.get('category')]

    # --- *** GET SUB-CATEGORY FROM FORM *** ---
    sub_category = form.sub_category.data if form.sub_category.data else None # Ensure empty string becomes None
    # --- *** END ADDITION *** ---

    urgency = form.urgency.data
    condition = form.condition.data
    sort_by = form.sort_by.data or 'newest' # Default sort

    # Text search (Title or Description)
    if search:
        search_term = f"%{search}%"
        query = query.filter(or_(Item.title.ilike(search_term), Item.description.ilike(search_term)))

    # Category filter (handles multiple selections)
    if categories:
        query = query.filter(Item.category.in_(categories))

    # --- *** ADD SUB-CATEGORY FILTER *** ---
    # Only filter by sub_category if a *single* main category is selected
    # (Filtering by sub-category across multiple main categories gets complex)
    if sub_category and categories and len(categories) == 1:
        query = query.filter(Item.sub_category == sub_category)
    elif sub_category:
        # If sub-category is selected but multiple/no main categories are, ignore sub-category filter (or show warning)
        # flash("Sub-category filter only applies when a single main category is selected.", "info")
        form.sub_category.data = '' # Clear the selection in the form for clarity
    # --- *** END ADDITION *** ---

    # Other attribute filters
    if urgency: query = query.filter_by(urgency_level=urgency)
    if condition: query = query.filter_by(condition=condition)

    # --- Execute Initial Query ---
    # Default sort needed before distance sort overrides (or applied later)
    # Applying order_by here might be less efficient if distance sorting happens later
    all_items = query.all()
    results = []


    # --- Location Filtering & Sorting ---
    user_lat, user_lon = None, None
    map_center_coords = None # ADDED: Initialize for map data
    map_radius_km = None # ADDED: Initialize for map data
    base_location_name = None
    items_with_distance = []

    # Determine base location for distance calculations
    radius_active = radius_str is not None and radius_str != ''
    sort_by_distance_active = sort_by == 'distance'

    if location_filter: # Use selected location from form
         base_location_name = location_filter
         map_center_coords = geocode_location(location_filter) # Assign to map_center_coords
         if map_center_coords and map_center_coords[0] is not None:
             user_lat, user_lon = map_center_coords
         else:
             map_center_coords = None # Ensure it's null if geocoding failed

    # Assign radius value
    if radius_active:
        try: map_radius_km = float(radius_str)
        except ValueError: map_radius_km = None; radius_active = False

    # Check if we have valid coordinates to proceed with distance logic
    center_coords_valid = user_lat is not None and user_lon is not None

    if (radius_active or sort_by_distance_active) and center_coords_valid:
        radius_km_filter = map_radius_km if radius_active else float('inf')
        for item in all_items:
            # --- *** Ensure Lat/Lon exist before calculating distance *** ---
            item_lat, item_lon = item.latitude, item.longitude
            if item_lat is not None and item_lon is not None:
                dist = haversine_distance(user_lat, user_lon, item_lat, item_lon)
                if dist <= radius_km_filter:
                    items_with_distance.append({'item': item, 'distance': dist})
            elif not radius_active: # If not filtering by radius, include items without coords for non-distance sort
                items_with_distance.append({'item': item, 'distance': float('inf')})
            # --- *** END CHANGE *** ---


        # Sort by distance if requested
        if sort_by_distance_active:
            items_with_distance.sort(key=lambda x: x['distance'])

        results = [item_dist['item'] for item_dist in items_with_distance] # Extract items
    else:
        # No distance filtering or sorting needed, use all items matching other filters
        results = all_items
        if (radius_active or sort_by_distance_active) and not center_coords_valid:
            flash(f"Could not find coordinates for '{base_location_name or 'selected location'}'. Cannot filter by radius or sort by distance.", "warning")
            if sort_by_distance_active: sort_by = 'newest' # Fallback sort if distance failed


    # --- Apply Non-Distance Sorting (if distance wasn't used or failed) ---
    if sort_by == 'oldest' and not (sort_by_distance_active and center_coords_valid):
        results.sort(key=lambda item: item.created_at if item.created_at else datetime.min) # Handle potential None
    elif sort_by == 'newest' and not (sort_by_distance_active and center_coords_valid):
        results.sort(key=lambda item: item.created_at if item.created_at else datetime.min, reverse=True)


    # --- Prepare data for Map View ---
    items_for_map = [
        {"item_id": item.item_id, "title": item.title, "latitude": item.latitude, "longitude": item.longitude}
        for item in results if item.latitude and item.longitude
    ]
    items_json = json.dumps(items_for_map)
    all_locations_coords_json = json.dumps(GEOCODE_DATA) # Pass all coords for JS lookup


    # --- *** ADD `sub_categories_json` TO RENDER_TEMPLATE *** ---
    return render_template("items/search_results.html",
                           items=results,
                           form=form,
                           items_json=items_json,
                           # Pass map data similar to dashboard
                           map_center_coords=map_center_coords,
                           map_radius_km=map_radius_km,
                           all_locations_coords=all_locations_coords_json,
                           sub_categories_json=json.dumps(SUB_CATEGORIES) # *** ADD THIS ***
                           )


# =========================
# FCM Token Registration & Service Worker
# =========================
@main.route('/register_fcm_token', methods=['POST'])
@login_required # Only logged-in users/orgs register tokens
def register_fcm_token():
    """Registers or updates the FCM token for the current user/org."""
    token = request.json.get('token')
    if not token:
        return jsonify({'success': False, 'error': 'No token provided'}), 400

    actor = current_user._get_current_object()
    try:
        if isinstance(actor, User):
            actor.fcm_token = token
            db.session.commit()
            current_app.logger.info(f"Updated FCM token for user {actor.user_id}")
            return jsonify({'success': True}), 200
        elif isinstance(actor, Organization):
            # Add fcm_token field to Organization model if needed
            # actor.fcm_token = token
            # db.session.commit()
            # current_app.logger.info(f"Updated FCM token for org {actor.org_id}")
            # return jsonify({'success': True}), 200
            current_app.logger.warning(f"FCM token registration not implemented for Organizations (Org ID: {actor.org_id})")
            return jsonify({'success': False, 'error': 'FCM not enabled for organizations'}), 400
        else:
             return jsonify({'success': False, 'error': 'Invalid account type for FCM registration'}), 400
    except Exception as e:
        current_app.logger.error(f"Error saving FCM token: {e}")
        db.session.rollback()
        return jsonify({'success': False, 'error': 'Database error saving token'}), 500


@main.route('/firebase-messaging-sw.js')
def firebase_messaging_sw():
    """Serves the Firebase service worker JavaScript file."""
    # Ensure correct Content-Type for JavaScript
    return send_from_directory('static', 'firebase-messaging-sw.js', mimetype='application/javascript')


# =========================
# ERROR HANDLERS
# =========================
@main.errorhandler(403)
def forbidden(e):
    """Renders the 403 Forbidden error page."""
    return render_template("errors/403.html"), 403

@main.errorhandler(404)
def not_found(e):
    """Renders the 404 Not Found error page."""
    return render_template("errors/404.html"), 404

@main.errorhandler(405)
def method_not_allowed(e):
    """Renders the 405 Method Not Allowed error page."""
    return render_template("errors/405.html"), 405

@main.errorhandler(500)
def server_error(e):
    """Renders the 500 Internal Server Error page."""
    # Log the error for debugging
    current_app.logger.error(f"Server Error: {e}", exc_info=True)
    # Rollback database session in case of error during request handling
    db.session.rollback()
    return render_template("errors/500.html"), 500