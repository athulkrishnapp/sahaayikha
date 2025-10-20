# app/forms.py

from flask_wtf import FlaskForm
from wtforms import (
    StringField, PasswordField, SubmitField, TextAreaField,
    SelectField, BooleanField, DateField, FileField,
    MultipleFileField, IntegerField, FormField, SelectMultipleField, FieldList
)
from wtforms.validators import (
    DataRequired, Email, EqualTo, Length, Optional, NumberRange, ValidationError
)
from flask_wtf.file import FileAllowed
import json
from werkzeug.security import check_password_hash # Ensure import
# --- CORRECTED IMPORT ---
from .utils import GEOCODE_DATA # Import GEOCODE_DATA instead
# ----------------------

# --- Keep KERALA_LOCATIONS (used elsewhere, e.g., Registration) ---
# This list provides display names including sub-locations
KERALA_LOCATIONS = sorted([
    ('', 'Select Location'),
    ('Alappuzha', 'Alappuzha'),
    ('Alappuzha - Ambalapuzha', 'Alappuzha - Ambalapuzha'),
    ('Alappuzha - Cherthala', 'Alappuzha - Cherthala'),
    ('Alappuzha - Haripad', 'Alappuzha - Haripad'),
    ('Alappuzha - Kayamkulam', 'Alappuzha - Kayamkulam'),
    ('Alappuzha - Mavelikkara', 'Alappuzha - Mavelikkara'),
    ('Ernakulam', 'Ernakulam'),
    ('Ernakulam - Aluva', 'Ernakulam - Aluva'),
    ('Ernakulam - Kochi', 'Ernakulam - Kochi'),
    ('Ernakulam - Kothamangalam', 'Ernakulam - Kothamangalam'),
    ('Ernakulam - Perumbavoor', 'Ernakulam - Perumbavoor'),
    ('Ernakulam - Thrikkakara', 'Ernakulam - Thrikkakara'),
    ('Idukki', 'Idukki'),
    ('Idukki - Adimali', 'Idukki - Adimali'),
    ('Idukki - Thodupuzha', 'Idukki - Thodupuzha'),
    ('Idukki - Kattappana', 'Idukki - Kattappana'),
    ('Idukki - Munnar', 'Idukki - Munnar'),
    ('Kannur', 'Kannur'),
    ('Kannur - Kannur City', 'Kannur - Kannur City'),
    ('Kannur - Taliparamba', 'Kannur - Taliparamba'),
    ('Kannur - Payyanur', 'Kannur - Payyanur'),
    ('Kasaragod', 'Kasaragod'), # Corrected spelling assumed
    ('Kasaragod - Kasaragod City', 'Kasaragod - Kasaragod City'),
    ('Kasaragod - Kanhangad', 'Kasaragod - Kanhangad'),
    ('Kollam', 'Kollam'),
    ('Kollam - Kollam City', 'Kollam - Kollam City'),
    ('Kollam - Punalur', 'Kollam - Punalur'),
    ('Kottayam', 'Kottayam'),
    ('Kottayam - Kottayam City', 'Kottayam - Kottayam City'),
    ('Kottayam - Changanassery', 'Kottayam - Changanassery'),
    ('Kozhikode', 'Kozhikode'),
    ('Kozhikode - Kozhikode City', 'Kozhikode - Kozhikode City'),
    ('Kozhikode - Vatakara', 'Kozhikode - Vatakara'),
    ('Malappuram', 'Malappuram'),
    ('Malappuram - Malappuram City', 'Malappuram - Malappuram City'),
    ('Malappuram - Manjeri', 'Malappuram - Manjeri'),
    ('Malappuram - Perinthalmanna', 'Malappuram - Perinthalmanna'),
    ('Palakkad', 'Palakkad'),
    ('Palakkad - Palakkad City', 'Palakkad - Palakkad City'),
    ('Palakkad - Ottapalam', 'Palakkad - Ottapalam'),
    ('Pathanamthitta', 'Pathanamthitta'),
    ('Pathanamthitta - Adoor', 'Pathanamthitta - Adoor'),
    ('Pathanamthitta - Pandalam', 'Pathanamthitta - Pandalam'),
    ('Pathanamthitta - Pathanamthitta City', 'Pathanamthitta - Pathanamthitta City'),
    ('Thiruvananthapuram', 'Thiruvananthapuram'),
    ('Thiruvananthapuram - Kowdiar', 'Thiruvananthapuram - Kowdiar'),
    ('Thiruvananthapuram - Kazhakoottam', 'Thiruvananthapuram - Kazhakoottam'),
    ('Thiruvananthapuram - Thiruvallam', 'Thiruvananthapuram - Thiruvallam'),
    ('Thrissur', 'Thrissur'),
    ('Thrissur - Thrissur City', 'Thrissur - Thrissur City'),
    ('Thrissur - Irinjalakuda', 'Thrissur - Irinjalakuda'),
    ('Thrissur - Guruvayur', 'Thrissur - Guruvayur'),
    ('Wayanad', 'Wayanad'),
    ('Wayanad - Kalpetta', 'Wayanad - Kalpetta'),
    ('Wayanad - Mananthavady', 'Wayanad - Mananthavady'),
    ('Wayanad - Sultan Bathery', 'Wayanad - Sultan Bathery'),
    ('Alappuzha - Ambalappuzha Market', 'Alappuzha - Ambalappuzha Market'),
    ('Kollam - Karunagappally', 'Kollam - Karunagappally'),
    ('Kollam - Kottarakkara', 'Kollam - Kottarakkara'),
    ('Kottayam - Vaikom', 'Kottayam - Vaikom'),
    ('Kottayam - Pala', 'Kottayam - Pala'),
    ('Ernakulam - Fort Kochi', 'Ernakulam - Fort Kochi'),
    ('Ernakulam - Mattancherry', 'Ernakulam - Mattancherry'),
    ('Thrissur - Chalakudy', 'Thrissur - Chalakudy'),
    ('Thrissur - Kodungallur', 'Thrissur - Kodungallur'),
    ('Palakkad - Chittur', 'Palakkad - Chittur'),
    ('Palakkad - Mannarkkad', 'Palakkad - Mannarkkad'),
    ('Malappuram - Tirur', 'Malappuram - Tirur'),
    ('Malappuram - Nilambur', 'Malappuram - Nilambur'),
    ('Malappuram - Kondotty', 'Malappuram - Kondotty'),
    ('Kannur - Iritty', 'Kannur - Iritty'),
    ('Kannur - Payyannur Market', 'Kannur - Payyannur Market'),
    ('Idukki - Thodupuzha Town', 'Idukki - Thodupuzha Town'),
    ('Idukki - Devikulam', 'Idukki - Devikulam'),
    ('Kasaragod - Nileshwar', 'Kasaragod - Nileshwar'),
    ('Kasaragod - Poinachi', 'Kasaragod - Poinachi'),
], key=lambda x: x[1])

# --- Keep CATEGORIES, EXPECTED_RETURN_CHOICES ---
CATEGORIES = [
    ('', 'Select Category...'),
    ('Books', 'Books'), ('Clothes', 'Clothes'), ('Electronics', 'Electronics'),
    ('Food & Snacks', 'Food & Snacks'), ('Furniture', 'Furniture'), ('Gardening Items', 'Gardening Items'),
    ('Kitchen Items', 'Kitchen Items'), ('Medicines', 'Medicines'), ('Shoes & Footwear', 'Shoes & Footwear'),
    ('Sports Equipment', 'Sports Equipment'), ('Stationery', 'Stationery'), ('Toys', 'Toys'),
    ('Bags & Luggage', 'Bags & Luggage'), ('Tools & Hardware', 'Tools & Hardware'), ('Pet Supplies', 'Pet Supplies'),
    ('Art Supplies', 'Art Supplies'), ('Baby Products', 'Baby Products'), ('Beverages', 'Beverages'),
    ('Cameras & Photography', 'Cameras & Photography'), ('Cleaning Supplies', 'Cleaning Supplies'),
    ('Computers & Accessories', 'Computers & Accessories'), ('Cosmetics', 'Cosmetics'), ('Decor', 'Decor'),
    ('Fitness Equipment', 'Fitness Equipment'), ('Garden Tools', 'Garden Tools'), ('Health & Wellness', 'Health & Wellness'),
    ('Home Appliances', 'Home Appliances'), ('Jewelry', 'Jewelry'), ('Lamps & Lighting', 'Lamps & Lighting'),
    ('Musical Instruments', 'Musical Instruments'), ('Office Supplies', 'Office Supplies'), ('Outdoor Gear', 'Outdoor Gear'),
    ('Party Supplies', 'Party Supplies'), ('Personal Care', 'Personal Care'),
    ('Travel Accessories', 'Travel Accessories'), ('Vehicles & Accessories', 'Vehicles & Accessories'),
    ('Other', 'Other')
]

EXPECTED_RETURN_CHOICES = [('', 'Select Expected Return...')] + CATEGORIES[1:] + [('Money', 'Money')]

# --- Keep CONDITIONS, URGENCY_LEVELS ---
CONDITIONS = [
    ('', 'Select Condition...'), ('New', 'New'), ('Like New', 'Like New'),
    ('Good', 'Good'), ('Fair', 'Fair'), ('Needs Repair', 'Needs Repair')
]

URGENCY_LEVELS = [
    ('', 'Select Urgency...'), ('Low', 'Low'), ('Medium', 'Medium'), ('Urgent', 'Urgent')
]


# -------------------------
# Search and Filter Forms
# -------------------------
class SearchForm(FlaskForm):
    search = StringField('Search', validators=[Optional()])
    location = SelectField('Near Location', choices=KERALA_LOCATIONS, validators=[Optional()])
    radius = SelectField('Radius',
                         choices=[('', 'Any Distance'), ('5', '5 km'), ('10', '10 km'), ('20', '20 km'), ('50', '50 km'), ('100', '100+ km')],
                         default='', validators=[Optional()])
    categories = SelectMultipleField('Categories', choices=CATEGORIES[1:], validators=[Optional()])
    urgency = SelectField('Urgency', choices=[('', 'All Urgencies')] + [(level[0], level[1]) for level in URGENCY_LEVELS if level[0]], validators=[Optional()])
    condition = SelectField('Condition', choices=[('', 'All Conditions')] + [(cond[0], cond[1]) for cond in CONDITIONS if cond[0]], validators=[Optional()])
    sort_by = SelectField('Sort by', choices=[('newest', 'Newest'), ('oldest', 'Oldest'), ('distance', 'Distance (Nearest First)')], default='newest', validators=[Optional()])
    submit = SubmitField('Search')

# -------------------------
# User / Org / Admin Forms
# -------------------------

class RegistrationForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired(), Length(max=255)])
    last_name = StringField('Last Name', validators=[Optional(), Length(max=255)])
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=255)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    phone = StringField('Phone', validators=[Optional(), Length(max=50)])
    location = SelectField('Location', choices=KERALA_LOCATIONS, validators=[DataRequired()])
    profile_picture = FileField('Profile Picture', validators=[Optional(), FileAllowed(['jpg', 'png', 'jpeg'])])
    search_radius = SelectField('Default Search Radius',
                                choices=[('5', '5 km'), ('10', '10 km'), ('20', '20 km'), ('50', '50 km'), ('100', '100+ km')],
                                default='20', validators=[DataRequired()])
    submit = SubmitField('Register')

class OrganizationRegistrationForm(FlaskForm):
    name = StringField('Organization Name', validators=[DataRequired(), Length(max=255)])
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=255)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    phone = StringField('Phone', validators=[Optional(), Length(max=100)])
    location = SelectField('Location', choices=KERALA_LOCATIONS, validators=[DataRequired()])
    profile_picture = FileField('Organization Logo/Profile', validators=[Optional(), FileAllowed(['jpg', 'png', 'jpeg'])])
    description = TextAreaField('About Your Organization', validators=[Optional(), Length(max=2000)])
    submit = SubmitField('Register Organization')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=255)])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

class OtpForm(FlaskForm):
    otp = StringField('OTP', validators=[DataRequired(), Length(min=6, max=6)])
    submit = SubmitField('Verify')

class ForgotPasswordForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Request Password Reset')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('New Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm New Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Reset Password')

# -------------------------
# Item & Trade Forms
# -------------------------
class ItemForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(max=255)])
    description = TextAreaField('Description', validators=[Optional()])
    category = SelectField('Category', choices=CATEGORIES, validators=[DataRequired()])
    type = SelectField('Type', choices=[('Trade', 'Trade'), ('Share', 'Share')], validators=[DataRequired()])
    condition = SelectField('Condition', choices=CONDITIONS, validators=[DataRequired()])
    urgency_level = SelectField('Urgency', choices=URGENCY_LEVELS, validators=[Optional()])
    expected_return = SelectField('Expected Return (for Trade)', choices=EXPECTED_RETURN_CHOICES, validators=[Optional()])
    images = MultipleFileField('Upload Images (Max 8)', validators=[Optional(), FileAllowed(['jpg', 'png', 'jpeg'])])
    submit = SubmitField('Post Item')

    def validate_expected_return(self, field):
        if self.type.data == 'Trade' and not field.data:
            raise ValidationError('Please specify what you expect in return for a trade.')
        if self.type.data == 'Share' and field.data:
            field.data = ''

# -------------------------
# Disaster Needs & Donations
# -------------------------
class DisasterNeedForm(FlaskForm):
    title = StringField('Need Title (e.g., "Kottayam Flood Relief")', validators=[DataRequired(), Length(max=255)])
    categories = SelectMultipleField('Categories (select multiple)', choices=CATEGORIES[1:], validators=[DataRequired()])
    description = TextAreaField('Description', validators=[DataRequired()])
    location = SelectField('Location', choices=KERALA_LOCATIONS, validators=[DataRequired()])
    submit = SubmitField('Post Need')

class OfferedItemForm(FlaskForm):
    """Sub-form for a single item within a larger donation offer."""
    class Meta:
        csrf = False

    title = StringField('Item Name', validators=[DataRequired(), Length(max=255)])
    category = SelectField('Category', choices=CATEGORIES, validators=[DataRequired()])
    description = TextAreaField('Description', validators=[Optional(), Length(max=1000)])
    quantity = IntegerField('Quantity', validators=[DataRequired(), NumberRange(min=1)], default=1)
    condition = SelectField('Condition', choices=[('New', 'New'), ('Used', 'Used')], validators=[DataRequired()])
    image = FileField('Image', validators=[Optional(), FileAllowed(['jpg', 'png', 'jpeg'])])
    manufacture_date = DateField('Manufacture Date', validators=[Optional()])
    expiry_date = DateField('Expiry Date', validators=[Optional()])

class DonationOfferForm(FlaskForm):
    """Main form for a user to offer a list of items."""
    offered_items = FieldList(FormField(OfferedItemForm), min_entries=1)
    submit = SubmitField('Submit Donation Offer')

# -------------------------
# Feedback, Reports, Follow
# -------------------------
class FeedbackForm(FlaskForm):
    message = TextAreaField('Message', validators=[DataRequired(), Length(max=2000)])
    submit = SubmitField('Submit')

class ReportForm(FlaskForm): # Generic Report
    reason = TextAreaField('Reason for Reporting', validators=[DataRequired(), Length(min=10, max=1000)])
    submit = SubmitField('Submit Report')

class OrganizationReportForm(FlaskForm): # Specific for reporting Org from offer page
    reason = TextAreaField('Reason for Reporting Organization', validators=[DataRequired(), Length(min=10, max=1000)])
    submit = SubmitField('Submit Report')

class CategoryFollowForm(FlaskForm):
    category = SelectField('Category', choices=CATEGORIES, validators=[DataRequired()])
    submit = SubmitField('Follow/Unfollow')

# -------------------------
# Chat Form
# -------------------------
class ChatForm(FlaskForm):
    message = StringField('Message', validators=[Optional(), Length(max=1000)])
    image = FileField('Image', validators=[Optional(), FileAllowed(['jpg', 'png', 'jpeg', 'gif'])])
    submit = SubmitField('Send')


# --- Profile Form (CORRECTED - No new password fields) ---
class ProfileForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired(), Length(max=64)])
    last_name = StringField('Last Name', validators=[Optional(), Length(max=64)])
    email = StringField('Email', render_kw={'readonly': True, 'disabled': True}, validators=[DataRequired(), Email()])
    phone = StringField('Phone Number', validators=[Optional(), Length(min=10, max=15)])
    location = SelectField('Location (District)', choices=[('', 'Select District...')] + [(d, d) for d in sorted(GEOCODE_DATA.keys())], validators=[DataRequired()])
    search_radius = SelectField('Default Search Radius (km)', choices=[('5', '5 km'), ('10', '10 km'), ('20', '20 km'), ('50', '50 km'), ('', 'Any distance')], default='10', validators=[Optional()])
    profile_picture = FileField('Update Profile Picture', validators=[Optional(), FileAllowed(['jpg', 'png', 'jpeg'], 'Images only!')])
    # REMOVED password field
    # REMOVED confirm_password field
    submit = SubmitField('Update Profile')