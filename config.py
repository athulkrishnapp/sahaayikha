# config.py
import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "replace-this-in-production")
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", "sqlite:///" + os.path.join(BASE_DIR, "sahaayikha.db")
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    ITEM_EXPIRY_DAYS_DEFAULT = int(os.environ.get("ITEM_EXPIRY_DAYS_DEFAULT", 30))

    # Email settings for sending OTP and password reset links
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = 'sahaayikha.team@gmail.com'
    MAIL_PASSWORD = 'ktfm zewf rrlf fitz'