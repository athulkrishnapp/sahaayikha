# app/email.py
from flask import current_app
from flask_mail import Message
from app import mail

def send_email(to, subject, template):
    """
    Sends an email to a recipient.
    """
    msg = Message(
        subject,
        recipients=[to],
        html=template,
        sender=current_app.config['MAIL_USERNAME']
    )
    mail.send(msg)