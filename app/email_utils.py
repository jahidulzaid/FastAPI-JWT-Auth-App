# app/email_utils.py
import smtplib
from email.message import EmailMessage

from .config import settings


def send_email(to_email: str, subject: str, body: str):
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = settings.EMAIL_FROM
    msg["To"] = to_email
    msg.set_content(body)

    with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT) as server:
        server.starttls()
        server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
        server.send_message(msg)
