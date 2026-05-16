from fastapi_mail import ConnectionConfig, FastMail, MessageSchema, MessageType, NameEmail
from src.settings import settings
from src.loggings import logging
from pathlib import Path
from datetime import datetime


TEMPLATE_DIR = Path (__file__).parent / "email_temlates"


def load_otp_template (user_name: str, otp_code: str) -> str:
    """Load the OTP verification HTML template and fill in placeholders."""
    template_path = TEMPLATE_DIR / "otp_verification.html"
    html = template_path.read_text (encoding="utf-8")
    html = html.replace ("{{ user_name }}", user_name)
    html = html.replace ("{{ otp_code }}", otp_code)
    html = html.replace ("{{ year }}", str (datetime.now ().year))
    return html


def load_security_alert_template(project_name: str, subject: str, reason: str, request_id: str) -> str:
    """Load the security alert HTML template and fill in placeholders."""
    template_path = TEMPLATE_DIR / "security_alert.html"
    html = template_path.read_text(encoding="utf-8")
    html = html.replace("{{ project_name }}", project_name)
    html = html.replace("{{ subject }}", subject)
    html = html.replace("{{ reason }}", reason)
    html = html.replace("{{ request_id }}", request_id)
    html = html.replace("{{ year }}", str(datetime.now().year))
    return html


def load_report_template(target_name: str, report_content: str) -> str:
    """Load the comprehensive security report HTML template."""
    template_path = TEMPLATE_DIR / "security_report.html"
    html = template_path.read_text(encoding="utf-8")
    html = html.replace("{{ target_name }}", target_name)
    html = html.replace("{{ report_content }}", report_content)
    html = html.replace("{{ date }}", datetime.now().strftime("%Y-%m-%d"))
    html = html.replace("{{ year }}", str(datetime.now().year))
    return html



mail_config = ConnectionConfig (
    MAIL_USERNAME = settings.MAIL_USERNAME,
    MAIL_PASSWORD = settings.MAIL_PASSWORD,
    MAIL_FROM = settings.MAIL_FROM,
    MAIL_PORT = settings.MAIL_PORT,
    MAIL_SERVER = settings.MAIL_SERVER,
    MAIL_STARTTLS = False,
    MAIL_SSL_TLS = True,
    USE_CREDENTIALS = True,
    VALIDATE_CERTS = True
)

async def send_email (to_email: str, subject: str, html_body: str) -> bool:
    message = MessageSchema (
        subject=subject,
        recipients=[to_email],
        body=html_body,
        subtype=MessageType.html,
        sender=NameEmail(name="LobsterPath", email=settings.MAIL_FROM) 
    )
    try:
        fm = FastMail (config=mail_config)
        await fm.send_message (message=message)
        return True
    except Exception as e:
        logging.exception ("Error sending mail")
        return False
