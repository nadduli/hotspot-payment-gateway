"""SMTP email delivery. Pointed at Mailtrap's sandbox in development."""

from email.message import EmailMessage

import aiosmtplib

from src.core.config import get_settings


class EmailDeliveryError(Exception):
    """Raised when an outbound email fails to send."""


async def send_email(to: str, subject: str, body: str) -> None:
    """Send a plain-text email.

    Raises:
        EmailDeliveryError: the SMTP server rejected the message or was unreachable.
    """
    settings = get_settings()
    message = EmailMessage()
    message["From"] = settings.email_from
    message["To"] = to
    message["Subject"] = subject
    message.set_content(body)

    try:
        await aiosmtplib.send(
            message,
            hostname=settings.smtp_host,
            port=settings.smtp_port,
            username=settings.smtp_username or None,
            password=settings.smtp_password.get_secret_value() or None,
            start_tls=settings.smtp_start_tls,
        )
    except (aiosmtplib.SMTPException, OSError) as e:
        raise EmailDeliveryError(f"Failed to send email to {to}") from e
