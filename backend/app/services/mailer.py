"""Delivery of one-time codes by email.

SMTP's STARTTLS protects the message in transit using the platform's TLS
stack. It performs none of this project's cryptography: every value the
system stores is protected by the RSA, ECC and HMAC implementations
written from scratch here.
"""
import smtplib
from email.message import EmailMessage

from app.config import (OTP_TRANSPORT, SMTP_FROM, SMTP_HOST, SMTP_PASSWORD,
                        SMTP_PORT, SMTP_USER)

TIMEOUT = 10          # seconds; a dead network must not hang a login


class MailError(Exception):
    pass


def mask(address: str) -> str:
    """m***a@gmail.com - enough to recognise the address, not to learn it."""
    if not address or "@" not in address:
        return "your registered address"
    local, domain = address.split("@", 1)
    if len(local) <= 2:
        return f"{local[0]}***@{domain}"
    return f"{local[0]}***{local[-1]}@{domain}"


def send_otp(address: str, code: str) -> None:
    """Deliver a code. With OTP_TRANSPORT=console it is printed instead."""
    if OTP_TRANSPORT != "smtp":
        print(f"[OTP] {address}: {code}", flush=True)
        return

    message = EmailMessage()
    message["Subject"] = "Your Land Record System verification code"
    message["From"] = SMTP_FROM
    message["To"] = address
    message.set_content(
        f"Your verification code is {code}\n\n"
        "It expires in five minutes and can be used once.\n"
        "If you did not try to sign in, you can ignore this message."
    )

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=TIMEOUT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.send_message(message)
    except (smtplib.SMTPException, OSError) as exc:
        raise MailError(f"could not send the verification code: {exc}") from None