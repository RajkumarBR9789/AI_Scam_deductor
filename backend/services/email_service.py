"""
Email delivery service for ScamShield — sends OTP and password-reset codes via Gmail SMTP.
"""

import logging
import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from config import settings

logger = logging.getLogger(__name__)


def _send_email(to_email: str, subject: str, text_body: str, html_body: str) -> bool:
    """Low-level SMTP send. Returns True on success, False on failure."""
    if not settings.EMAIL_USER or not settings.EMAIL_PASSWORD:
        logger.warning("SMTP credentials not configured. Email not sent.")
        return False

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = f"ScamShield <{settings.EMAIL_FROM}>"
        msg["To"] = to_email

        msg.attach(MIMEText(text_body, "plain"))
        msg.attach(MIMEText(html_body, "html"))

        context = ssl.create_default_context()
        with smtplib.SMTP(settings.EMAIL_HOST, settings.EMAIL_PORT, timeout=10) as server:
            server.ehlo()
            server.starttls(context=context)
            server.login(settings.EMAIL_USER, settings.EMAIL_PASSWORD)
            server.sendmail(settings.EMAIL_FROM, to_email, msg.as_string())

        logger.info("Email sent successfully to %s", to_email)
        return True
    except Exception as exc:
        logger.error("Failed to send email to %s: %s", to_email, exc)
        return False


def send_otp_email(to_email: str, otp_code: str, full_name: str = "") -> bool:
    """
    Send a 6-digit OTP verification email to *to_email* via Gmail SMTP (TLS).
    Returns True on success, False on failure.
    """
    name = full_name.strip() or to_email.split("@")[0]

    html_body = f"""
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#0A0A0A;font-family:'Courier New',monospace">
  <table width="100%" cellpadding="0" cellspacing="0">
    <tr>
      <td align="center" style="padding:40px 20px">
        <table width="480" style="background:#1A1A1A;border:1px solid #333;padding:40px">
          <tr>
            <td>
              <h1 style="color:#FFFFFF;margin:0 0 8px">⚡ ScamShield</h1>
              <p style="color:#888;margin:0 0 32px;font-size:13px">Detect. Protect. Trust.</p>
              <hr style="border:0;border-top:1px solid #333;margin-bottom:32px">

              <p style="color:#FFFFFF;font-size:15px">Hi <strong>{name}</strong>,</p>
              <p style="color:#AAAAAA;font-size:14px">
                Use the code below to verify your email address.
                This code expires in <strong style="color:#FFFFFF">{settings.OTP_EXPIRE_MINUTES} minutes</strong>.
              </p>

              <div style="background:#0A0A0A;border:1px solid #FFFFFF;padding:24px;
                          text-align:center;margin:24px 0">
                <span style="font-size:36px;font-weight:bold;color:#00FF88;
                              letter-spacing:12px;font-family:'Courier New',monospace">
                  {otp_code}
                </span>
              </div>

              <p style="color:#666;font-size:12px">
                If you did not create a ScamShield account, ignore this email.
              </p>

              <hr style="border:0;border-top:1px solid #333;margin-top:32px">
              <p style="color:#444;font-size:11px;margin:16px 0 0">
                &copy; 2025 ScamShield. All rights reserved.
              </p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>
"""

    text_body = (
        f"ScamShield — Email Verification\n\n"
        f"Hi {name},\n\n"
        f"Your OTP code is: {otp_code}\n\n"
        f"It expires in {settings.OTP_EXPIRE_MINUTES} minutes.\n\n"
        f"Ignore this email if you did not sign up for ScamShield."
    )

    return _send_email(
        to_email,
        "⚡ ScamShield — Email Verification Code",
        text_body,
        html_body,
    )


def send_reset_password_email(to_email: str, reset_code: str, full_name: str = "") -> bool:
    """
    Send a 6-digit password-reset code to *to_email*.
    Returns True on success, False on failure.
    """
    name = full_name.strip() or to_email.split("@")[0]
    expire_label = (
        "1 minute" if settings.RESET_TOKEN_EXPIRE_MINUTES == 1
        else f"{settings.RESET_TOKEN_EXPIRE_MINUTES} minutes"
    )

    html_body = f"""
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#0A0A0A;font-family:'Courier New',monospace">
  <table width="100%" cellpadding="0" cellspacing="0">
    <tr>
      <td align="center" style="padding:40px 20px">
        <table width="480" style="background:#1A1A1A;border:1px solid #333;padding:40px">
          <tr>
            <td>
              <h1 style="color:#FFFFFF;margin:0 0 8px">⚡ ScamShield</h1>
              <p style="color:#888;margin:0 0 32px;font-size:13px">Password Reset Request</p>
              <hr style="border:0;border-top:1px solid #333;margin-bottom:32px">

              <p style="color:#FFFFFF;font-size:15px">Hi <strong>{name}</strong>,</p>
              <p style="color:#AAAAAA;font-size:14px">
                We received a request to reset your password.
                Use the code below — it expires in
                <strong style="color:#FFFFFF">{expire_label}</strong>.
              </p>

              <div style="background:#0A0A0A;border:1px solid #FFFFFF;padding:24px;
                          text-align:center;margin:24px 0">
                <span style="font-size:36px;font-weight:bold;color:#FF6B6B;
                              letter-spacing:12px;font-family:'Courier New',monospace">
                  {reset_code}
                </span>
              </div>

              <p style="color:#666;font-size:12px">
                ⚠️ If you didn't request this, ignore this email.
                Your password will remain unchanged.
              </p>

              <hr style="border:0;border-top:1px solid #333;margin-top:32px">
              <p style="color:#444;font-size:11px;margin:16px 0 0">
                &copy; 2025 ScamShield. All rights reserved.
              </p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>
"""

    text_body = (
        f"ScamShield — Password Reset\n\n"
        f"Hi {name},\n\n"
        f"Your password reset code is: {reset_code}\n\n"
        f"It expires in {expire_label}.\n\n"
        f"If you didn't request this, ignore this email."
    )

    return _send_email(
        to_email,
        "⚡ ScamShield — Password Reset Code",
        text_body,
        html_body,
    )
