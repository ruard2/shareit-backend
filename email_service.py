"""
email_service.py – SMTP e-mailhelper voor de Spullen Delen app.

Configureer via omgevingsvariabelen:
  SMTP_HOST     – bijv. smtp.gmail.com
  SMTP_PORT     – bijv. 587
  SMTP_USER     – afzender e-mailadres
  SMTP_PASSWORD – wachtwoord / app-wachtwoord
  SMTP_FROM     – displaynaam + adres (optioneel, valt terug op SMTP_USER)

Als SMTP_HOST niet is ingesteld, wordt de mail alleen gelogged (dev-modus).
"""

import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


def send_email(to: str, subject: str, body_text: str, body_html: str | None = None) -> bool:
    """
    Verstuur een e-mail.
    Geeft True terug bij succes, False bij mislukking.
    """
    host = os.getenv("SMTP_HOST", "")
    port = int(os.getenv("SMTP_PORT", "587"))
    user = os.getenv("SMTP_USER", "")
    password = os.getenv("SMTP_PASSWORD", "")
    from_addr = os.getenv("SMTP_FROM", user)

    if not host or not user:
        # Dev-modus: print naar console
        print(f"[EMAIL DEV-MODUS] Aan: {to}")
        print(f"  Onderwerp: {subject}")
        print(f"  Tekst: {body_text}")
        return True

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = from_addr
        msg["To"] = to

        msg.attach(MIMEText(body_text, "plain", "utf-8"))
        if body_html:
            msg.attach(MIMEText(body_html, "html", "utf-8"))

        with smtplib.SMTP(host, port, timeout=10) as smtp:
            smtp.ehlo()
            smtp.starttls()
            smtp.login(user, password)
            smtp.sendmail(from_addr, [to], msg.as_string())

        return True
    except Exception as exc:
        print(f"[EMAIL FOUT] {exc}")
        return False


def send_pin_reset_email(to: str, user_name: str, reset_token: str) -> bool:
    """
    Stuur de PIN-reset e-mail naar de gebruiker.
    """
    subject = "Jouw pincode opnieuw instellen – Spullen Delen"

    body_text = (
        f"Hoi {user_name},\n\n"
        "Je hebt een verzoek ingediend om je pincode opnieuw in te stellen.\n\n"
        f"Jouw reset-code: {reset_token}\n\n"
        "Voer deze code in de app in binnen 30 minuten.\n\n"
        "Als je dit niet hebt aangevraagd, kun je deze e-mail negeren.\n\n"
        "Met vriendelijke groet,\nHet Spullen Delen team"
    )

    body_html = f"""
    <html><body>
      <p>Hoi <strong>{user_name}</strong>,</p>
      <p>Je hebt een verzoek ingediend om je pincode opnieuw in te stellen.</p>
      <p style="font-size:24px; letter-spacing:4px; font-weight:bold;">{reset_token}</p>
      <p>Voer deze code in de app in binnen <strong>30 minuten</strong>.</p>
      <p>Als je dit niet hebt aangevraagd, kun je deze e-mail negeren.</p>
      <br><p>Met vriendelijke groet,<br>Het Spullen Delen team</p>
    </body></html>
    """

    return send_email(to, subject, body_text, body_html)
