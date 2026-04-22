from __future__ import annotations

import asyncio
import smtplib
from email.message import EmailMessage

from sqlalchemy import select

from core.config import SMTPSettings
from core.database import Database
from core.models import AlertRecipient


class EmailAlertService:
    def __init__(self, db: Database, smtp_settings: SMTPSettings):
        self.db = db
        self.smtp_settings = smtp_settings

    async def send_detection(self, detection: dict) -> None:
        recipients = await self._active_recipients(detection["severity"])
        if not recipients:
            return
        await asyncio.to_thread(self._send_message, recipients, detection)

    async def _active_recipients(self, severity: str) -> list[str]:
        async with self.db.session_factory() as session:
            rows = await session.scalars(select(AlertRecipient).where(AlertRecipient.enabled.is_(True)))
            recipients: list[str] = []
            for row in rows.all():
                if severity == "medium" and row.send_medium:
                    recipients.append(row.email)
                elif severity == "high" and row.send_high:
                    recipients.append(row.email)
                elif severity == "critical" and row.send_critical:
                    recipients.append(row.email)
            return recipients

    def _send_message(self, recipients: list[str], detection: dict) -> None:
        message = EmailMessage()
        message["Subject"] = f"[{detection['severity'].upper()}] {detection['summary']}"
        message["From"] = self.smtp_settings.sender
        message["To"] = ", ".join(recipients)
        message.set_content(
            "\n".join(
                [
                    f"Attack type: {detection['event_type']}",
                    f"IP: {detection.get('ip') or 'N/A'}",
                    f"Timestamp: {detection['created_at']}",
                    f"Log source: {detection['source']}",
                    f"Action taken: {detection.get('action_taken') or 'observed'}",
                    "",
                    "Sample log:",
                    detection["sample_log"],
                ]
            )
        )
        if self.smtp_settings.use_tls:
            with smtplib.SMTP_SSL(self.smtp_settings.host, self.smtp_settings.port) as server:
                self._smtp_login(server)
                server.send_message(message)
            return
        with smtplib.SMTP(self.smtp_settings.host, self.smtp_settings.port) as server:
            if self.smtp_settings.use_starttls:
                server.starttls()
            self._smtp_login(server)
            server.send_message(message)

    def _smtp_login(self, server: smtplib.SMTP) -> None:
        if self.smtp_settings.username and self.smtp_settings.password:
            server.login(self.smtp_settings.username, self.smtp_settings.password)
