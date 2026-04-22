from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy import and_, func, select

from core.config import FirewallSettings, ThresholdSettings
from core.database import Database
from core.models import BlockedIP
from detectors.base import Detection
from responders.firewall import FirewallManager


class BanManager:
    def __init__(
        self,
        db: Database,
        firewall_settings: FirewallSettings,
        thresholds: ThresholdSettings,
    ):
        self.db = db
        self.firewall = FirewallManager(firewall_settings.provider)
        self.whitelist = set(firewall_settings.whitelist_ips + firewall_settings.admin_ips)
        self.thresholds = thresholds

    async def handle_detection(self, detection: Detection) -> str | None:
        if not detection.should_block or not detection.ip:
            return None
        if detection.ip in self.whitelist:
            return "whitelisted"

        async with self.db.session_factory() as session:
            history_count = await session.scalar(
                select(func.count(BlockedIP.id)).where(BlockedIP.ip == detection.ip)
            )
            current_count = int(history_count or 0) + 1
            permanent = current_count >= self.thresholds.permanent_ban_after
            duration = None if permanent else self.thresholds.temp_ban_minutes * 60 * current_count
            provider = await self.firewall.ban(
                detection.ip,
                detection.summary,
                duration_seconds=duration,
            )
            expires_at = None if permanent or duration is None else datetime.utcnow() + timedelta(seconds=duration)
            session.add(
                BlockedIP(
                    ip=detection.ip,
                    source=detection.source,
                    reason=detection.summary,
                    event_type=detection.event_type,
                    permanent=permanent,
                    expires_at=expires_at,
                )
            )
            await session.commit()
            return f"{provider}:{'permanent' if permanent else duration}"

    async def manual_block(
        self,
        ip: str,
        reason: str,
        permanent: bool,
        duration_minutes: int,
    ) -> str:
        if ip in self.whitelist:
            return "whitelisted"
        duration = None if permanent else duration_minutes * 60
        provider = await self.firewall.ban(ip, reason, duration_seconds=duration)
        async with self.db.session_factory() as session:
            session.add(
                BlockedIP(
                    ip=ip,
                    source="manual",
                    reason=reason,
                    event_type="manual_block",
                    permanent=permanent,
                    expires_at=None if permanent else datetime.utcnow() + timedelta(seconds=duration),
                )
            )
            await session.commit()
        return provider

    async def unblock(self, ip: str) -> str:
        provider = await self.firewall.unban(ip)
        async with self.db.session_factory() as session:
            rows = await session.scalars(
                select(BlockedIP).where(and_(BlockedIP.ip == ip, BlockedIP.active.is_(True)))
            )
            for row in rows.all():
                row.active = False
                row.released_at = datetime.utcnow()
            await session.commit()
        return provider

    async def release_expired_bans(self) -> None:
        async with self.db.session_factory() as session:
            rows = await session.scalars(
                select(BlockedIP).where(
                    and_(
                        BlockedIP.active.is_(True),
                        BlockedIP.permanent.is_(False),
                        BlockedIP.expires_at.is_not(None),
                        BlockedIP.expires_at <= datetime.utcnow(),
                    )
                )
            )
            for block in rows.all():
                await self.firewall.unban(block.ip)
                block.active = False
                block.released_at = datetime.utcnow()
            await session.commit()
