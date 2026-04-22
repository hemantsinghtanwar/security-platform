from __future__ import annotations

import asyncio
import json
import logging
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path

from geoip2.database import Reader
from geoip2.errors import AddressNotFoundError
from sqlalchemy import desc, func, select

from alerts.abuseipdb import AbuseIPDBClient
from alerts.emailer import EmailAlertService
from core.account_resolver import AccountResolver
from core.analytics import TrafficAnalytics
from core.config import AppSettings
from core.database import Database
from core.event_bus import EventBus
from core.log_tailer import LogRecord, LogTailer
from core.metrics import collect_system_metrics
from core.models import AlertRecipient, Base, BlockedIP, Event, Setting
from detectors.api import APIDetector
from detectors.auth import AuthDetector
from detectors.base import Detection, Detector
from detectors.ddos import ConnectionFloodDetector
from detectors.mail import MailDetector
from detectors.malware import PHPMalwareDetector
from detectors.modsec import ModSecurityDetector
from detectors.node import NodeDetector
from detectors.resource import ResourceDetector
from detectors.system import SystemDetector
from detectors.web import WebDetector
from responders.ban_manager import BanManager


logger = logging.getLogger(__name__)


class SecurityEngine:
    def __init__(self, settings: AppSettings, db: Database, event_bus: EventBus):
        self.settings = settings
        self.db = db
        self.event_bus = event_bus
        self.analytics = TrafficAnalytics()
        self.emailer = EmailAlertService(db, settings.smtp)
        self.abuseipdb = AbuseIPDBClient(settings.abuseipdb)
        self.ban_manager = BanManager(db, settings.firewall, settings.thresholds)
        self.account_resolver = AccountResolver()
        self.geoip_reader = self._build_geoip_reader()
        self.detector_failures: dict[str, tuple[str, datetime]] = {}
        self.log_detectors: list[Detector] = [
            AuthDetector(settings.thresholds, self.analytics),
            WebDetector(settings.thresholds, self.analytics),
            MailDetector(settings.thresholds, self.analytics),
            APIDetector(settings.thresholds, self.analytics),
            ModSecurityDetector(),
            SystemDetector(),
            ResourceDetector(settings.thresholds),
        ]
        self.scan_detectors: list[tuple[Detector, int, int]] = [
            (
                PHPMalwareDetector(db, settings.scans, settings.thresholds),
                settings.thresholds.php_scan_interval_minutes * 60,
                30,
            ),
            (
                NodeDetector(settings.scans, settings.thresholds),
                settings.thresholds.node_scan_interval_seconds,
                10,
            ),
            (
                ResourceDetector(settings.thresholds),
                settings.thresholds.resource_scan_interval_seconds,
                10,
            ),
            (
                ConnectionFloodDetector(settings.thresholds, settings.api.port),
                10,
                5,
            ),
        ]
        self.tailer = LogTailer(
            patterns=settings.logs.all_patterns(),
            interval_seconds=settings.thresholds.log_scan_interval_seconds,
            refresh_seconds=settings.thresholds.log_refresh_interval_seconds,
            callback=self._handle_log_record,
        )
        self.tasks: list[asyncio.Task] = []

    async def start(self) -> None:
        await self._initialize_storage()
        self.tasks.append(asyncio.create_task(self.tailer.run(), name="log-tailer"))
        self.tasks.append(asyncio.create_task(self._ban_cleanup_loop(), name="ban-cleanup"))
        for detector, interval, initial_delay in self.scan_detectors:
            self.tasks.append(
                asyncio.create_task(
                    self._run_detector_loop(detector, interval, initial_delay),
                    name=f"scan-{detector.name}",
                )
            )

    async def stop(self) -> None:
        await self.tailer.stop()
        for task in self.tasks:
            task.cancel()
        if self.tasks:
            await asyncio.gather(*self.tasks, return_exceptions=True)
        if self.geoip_reader:
            self.geoip_reader.close()

    async def _initialize_storage(self) -> None:
        async with self.db.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        async with self.db.session_factory() as session:
            existing = await session.scalar(
                select(AlertRecipient).where(AlertRecipient.email == self.settings.admin_email)
            )
            if existing is None:
                session.add(AlertRecipient(email=self.settings.admin_email, name="Admin"))
            for key, value in {
                "smtp_host": self.settings.smtp.host,
                "smtp_port": str(self.settings.smtp.port),
                "smtp_sender": self.settings.smtp.sender,
                "smtp_username": self.settings.smtp.username or "",
                "smtp_password": self.settings.smtp.password or "",
                "smtp_use_tls": json.dumps(self.settings.smtp.use_tls),
                "smtp_use_starttls": json.dumps(self.settings.smtp.use_starttls),
            }.items():
                row = await session.get(Setting, key)
                if row is None:
                    session.add(Setting(key=key, value=value))
            await session.commit()

    async def _handle_log_record(self, record: LogRecord) -> None:
        await self.event_bus.publish_log(
            {
                "source": record.path,
                "category": record.category,
                "line": record.line,
                "created_at": datetime.utcnow().isoformat(),
            }
        )
        for detector in self.log_detectors:
            findings = await detector.detect(record)
            for finding in findings:
                await self._process_detection(finding)

    async def _run_detector_loop(self, detector: Detector, interval: int, initial_delay: int = 0) -> None:
        if initial_delay > 0:
            await asyncio.sleep(initial_delay)
        while True:
            try:
                findings = await detector.run_scan()
                for finding in findings:
                    await self._process_detection(finding)
            except Exception as exc:  # pragma: no cover - defensive background loop
                logger.exception("Detector %s raised an exception", detector.name)
                await self._record_detector_failure(detector.name, exc)
            await asyncio.sleep(interval)

    async def _record_detector_failure(self, detector_name: str, exc: Exception) -> None:
        message = str(exc)
        now = datetime.utcnow()
        last = self.detector_failures.get(detector_name)
        if last and last[0] == message and (now - last[1]).total_seconds() < 300:
            return
        self.detector_failures[detector_name] = (message, now)
        await self._process_detection(
            Detection(
                source=f"detector:{detector_name}",
                service="platform",
                event_type="detector_failure",
                severity="medium",
                summary="Background detector raised an exception",
                message=message,
                sample_log=message,
                confidence=50,
                raw_data={"detector": detector_name},
            )
        )

    async def _ban_cleanup_loop(self) -> None:
        while True:
            await self.ban_manager.release_expired_bans()
            await asyncio.sleep(60)

    async def _process_detection(self, detection: Detection) -> None:
        self.analytics.attack_types[detection.event_type] += 1
        event_created_at = datetime.utcnow()
        owner = self.account_resolver.resolve(detection.domain, detection.source)
        if owner["domain"] and not detection.domain:
            detection.domain = owner["domain"]
        detection.raw_data = {
            **detection.raw_data,
            "account": owner["account"],
            "resolved_domain": owner["domain"],
        }
        country = None
        abuse_data = None
        if detection.ip:
            country = self._lookup_country(detection.ip)
            try:
                abuse_data = await self.abuseipdb.check_ip(detection.ip)
            except Exception:
                abuse_data = None

        action_taken = await self.ban_manager.handle_detection(detection)
        payload = {
            "source": detection.source,
            "service": detection.service,
            "event_type": detection.event_type,
            "severity": detection.severity,
            "summary": detection.summary,
            "message": detection.message,
            "ip": detection.ip,
            "domain": detection.domain,
            "path": detection.path,
            "action_taken": action_taken,
            "sample_log": detection.sample_log,
            "raw_data": {**detection.raw_data, "abuseipdb": abuse_data or {}},
            "country": country,
            "confidence": detection.confidence,
            "created_at": event_created_at,
        }
        async with self.db.session_factory() as session:
            event = Event(**payload)
            session.add(event)
            await session.commit()
            await session.refresh(event)
            outbound = {
                **{**payload, "created_at": event.created_at.isoformat()},
                "id": event.id,
            }
        await self.event_bus.publish_event(outbound)
        if detection.severity in {"high", "critical"}:
            await self.emailer.send_detection(outbound)

    def _build_geoip_reader(self) -> Reader | None:
        if not self.settings.geoip.enabled or not self.settings.geoip.city_db_path:
            return None
        path = Path(self.settings.geoip.city_db_path)
        if not path.exists():
            return None
        return Reader(str(path))

    def _lookup_country(self, ip: str) -> str | None:
        if not self.geoip_reader:
            return None
        try:
            return self.geoip_reader.city(ip).country.name
        except (AddressNotFoundError, ValueError):
            return None

    async def overview(self) -> dict:
        metrics = collect_system_metrics(self.settings.api.port)
        analytics_snapshot = self.analytics.snapshot()
        top_attackers = metrics["top_connection_sources"] or analytics_snapshot["top_attackers"]
        async with self.db.session_factory() as session:
            recent_events = await session.scalar(
                select(func.count(Event.id)).where(Event.created_at >= datetime.utcnow() - timedelta(days=1))
            )
            blocked_count = await session.scalar(
                select(func.count(BlockedIP.id)).where(BlockedIP.active.is_(True))
            )
            xmlrpc_count = await session.scalar(
                select(func.count(Event.id)).where(Event.event_type == "xmlrpc_bruteforce")
            )
            wp_login_count = await session.scalar(
                select(func.count(Event.id)).where(Event.event_type == "wp_login_bruteforce")
            )
            mail_abuse_count = await session.scalar(
                select(func.count(Event.id)).where(Event.service == "mail")
            )
            recent_rows = await session.scalars(
                select(Event).order_by(desc(Event.created_at)).limit(500)
            )
            recent_event_rows = recent_rows.all()
        top_domains = self._top_domains(recent_event_rows)
        top_accounts = self._top_accounts(recent_event_rows)
        return {
            **analytics_snapshot,
            "top_attackers": top_attackers,
            "top_domains": top_domains,
            "top_accounts": top_accounts,
            "blocked_ips": int(blocked_count or 0),
            "recent_events": int(recent_events or 0),
            "cpu_percent": metrics["cpu_percent"],
            "memory_percent": metrics["memory_percent"],
            "disk_percent": metrics["disk_percent"],
            "active_connections": metrics["active_connections"],
            "app_port_connections": metrics["app_port_connections"],
            "wordpress_insights": {
                "xmlrpc_attacks": int(xmlrpc_count or 0),
                "wp_login_bruteforce": int(wp_login_count or 0),
            },
            "mail_insights": {
                "mail_events": int(mail_abuse_count or 0),
                "outbound_keys": len(self.analytics.mail_outbound.top(50)),
            },
            "firewall": {
                "provider": self.settings.firewall.provider,
                "chain": self.settings.firewall.iptables_chain,
                "whitelist_size": len(self.ban_manager.whitelist),
            },
        }

    async def recent_events(self, limit: int = 100) -> list[Event]:
        async with self.db.session_factory() as session:
            rows = await session.scalars(select(Event).order_by(desc(Event.created_at)).limit(limit))
            return rows.all()

    def _top_domains(self, events: list[Event], limit: int = 10) -> list[dict]:
        counter: Counter[str] = Counter()
        for event in events:
            if event.domain:
                counter[event.domain] += 1
                continue
            resolved = (event.raw_data or {}).get("resolved_domain")
            if resolved:
                counter[str(resolved)] += 1
        return [{"domain": domain, "count": count} for domain, count in counter.most_common(limit)]

    def _top_accounts(self, events: list[Event], limit: int = 10) -> list[dict]:
        counter: Counter[str] = Counter()
        for event in events:
            account = (event.raw_data or {}).get("account")
            if account:
                counter[str(account)] += 1
        return [{"account": account, "count": count} for account, count in counter.most_common(limit)]
