from __future__ import annotations

import re
from collections import defaultdict

from core.analytics import TrafficAnalytics
from core.config import ThresholdSettings
from core.log_tailer import LogRecord
from detectors.base import Detection, Detector


IP_RE = re.compile(r"(?:(?:from|rip=|rhost=|\[)(?P<ip>\d{1,3}(?:\.\d{1,3}){3}))")
SSH_RE = re.compile(r"(Failed password|Invalid user|authentication failure)", re.I)
FTP_RE = re.compile(r"(pure-ftpd|proftpd).*(authentication failed|login failed)", re.I)
CPANEL_RE = re.compile(r"(login failed|failed login|cphulk|security policy triggered)", re.I)
MAIL_RE = re.compile(r"(imap-login|pop3-login|dovecot).*(auth failed|disconnected)", re.I)
WHM_RE = re.compile(r"(whostmgrd|whm).*(failed|denied)", re.I)


class AuthDetector(Detector):
    name = "auth"

    def __init__(self, thresholds: ThresholdSettings, analytics: TrafficAnalytics):
        self.thresholds = thresholds
        self.analytics = analytics
        self.last_alert_count: dict[str, int] = defaultdict(int)

    async def detect(self, record: LogRecord) -> list[Detection]:
        service = self._service_for(record)
        if not service:
            return []
        ip = self._extract_ip(record.line)
        if not ip:
            return []

        key = f"{service}:{ip}"
        count = self.analytics.failures.add(key)
        threshold = self._threshold_for(service)
        if count < threshold or self.last_alert_count[key] == count:
            return []

        self.last_alert_count[key] = count
        severity = "high" if count < (threshold * 2) else "critical"
        return [
            Detection(
                source=record.path,
                service=service,
                event_type="brute_force",
                severity=severity,
                summary=f"{service.upper()} brute force detected",
                message=f"{count} failed {service} logins observed from {ip} within the detection window.",
                sample_log=record.line,
                ip=ip,
                confidence=85,
                raw_data={"count": count, "category": record.category},
                should_block=True,
            )
        ]

    def _extract_ip(self, line: str) -> str | None:
        match = IP_RE.search(line)
        if match:
            return match.group("ip")
        fallback = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", line)
        return fallback.group(1) if fallback else None

    def _service_for(self, record: LogRecord) -> str | None:
        line = record.line
        path = record.path.lower()
        if "secure" in path and SSH_RE.search(line):
            return "ssh"
        if FTP_RE.search(line):
            return "ftp"
        if "login_log" in path and CPANEL_RE.search(line):
            return "cpanel"
        if "cphulk" in path:
            return "cpanel"
        if MAIL_RE.search(line):
            return "email"
        if WHM_RE.search(line):
            return "whm"
        return None

    def _threshold_for(self, service: str) -> int:
        if service == "ssh":
            return self.thresholds.ssh_failures_per_5m
        if service == "email":
            return self.thresholds.mail_auth_failures_per_10m
        return self.thresholds.cpanel_failures_per_5m
