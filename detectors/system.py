from __future__ import annotations

import re

from core.log_tailer import LogRecord
from detectors.base import Detection, Detector


MYSQL_AUTH_RE = re.compile(r"(Access denied for user|Aborted connection)", re.I)
SYSTEM_ERROR_RE = re.compile(r"(segfault|oom-killer|denied|pam_unix)", re.I)
IP_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")


class SystemDetector(Detector):
    name = "system"

    async def detect(self, record: LogRecord) -> list[Detection]:
        line = record.line
        findings: list[Detection] = []
        ip_match = IP_RE.search(line)
        ip = ip_match.group(1) if ip_match else None

        if "mysqld.log" in record.path and MYSQL_AUTH_RE.search(line):
            findings.append(
                Detection(
                    source=record.path,
                    service="mysql",
                    event_type="mysql_auth_anomaly",
                    severity="medium",
                    summary="MySQL authentication anomaly detected",
                    message="MySQL logs show repeated access denial or aborted connections.",
                    sample_log=line,
                    ip=ip,
                    confidence=65,
                )
            )

        if ("messages" in record.path or "secure" in record.path) and SYSTEM_ERROR_RE.search(line):
            findings.append(
                Detection(
                    source=record.path,
                    service="system",
                    event_type="system_security_signal",
                    severity="medium",
                    summary="System security signal detected",
                    message="System logs contain a security-relevant message that deserves review.",
                    sample_log=line,
                    ip=ip,
                    confidence=55,
                )
            )
        return findings
