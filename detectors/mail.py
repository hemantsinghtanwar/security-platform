from __future__ import annotations

import re
from collections import defaultdict

from core.analytics import TrafficAnalytics
from core.config import ThresholdSettings
from core.log_tailer import LogRecord
from detectors.base import Detection, Detector


DELIVERY_RE = re.compile(r"\s=>\s.*A=(?P<auth>[^\s:]+:[^\s]+)")
IP_RE = re.compile(r"\[(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\]")
SPAM_RE = re.compile(r"(spam|phishing|malware|rejected RCPT|blacklist|spamassassin)", re.I)
AUTH_FAIL_RE = re.compile(r"(auth failed|authentication failure|login failed)", re.I)


class MailDetector(Detector):
    name = "mail"

    def __init__(self, thresholds: ThresholdSettings, analytics: TrafficAnalytics):
        self.thresholds = thresholds
        self.analytics = analytics
        self.last_emitted: dict[str, int] = defaultdict(int)

    async def detect(self, record: LogRecord) -> list[Detection]:
        line = record.line
        findings: list[Detection] = []

        if AUTH_FAIL_RE.search(line):
            ip = self._extract_ip(line)
            if ip:
                key = f"mail-auth:{ip}"
                count = self.analytics.failures.add(key)
                if count >= self.thresholds.mail_auth_failures_per_10m and self.last_emitted[key] != count:
                    self.last_emitted[key] = count
                    findings.append(
                        Detection(
                            source=record.path,
                            service="mail",
                            event_type="mail_bruteforce",
                            severity="high",
                            summary="Mail authentication brute force detected",
                            message=f"{ip} caused {count} failed mail authentications.",
                            sample_log=line,
                            ip=ip,
                            confidence=85,
                            should_block=True,
                        )
                    )

        delivery = DELIVERY_RE.search(line)
        if delivery:
            sender = delivery.group("auth")
            key = f"mail-out:{sender}"
            count = self.analytics.mail_outbound.add(key)
            if count >= self.thresholds.outbound_emails_per_10m and self.last_emitted[key] != count:
                self.last_emitted[key] = count
                findings.append(
                    Detection(
                        source=record.path,
                        service="mail",
                        event_type="mail_abuse",
                        severity="critical",
                        summary="High outbound email rate detected",
                        message=f"{sender} sent {count} outbound emails within 10 minutes.",
                        sample_log=line,
                        ip=self._extract_ip(line),
                        confidence=90,
                        raw_data={"sender": sender, "count": count},
                    )
                )

        if SPAM_RE.search(line):
            findings.append(
                Detection(
                    source=record.path,
                    service="mail",
                    event_type="spam_signal",
                    severity="medium",
                    summary="Spam-related mail log entry detected",
                    message="Mail logs contain spam or blacklist indicators that warrant review.",
                    sample_log=line,
                    ip=self._extract_ip(line),
                    confidence=70,
                )
            )
        return findings

    def _extract_ip(self, line: str) -> str | None:
        match = IP_RE.search(line)
        return match.group("ip") if match else None
