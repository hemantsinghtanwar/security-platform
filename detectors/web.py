from __future__ import annotations

import os
import re
from collections import defaultdict

from core.analytics import TrafficAnalytics
from core.config import ThresholdSettings
from core.log_tailer import LogRecord
from detectors.base import Detection, Detector


APACHE_RE = re.compile(
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+\S+\s+\S+\s+\[[^\]]+\]\s+"(?P<method>[A-Z]+)\s+(?P<path>\S+)'
)
SQLI_RE = re.compile(r"(union(\+|%20)+select|select.+from|sleep\(|benchmark\(|or 1=1)", re.I)
XSS_RE = re.compile(r"(<script|%3Cscript|onerror=|javascript:)", re.I)
LFI_RFI_RE = re.compile(r"(\.\./|\.\.\\|php://|expect://|https?://.+\?=)", re.I)
SENSITIVE_RE = re.compile(r"(/wp-admin|/xmlrpc\.php|/\.env|/vendor/|/phpmyadmin)", re.I)


class WebDetector(Detector):
    name = "web"

    def __init__(self, thresholds: ThresholdSettings, analytics: TrafficAnalytics):
        self.thresholds = thresholds
        self.analytics = analytics
        self.last_spike_rps = 0
        self.last_emitted: dict[str, int] = defaultdict(int)

    async def detect(self, record: LogRecord) -> list[Detection]:
        findings: list[Detection] = []
        parsed = self._parse_apache(record)
        if not parsed:
            if "error_log" in record.path.lower() and "modsecurity" not in record.line.lower():
                return []
            return findings

        ip, method, path, domain = parsed
        self.analytics.record_request_global()
        per_minute = self.analytics.requests_per_ip.add(ip)
        current_rps = self.analytics.per_second_counter.count("global")
        baseline = self.analytics.rps_ewma.update(current_rps)

        if per_minute >= self.thresholds.requests_per_minute:
            findings.append(
                self._threshold_detection(
                    key=f"rpm:{ip}",
                    count=per_minute,
                    threshold=self.thresholds.requests_per_minute,
                    source=record.path,
                    service="apache",
                    event_type="traffic_flood",
                    severity="high",
                    summary="Request flood detected",
                    message=f"{ip} exceeded per-minute request threshold with {per_minute} requests.",
                    record=record,
                    ip=ip,
                    domain=domain,
                    path=path,
                    should_block=True,
                    confidence=80,
                )
            )

        if current_rps >= self.thresholds.requests_per_second_spike and current_rps > max(5, baseline * 2):
            if current_rps != self.last_spike_rps:
                self.last_spike_rps = current_rps
                findings.append(
                    Detection(
                        source=record.path,
                        service="apache",
                        event_type="traffic_spike",
                        severity="high",
                        summary="Traffic spike detected",
                        message=f"Observed {current_rps} requests/sec against a baseline near {baseline:.2f}.",
                        sample_log=record.line,
                        ip=ip,
                        domain=domain,
                        path=path,
                        confidence=70,
                        raw_data={"current_rps": current_rps, "baseline": baseline},
                    )
                )

        lower_path = path.lower()
        if SQLI_RE.search(lower_path):
            findings.append(self._attack(record, ip, domain, path, "sql_injection", "critical", "SQL injection pattern detected", True, 95))
        if XSS_RE.search(lower_path):
            findings.append(self._attack(record, ip, domain, path, "xss", "high", "XSS pattern detected", True, 90))
        if LFI_RFI_RE.search(lower_path):
            findings.append(self._attack(record, ip, domain, path, "lfi_rfi", "critical", "LFI/RFI pattern detected", True, 92))
        if SENSITIVE_RE.search(lower_path):
            findings.append(
                Detection(
                    source=record.path,
                    service="apache",
                    event_type="sensitive_path_access",
                    severity="medium",
                    summary="Sensitive path access observed",
                    message=f"{ip} requested sensitive path {path}.",
                    sample_log=record.line,
                    ip=ip,
                    domain=domain,
                    path=path,
                    confidence=65,
                    raw_data={"method": method},
                )
            )

        if method == "POST" and "/xmlrpc.php" in lower_path:
            count = self.analytics.xmlrpc_posts.add(ip)
            if count >= self.thresholds.xmlrpc_posts_per_5m:
                findings.append(
                    self._threshold_detection(
                        key=f"xmlrpc:{ip}",
                        count=count,
                        threshold=self.thresholds.xmlrpc_posts_per_5m,
                        source=record.path,
                        service="wordpress",
                        event_type="xmlrpc_bruteforce",
                        severity="high",
                        summary="WordPress XML-RPC flood detected",
                        message=f"{ip} sent {count} XML-RPC POST requests in 5 minutes.",
                        record=record,
                        ip=ip,
                        domain=domain,
                        path=path,
                        should_block=True,
                        confidence=88,
                    )
                )

        if method == "POST" and "/wp-login.php" in lower_path:
            count = self.analytics.wp_logins.add(ip)
            if count >= self.thresholds.wp_login_posts_per_5m:
                findings.append(
                    self._threshold_detection(
                        key=f"wplogin:{ip}",
                        count=count,
                        threshold=self.thresholds.wp_login_posts_per_5m,
                        source=record.path,
                        service="wordpress",
                        event_type="wp_login_bruteforce",
                        severity="high",
                        summary="WordPress login brute force detected",
                        message=f"{ip} triggered {count} POST requests to wp-login.php in 5 minutes.",
                        record=record,
                        ip=ip,
                        domain=domain,
                        path=path,
                        should_block=True,
                        confidence=88,
                    )
                )

        return [finding for finding in findings if finding is not None]

    def _parse_apache(self, record: LogRecord) -> tuple[str, str, str, str | None] | None:
        match = APACHE_RE.search(record.line)
        if not match:
            return None
        domain = None
        if "/domlogs/" in record.path:
            domain = os.path.basename(record.path)
        return match.group("ip"), match.group("method"), match.group("path"), domain

    def _attack(
        self,
        record: LogRecord,
        ip: str,
        domain: str | None,
        path: str,
        event_type: str,
        severity: str,
        summary: str,
        should_block: bool,
        confidence: int,
    ) -> Detection:
        return Detection(
            source=record.path,
            service="apache",
            event_type=event_type,
            severity=severity,
            summary=summary,
            message=f"Potential {event_type.replace('_', ' ')} request from {ip} targeting {path}.",
            sample_log=record.line,
            ip=ip,
            domain=domain,
            path=path,
            confidence=confidence,
            should_block=should_block,
        )

    def _threshold_detection(
        self,
        *,
        key: str,
        count: int,
        threshold: int,
        source: str,
        service: str,
        event_type: str,
        severity: str,
        summary: str,
        message: str,
        record: LogRecord,
        ip: str,
        domain: str | None,
        path: str,
        should_block: bool,
        confidence: int,
    ) -> Detection | None:
        if self.last_emitted[key] == count:
            return None
        self.last_emitted[key] = count
        return Detection(
            source=source,
            service=service,
            event_type=event_type,
            severity=severity,
            summary=summary,
            message=message,
            sample_log=record.line,
            ip=ip,
            domain=domain,
            path=path,
            confidence=confidence,
            should_block=should_block,
            raw_data={"count": count, "threshold": threshold},
        )
