from __future__ import annotations

import re

from core.log_tailer import LogRecord
from detectors.base import Detection, Detector


CLIENT_RE = re.compile(r"(?:client |\[client )(?P<ip>\d{1,3}(?:\.\d{1,3}){3})")
RULE_RE = re.compile(r'\[id "(?P<rule>\d+)"\]')


class ModSecurityDetector(Detector):
    name = "modsec"

    async def detect(self, record: LogRecord) -> list[Detection]:
        if "modsec_audit" not in record.path and "modsecurity" not in record.line.lower():
            return []
        ip_match = CLIENT_RE.search(record.line)
        rule_match = RULE_RE.search(record.line)
        ip = ip_match.group("ip") if ip_match else None
        rule = rule_match.group("rule") if rule_match else None
        return [
            Detection(
                source=record.path,
                service="modsecurity",
                event_type="modsecurity_alert",
                severity="high",
                summary="ModSecurity alert observed",
                message="ModSecurity generated an alert that may indicate exploit traffic.",
                sample_log=record.line,
                ip=ip,
                confidence=88,
                raw_data={"rule_id": rule},
                should_block=ip is not None,
            )
        ]
