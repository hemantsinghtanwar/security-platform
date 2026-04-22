from __future__ import annotations

import re
from collections import defaultdict

from core.analytics import TrafficAnalytics
from core.config import ThresholdSettings
from core.log_tailer import LogRecord
from detectors.base import Detection, Detector


API_IP_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")
API_USER_RE = re.compile(r"(?:user|username|owner)=([A-Za-z0-9._-]+)")


class APIDetector(Detector):
    name = "api"

    def __init__(self, thresholds: ThresholdSettings, analytics: TrafficAnalytics):
        self.thresholds = thresholds
        self.analytics = analytics
        self.last_emitted: dict[str, int] = defaultdict(int)

    async def detect(self, record: LogRecord) -> list[Detection]:
        if "api_log" not in record.path:
            return []
        ip_match = API_IP_RE.search(record.line)
        if not ip_match:
            return []
        ip = ip_match.group(1)
        user_match = API_USER_RE.search(record.line)
        user = user_match.group(1) if user_match else "unknown"
        key = f"{user}:{ip}"
        count = self.analytics.api_calls.add(key)
        if count < self.thresholds.api_calls_per_5m or self.last_emitted[key] == count:
            return []
        self.last_emitted[key] = count
        return [
            Detection(
                source=record.path,
                service="cpanel_api",
                event_type="api_abuse",
                severity="high",
                summary="WHM/cPanel API abuse detected",
                message=f"{user}@{ip} made {count} API calls within 5 minutes.",
                sample_log=record.line,
                ip=ip,
                confidence=80,
                raw_data={"user": user, "count": count},
                should_block=True,
            )
        ]
