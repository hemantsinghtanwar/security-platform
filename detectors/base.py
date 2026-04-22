from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from core.log_tailer import LogRecord


@dataclass(slots=True)
class Detection:
    source: str
    service: str
    event_type: str
    severity: str
    summary: str
    message: str
    sample_log: str
    ip: str | None = None
    domain: str | None = None
    path: str | None = None
    confidence: int = 60
    raw_data: dict[str, Any] = field(default_factory=dict)
    should_block: bool = False


class Detector:
    name = "base"

    async def detect(self, record: LogRecord) -> list[Detection]:
        return []

    async def run_scan(self) -> list[Detection]:
        return []
