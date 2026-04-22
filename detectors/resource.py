from __future__ import annotations

import re

import psutil

from core.config import ThresholdSettings
from core.log_tailer import LogRecord
from detectors.base import Detection, Detector


DCPUMON_RE = re.compile(r"user=(?P<user>\S+).*cpu=(?P<cpu>\d+).*mem=(?P<mem>\d+)", re.I)


class ResourceDetector(Detector):
    name = "resource"

    def __init__(self, thresholds: ThresholdSettings):
        self.thresholds = thresholds

    async def detect(self, record: LogRecord) -> list[Detection]:
        if "dcpumon" not in record.path:
            return []
        match = DCPUMON_RE.search(record.line)
        if not match:
            return []
        cpu = float(match.group("cpu"))
        mem = float(match.group("mem"))
        if cpu < self.thresholds.process_cpu_percent and mem < self.thresholds.process_memory_mb:
            return []
        return [
            Detection(
                source=record.path,
                service="dcpumon",
                event_type="resource_abuse",
                severity="high",
                summary="High resource usage detected",
                message=f"User {match.group('user')} exceeded resource thresholds.",
                sample_log=record.line,
                confidence=80,
                raw_data={"user": match.group("user"), "cpu": cpu, "memory_mb": mem},
            )
        ]

    async def run_scan(self) -> list[Detection]:
        findings: list[Detection] = []
        for proc in psutil.process_iter(["pid", "name", "username", "cpu_percent", "memory_info", "cmdline"]):
            try:
                info = proc.info
                cpu = float(info.get("cpu_percent") or 0.0)
                memory_mb = round((info["memory_info"].rss or 0) / (1024 * 1024), 2)
                if cpu < self.thresholds.process_cpu_percent and memory_mb < self.thresholds.process_memory_mb:
                    continue
                findings.append(
                    Detection(
                        source=f"pid:{info['pid']}",
                        service="system",
                        event_type="process_abuse",
                        severity="high",
                        summary="Abnormal process behavior detected",
                        message=f"Process {info['name']} is above resource thresholds.",
                        sample_log=" ".join(info.get("cmdline") or []) or info["name"],
                        confidence=75,
                        raw_data={
                            "username": info.get("username"),
                            "cpu_percent": cpu,
                            "memory_mb": memory_mb,
                        },
                    )
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied, KeyError):
                continue
        return findings
