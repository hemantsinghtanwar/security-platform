from __future__ import annotations

from collections import Counter

import psutil

from core.config import ThresholdSettings
from detectors.base import Detection, Detector


class ConnectionFloodDetector(Detector):
    name = "connection_flood"

    def __init__(self, thresholds: ThresholdSettings, app_port: int):
        self.thresholds = thresholds
        self.app_port = app_port
        self.last_emitted: dict[str, int] = {}

    async def run_scan(self) -> list[Detection]:
        per_ip: Counter[str] = Counter()
        try:
            for connection in psutil.net_connections(kind="inet"):
                if not connection.laddr or int(connection.laddr.port) != self.app_port or not connection.raddr:
                    continue
                if connection.status not in {
                    psutil.CONN_ESTABLISHED,
                    psutil.CONN_SYN_RECV,
                    psutil.CONN_SYN_SENT,
                    psutil.CONN_TIME_WAIT,
                }:
                    continue
                per_ip[str(connection.raddr.ip)] += 1
        except psutil.AccessDenied:
            return []

        findings: list[Detection] = []
        for ip, count in per_ip.items():
            if count < self.thresholds.concurrent_connection_threshold:
                continue
            if self.last_emitted.get(ip) == count:
                continue
            self.last_emitted[ip] = count
            findings.append(
                Detection(
                    source=f"socket:{self.app_port}",
                    service="app_port",
                    event_type="ddos_connection_flood",
                    severity="critical" if count >= (self.thresholds.concurrent_connection_threshold * 2) else "high",
                    summary="Connection flood detected on platform port",
                    message=f"{ip} opened {count} concurrent connections to port {self.app_port}.",
                    sample_log=f"{ip} -> {self.app_port} ({count} concurrent connections)",
                    ip=ip,
                    confidence=92,
                    raw_data={"count": count, "port": self.app_port},
                    should_block=True,
                )
            )
        return findings
