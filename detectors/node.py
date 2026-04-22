from __future__ import annotations

from pathlib import Path

import psutil

from core.config import ScanSettings, ThresholdSettings
from core.metrics import listening_ports_for_process
from detectors.base import Detection, Detector


class NodeDetector(Detector):
    name = "node"

    def __init__(self, scans: ScanSettings, thresholds: ThresholdSettings):
        self.scans = scans
        self.thresholds = thresholds

    async def run_scan(self) -> list[Detection]:
        findings: list[Detection] = []
        for proc in psutil.process_iter(["pid", "name", "cmdline", "cpu_percent", "memory_info"]):
            try:
                info = proc.info
                name = (info.get("name") or "").lower()
                if name not in {"node", "nodejs"}:
                    continue
                cmdline = " ".join(info.get("cmdline") or [])
                cpu = float(info.get("cpu_percent") or 0.0)
                memory_mb = round((info["memory_info"].rss or 0) / (1024 * 1024), 2)
                ports = list(listening_ports_for_process(info["pid"]))
                suspicious_path = any(part.startswith("/tmp") or "/.cache/" in part for part in cmdline.split())
                unexpected_ports = [port for port in ports if port not in self.scans.node_allowed_ports]

                if cpu >= self.thresholds.node_cpu_percent or memory_mb >= self.thresholds.node_memory_mb:
                    findings.append(
                        Detection(
                            source=f"pid:{info['pid']}",
                            service="nodejs",
                            event_type="node_resource_abuse",
                            severity="high",
                            summary="Node.js resource abuse detected",
                            message=f"Node process {info['pid']} is consuming high resources.",
                            sample_log=cmdline,
                            confidence=85,
                            raw_data={"cpu_percent": cpu, "memory_mb": memory_mb, "ports": ports},
                        )
                    )
                if unexpected_ports or suspicious_path:
                    findings.append(
                        Detection(
                            source=f"pid:{info['pid']}",
                            service="nodejs",
                            event_type="node_suspicious_runtime",
                            severity="critical",
                            summary="Suspicious Node.js runtime detected",
                            message="Node.js process is listening on unexpected ports or running from an unsafe path.",
                            sample_log=cmdline,
                            confidence=90,
                            raw_data={
                                "ports": unexpected_ports,
                                "suspicious_path": suspicious_path,
                                "cwd_guess": str(Path(cmdline.split()[1]).parent) if len(cmdline.split()) > 1 else None,
                            },
                        )
                    )
            except (psutil.NoSuchProcess, psutil.AccessDenied, IndexError, KeyError):
                continue
        return findings
