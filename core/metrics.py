from __future__ import annotations

import os
from collections.abc import Iterable

import psutil


def collect_system_metrics() -> dict:
    vm = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    load = list(os.getloadavg()) if hasattr(os, "getloadavg") else [0.0, 0.0, 0.0]
    return {
        "cpu_percent": psutil.cpu_percent(interval=None),
        "memory_percent": vm.percent,
        "disk_percent": disk.percent,
        "load_average": [round(value, 2) for value in load],
        "active_connections": active_connection_count(),
        "top_processes": top_processes(),
    }


def active_connection_count() -> int:
    try:
        return len(psutil.net_connections(kind="inet"))
    except psutil.AccessDenied:
        return 0


def top_processes(limit: int = 10) -> list[dict]:
    processes: list[dict] = []
    for proc in psutil.process_iter(["pid", "name", "username", "cpu_percent", "memory_info"]):
        try:
            info = proc.info
            memory_mb = round((info["memory_info"].rss or 0) / (1024 * 1024), 2)
            processes.append(
                {
                    "pid": info["pid"],
                    "name": info["name"],
                    "username": info["username"],
                    "cpu_percent": info["cpu_percent"],
                    "memory_mb": memory_mb,
                }
            )
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    processes.sort(key=lambda item: (item["cpu_percent"], item["memory_mb"]), reverse=True)
    return processes[:limit]


def listening_ports_for_process(pid: int) -> Iterable[int]:
    try:
        process = psutil.Process(pid)
        for connection in process.net_connections(kind="inet"):
            if connection.status == psutil.CONN_LISTEN and connection.laddr:
                yield int(connection.laddr.port)
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return []
