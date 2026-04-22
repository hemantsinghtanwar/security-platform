from __future__ import annotations

import os
from collections import Counter
from collections.abc import Iterable

import psutil


def collect_system_metrics(app_port: int | None = None) -> dict:
    vm = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    load = list(os.getloadavg()) if hasattr(os, "getloadavg") else [0.0, 0.0, 0.0]
    connection_attackers = top_connection_sources(app_port) if app_port else []
    return {
        "cpu_percent": psutil.cpu_percent(interval=None),
        "memory_percent": vm.percent,
        "disk_percent": disk.percent,
        "load_average": [round(value, 2) for value in load],
        "active_connections": active_connection_count(),
        "app_port_connections": app_port_connection_count(app_port) if app_port else 0,
        "top_connection_sources": connection_attackers,
        "top_processes": top_processes(),
    }


def active_connection_count() -> int:
    try:
        return len(psutil.net_connections(kind="inet"))
    except psutil.AccessDenied:
        return 0


def app_port_connection_count(app_port: int) -> int:
    try:
        total = 0
        for connection in psutil.net_connections(kind="inet"):
            if (
                connection.laddr
                and int(connection.laddr.port) == app_port
                and connection.raddr
                and connection.status in {psutil.CONN_ESTABLISHED, psutil.CONN_SYN_RECV, psutil.CONN_SYN_SENT}
            ):
                total += 1
        return total
    except psutil.AccessDenied:
        return 0


def top_connection_sources(app_port: int, limit: int = 10) -> list[dict]:
    counter: Counter[str] = Counter()
    try:
        for connection in psutil.net_connections(kind="inet"):
            if not connection.laddr or int(connection.laddr.port) != app_port or not connection.raddr:
                continue
            if connection.status not in {
                psutil.CONN_ESTABLISHED,
                psutil.CONN_SYN_RECV,
                psutil.CONN_SYN_SENT,
                psutil.CONN_TIME_WAIT,
            }:
                continue
            counter[str(connection.raddr.ip)] += 1
    except psutil.AccessDenied:
        return []
    return [{"ip": ip, "count": count} for ip, count in counter.most_common(limit)]


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
