from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, field_validator


class SMTPSettings(BaseModel):
    host: str = "localhost"
    port: int = 25
    username: str | None = None
    password: str | None = None
    sender: str = "security-platform@localhost"
    use_tls: bool = False
    use_starttls: bool = False


class DatabaseSettings(BaseModel):
    url: str = "sqlite+aiosqlite:////var/lib/security-platform/security-platform.db"


class APISettings(BaseModel):
    host: str = "0.0.0.0"
    port: int = 8443
    jwt_secret: str = "change-me-in-production"
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 480
    secure_cookies: bool = False
    allowed_origins: list[str] = Field(default_factory=lambda: ["*"])


class ThresholdSettings(BaseModel):
    ssh_failures_per_5m: int = 8
    cpanel_failures_per_5m: int = 8
    mail_auth_failures_per_10m: int = 10
    requests_per_minute: int = 900
    requests_per_second_spike: int = 80
    concurrent_connection_threshold: int = 250
    xmlrpc_posts_per_5m: int = 20
    wp_login_posts_per_5m: int = 20
    api_calls_per_5m: int = 150
    outbound_emails_per_10m: int = 250
    node_cpu_percent: float = 85.0
    node_memory_mb: int = 1024
    process_cpu_percent: float = 95.0
    process_memory_mb: int = 2048
    temp_ban_minutes: int = 30
    permanent_ban_after: int = 5
    php_scan_interval_minutes: int = 15
    node_scan_interval_seconds: int = 60
    resource_scan_interval_seconds: int = 60
    log_scan_interval_seconds: int = 1
    log_refresh_interval_seconds: int = 30
    max_php_files_per_cycle: int = 1000


class AbuseIPDBSettings(BaseModel):
    enabled: bool = False
    api_key: str | None = None
    confidence_threshold: int = 75


class GeoIPSettings(BaseModel):
    enabled: bool = False
    city_db_path: str | None = None


class FirewallSettings(BaseModel):
    provider: str = "iptables"
    iptables_chain: str = "SECURITY_PLATFORM"
    whitelist_ips: list[str] = Field(default_factory=list)
    admin_ips: list[str] = Field(default_factory=list)

    @field_validator("whitelist_ips", "admin_ips", mode="before")
    @classmethod
    def _ensure_list(cls, value: Any) -> list[str]:
        if value is None:
            return []
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return list(value)


class LogSourceSettings(BaseModel):
    system_messages: list[str] = Field(
        default_factory=lambda: ["/var/log/messages", "/var/log/secure"]
    )
    cpanel: list[str] = Field(
        default_factory=lambda: [
            "/usr/local/cpanel/logs/access_log",
            "/usr/local/cpanel/logs/login_log",
            "/usr/local/cpanel/logs/error_log",
            "/usr/local/cpanel/logs/cphulkd.log",
            "/usr/local/cpanel/logs/cphulkd_errors.log",
            "/usr/local/cpanel/logs/api_log",
            "/usr/local/cpanel/logs/session_log",
        ]
    )
    mail: list[str] = Field(
        default_factory=lambda: [
            "/var/log/exim_mainlog",
            "/var/log/exim_rejectlog",
            "/var/log/maillog",
        ]
    )
    web: list[str] = Field(
        default_factory=lambda: [
            "/etc/apache2/logs/domlogs/*",
            "/var/log/apache2/error_log",
            "/var/log/apache2/modsec_audit.log",
        ]
    )
    mysql: list[str] = Field(default_factory=lambda: ["/var/log/mysqld.log"])
    performance: list[str] = Field(default_factory=lambda: ["/var/log/dcpumon/*"])

    def all_patterns(self) -> dict[str, list[str]]:
        return {
            "system": self.system_messages,
            "cpanel": self.cpanel,
            "mail": self.mail,
            "web": self.web,
            "mysql": self.mysql,
            "performance": self.performance,
        }


class ScanSettings(BaseModel):
    php_roots: list[str] = Field(default_factory=lambda: ["/home"])
    node_allowed_ports: list[int] = Field(default_factory=lambda: [80, 443, 3000, 8080])


class AppSettings(BaseModel):
    platform_name: str = "WHM Security Platform"
    config_path: str = "/etc/security-platform/config.yml"
    admin_email: str = "hemant@cloudtechtiq.com"
    database: DatabaseSettings = Field(default_factory=DatabaseSettings)
    api: APISettings = Field(default_factory=APISettings)
    smtp: SMTPSettings = Field(default_factory=SMTPSettings)
    thresholds: ThresholdSettings = Field(default_factory=ThresholdSettings)
    abuseipdb: AbuseIPDBSettings = Field(default_factory=AbuseIPDBSettings)
    geoip: GeoIPSettings = Field(default_factory=GeoIPSettings)
    firewall: FirewallSettings = Field(default_factory=FirewallSettings)
    logs: LogSourceSettings = Field(default_factory=LogSourceSettings)
    scans: ScanSettings = Field(default_factory=ScanSettings)


@dataclass(slots=True)
class LoadedSettings:
    data: AppSettings
    path: Path


def load_settings(config_path: str | Path | None = None) -> LoadedSettings:
    chosen = Path(config_path or os.getenv("SECURITY_PLATFORM_CONFIG", "/etc/security-platform/config.yml"))
    if chosen.exists():
        import yaml

        raw = yaml.safe_load(chosen.read_text()) or {}
        settings = AppSettings.model_validate(raw)
        return LoadedSettings(data=settings, path=chosen)
    settings = AppSettings()
    fallback_path = Path(settings.config_path)
    return LoadedSettings(data=settings, path=fallback_path)
