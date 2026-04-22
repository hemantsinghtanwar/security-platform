from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class LoginRequest(BaseModel):
    username: str
    password: str


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    username: str
    is_active: bool


class EventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    source: str
    service: str
    event_type: str
    severity: str
    summary: str
    message: str
    ip: str | None
    domain: str | None
    path: str | None
    action_taken: str | None
    sample_log: str
    raw_data: dict[str, Any]
    country: str | None
    confidence: int
    created_at: datetime


class BlockedIPOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    ip: str
    source: str
    reason: str
    event_type: str
    permanent: bool
    expires_at: datetime | None
    active: bool
    created_at: datetime
    released_at: datetime | None


class ManualBlockRequest(BaseModel):
    ip: str
    reason: str = Field(min_length=3, max_length=255)
    permanent: bool = False
    duration_minutes: int = Field(default=60, ge=1, le=43200)


class AlertRecipientCreate(BaseModel):
    email: EmailStr
    name: str | None = None
    enabled: bool = True
    send_medium: bool = True
    send_high: bool = True
    send_critical: bool = True


class AlertRecipientOut(AlertRecipientCreate):
    model_config = ConfigDict(from_attributes=True)
    id: int


class EmailSettingsOut(BaseModel):
    host: str
    port: int
    sender: str
    use_tls: bool
    use_starttls: bool
    username: str | None = None


class EmailSettingsUpdate(BaseModel):
    host: str
    port: int = Field(ge=1, le=65535)
    sender: EmailStr
    username: str | None = None
    password: str | None = None
    use_tls: bool = False
    use_starttls: bool = False


class OverviewOut(BaseModel):
    requests_per_second: float
    active_connections: int
    top_attackers: list[dict[str, Any]]
    attack_counts: list[dict[str, Any]]
    blocked_ips: int
    recent_events: int
    cpu_percent: float
    memory_percent: float
    disk_percent: float
    wordpress_insights: dict[str, Any]
    mail_insights: dict[str, Any]


class MetricsOut(BaseModel):
    cpu_percent: float
    memory_percent: float
    disk_percent: float
    load_average: list[float]
    top_processes: list[dict[str, Any]]
    active_connections: int
