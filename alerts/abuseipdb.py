from __future__ import annotations

import httpx

from core.config import AbuseIPDBSettings


class AbuseIPDBClient:
    def __init__(self, settings: AbuseIPDBSettings):
        self.settings = settings

    async def check_ip(self, ip: str) -> dict | None:
        if not self.settings.enabled or not self.settings.api_key:
            return None
        headers = {"Key": self.settings.api_key, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 30}
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers=headers,
                params=params,
            )
            response.raise_for_status()
            data = response.json().get("data", {})
            return {
                "abuse_confidence_score": data.get("abuseConfidenceScore"),
                "country_code": data.get("countryCode"),
                "usage_type": data.get("usageType"),
            }
