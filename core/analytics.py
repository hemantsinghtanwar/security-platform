from __future__ import annotations

import time
from collections import Counter, defaultdict, deque


class RollingCounter:
    def __init__(self, window_seconds: int):
        self.window_seconds = window_seconds
        self.values: dict[str, deque[float]] = defaultdict(deque)

    def add(self, key: str, timestamp: float | None = None) -> int:
        ts = timestamp or time.time()
        bucket = self.values[key]
        bucket.append(ts)
        self._trim(bucket, ts)
        return len(bucket)

    def count(self, key: str, timestamp: float | None = None) -> int:
        ts = timestamp or time.time()
        bucket = self.values[key]
        self._trim(bucket, ts)
        return len(bucket)

    def top(self, limit: int = 10) -> list[tuple[str, int]]:
        now = time.time()
        counts: list[tuple[str, int]] = []
        for key, bucket in self.values.items():
            self._trim(bucket, now)
            if bucket:
                counts.append((key, len(bucket)))
        counts.sort(key=lambda item: item[1], reverse=True)
        return counts[:limit]

    def _trim(self, bucket: deque[float], timestamp: float) -> None:
        cutoff = timestamp - self.window_seconds
        while bucket and bucket[0] < cutoff:
            bucket.popleft()


class EWMA:
    def __init__(self, alpha: float = 0.3):
        self.alpha = alpha
        self.value: float | None = None

    def update(self, sample: float) -> float:
        if self.value is None:
            self.value = sample
        else:
            self.value = (self.alpha * sample) + ((1.0 - self.alpha) * self.value)
        return self.value


class TrafficAnalytics:
    def __init__(self):
        self.requests_per_ip = RollingCounter(window_seconds=60)
        self.xmlrpc_posts = RollingCounter(window_seconds=300)
        self.wp_logins = RollingCounter(window_seconds=300)
        self.api_calls = RollingCounter(window_seconds=300)
        self.mail_outbound = RollingCounter(window_seconds=600)
        self.failures = RollingCounter(window_seconds=300)
        self.per_second_counter = RollingCounter(window_seconds=1)
        self.connection_samples: deque[tuple[float, int]] = deque(maxlen=300)
        self.attack_types: Counter[str] = Counter()
        self.rps_ewma = EWMA(alpha=0.2)

    def record_request(self, ip: str) -> tuple[int, float]:
        per_minute = self.requests_per_ip.add(ip)
        current_rps = sum(count for _, count in self.per_second_counter.top(limit=5000))
        baseline = self.rps_ewma.update(current_rps)
        return per_minute, baseline

    def record_request_global(self) -> int:
        return self.per_second_counter.add("global")

    def snapshot(self) -> dict:
        return {
            "top_attackers": [
                {"ip": ip, "count": count} for ip, count in self.requests_per_ip.top()
            ],
            "attack_counts": [
                {"event_type": event_type, "count": count}
                for event_type, count in self.attack_types.most_common(10)
            ],
            "requests_per_second": float(self.per_second_counter.count("global")),
        }
