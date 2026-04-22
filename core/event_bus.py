from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator
from dataclasses import dataclass
from datetime import datetime


@dataclass(slots=True)
class StreamMessage:
    channel: str
    payload: dict
    created_at: datetime


class EventBus:
    def __init__(self, max_queue_size: int = 500):
        self._event_subscribers: set[asyncio.Queue] = set()
        self._log_subscribers: set[tuple[asyncio.Queue, str | None]] = set()
        self.max_queue_size = max_queue_size

    async def publish_event(self, payload: dict) -> None:
        dead: list[asyncio.Queue] = []
        for queue in self._event_subscribers:
            try:
                queue.put_nowait(StreamMessage("event", payload, datetime.utcnow()))
            except asyncio.QueueFull:
                dead.append(queue)
        for queue in dead:
            self._event_subscribers.discard(queue)

    async def publish_log(self, payload: dict) -> None:
        dead: list[tuple[asyncio.Queue, str | None]] = []
        for queue, source_filter in self._log_subscribers:
            if source_filter and payload.get("source") != source_filter:
                continue
            try:
                queue.put_nowait(StreamMessage("log", payload, datetime.utcnow()))
            except asyncio.QueueFull:
                dead.append((queue, source_filter))
        for item in dead:
            self._log_subscribers.discard(item)

    async def subscribe_events(self) -> AsyncGenerator[StreamMessage, None]:
        queue: asyncio.Queue[StreamMessage] = asyncio.Queue(self.max_queue_size)
        self._event_subscribers.add(queue)
        try:
            while True:
                yield await queue.get()
        finally:
            self._event_subscribers.discard(queue)

    async def subscribe_logs(self, source: str | None = None) -> AsyncGenerator[StreamMessage, None]:
        queue: asyncio.Queue[StreamMessage] = asyncio.Queue(self.max_queue_size)
        token = (queue, source)
        self._log_subscribers.add(token)
        try:
            while True:
                yield await queue.get()
        finally:
            self._log_subscribers.discard(token)
