from __future__ import annotations

import asyncio
import glob
from dataclasses import dataclass
from pathlib import Path
from typing import Awaitable, Callable


@dataclass(slots=True)
class LogRecord:
    category: str
    pattern: str
    path: str
    line: str


@dataclass(slots=True)
class FileCursor:
    path: str
    inode: int
    offset: int


class LogTailer:
    def __init__(
        self,
        patterns: dict[str, list[str]],
        interval_seconds: int,
        refresh_seconds: int,
        callback: Callable[[LogRecord], Awaitable[None]],
    ):
        self.patterns = patterns
        self.interval_seconds = interval_seconds
        self.refresh_seconds = refresh_seconds
        self.callback = callback
        self._cursors: dict[str, FileCursor] = {}
        self._stopped = asyncio.Event()

    async def run(self) -> None:
        refresh_counter = 0
        while not self._stopped.is_set():
            if refresh_counter == 0:
                self._refresh_files()
            await self._poll_once()
            refresh_counter = (refresh_counter + self.interval_seconds) % max(
                self.refresh_seconds,
                self.interval_seconds,
            )
            await asyncio.sleep(self.interval_seconds)

    async def stop(self) -> None:
        self._stopped.set()

    def _refresh_files(self) -> None:
        discovered: dict[str, FileCursor] = {}
        for category, patterns in self.patterns.items():
            for pattern in patterns:
                for path in glob.glob(pattern):
                    file_path = Path(path)
                    if not file_path.is_file():
                        continue
                    stat = file_path.stat()
                    cursor = self._cursors.get(path)
                    if cursor and cursor.inode == stat.st_ino:
                        discovered[path] = cursor
                        continue
                    discovered[path] = FileCursor(path=path, inode=stat.st_ino, offset=stat.st_size)
        self._cursors = discovered

    async def _poll_once(self) -> None:
        for category, patterns in self.patterns.items():
            for pattern in patterns:
                for path in glob.glob(pattern):
                    file_path = Path(path)
                    if not file_path.is_file():
                        continue
                    try:
                        await self._consume_file(category, pattern, file_path)
                    except FileNotFoundError:
                        continue

    async def _consume_file(self, category: str, pattern: str, file_path: Path) -> None:
        stat = file_path.stat()
        cursor = self._cursors.get(str(file_path))
        if cursor is None or cursor.inode != stat.st_ino or stat.st_size < cursor.offset:
            cursor = FileCursor(path=str(file_path), inode=stat.st_ino, offset=0)
        with file_path.open("r", encoding="utf-8", errors="ignore") as handle:
            handle.seek(cursor.offset)
            while True:
                line = handle.readline()
                if not line:
                    break
                await self.callback(
                    LogRecord(
                        category=category,
                        pattern=pattern,
                        path=str(file_path),
                        line=line.rstrip(),
                    )
                )
            cursor.offset = handle.tell()
        self._cursors[str(file_path)] = cursor
