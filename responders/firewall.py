from __future__ import annotations

import asyncio
import shutil


class FirewallManager:
    def __init__(self, provider: str = "auto"):
        self.provider = provider
        self.command = self._select_provider(provider)

    def _select_provider(self, provider: str) -> str:
        if provider != "auto":
            return provider
        if shutil.which("csf"):
            return "csf"
        if shutil.which("iptables"):
            return "iptables"
        return "none"

    async def ban(self, ip: str, reason: str, duration_seconds: int | None = None) -> str:
        if self.command == "csf":
            if duration_seconds:
                cmd = ["csf", "-td", ip, str(duration_seconds), reason]
            else:
                cmd = ["csf", "-d", ip, reason]
            proc = await asyncio.create_subprocess_exec(*cmd)
            await proc.wait()
            return "csf"
        if self.command == "iptables":
            check = await asyncio.create_subprocess_exec(
                "iptables",
                "-C",
                "INPUT",
                "-s",
                ip,
                "-j",
                "DROP",
            )
            await check.wait()
            if check.returncode != 0:
                proc = await asyncio.create_subprocess_exec(
                    "iptables",
                    "-I",
                    "INPUT",
                    "-s",
                    ip,
                    "-j",
                    "DROP",
                )
                await proc.wait()
            return "iptables"
        return "noop"

    async def unban(self, ip: str) -> str:
        if self.command == "csf":
            proc = await asyncio.create_subprocess_exec("csf", "-dr", ip)
            await proc.wait()
            return "csf"
        if self.command == "iptables":
            proc = await asyncio.create_subprocess_exec(
                "iptables",
                "-D",
                "INPUT",
                "-s",
                ip,
                "-j",
                "DROP",
            )
            await proc.wait()
            return "iptables"
        return "noop"
