from __future__ import annotations

import asyncio
import shutil


class FirewallManager:
    def __init__(self, provider: str = "iptables", iptables_chain: str = "SECURITY_PLATFORM"):
        self.provider = provider
        self.iptables_chain = iptables_chain
        self.command = self._select_provider(provider)

    def _select_provider(self, provider: str) -> str:
        if provider in {"iptables", "none"}:
            return provider
        if provider != "auto":
            return "none"
        if shutil.which("iptables"):
            return "iptables"
        return "none"

    async def ban(self, ip: str, reason: str, duration_seconds: int | None = None) -> str:
        if self.command == "iptables":
            await self._ensure_iptables_chain()
            if not await self._rule_exists(self.iptables_chain, ip):
                await self._run_iptables(
                    "-I",
                    self.iptables_chain,
                    "-s",
                    ip,
                    "-j",
                    "DROP",
                )
            return "iptables"
        return "noop"

    async def unban(self, ip: str) -> str:
        if self.command == "iptables":
            while await self._rule_exists(self.iptables_chain, ip):
                await self._run_iptables(
                    "-D",
                    self.iptables_chain,
                    "-s",
                    ip,
                    "-j",
                    "DROP",
                    check=False,
                )
            return "iptables"
        return "noop"

    async def _ensure_iptables_chain(self) -> None:
        if not await self._chain_exists(self.iptables_chain):
            await self._run_iptables("-N", self.iptables_chain)
        input_jump_exists = await self._run_iptables(
            "-C",
            "INPUT",
            "-j",
            self.iptables_chain,
            check=False,
        )
        if input_jump_exists != 0:
            await self._run_iptables(
                "-D",
                "INPUT",
                "-j",
                self.iptables_chain,
                check=False,
            )
            await self._run_iptables("-I", "INPUT", "1", "-j", self.iptables_chain)

    async def _chain_exists(self, chain: str) -> bool:
        return await self._run_iptables("-L", chain, check=False) == 0

    async def _rule_exists(self, chain: str, ip: str) -> bool:
        return (
            await self._run_iptables(
                "-C",
                chain,
                "-s",
                ip,
                "-j",
                "DROP",
                check=False,
            )
            == 0
        )

    async def _run_iptables(self, *args: str, check: bool = True) -> int:
        proc = await asyncio.create_subprocess_exec("iptables", "-w", *args)
        await proc.wait()
        if check and proc.returncode != 0:
            raise RuntimeError(f"iptables {' '.join(args)} failed with exit code {proc.returncode}")
        return proc.returncode
