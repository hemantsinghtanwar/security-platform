from __future__ import annotations

from pathlib import Path


class AccountResolver:
    def __init__(
        self,
        trueuserdomains_path: str = "/etc/trueuserdomains",
        userdomains_path: str = "/etc/userdomains",
    ):
        self.trueuserdomains_path = Path(trueuserdomains_path)
        self.userdomains_path = Path(userdomains_path)
        self.domain_to_account = self._load_mappings()

    def resolve(self, domain: str | None = None, source_path: str | None = None) -> dict[str, str | None]:
        normalized_domain = self._normalize_domain(domain, source_path)
        account = self.domain_to_account.get(normalized_domain) if normalized_domain else None
        if account is None and source_path:
            account = self._account_from_path(source_path)
        return {
            "domain": normalized_domain,
            "account": account,
        }

    def _load_mappings(self) -> dict[str, str]:
        mappings: dict[str, str] = {}
        for path in (self.trueuserdomains_path, self.userdomains_path):
            if not path.exists():
                continue
            for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
                if ":" not in line:
                    continue
                domain, account = [item.strip() for item in line.split(":", 1)]
                if domain and account:
                    mappings[domain.lower()] = account
        return mappings

    def _normalize_domain(self, domain: str | None, source_path: str | None) -> str | None:
        candidate = domain
        if source_path and "/domlogs/" in source_path:
            candidate = Path(source_path).name
        if not candidate:
            return None
        return candidate.lower()

    def _account_from_path(self, source_path: str) -> str | None:
        try:
            path = Path(source_path)
        except TypeError:
            return None
        parts = path.parts
        if "home" in parts:
            idx = parts.index("home")
            if idx + 1 < len(parts):
                return parts[idx + 1]
        return None
