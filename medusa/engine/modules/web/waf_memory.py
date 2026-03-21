"""WAF memory — session-scoped bypass memory."""
from __future__ import annotations

__all__ = ["WAFMemory"]


class WAFMemory:
    """Persistent WAF bypass memory within session."""

    def __init__(self) -> None:
        self._blocks: dict[str, set[str]] = {}
        self._successes: dict[str, list[str]] = {}

    def record_block(
        self,
        waf_vendor: str,
        payload: str,
        mutation_applied: str,
        response_code: int,
        response_signature: str,
    ) -> None:
        """Record blocked mutation."""
        key = f"{waf_vendor}:{mutation_applied}"
        if key not in self._blocks:
            self._blocks[key] = set()
        self._blocks[key].add(response_signature)

    def record_success(
        self,
        waf_vendor: str,
        payload: str,
        mutation_applied: str,
        bypass_variant: str,
    ) -> None:
        """Record successful bypass."""
        if waf_vendor not in self._successes:
            self._successes[waf_vendor] = []
        self._successes[waf_vendor].append(mutation_applied)

    def get_skip_list(self, waf_vendor: str) -> set[str]:
        """Return mutations to skip for this WAF."""
        return set()

    def get_priority_mutations(self, waf_vendor: str) -> list[str]:
        """Return high-value mutations for this WAF."""
        return self._successes.get(waf_vendor, [])
