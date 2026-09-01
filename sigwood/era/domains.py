"""Bounded, aggregate-only registrable-domain eligibility and ledgers."""

from __future__ import annotations

import ipaddress
from collections import Counter
from dataclasses import dataclass
from typing import Callable

from sigwood.common.tld import TLD_EXTRACT


DOMAIN_CAP = 1_000_000


def effective_psl_snapshot_bytes(*, extractor: object = TLD_EXTRACT) -> bytes:
    """Return a deterministic byte view of the offline extractor's suffix set.

    The closure identity must bind the actual no-network PSL material used by
    the registrable-domain eligibility rule, rather than only the installed
    library version.  The ordered list is
    an implementation input, not an output or a persisted domain identity.
    """
    suffixes = getattr(extractor, "tlds", None)
    if not isinstance(suffixes, list) or not all(isinstance(item, str) for item in suffixes):
        raise RuntimeError("effective PSL snapshot is unavailable")
    return "\n".join(sorted(suffixes)).encode("utf-8")


@dataclass(frozen=True)
class DomainLedgerFacts:
    """Identity-free registrable-domain ledger facts safe for cards and receipts."""

    cap: int
    cap_exceeded: bool
    psl_available: bool
    excluded: tuple[tuple[str, int], ...]
    retained_domains: int


@dataclass(frozen=True)
class DomainHistory:
    """One bounded identity's eligible-week presence, never rendered directly."""

    first_week: tuple[int, int]
    weeks: frozenset[tuple[int, int]]


def registrable_domain(query: object, *, extractor: Callable[[str], object] = TLD_EXTRACT) -> tuple[str | None, str | None]:
    """Apply the registrable-domain eligibility rule once.

    Return a registrable key or a counted exclusion reason.
    """
    if not isinstance(query, str):
        return None, "malformed"
    name = query.strip().lower().rstrip(".")
    if not name or any(not label for label in name.split(".")):
        return None, "malformed"
    if name.endswith(".arpa") or name == "arpa":
        return None, "ptr-arpa"
    if name.endswith(".local") or name == "local":
        return None, "mdns-local"
    try:
        ipaddress.ip_address(name)
    except ValueError:
        pass
    else:
        return None, "ip-literal"
    if "." not in name:
        return None, "single-label"
    try:
        extracted = extractor(name)
    except Exception:
        return None, "psl-unavailable"
    registrable = getattr(extracted, "top_domain_under_public_suffix", "")
    suffix = getattr(extracted, "suffix", "")
    if not suffix:
        return None, "malformed"
    if not registrable:
        return None, "public-suffix-only"
    return str(registrable), None


class DomainLedger:
    """Exact fixed-cap first-week/presence ledger with sticky abstention."""

    def __init__(self, *, cap: int = DOMAIN_CAP) -> None:
        if cap <= 0:
            raise ValueError("domain cap must be positive")
        self.cap = cap
        self._domains: dict[str, DomainHistory] = {}
        self._excluded: Counter[str] = Counter()
        self._cap_exceeded = False
        self._psl_available = True

    def add(self, query: object, week: tuple[int, int]) -> None:
        key, reason = registrable_domain(query)
        if reason is not None:
            self._excluded[reason] += 1
            if reason == "psl-unavailable":
                self._psl_available = False
            return
        assert key is not None
        prior = self._domains.get(key)
        if prior is None:
            if len(self._domains) >= self.cap:
                self._cap_exceeded = True
                return
            self._domains[key] = DomainHistory(week, frozenset({week}))
            return
        self._domains[key] = DomainHistory(prior.first_week, prior.weeks | {week})

    def merge(self, other: "DomainLedger") -> "DomainLedger":
        if self.cap != other.cap:
            raise ValueError("domain ledgers must share a cap")
        merged = DomainLedger(cap=self.cap)
        merged._excluded = self._excluded + other._excluded
        merged._cap_exceeded = self._cap_exceeded or other._cap_exceeded
        merged._psl_available = self._psl_available and other._psl_available
        for key in sorted(set(self._domains) | set(other._domains)):
            left, right = self._domains.get(key), other._domains.get(key)
            if left is None:
                chosen = right
            elif right is None:
                chosen = left
            else:
                first = min(left.first_week, right.first_week)
                chosen = DomainHistory(first, left.weeks | right.weeks)
            assert chosen is not None
            if len(merged._domains) >= merged.cap:
                merged._cap_exceeded = True
                break
            merged._domains[key] = chosen
        return merged

    @property
    def histories(self) -> tuple[DomainHistory, ...]:
        return tuple(self._domains[key] for key in sorted(self._domains))

    @property
    def facts(self) -> DomainLedgerFacts:
        return DomainLedgerFacts(
            cap=self.cap,
            cap_exceeded=self._cap_exceeded,
            psl_available=self._psl_available,
            excluded=tuple(sorted(self._excluded.items())),
            retained_domains=len(self._domains),
        )
