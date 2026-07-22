"""Allowlist loading and matching.

Two formats:
- Pattern files: flat text, one glob or regex per line, # comments.
  Used for high-volume domain and IP lists.
- Stanza entries: TOML [[allowlist.entry]] blocks with match type, detector scoping,
  and human-readable comments. Loaded from config inline or from allowlist_dir/*.toml.

AllowlistMatcher is the runner's single interface for pre-detector suppression.

Flat numeric rule format (for conn log suppression)
─────────────────────────────────────────────────────
One rule per line. # comments supported. Blank lines ignored.
A rule is whitespace-separated tokens:

  IP/CIDR/wildcard fields  - zero, one, or two; unordered for pair matching
  port/proto token         - leading colon: :443  :123/udp  :*/tcp

Examples:
  192.0.2.10  198.51.100.1  :22/tcp    # specific pair, specific port+proto
  192.0.2.10  :22                       # any flow involving this IP on port 22
  192.0.2.0/24  :443                    # entire subnet, port 443, any proto
  *  :123/udp                           # any host, UDP 123
  :6556                                 # port only - suppress everywhere
  192.0.2.33                            # bare IP - all traffic involving this host
"""

from __future__ import annotations

import ipaddress
import re
import warnings
from dataclasses import dataclass, field
from fnmatch import translate
from pathlib import Path
from typing import Any

import pandas as pd


@dataclass
class AllowlistEntry:
    """A single stanza-style allowlist entry with match type and optional detector scope."""

    match: str
    comment: str = ""
    detectors: list[str] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class NumericRule:
    """A parsed flat-file numeric suppression rule.

    ip1, ip2 - IP address, CIDR range, '*' wildcard, or None (matches anything).
    IP pair matching is unordered: a rule fires regardless of which end is src/dst.
    port - destination port number, or None to match any port.
    proto - 'tcp', 'udp', 'icmp', or None to match any protocol.
    detectors - if non-empty, rule applies only to listed detectors.
    """

    ip1: str | None = None
    ip2: str | None = None
    port: int | None = None
    proto: str | None = None
    detectors: list[str] = field(default_factory=list)
    comment: str = ""


@dataclass(frozen=True)
class MalformedPattern:
    """A flat-list pattern that failed to compile - dropped from matching and
    surfaced as a runner advisory rather than raising mid-run.

    ``source`` (file path str) and ``lineno`` (1-based original line) carry
    provenance for the ``file:line`` advisory; both are ``None`` for direct
    constructor callers that pass no sources.
    """

    pattern: str
    source: str | None
    lineno: int | None


def _compile_domain_patterns(
    patterns: list[str],
    sources: list[tuple[str | None, int | None]],
    *,
    source_kind: str = "domain",
) -> tuple["re.Pattern[str] | None", list["re.Pattern[str]"], tuple[MalformedPattern, ...]]:
    """Compile domain patterns into a two-lane match engine.

    Host patterns share this pattern grammar and compile through the same engine.

    Returns ``(union, fallback, malformed)``:

    - ``union`` - ONE alternation regex (``re.IGNORECASE``) over globs +
      union-safe ``re:`` bodies, or ``None`` when there is no union arm. ZERO
      capturing groups by construction (globs become flag-scoped non-capturing
      groups via ``fnmatch.translate``; ``re:`` bodies wrap in ``(?:...)``), so it
      ALWAYS compiles and never trips pandas' capturing-group ``UserWarning``.
    - ``fallback`` - individually compiled ``re.Pattern`` objects
      (``re.IGNORECASE``) for valid ``re:`` bodies that are NOT union-safe
      (capturing/named group, backreference, or a GLOBAL inline flag). A union
      would silently renumber backrefs, fail on duplicate names, or reject a
      leading ``(?i)`` - so these stay individual.
    - ``malformed`` - ``re:`` bodies that fail ``re.compile`` outright: dropped +
      recorded (today they raise ``re.error`` mid-run).

    Case parity (required): glob arms build from ``pattern.lower()`` and carry
    a leading ``\\A`` (``str.contains`` is unanchored and ``fnmatch.translate``
    anchors only the end, so glob ``example.com`` must not match
    ``notexample.com``). ``re:`` arms stay search-style (intentionally unanchored)
    and are NEVER lowercased - the DATA is lowered before matching instead, which
    keeps scoped case flags like ``(?-i:...)`` exact.
    """
    # Lockstep invariant: a short sources list would let zip() silently truncate
    # the patterns - every remaining pattern dropped from matching, a fail-open
    # loss of allowlist coverage. Catch internal drift loudly rather than ever
    # under-suppressing.
    if len(sources) != len(patterns):
        raise ValueError(
            f"{source_kind}_pattern_sources length ({len(sources)}) does not match "
            f"{source_kind}_patterns length ({len(patterns)}) - internal lockstep drift"
        )

    union_arms: list[str] = []
    fallback: list["re.Pattern[str]"] = []
    malformed: list[MalformedPattern] = []

    for pattern, (source, lineno) in zip(patterns, sources):
        if pattern.startswith("re:"):
            body = pattern[3:]
            try:
                compiled = re.compile(body)
            except re.error:
                malformed.append(MalformedPattern(pattern, source, lineno))
                continue
            union_safe = compiled.groups == 0
            if union_safe:
                try:
                    re.compile("(?:" + body + ")")
                except re.error:
                    # A global inline flag (e.g. leading "(?i)") is no longer at
                    # the start once wrapped → re.error → route to fallback.
                    union_safe = False
            if union_safe:
                union_arms.append("(?:" + body + ")")
            else:
                fallback.append(re.compile(body, re.IGNORECASE))
        else:
            # Glob: lower the pattern (fnmatch parity) and
            # anchor the start explicitly (translate supplies \Z only).
            union_arms.append(r"\A" + translate(pattern.lower()))

    union = re.compile("|".join(union_arms), re.IGNORECASE) if union_arms else None
    return union, fallback, tuple(malformed)


class AllowlistMatcher:
    """Pre-loaded allowlist ready to query.

    Constructed by the framework and passed to detectors via DetectorContext.
    """

    def __init__(
        self,
        domain_patterns: list[str] | None = None,
        entries: list[AllowlistEntry] | None = None,
        numeric_rules: list[NumericRule] | None = None,
        domain_pattern_sources: list[tuple[str | None, int | None]] | None = None,
        host_patterns: list[str] | None = None,
        host_pattern_sources: list[tuple[str | None, int | None]] | None = None,
    ) -> None:
        self._domain_patterns: list[str] = domain_patterns or []
        self._host_patterns: list[str] = host_patterns or []
        self._entries: list[AllowlistEntry] = entries or []
        self._numeric_rules: list[NumericRule] = numeric_rules or []
        # Provenance parallel to _domain_patterns (file path str + original
        # lineno), used only for the malformed advisory. Absent → no file:line.
        if domain_pattern_sources is None:
            sources = [(None, None)] * len(self._domain_patterns)
        else:
            sources = list(domain_pattern_sources)
        # Build the two-lane engine EAGERLY (sub-ms; numeric-only matchers build
        # to empty instantly) so the malformed set is known at construction.
        (
            self._domain_regex,
            self._domain_fallback,
            self._malformed_domain_patterns,
        ) = _compile_domain_patterns(self._domain_patterns, sources)
        if host_pattern_sources is None:
            host_sources = [(None, None)] * len(self._host_patterns)
        else:
            host_sources = list(host_pattern_sources)
        (
            self._host_regex,
            self._host_fallback,
            self._malformed_host_patterns,
        ) = _compile_domain_patterns(
            self._host_patterns, host_sources, source_kind="host"
        )

    @property
    def malformed_patterns(self) -> tuple[MalformedPattern, ...]:
        """Flat-list patterns dropped at compile time, domain first. The runner
        surfaces them as a per-pattern advisory."""
        return self._malformed_domain_patterns + self._malformed_host_patterns

    def _has_domain_patterns(self) -> bool:
        """True when any domain matching can fire (union OR a fallback pattern).

        Checks the COMPILED lanes, not the raw pattern list - every pattern
        may have been malformed and dropped."""
        return self._domain_regex is not None or bool(self._domain_fallback)

    def _has_host_patterns(self) -> bool:
        """True when any host matching can fire after malformed patterns drop."""
        return self._host_regex is not None or bool(self._host_fallback)

    @staticmethod
    def _match_series_with_engine(
        s: pd.Series,
        union: "re.Pattern[str] | None",
        fallback: list["re.Pattern[str]"],
    ) -> pd.Series:
        """Match lowered string values through one compiled two-lane engine."""
        out = pd.Series(False, index=s.index)
        if union is not None:
            out = out | s.str.contains(union, na=False)
        if fallback:
            with warnings.catch_warnings():
                # Tightly scoped to pandas' capturing-group warning. User regex
                # groups stay intact because backreferences make rewriting unsafe.
                warnings.filterwarnings(
                    "ignore", message=".*match groups.*", category=UserWarning
                )
                for cp in fallback:
                    out = out | s.str.contains(cp, na=False)
        return out

    def _match_series(self, s: pd.Series) -> pd.Series:
        """Boolean Series: True where a value (ALREADY str + lowered) matches any
        active domain pattern. Union first (zero groups → no warning), then each
        fallback pattern (capturing groups → pandas UserWarning, suppressed)."""
        return self._match_series_with_engine(
            s, self._domain_regex, self._domain_fallback
        )

    def _match_distinct(self, values: pd.Series) -> pd.Series:
        """Two-probe match over already-str-lowered values: a value matches if the
        bare value OR its apex probe (``"x." + value``) matches. The apex probe is
        required - ``re:\\.akamai\\.net$`` misses bare ``akamai.net`` but hits
        ``x.akamai.net``. ``"x."`` is lowercase, so the probe stays lowered."""
        return self._match_series(values) | self._match_series("x." + values)

    def _match_host_distinct(self, values: pd.Series) -> pd.Series:
        """Bare-value host match over already-str-lowered distinct values."""
        return self._match_series_with_engine(
            values, self._host_regex, self._host_fallback
        )

    def is_domain_allowed(self, domain: str, detector: str | None = None) -> bool:
        """Return True if domain matches any pattern in the loaded domain lists.

        DNS is case-insensitive by spec, so the DATA is lowered before matching
        (both lanes), mirroring the historical per-row logic. The compiled engine
        carries ``re.IGNORECASE``; ``re:`` bodies are never lowercased (lowering a
        body would break scoped case flags like ``(?-i:...)``). Backed by the SAME
        compiled objects the vector paths use, so scalar and vector cannot drift.
        """
        d = str(domain).lower()
        if self._domain_regex is not None and self._domain_regex.search(d):
            return True
        return any(cp.search(d) for cp in self._domain_fallback)

    def filter_df(self, df: pd.DataFrame, detector: str) -> pd.DataFrame:
        """Remove allowlisted rows from a normalized log DataFrame.

        Connection logs use canonical src, dst, port, proto columns and numeric rules.
        DNS logs use query plus domain patterns. Non-query system logs use host
        patterns after numeric filtering. Missing columns are handled gracefully.
        """
        if df.empty:
            return df

        if "query" in df.columns:
            return self._filter_domain_df(df, detector)
        out = self._filter_numeric_df(df, detector)
        if "host" in out.columns:
            out = self._filter_host_df(out, detector)
        return out

    def _filter_domain_df(self, df: pd.DataFrame, detector: str) -> pd.DataFrame:
        """Remove DNS rows whose query matches a loaded domain pattern.

        Vectorized over DISTINCT lowered queries (DNS query columns repeat
        enormously, so the regex work runs once per distinct value, not per row),
        then broadcast back via a hashed lookup. Domain suppression is scope-blind
        - ``detector`` is unused, matching the historical per-row logic."""
        if not self._has_domain_patterns():
            return df.copy()
        qs = df["query"].astype(str).str.lower()
        uniq = pd.Series(qs.unique())
        m = self._match_distinct(uniq)
        lut = dict(zip(uniq.to_numpy(), m.to_numpy()))
        drop = qs.map(lut).astype(bool)
        return df[~drop].copy()

    def _filter_numeric_df(self, df: pd.DataFrame, detector: str) -> pd.DataFrame:
        """Remove connection rows matching flat numeric suppression rules."""
        has_src = "src" in df.columns
        has_dst = "dst" in df.columns
        has_port = "port" in df.columns
        has_proto = "proto" in df.columns

        drop_mask = pd.Series(False, index=df.index)

        for rule in self._numeric_rules:
            if rule.detectors and detector not in rule.detectors:
                continue
            rule_mask = _numeric_rule_mask(df, rule, has_src, has_dst, has_port, has_proto)
            drop_mask |= rule_mask

        return df[~drop_mask].copy()

    def _filter_host_df(self, df: pd.DataFrame, detector: str) -> pd.DataFrame:
        """Remove system-log rows whose lowered host matches a host pattern.

        Host suppression is scope-blind, so ``detector`` is unused. Matching is
        over bare values only; DNS's registrable-domain apex probe does not apply.
        """
        if not self._has_host_patterns():
            return df.copy()
        hosts = df["host"].astype(str).str.lower()
        uniq = pd.Series(hosts.unique())
        matched = self._match_host_distinct(uniq)
        lut = dict(zip(uniq.to_numpy(), matched.to_numpy()))
        drop = hosts.map(lut).astype(bool)
        return df[~drop].copy()

    def count_domain_suppressed(self, df: pd.DataFrame) -> int:
        """Count rows a domain list would suppress - SCOPE-BLIND parity with
        ``_filter_domain_df`` (match where ``is_domain_allowed(q)`` OR
        ``is_domain_allowed("x." + q)``). For the run-summary disclosure line:
        "how much of the data the allowlist covers", not per-detector.

        Short-circuits to 0 when there is nothing to match (no patterns, empty
        frame, no ``query`` column) so a counting pass never maps over a frame
        for nothing.
        """
        if df.empty or not self._has_domain_patterns() or "query" not in df.columns:
            return 0
        qs = df["query"].astype(str).str.lower()
        vc = qs.value_counts()
        if vc.empty:
            return 0
        m = self._match_distinct(pd.Series(vc.index))
        return int(vc.to_numpy()[m.to_numpy()].sum())

    def count_numeric_suppressed(self, df: pd.DataFrame) -> int:
        """Count rows any numeric rule would suppress, INCLUDING stanza-derived
        rules (already merged into ``self._numeric_rules``) and IGNORING each
        rule's ``detectors`` scope - scope-blind on purpose (the headline is
        coverage, not a single detector's view).

        Short-circuits to 0 when there are no numeric rules or the frame is
        empty.
        """
        if df.empty or not self._numeric_rules:
            return 0
        has_src = "src" in df.columns
        has_dst = "dst" in df.columns
        has_port = "port" in df.columns
        has_proto = "proto" in df.columns
        drop_mask = pd.Series(False, index=df.index)
        for rule in self._numeric_rules:
            drop_mask |= _numeric_rule_mask(df, rule, has_src, has_dst, has_port, has_proto)
        return int(drop_mask.sum())

    def count_host_suppressed(self, df: pd.DataFrame) -> tuple[int, set[str]]:
        """Return suppressed rows and distinct matched lowered host values."""
        if df.empty or not self._has_host_patterns() or "host" not in df.columns:
            return (0, set())
        hosts = df["host"].astype(str).str.lower()
        counts = hosts.value_counts()
        if counts.empty:
            return (0, set())
        matched = self._match_host_distinct(pd.Series(counts.index))
        mask = matched.to_numpy()
        values = {str(value) for value in counts.index[mask]}
        return (int(counts.to_numpy()[mask].sum()), values)


def _numeric_rule_mask(
    df: pd.DataFrame,
    rule: NumericRule,
    has_src: bool,
    has_dst: bool,
    has_port: bool,
    has_proto: bool,
) -> pd.Series:
    """Build a boolean mask for rows matching rule (True = this row is allowlisted)."""
    idx = df.index
    mask = pd.Series(True, index=idx)

    # Port filter
    if rule.port is not None:
        if not has_port:
            return pd.Series(False, index=idx)
        mask &= df["port"] == rule.port

    # Proto filter
    if rule.proto is not None:
        if not has_proto:
            return pd.Series(False, index=idx)
        mask &= df["proto"] == rule.proto

    # IP filter
    if rule.ip1 is not None or rule.ip2 is not None:
        if not has_src or not has_dst:
            return pd.Series(False, index=idx)
        ip_mask = _ip_pair_mask(df, rule.ip1, rule.ip2)
        mask &= ip_mask

    return mask


def _ip_pair_mask(
    df: pd.DataFrame,
    ip1: str | None,
    ip2: str | None,
) -> pd.Series:
    """Return True for rows whose (src, dst) pair matches the rule (unordered).

    With one IP field:  src OR dst matches that IP.
    With two IP fields: (src matches ip1 AND dst matches ip2) OR vice versa.
    """
    if ip2 is None:
        # Single IP - matches any flow involving ip1
        return _ip_series_matches(df["src"], ip1) | _ip_series_matches(df["dst"], ip1)

    if ip1 is None:
        return _ip_series_matches(df["src"], ip2) | _ip_series_matches(df["dst"], ip2)

    # Ordered pair in either direction
    fwd = _ip_series_matches(df["src"], ip1) & _ip_series_matches(df["dst"], ip2)
    rev = _ip_series_matches(df["src"], ip2) & _ip_series_matches(df["dst"], ip1)
    return fwd | rev


def _ip_series_matches(series: pd.Series, spec: str) -> pd.Series:
    """Vectorized: return True for each row where the IP matches spec.

    spec may be: '*' (wildcard), a CIDR range, or an exact IP address.
    CIDR ranges use ipaddress stdlib - no additional dependencies.
    """
    if spec == "*":
        return pd.Series(True, index=series.index)

    if "/" in spec:
        try:
            net = ipaddress.ip_network(spec, strict=False)
        except ValueError:
            return pd.Series(False, index=series.index)
        return series.map(lambda ip: _ip_in_network(ip, net))

    return series == spec


def _ip_in_network(ip_str: Any, net: ipaddress.IPv4Network | ipaddress.IPv6Network) -> bool:
    """Return True if ip_str is a valid IP contained in net."""
    if not isinstance(ip_str, str):
        return False
    try:
        return ipaddress.ip_address(ip_str) in net
    except ValueError:
        return False


def _parse_numeric_rule_line(line: str) -> NumericRule | None:
    """Parse one line of a flat numeric rule file into a NumericRule.

    Returns None for blank lines, comment-only lines, or malformed rules.
    """
    if "#" in line:
        line = line[: line.index("#")]
    line = line.strip()
    if not line:
        return None

    tokens = line.split()
    ip_tokens: list[str] = []
    port: int | None = None
    proto: str | None = None

    for token in tokens:
        if token.startswith(":"):
            # Port/proto token: :443  :123/udp  :*/tcp
            port_part = token[1:]
            if "/" in port_part:
                port_str, proto_str = port_part.rsplit("/", 1)
                if proto_str != "*":
                    proto = proto_str.lower()
            else:
                port_str = port_part
            if port_str != "*":
                try:
                    port = int(port_str)
                except ValueError:
                    return None  # malformed port
        else:
            ip_tokens.append(token)

    if len(ip_tokens) > 2:
        return None  # too many IP fields

    ip1 = ip_tokens[0] if len(ip_tokens) >= 1 else None
    ip2 = ip_tokens[1] if len(ip_tokens) >= 2 else None

    return NumericRule(ip1=ip1, ip2=ip2, port=port, proto=proto)


def load_pattern_file_lines(path: Path) -> list[tuple[str, int]]:
    """Load a flat domain pattern file as ``(pattern, lineno)`` pairs.

    ``lineno`` is the 1-based ORIGINAL line number, assigned BEFORE comments and
    blank lines are stripped, so a malformed-pattern advisory can name the real
    file line. Inline # comments are stripped before the pattern is recorded
    (matching the numeric rule parser); fully-commented and blank lines are
    dropped. The single parser - ``load_pattern_file`` delegates here.
    """
    out: list[tuple[str, int]] = []
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if "#" in line:
            line = line[: line.index("#")]
        line = line.strip()
        if line:
            out.append((line, lineno))
    return out


def load_pattern_file(path: Path) -> list[str]:
    """Load a flat domain pattern file, stripping comments and blank lines.

    Thin wrapper over ``load_pattern_file_lines`` - callers that don't need line
    numbers get the bare pattern list (no behavior drift in ``pattern_count``).
    """
    return [pattern for pattern, _ in load_pattern_file_lines(path)]


def load_numeric_rule_file(path: Path) -> list[NumericRule]:
    """Load a flat numeric rule file and return parsed NumericRule objects."""
    rules: list[NumericRule] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        rule = _parse_numeric_rule_line(line)
        if rule is not None:
            rules.append(rule)
    return rules


def _entry_from_raw(raw: dict[str, Any], *, where: str) -> AllowlistEntry:
    """Build one AllowlistEntry from a raw stanza dict, with an actionable error.

    ``where`` names the stanza's origin for the message (a *.toml path, or the
    config file's inline ``[[allowlist.entry]]`` table). A stanza without a
    ``match`` key is a user-config mistake and must surface as an actionable
    message at the CLI boundary, never a bare ``KeyError: 'match'``.
    """
    if "match" not in raw:
        raise ValueError(
            f"{where}: allowlist stanza has no 'match' key - each "
            f"[[allowlist.entry]] needs one (e.g. match = \"ip_pair\" or "
            f"match = \"dst_port\")"
        )
    extra = {k: v for k, v in raw.items() if k not in ("match", "comment", "detectors")}
    return AllowlistEntry(
        match=raw["match"],
        comment=raw.get("comment", ""),
        detectors=_as_list(raw.get("detectors", [])),
        extra=extra,
    )


def load_stanza_file(path: Path) -> list[AllowlistEntry]:
    """Load a TOML stanza file and return a list of AllowlistEntry objects."""
    import tomllib

    with path.open("rb") as fh:
        try:
            data = tomllib.load(fh)
        except tomllib.TOMLDecodeError as exc:
            # Name the file: a drop-in's parse error must point the operator at
            # the offending stanza file, not read as an anonymous TOML failure.
            raise ValueError(f"{path.name}: not valid TOML - {exc}") from exc

    return [
        _entry_from_raw(raw, where=path.name)
        for raw in data.get("allowlist", {}).get("entry", [])
    ]


# Shipped package data - located relative to this file so it works for both
# editable installs (sigwood/data/) and regular installs (site-packages/sigwood/data/).
# Package-local: NOT routed through SIGWOOD_ROOT (that rail is for config-file values).
_PACKAGE_DIR = Path(__file__).parent.parent


@dataclass(frozen=True)
class ShippedList:
    """One curated list sigwood ships. ``default_on`` is the install-default
    enabled state; an operator overrides it per name under ``[allowlist.lists]``.
    ``filename`` is package-local (under ``data/allowlist/``)."""

    name: str
    kind: str          # "domain" | "numeric"
    default_on: bool
    filename: str
    summary: str


# Registry - order IS load order. Every shipped list is named, toggleable, and
# self-describing (replacing the former bare package-data path list).
_SHIPPED_LISTS: tuple[ShippedList, ...] = (
    ShippedList(
        "common", "domain", True, "domains_common",
        "broad internet infrastructure (CAs, root NS, major clouds/CDNs)",
    ),
    ShippedList(
        "devices", "domain", True, "domains_devices",
        "consumer IoT / smart-home phone-home",
    ),
    ShippedList(
        "homelab", "domain", False, "domains_homelab",
        "self-hosted tooling (opt-in)",
    ),
)


def _shipped_path(spec: ShippedList) -> Path:
    """Package-local path for a shipped list (NOT routed through SIGWOOD_ROOT)."""
    return _PACKAGE_DIR / "data" / "allowlist" / spec.filename


@dataclass(frozen=True)
class ResolvedList:
    """One list in the resolved plan - shipped, drop-in, or config-path. Carries
    everything the readout needs and the matcher consumes. ``pattern_count`` is
    the stripped/loadable line count and is INDEPENDENT of ``enabled`` (a disabled
    homelab still reads "22 domains")."""

    name: str
    kind: str          # "domain" | "numeric" | "host"
    origin: str        # "shipped" | "dropin" | "config-path"
    path: Path
    enabled: bool
    state_reason: str  # terse provenance for the readout ("default" / "config" / "drop-in" / "config path")
    pattern_count: int


@dataclass(frozen=True)
class IgnoredDropin:
    """An allowlist.d entry that does NOT load as a list under the dot rule but whose
    dot-stripped head names a list kind - surfaced by the readout as a rename nudge.
    READOUT-ONLY advisory: never enters matcher construction or any machine output."""

    name: str        # the on-disk filename that did not load
    suggested: str   # the dot-free name to rename it to


@dataclass(frozen=True)
class AllowlistPlan:
    """The COMPLETE resolved allowlist state - the single spine both the matcher
    and the ``allowlist`` verb consume so the readout can never drift from what is
    loaded. Returned complete even when ``master_enabled`` is False (the readout
    still works); turning suppression off happens at ``matcher_from_plan``, not
    here."""

    master_enabled: bool
    lists: list[ResolvedList]            # INCLUDES disabled shipped (enabled=False) for the readout
    entries: tuple[AllowlistEntry, ...]  # resolved stanzas: inline [[allowlist.entry]] + allowlist_dir/*.toml
    ignored: tuple[IgnoredDropin, ...] = ()  # readout-only dot-rule advisory; NOT matcher/machine output


def resolve_allowlist_dir(config: dict[str, Any]) -> Path | None:
    """The resolved ``allowlist.d`` directory - the SINGLE owner of allowlist-dir
    semantics, shared by ``resolve_allowlist_plan`` and the ``allowlist`` verb so
    discovery and ``copy`` can never disagree about where lists live.

    Falls back to the default ONLY when the key is ABSENT (``None``); an explicit
    ``allowlist_dir = ""`` is PRESERVED - it resolves to no directory (suppression
    drop-ins disabled), distinct from "unset". Returns ``None`` when there is no
    directory (empty value, or ``resolve_path`` yields nothing)."""
    from sigwood.common.config import default_allowlist_paths
    from sigwood.common.paths import effective_root, resolve_path

    allowlist_cfg = config.get("allowlist", {})
    allowlist_dir = allowlist_cfg.get("allowlist_dir")
    if allowlist_dir is None:
        allowlist_dir = default_allowlist_paths()["allowlist_dir"]
    resolved = resolve_path(allowlist_dir, effective_root(config))
    return Path(resolved) if resolved else None


def _classify_dropin(name: str) -> str | None:
    """Classify an allowlist.d entry BY NAME.

    Returns "domain" | "numeric" | "host" | "stanza" | None.

    Pure over the name; every caller gates ``is_file()`` itself (a DIRECTORY named
    ``x.toml`` or ``domains_x`` must never load or be deleted). The dot rule, in this
    exact clause order (a later clause must not shadow an earlier one): an ACTIVE flat
    list is a dot-free name typed by PREFIX; a dot means ``*.toml`` (a parsed format)
    or ignored; hidden and ``~``-terminated names are ignored. Case-sensitive (UNIX).
    Mirrored stdlib-only in ``cli_init._classify_dropin``; a drift test pins the two.
    """
    if name.startswith("."):        # hidden
        return None
    if name.endswith("~"):          # editor backup
        return None
    if name.endswith(".toml"):      # a dot naming a parsed format
        return "stanza"
    if "." in name:                 # any other dot: ignored
        return None
    if name.startswith("domains"):
        return "domain"
    if name.startswith("connections"):
        return "numeric"
    if name.startswith("hosts"):
        return "host"
    return None


def _ignored_suggestion(name: str) -> str | None:
    """The dot-free name to suggest for a NON-loading allowlist.d entry, or ``None``
    to stay silent. Reports ONLY a file whose dot-stripped HEAD classifies AS a list
    kind (domain/numeric/host) - recognized-AS-the-branch, not merely prefixed - and never
    a stanza, hidden, or ``~``-backup. Pure over the name; caller gates ``is_file()``.
    """
    if _classify_dropin(name) is not None:          # loads as list/stanza - not ignored
        return None
    if name.startswith(".") or name.endswith("~"):  # never nudge a hidden / editor backup
        return None
    head = name.split(".", 1)[0]
    return head if _classify_dropin(head) in ("domain", "numeric", "host") else None


def resolve_allowlist_plan(config: dict[str, Any]) -> AllowlistPlan:
    """Resolve the COMPLETE allowlist state from the ``[allowlist]`` config section.

    PURE: no mutation, reads NO CLI flags. It DOES stat+read the files/dir it
    points to - needed for the stripped/loadable ``pattern_count`` AND to load the
    stanza ``entries``. Config-supplied path values flow through
    ``resolve_path(value, root)`` so SIGWOOD_ROOT applies; absent keys fall back to the
    single source of truth in ``config.py`` via ``default_allowlist_paths()``.

    Both ``matcher_from_plan`` and the readout consume this object and NEITHER
    touches config again - structurally drift-free.
    """
    from sigwood.common.config import default_allowlist_paths
    from sigwood.common.paths import effective_root, resolve_path

    allowlist_cfg = config.get("allowlist", {})
    master_enabled = bool(allowlist_cfg.get("enabled", True))
    lists_cfg = allowlist_cfg.get("lists", {}) or {}
    root = effective_root(config)
    defaults = default_allowlist_paths()

    # Resolve the allowlist.d directory once (shared owner) - it drives BOTH the
    # *.toml classification stanzas and the dot-free domains* / connections* /
    # hosts* flat-file drop-in discovery (the dot rule; see _classify_dropin).
    dir_path = resolve_allowlist_dir(config)
    have_dir = dir_path is not None and dir_path.is_dir()

    # ONE iterdir() pass buckets every entry by the dot rule, preserving the emission
    # order below. is_file() gates each LOAD bucket (a DIRECTORY named domains_x or
    # x.toml must never load or be fed to load_stanza_file); the ignored bucket is a
    # readout-only advisory.
    domain_dropins: list[Path] = []
    numeric_dropins: list[Path] = []
    host_dropins: list[Path] = []
    stanza_files: list[Path] = []
    ignored: list[IgnoredDropin] = []
    if have_dir:
        for entry in dir_path.iterdir():
            kind = _classify_dropin(entry.name)
            if kind is None:
                if entry.is_file():
                    sug = _ignored_suggestion(entry.name)
                    if sug is not None:
                        ignored.append(IgnoredDropin(entry.name, sug))
                continue
            if not entry.is_file():
                continue
            if kind == "domain":
                domain_dropins.append(entry)
            elif kind == "numeric":
                numeric_dropins.append(entry)
            elif kind == "host":
                host_dropins.append(entry)
            else:  # "stanza"
                stanza_files.append(entry)
    domain_dropins.sort()
    numeric_dropins.sort()
    host_dropins.sort()
    stanza_files.sort()
    ignored.sort(key=lambda ig: ig.name)

    # First-seen dedup by resolved path, preserving load order:
    # shipped (registry order) -> domain drop-ins (sorted) -> numeric drop-ins
    # (sorted) -> host drop-ins (sorted) -> config-path domain -> config-path numeric.
    # NO same-basename
    # shadow - every drop-in is additive; replacing a shipped list is `allowlist
    # disable <name>`.
    seen: set[str] = set()
    resolved_lists: list[ResolvedList] = []

    def _emit(name: str, kind: str, origin: str, path: Path, enabled: bool, state_reason: str) -> None:
        key = str(path.resolve())  # non-strict: missing files already filtered by exists()
        if key in seen:
            return
        seen.add(key)
        loader = (
            load_numeric_rule_file if kind == "numeric" else load_pattern_file
        )
        count = len(loader(path))
        resolved_lists.append(
            ResolvedList(name, kind, origin, path, enabled, state_reason, count)
        )

    # Tier 1 - shipped curated lists (always present; enabled per config/default).
    for spec in _SHIPPED_LISTS:
        path = _shipped_path(spec)
        if not path.exists():
            continue
        enabled = bool(lists_cfg.get(spec.name, spec.default_on))
        state_reason = "config" if spec.name in lists_cfg else "default"
        _emit(spec.name, spec.kind, "shipped", path, enabled, state_reason)
    # Tier 2 - allowlist.d drop-ins (additive; master switch is their only gate).
    for path in domain_dropins:
        _emit(path.name, "domain", "dropin", path, True, "drop-in")
    for path in numeric_dropins:
        _emit(path.name, "numeric", "dropin", path, True, "drop-in")
    for path in host_dropins:
        _emit(path.name, "host", "dropin", path, True, "drop-in")
    # Tier 3 - explicit config paths (default [] - escape hatch outside allowlist.d).
    domain_pattern_paths = allowlist_cfg.get("domain_patterns")
    if domain_pattern_paths is None:
        domain_pattern_paths = defaults["domain_patterns"]
    for path_str in _as_list(domain_pattern_paths):
        resolved = resolve_path(path_str, root)
        if resolved is None:
            continue
        path = Path(resolved)
        if path.exists():
            _emit(path.name, "domain", "config-path", path, True, "config path")
    connection_rule_paths = allowlist_cfg.get("connection_rules")
    if connection_rule_paths is None:
        connection_rule_paths = defaults["connection_rules"]
    for path_str in _as_list(connection_rule_paths):
        resolved = resolve_path(path_str, root)
        if resolved is None:
            continue
        path = Path(resolved)
        if path.exists():
            _emit(path.name, "numeric", "config-path", path, True, "config path")

    # TOML stanza entries: inline [[allowlist.entry]] plus every *.toml in
    # allowlist.d. Today ip_pair / dst_port stanzas convert to numeric
    # suppression in matcher_from_plan; the classification role (a detector
    # consuming what-a-thing-is) has no shipped consumer yet.
    entries: list[AllowlistEntry] = []
    for raw in allowlist_cfg.get("entry", []):
        entries.append(_entry_from_raw(raw, where="[[allowlist.entry]] in config"))
    for toml_file in stanza_files:            # is_file-gated + sorted in the pass above
        entries.extend(load_stanza_file(toml_file))

    return AllowlistPlan(
        master_enabled=master_enabled,
        lists=resolved_lists,
        entries=tuple(entries),
        ignored=tuple(ignored),
    )


def matcher_from_plan(plan: AllowlistPlan, *, force_off: bool = False) -> AllowlistMatcher:
    """Build the suppression matcher from a resolved plan.

    ``force_off`` (``--no-allowlist``) OR a false master switch returns a FULLY
    EMPTY matcher - before touching lists OR entries - so EVERY suppressive
    effect is disabled, including stanza-to-numeric conversion. No shipped
    detector reads classification metadata today, so the empty matcher loses
    nothing.
    """
    if force_off or not plan.master_enabled:
        return AllowlistMatcher()

    domain_patterns: list[str] = []
    domain_pattern_sources: list[tuple[str | None, int | None]] = []
    host_patterns: list[str] = []
    host_pattern_sources: list[tuple[str | None, int | None]] = []
    numeric_rules: list[NumericRule] = []
    for rl in plan.lists:
        if not rl.enabled:
            continue
        if rl.kind == "domain":
            # Load WITH provenance (path str + original lineno), built in lockstep
            # so the two parallel lists cannot drift. Only ENABLED lists are
            # loaded, so a disabled list's malformed lines are never compiled.
            src = str(rl.path)
            for pattern, lineno in load_pattern_file_lines(rl.path):
                domain_patterns.append(pattern)
                domain_pattern_sources.append((src, lineno))
        elif rl.kind == "host":
            src = str(rl.path)
            for pattern, lineno in load_pattern_file_lines(rl.path):
                host_patterns.append(pattern)
                host_pattern_sources.append((src, lineno))
        else:
            numeric_rules.extend(load_numeric_rule_file(rl.path))

    entries = list(plan.entries)
    # Convert ip_pair / dst_port stanza entries to NumericRules so filter_df()
    # applies them without a format migration.
    for entry in entries:
        rule = _stanza_to_numeric_rule(entry)
        if rule is not None:
            numeric_rules.append(rule)

    return AllowlistMatcher(
        domain_patterns=domain_patterns,
        entries=entries,
        numeric_rules=numeric_rules,
        domain_pattern_sources=domain_pattern_sources,
        host_patterns=host_patterns,
        host_pattern_sources=host_pattern_sources,
    )


def build_matcher(config: dict[str, Any], *, force_off: bool = False) -> AllowlistMatcher:
    """Construct an AllowlistMatcher from the ``[allowlist]`` config section.

    Thin wrapper over the resolver + ``matcher_from_plan`` spine, kept for
    existing (mostly test / notebook) callers. The runner resolves the plan ONCE
    itself and builds via ``matcher_from_plan`` so the banner and the matcher
    share one object.
    """
    return matcher_from_plan(resolve_allowlist_plan(config), force_off=force_off)


def _as_list(value: Any) -> list[str]:
    """Return a forgiving string list from TOML arrays or comma-separated strings."""
    if value is None:
        return []
    if isinstance(value, str):
        return [part.strip() for part in value.split(",") if part.strip()]
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return [str(value).strip()]


def _stanza_to_numeric_rule(entry: AllowlistEntry) -> NumericRule | None:
    """Convert a TOML stanza entry to a NumericRule for use in filter_df().

    Only ip_pair and dst_port match types are supported; others return None.
    """
    if entry.match == "ip_pair":
        src = entry.extra.get("src")
        dst = entry.extra.get("dst")
        dst_port = entry.extra.get("dst_port")
        port = int(dst_port) if dst_port is not None else None
        return NumericRule(
            ip1=src,
            ip2=dst,
            port=port,
            detectors=list(entry.detectors),
            comment=entry.comment,
        )
    if entry.match == "dst_port":
        value = entry.extra.get("value")
        port = int(value) if value is not None else None
        return NumericRule(port=port, detectors=list(entry.detectors), comment=entry.comment)
    return None
