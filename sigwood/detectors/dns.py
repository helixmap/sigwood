"""DNS detector - HDBSCAN clustering of DNS query behavior.

Pipeline (Zeek path):
1. Receive pre-filtered, canonical-schema DNS data from the parser
2. Engineer per-query features: RTT, TTL, query length/depth, TLD distribution
3. HDBSCAN clusters the feature vectors; noise points are the anomaly signal
4. Rank noise domains by label score; group by registrable domain (eTLD+1)
5. Return group findings (2+ subdomains sharing a registrable domain) first,
   then singleton findings, both sorted by label score descending

Pipeline (pihole path):
1. Build per-domain aggregate from dnsmasq event fragments (query events only)
2. Cluster aggregate rows; noise domains are the anomaly signal
3. Same label-score rank and group/singleton logic via shared back half

Dispatch:
- zeek only   → Zeek per-query path
- pihole only → pihole per-domain aggregate path
- both        → Zeek per-query path; pihole block data joined before clustering

Domain allowlist suppression is applied by the runner before this detector receives data.

Investigation pivot: dns.log → conn.log → whois → VirusTotal → Shodan → ASN.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import math
from numbers import Real
import shlex
from datetime import datetime, timezone
from typing import Any

import numpy as np
import pandas as pd
from sigwood.common.clustering import ACTIVE_BACKEND, fit_predict_interruptible
from sklearn.preprocessing import StandardScaler

from sigwood.common.display import plural
from sigwood.common.finding import DetectorContext, Finding, MethodTag, Severity
from sigwood.common.tld import TLD_EXTRACT as _TLD_EXTRACT

DETECTOR_NAME = "dns"
STATUS = "available"
IN_DEFAULT_HUNT: bool = True

# dns can be satisfied by either Zeek dns logs or Pi-hole/dnsmasq logs.
# Neither is hard-required; at least one must be present and satisfiable to run.
REQUIRED_LOGS: list[dict] = []

OPTIONAL_LOGS = [
    {"source": "zeek_dir",   "pattern": "dns*.log*"},
    {"source": "pihole_dir", "pattern": "pihole*.log*"},
]

REQUIRES_ONE_OF_OPTIONAL = True
# The reason NEVER embeds the detector name - both render surfaces (the live skip
# warning and the dry-run banner) prefix it, so a name here double-names ("dns - dns
# - …").
REQUIRES_ONE_OF_OPTIONAL_REASON = (
    "no DNS source found (need zeek_dir dns logs or pihole_dir logs)"
)

DEFAULT_CONFIG = {
    "min_cluster_size": 2000,
    "min_samples": 100,
    "threshold": 1.8,
    # Below-gate group promotion (Zeek path only). Individually low-scoring
    # names become visible as an INFO group only when a parent carries enough
    # distinct subdomains and their lookups are overwhelmingly NXDOMAIN.
    "promote_below_gate": True,
    "promote_min_subdomains": 5,
    "promote_min_nxdomain_fraction": 0.9,
    # thresh_high_entropy / scan_min_high_entropy_fraction gate the per-label
    # suspicion score (dns.entropy() - a weighted lexical heuristic, NOT Shannon
    # entropy), not an information-theoretic measure.
    "thresh_high_entropy": 1.8,
    # Dense-cluster scan (Zeek and standalone Pi-hole paths). A sustained
    # high-volume tunnel self-clusters past min_cluster_size and escapes the
    # noise-only label-score gate. This scan surfaces dominant-registrable-domain
    # members of clusters that are overwhelmingly high-entropy AND concentrated
    # under one eTLD+1 (the tunnel shape). Conservative by construction so a benign
    # high-entropy cluster does not flood. scan_dense_clusters=False keeps Zeek on
    # the noise-only path and Pi-hole on its shipped counts-disclosure path.
    "scan_dense_clusters": True,
    "scan_min_high_entropy_fraction": 0.8,   # both-path frac >= thresh_high_entropy
    "scan_min_cluster_members": 100,         # Zeek cluster-size floor (rows)
    "scan_min_regdomain_share": 0.8,         # both-path registrable-domain share
    "scan_max_members_per_cluster": 500,     # both-path surfaced-sample cap (perf)
    "pihole": {
        "min_cluster_size": 25,   # ~2K aggregated domain rows, not per-query
        "min_samples": 10,
    },
}


def validate_config(cfg: dict) -> None:
    """Validate DNS's overlaid tuning section without mutation."""
    if not isinstance(cfg, dict):
        raise ValueError("[detectors.dns] must be a table")

    min_cluster_size = cfg.get(
        "min_cluster_size", DEFAULT_CONFIG["min_cluster_size"]
    )
    if (
        isinstance(min_cluster_size, bool)
        or not isinstance(min_cluster_size, int)
        or min_cluster_size < 2
    ):
        raise ValueError(
            "[detectors.dns].min_cluster_size must be an integer greater than "
            "or equal to 2"
        )

    for key in (
        "min_samples",
        "promote_min_subdomains",
        "scan_min_cluster_members",
        "scan_max_members_per_cluster",
    ):
        value = cfg.get(key, DEFAULT_CONFIG[key])
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise ValueError(
                f"[detectors.dns].{key} must be a positive integer"
            )

    for key in ("threshold", "thresh_high_entropy"):
        value = cfg.get(key, DEFAULT_CONFIG[key])
        if (
            isinstance(value, bool)
            or not isinstance(value, Real)
            or not math.isfinite(float(value))
        ):
            raise ValueError(f"[detectors.dns].{key} must be a finite number")

    for key in ("promote_below_gate", "scan_dense_clusters"):
        value = cfg.get(key, DEFAULT_CONFIG[key])
        if not isinstance(value, bool):
            raise ValueError(f"[detectors.dns].{key} must be a boolean")

    for key in (
        "promote_min_nxdomain_fraction",
        "scan_min_high_entropy_fraction",
        "scan_min_regdomain_share",
    ):
        value = cfg.get(key, DEFAULT_CONFIG[key])
        if (
            isinstance(value, bool)
            or not isinstance(value, Real)
            or not math.isfinite(float(value))
            or not 0 <= float(value) <= 1
        ):
            raise ValueError(
                f"[detectors.dns].{key} must be a finite number from 0 through 1"
            )

    pihole = cfg.get("pihole", DEFAULT_CONFIG["pihole"])
    if not isinstance(pihole, dict):
        raise ValueError("[detectors.dns].pihole must be a table")

    pihole_cluster_size = pihole.get(
        "min_cluster_size", DEFAULT_CONFIG["pihole"]["min_cluster_size"]
    )
    if (
        isinstance(pihole_cluster_size, bool)
        or not isinstance(pihole_cluster_size, int)
        or pihole_cluster_size < 2
    ):
        raise ValueError(
            "[detectors.dns.pihole].min_cluster_size must be an integer greater "
            "than or equal to 2"
        )

    pihole_min_samples = pihole.get(
        "min_samples", DEFAULT_CONFIG["pihole"]["min_samples"]
    )
    if (
        isinstance(pihole_min_samples, bool)
        or not isinstance(pihole_min_samples, int)
        or pihole_min_samples < 1
    ):
        raise ValueError(
            "[detectors.dns.pihole].min_samples must be a positive integer"
        )

# Resolved at clustering import - accurate by read time. "fast-HDBSCAN" when
# the accelerator extra is installed, "HDBSCAN" otherwise. Both glow named -
# either way it's a published algorithm.
DETECTOR_METHOD = MethodTag(
    "fast-HDBSCAN" if ACTIVE_BACKEND == "fast_hdbscan" else "HDBSCAN",
    named=True,
)
DETECTOR_MISSION: str = (
    "Finds domain names and query patterns that stand apart from the rest, "
    "including generated-looking names (scored by entropy) of the sort malware "
    "uses for disposable command domains, and dense groups that can accompany "
    "automated traffic."
)

_NXDOMAIN_MAJORITY = 0.5
_NXDOMAIN_MIN_FAILURES = 2
_RESOLUTION_BASIS = "resolution-outcome"
_VOLUME_BASIS = "volume-concentration"
_DENSE_TUNNEL_MIN_CHILDREN = 2
# Frozen from the U-01 Pi-hole dense calibration record; not an operator lever.
_PIHOLE_SCAN_MIN_CLUSTER_MEMBERS = 25


@dataclass(frozen=True)
class PiholeClusterResult:
    """Standalone Pi-hole clustering result and whether dense clusters were scanned."""

    candidates: pd.DataFrame | None
    cluster_count: int
    total_members: int
    scanned: bool


def _nxdomain_stats(
    distribution: dict[Any, Any] | pd.Series,
) -> tuple[float, int] | None:
    """Return ``(NXDOMAIN fraction, count)`` for measurable rcode evidence.

    A Series is the group-constructor seam: its member dictionaries are
    accumulated before the same calculation used for a singleton. Unknown
    rcode keys remain in the denominator but never count as NXDOMAIN. Invalid
    counts are skipped so malformed additive evidence cannot crash detection.
    """
    if isinstance(distribution, dict):
        distributions = (distribution,)
    elif isinstance(distribution, pd.Series):
        distributions = tuple(
            item for item in distribution.tolist() if isinstance(item, dict)
        )
    else:
        return None
    if not distributions:
        return None

    total = 0
    nxdomain_count = 0
    for item in distributions:
        for raw_key, raw_count in item.items():
            try:
                count_float = float(raw_count)
            except (TypeError, ValueError, OverflowError):
                continue
            if (
                not math.isfinite(count_float)
                or count_float < 0
                or not count_float.is_integer()
            ):
                continue
            count = int(count_float)
            total += count

            try:
                key_number = float(raw_key)
            except (TypeError, ValueError, OverflowError):
                continue
            if math.isfinite(key_number) and key_number == 3:
                nxdomain_count += count

    if total <= 0:
        return None
    return nxdomain_count / total, nxdomain_count


def _severity_for(
    nxdomain_stats: tuple[float, int] | None,
    *,
    dense_origin: bool,
    has_public_suffix: bool,
) -> tuple[Severity, list[str]]:
    """Assign DNS severity from corroborating behavior, in stable basis order."""
    basis: list[str] = []
    if (
        has_public_suffix
        and nxdomain_stats is not None
        and nxdomain_stats[0] >= _NXDOMAIN_MAJORITY
        and nxdomain_stats[1] >= _NXDOMAIN_MIN_FAILURES
    ):
        basis.append(_RESOLUTION_BASIS)
    if dense_origin:
        basis.append(_VOLUME_BASIS)
    return (Severity.HIGH if basis else Severity.MEDIUM), basis


def _behavior_sentence(
    nxdomain_stats: tuple[float, int] | None,
    severity_basis: list[str],
) -> str:
    """Second sentence for non-dense findings; additive sentence for dense."""
    if _RESOLUTION_BASIS in severity_basis and nxdomain_stats is not None:
        fraction, count = nxdomain_stats
        return (
            f" {count} lookups under this name failed to resolve "
            f"({fraction:.0%} of the total)."
        )
    return (
        " The label score is the only signal - nothing in the query behavior "
        "corroborates it."
    )


def _finite_ts_bounds(
    values: pd.Series | None,
) -> tuple[float | None, float | None]:
    """Return the minimum and maximum finite numeric timestamps."""
    if values is None:
        return None, None
    numeric = pd.to_numeric(values, errors="coerce")
    finite = numeric[np.isfinite(numeric)]
    if finite.empty:
        return None, None
    return float(finite.min()), float(finite.max())


def _event_time_evidence(
    first_ts: Any,
    last_ts: Any,
) -> dict[str, str | float | None]:
    """Project numeric event bounds into the DNS evidence contract."""
    try:
        first = float(first_ts)
        last = float(last_ts)
    except (TypeError, ValueError, OverflowError):
        first = last = math.nan
    if not math.isfinite(first) or not math.isfinite(last):
        return {
            "first_seen": None,
            "last_seen": None,
            "span_seconds": None,
        }
    try:
        first_seen = datetime.fromtimestamp(first, timezone.utc).isoformat()
        last_seen = datetime.fromtimestamp(last, timezone.utc).isoformat()
    except (OSError, OverflowError, ValueError):
        return {
            "first_seen": None,
            "last_seen": None,
            "span_seconds": None,
        }
    return {
        "first_seen": first_seen,
        "last_seen": last_seen,
        "span_seconds": float(last - first),
    }


def _meets_dense_child_floor(value: Any) -> bool:
    """Return whether a dense cluster has enough distinct child names."""
    try:
        count = float(value)
    except (TypeError, ValueError, OverflowError):
        return False
    return (
        math.isfinite(count)
        and count >= _DENSE_TUNNEL_MIN_CHILDREN
    )


def _group_supports_dense_tunnel(grp: pd.DataFrame) -> bool:
    """Return whether any distinct dense cluster clears the child floor."""
    if (
        "dense_cluster_id" not in grp.columns
        or "cluster_true_member_count" not in grp.columns
    ):
        return False
    dense = grp.dropna(subset=["dense_cluster_id"])
    if dense.empty:
        return False
    per_cluster = dense.groupby(
        "dense_cluster_id", sort=False,
    )["cluster_true_member_count"].first()
    return any(_meets_dense_child_floor(value) for value in per_cluster)


# ---------------------------------------------------------------------------
# Feature helpers
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class _QueryShape:
    length: int
    parts: int
    suffix_len: int
    domain_len: int
    suffix: str

def entropy(s: str) -> float:
    """Weighted lexical suspicion score (the "label score") for a domain label.

    NOT Shannon entropy: a hand-weighted composite of normalized Shannon
    entropy plus character-class heuristics (digit / vowel / unique-char /
    run ratios), tuned to separate DGA/random labels from human-readable ones.
    Higher score = more suspicious. Blind spot: the digit weight makes benign
    digit-heavy labels (hex IDs, versioned hostnames) score high, while
    dictionary-word DGAs score low.
    """
    if not s:
        return 0.0
    s = s.lower()
    n = len(s)

    # Counter collects character frequencies in one pass; score arithmetic stays unchanged.
    counts = Counter(s)
    probs = [counts[character] / n for character in set(s)]
    shannon = -sum(p * math.log2(p) for p in probs)

    digits = sum(c.isdigit() for c in s) / n
    vowels = sum(c in 'aeiou' for c in s) / n
    unique_ratio = len(counts) / n

    max_run = run = 1
    for i in range(1, n):
        run = run + 1 if s[i] == s[i - 1] else 1
        max_run = max(max_run, run)
    run_penalty = max_run / n

    norm_entropy = shannon / math.log2(36)

    return (
        1.5 * norm_entropy +
        0.5 * unique_ratio +
        1.0 * digits -
        0.5 * vowels -
        0.3 * run_penalty
    )


def _query_labels(query: str) -> tuple[str, ...]:
    """Return meaningful DNS labels for structural feature extraction.

    A trailing root dot is representation, not content, so `example.com.` and
    `example.com` should cluster identically. Empty labels from malformed input
    are ignored rather than becoming artificial zero-length suffix/domain
    features.
    """
    normalized = str(query).strip().rstrip(".").lower()
    if not normalized:
        return ()
    return tuple(label for label in normalized.split(".") if label)


def _query_shape(query: str) -> _QueryShape:
    labels = _query_labels(query)
    suffix = labels[-1] if labels else ""
    domain = labels[-2] if len(labels) >= 2 else ""
    return _QueryShape(
        length=len(".".join(labels)),
        parts=len(labels),
        suffix_len=len(suffix),
        domain_len=len(domain),
        suffix=suffix,
    )


def _query_shape_frame(queries: pd.Series) -> pd.DataFrame:
    shape_by_query = {
        query: _query_shape(query)
        for query in queries.unique()
    }
    shapes = queries.map(shape_by_query)
    return pd.DataFrame(
        {
            "length": [shape.length for shape in shapes],
            "parts": [shape.parts for shape in shapes],
            "suffix_len": [shape.suffix_len for shape in shapes],
            "domain_len": [shape.domain_len for shape in shapes],
            "suffix": [shape.suffix for shape in shapes],
        },
        index=queries.index,
    )


def _add_top_suffix_dummies(feat: pd.DataFrame, suffixes: pd.Series) -> pd.DataFrame:
    """Add a deterministic, batch-relative top-20 suffix vocabulary."""
    suffix_counts = suffixes.value_counts().sort_index()
    ranked_suffixes = suffix_counts.sort_values(ascending=False, kind="stable")
    top_suffixes = ranked_suffixes.head(20).index
    suffix_col = suffixes.where(suffixes.isin(top_suffixes), "other")
    feat["TLD"] = suffix_col.values
    return pd.get_dummies(feat, columns=["TLD"], drop_first=False)


def summit(val: Any) -> float:
    """Sum TTL list or pass through scalar."""
    if isinstance(val, (int, float)):
        return float(val)
    return np.array(val, dtype=np.float32).sum()


def _registrable_key(query: str, ext: Any) -> str:
    """Grouping key for a query.

    Use the registrable domain, or for a name with no public suffix the last
    label, so a private namespace (``*.lan``) folds to one family instead of
    independent singletons.
    """
    reg = ext.top_domain_under_public_suffix
    if reg:
        return reg
    parts = [label for label in query.split(".") if label]
    return parts[-1] if parts else query


def _has_public_suffix(ext: Any) -> bool:
    """Return whether the extractor found a registrable public-suffix domain."""
    return bool(ext.top_domain_under_public_suffix)


def _max_subdomain_entropy(query: str, ext: Any) -> float:
    """Max entropy across the subdomain labels left of the registrable domain.

    For api-409632fc.example.com the registrable domain is example.com, so only
    ["api-409632fc"] is scored. For foo.bar.baz.example.com the labels ["foo",
    "bar", "baz"] are scored and the max is returned. When the query equals the
    registrable domain (no subdomain prefix), the domain label itself is scored
    as a fallback.
    """
    normalized_query = query.rstrip(".")
    reg = ext.top_domain_under_public_suffix
    if reg:
        if normalized_query.endswith("." + reg):
            prefix = normalized_query[: -(len(reg) + 1)]
            labels = [lbl for lbl in prefix.split(".") if lbl]
        else:
            # query IS the registrable domain - score its domain label
            labels = [ext.domain] if ext.domain else []
    else:
        parts = [label for label in normalized_query.split(".") if label]
        labels = parts[:-1] or parts
    return max(entropy(lbl) for lbl in labels) if labels else 0.0


# ---------------------------------------------------------------------------
# Feature engineering - Zeek per-query
# ---------------------------------------------------------------------------

def _build_features(df: pd.DataFrame) -> pd.DataFrame:
    """Build a standardized feature matrix for HDBSCAN from a filtered dns DataFrame."""
    qs = df["query"]
    shape = _query_shape_frame(qs)
    feat = pd.DataFrame(index=df.index)

    if "rtt" in df.columns:
        # Keep rare missingness bounded at 0/1. Scaling a rare binary feature
        # would give missing rows disproportionate weight in cluster distance.
        feat["rtt_missing"] = df["rtt"].isna().astype(float)
        rtt_median = df["rtt"].median()
        rtt_fill = 0.0 if pd.isna(rtt_median) else float(rtt_median)
        feat["rtt"] = np.log1p(df["rtt"].fillna(rtt_fill))

    if "ttl" in df.columns:
        feat["ttl"] = np.log1p(df["ttl"].fillna(0).apply(summit))

    # Resolution outcome belongs to _nxdomain_stats and finding evidence; it is
    # a severity corroborator, never an ordinal clustering feature.

    feat["qlen"] = shape["length"].values
    feat["qparts"] = shape["parts"].values
    feat["sufflen"] = shape["suffix_len"].values
    feat["domlen"] = shape["domain_len"].values

    if "answer" in df.columns:
        feat["answer"] = df["answer"].apply(
            lambda x: len(x) if isinstance(x, list) else 0
        ).values

    if "tc" in df.columns:
        feat["tc"] = df["tc"].fillna(0).astype(int).values

    # DNS suffix one-hot (top 20 suffixes + other bucket).
    feat = _add_top_suffix_dummies(feat, shape["suffix"])

    # Standardize numeric columns
    num_cols = [c for c in ["rtt", "ttl", "qlen", "qparts", "sufflen", "domlen", "answer"]
                if c in feat.columns]
    scaler = StandardScaler()
    scaled = scaler.fit_transform(feat[num_cols].values)
    feat[num_cols] = np.nan_to_num(scaled, nan=0.0)

    return feat


# ---------------------------------------------------------------------------
# Feature engineering - pihole per-domain aggregate
# ---------------------------------------------------------------------------

def _build_pihole_aggregate(pihole_df: pd.DataFrame) -> pd.DataFrame:
    """Build a per-domain aggregate row from a pihole events DataFrame.

    Returns one row per unique query domain with behavioral and evidence columns.
    Null or non-string query values are dropped before any string operations.
    Excludes dnssec_query, dhcp, and pihole_hostname from the query baseline;
    special events are counted as an annotation but excluded from cluster features.
    block_ratio = block_count / clip(total_count, 1), always 0.0 when no events -
    never NaN. Evidence-only; not in the feature matrix.
    """
    # Defensive: drop rows where query is null or not a string.
    valid_mask = pihole_df["query"].notna() & pihole_df["query"].apply(
        lambda x: isinstance(x, str)
    )
    pihole_df = pihole_df[valid_mask].copy()
    if pihole_df.empty:
        return pd.DataFrame()

    # Domain universe: query events only (excludes dnssec_query, dhcp, pihole_hostname).
    query_events = pihole_df[pihole_df["event_type"] == "query"].copy()
    if query_events.empty:
        return pd.DataFrame()

    # Drop degenerate queries (same filter as the Zeek path).
    has_dot = query_events["query"].str.count(r"\.") > 0
    has_domain = query_events["query"].apply(lambda q: _TLD_EXTRACT(q).domain != "")
    query_events = query_events[has_dot & has_domain].copy()
    if query_events.empty:
        return pd.DataFrame()

    if "ts" in query_events.columns:
        event_ts = pd.to_numeric(query_events["ts"], errors="coerce")
        query_events["_event_ts"] = event_ts.where(
            np.isfinite(event_ts), np.nan,
        )
    else:
        query_events["_event_ts"] = np.nan

    valid_domains = set(query_events["query"].unique())

    # Full event stream restricted to valid domains for ratio computation.
    full = pihole_df[pihole_df["query"].isin(valid_domains)]

    forward_counts = (
        full[full["event_type"] == "forwarded"].groupby("query").size()
    )
    cache_counts = (
        full[full["event_type"] == "cached"].groupby("query").size()
    )
    # gravity_blocked + regex_blocked collapsed into one "blocked" notion.
    block_counts = (
        full[full["event_type"].isin(["gravity_blocked", "regex_blocked"])]
        .groupby("query").size()
    )
    special_counts = (
        full[full["event_type"] == "special"].groupby("query").size()
    )
    total_counts = full.groupby("query").size()

    query_groups = query_events.groupby("query")
    query_counts    = query_groups.size()
    client_nunique  = query_groups["src"].nunique()
    querier_ips_s   = query_groups["src"].apply(
        lambda x: sorted(x.dropna().unique().tolist())
    )
    unique_qtypes_s = query_groups["qtype"].nunique()
    qtype_counts_s  = query_groups["qtype"].apply(
        lambda x: x.value_counts().to_dict()
    )
    first_ts_s = query_groups["_event_ts"].min()
    last_ts_s = query_groups["_event_ts"].max()

    domains = query_counts.index

    agg = pd.DataFrame(index=domains)
    agg.index.name = "query"
    agg["query_count"]   = query_counts
    agg["forward_count"] = forward_counts.reindex(domains, fill_value=0)
    agg["cache_count"]   = cache_counts.reindex(domains, fill_value=0)
    agg["block_count"]   = block_counts.reindex(domains, fill_value=0)
    agg["special_count"] = special_counts.reindex(domains, fill_value=0)
    agg["total_count"]   = total_counts.reindex(domains, fill_value=0)
    agg["unique_clients"] = client_nunique.reindex(domains, fill_value=0)
    agg["unique_qtypes"]  = unique_qtypes_s.reindex(domains, fill_value=0)
    agg["querier_ips"]    = querier_ips_s.reindex(domains)
    agg["qtype_counts"]   = qtype_counts_s.reindex(domains)
    agg["first_ts"]       = first_ts_s.reindex(domains)
    agg["last_ts"]        = last_ts_s.reindex(domains)

    # Ratios: clip denominator to 1, then fillna(0.0) as a backstop. Evidence-only.
    agg["forward_ratio"] = (
        agg["forward_count"] / agg["query_count"].clip(lower=1)
    ).fillna(0.0)
    agg["cache_ratio"] = (
        agg["cache_count"] / agg["query_count"].clip(lower=1)
    ).fillna(0.0)
    agg["block_ratio"] = (
        agg["block_count"] / agg["total_count"].clip(lower=1)
    ).fillna(0.0)
    agg["was_blocked"] = agg["block_ratio"] > 0

    # unique_sources is the shared-contract alias for unique_clients.
    agg["unique_sources"] = agg["unique_clients"]

    # Fix list/dict columns that may be NaN after reindex on sparse domains.
    agg["querier_ips"]  = agg["querier_ips"].apply(
        lambda x: x if isinstance(x, list) else []
    )
    agg["qtype_counts"] = agg["qtype_counts"].apply(
        lambda x: x if isinstance(x, dict) else {}
    )

    return agg.reset_index()  # "query" becomes a column


def _build_pihole_features(agg_df: pd.DataFrame) -> pd.DataFrame:
    """Build a standardized feature matrix for pihole domain-level HDBSCAN.

    block_ratio, was_blocked, special_count, and raw count columns are NOT
    included - they are evidence-only.
    """
    feat = pd.DataFrame(index=agg_df.index)
    qs = agg_df["query"]
    shape = _query_shape_frame(qs)

    # Structural features.
    feat["q_len"]        = shape["length"].values
    feat["q_parts"]      = shape["parts"].values
    feat["q_suffix_len"] = shape["suffix_len"].values
    feat["q_domain_len"] = shape["domain_len"].values

    # Behavioral features.
    feat["log1p_query_count"]   = np.log1p(agg_df["query_count"].values)
    feat["log1p_unique_clients"] = np.log1p(agg_df["unique_clients"].values)
    feat["unique_qtypes"]        = agg_df["unique_qtypes"].values.astype(float)
    feat["log1p_forward_ratio"]  = np.log1p(agg_df["forward_ratio"].values)
    feat["log1p_cache_ratio"]    = np.log1p(agg_df["cache_ratio"].values)

    # DNS suffix one-hot (top 20 + other bucket) - same logic as _build_features.
    feat = _add_top_suffix_dummies(feat, shape["suffix"])

    # Standardize numeric columns.
    num_cols = [c for c in [
        "q_len", "q_parts", "q_suffix_len", "q_domain_len",
        "log1p_query_count", "log1p_unique_clients", "unique_qtypes",
        "log1p_forward_ratio", "log1p_cache_ratio",
    ] if c in feat.columns]
    scaler = StandardScaler()
    scaled = scaler.fit_transform(feat[num_cols].values)
    feat[num_cols] = np.nan_to_num(scaled, nan=0.0)

    return feat


# ---------------------------------------------------------------------------
# Source paths
# ---------------------------------------------------------------------------

def _surface_dense_clusters(
    dns_df: pd.DataFrame,
    labels: np.ndarray,
    *,
    thresh_high: float,
    scan_cfg: dict,
    member_floor: int,
    query_weight: pd.Series | None = None,
) -> tuple[pd.DataFrame, set[str]]:
    """Scan non-noise clusters for the DNS-tunnel shape and surface their members.

    A sustained high-volume tunnel forms its own dense cluster (a real label),
    so the noise-only candidate set never sees it. For each non-noise cluster,
    over its member rows, gate on three signals:
      - the fraction of members whose _max_subdomain_entropy clears thresh_high,
      - the cluster size (members at the caller's row/domain grain),
      - the share of members under the single most-common registrable domain
        (a tunnel concentrates under one parent; a benign high-entropy cluster
        spreads across many).
    A cluster passing all three has its dominant-registrable-domain members
    surfaced as candidates.

    Returns (sample_rows, dominant_queries):
      - sample_rows: the surfaced dominant-domain candidate queries, capped per
        cluster at scan_max_members_per_cluster (highest label score first), each
        carrying dense_cluster_id, cluster_true_member_count (the DOMINANT-domain
        distinct-subdomain count), and cluster_true_query_total (the
        cluster-local query-event total under the dominant domain - NOT
        whole-cluster totals). With ``query_weight`` this is a weighted sum;
        otherwise it is the row count.
      - dominant_queries: every surfaced cluster's FULL (uncapped) dominant query
        set, which the caller removes from the noise set so a counted member is
        never also tallied as an independent noise row.

    Empty frame + empty set when disabled or nothing passes the gate. Cost is
    bounded: one _TLD_EXTRACT per DISTINCT member query, broadcast to rows.

    ``query_weight`` must have the same index and length as ``dns_df``. It affects
    only ``cluster_true_query_total``; all gates and member counts remain unweighted.
    """
    empty_cols = [
        "query", "dense_cluster_id",
        "cluster_true_member_count", "cluster_true_query_total",
    ]
    if not scan_cfg["scan_dense_clusters"]:
        return pd.DataFrame(columns=empty_cols), set()

    if query_weight is not None and (
        len(query_weight) != len(dns_df)
        or not query_weight.index.equals(dns_df.index)
    ):
        raise ValueError("query_weight must align exactly with dns_df")

    frac_floor   = scan_cfg["scan_min_high_entropy_fraction"]
    share_floor  = scan_cfg["scan_min_regdomain_share"]
    cap          = scan_cfg["scan_max_members_per_cluster"]

    records: list[dict[str, Any]] = []
    dominant_queries: set[str] = set()
    # A query whose rows split across two dense clusters (same feature-derived
    # shape, different rtt/ttl) is attributed to the FIRST cluster that claims it,
    # so cross-cluster query attribution is DISJOINT: no query is counted in two
    # clusters' true totals (which would double-count a shared subdomain under one
    # parent) and no row is duplicated by the candidate merge downstream.
    claimed: set[str] = set()

    for lbl in np.unique(labels[labels != -1]):
        member_mask = labels == lbl
        member_q = dns_df.loc[member_mask, "query"]
        member_weight = (
            query_weight.loc[member_mask]
            if query_weight is not None
            else None
        )
        if len(member_q) < member_floor:
            continue  # size floor - cheap reject before any extract

        # One _TLD_EXTRACT per DISTINCT member query; broadcast to rows.
        ent_by_q: dict[str, float] = {}
        reg_by_q: dict[str, str] = {}
        for q in member_q.unique():
            ext = _TLD_EXTRACT(q)
            ent_by_q[q] = _max_subdomain_entropy(q, ext)
            reg_by_q[q] = _registrable_key(q, ext)

        row_ent = member_q.map(ent_by_q)
        row_reg = member_q.map(reg_by_q)

        # Gates read the cluster's FULL membership (all rows decide tunnel-shape).
        if float((row_ent >= thresh_high).mean()) < frac_floor:
            continue

        dominant_reg = row_reg.value_counts().idxmax()
        dom_mask = row_reg == dominant_reg
        if float(dom_mask.mean()) < share_floor:
            continue

        dom_q = member_q[dom_mask]
        dom_weight = member_weight[dom_mask] if member_weight is not None else None
        # Only dominant queries not already claimed by an earlier cluster.
        dominant_distinct = [q for q in dict.fromkeys(dom_q.tolist()) if q not in claimed]
        if not dominant_distinct:
            continue  # every dominant query already attributed elsewhere
        claimed.update(dominant_distinct)
        dominant_queries.update(dominant_distinct)

        owned = set(dominant_distinct)
        true_member_count = len(dominant_distinct)
        owned_mask = dom_q.isin(owned)
        true_query_total = int(
            dom_weight[owned_mask].sum()
            if dom_weight is not None
            else owned_mask.sum()
        )

        # Surfaced sample: owned dominant queries by label score desc, capped.
        ranked = sorted(dominant_distinct, key=lambda q: ent_by_q[q], reverse=True)[:cap]
        for q in ranked:
            records.append({
                "query": q,
                "dense_cluster_id": int(lbl),
                "cluster_true_member_count": true_member_count,
                "cluster_true_query_total": true_query_total,
            })

    if not records:
        return pd.DataFrame(columns=empty_cols), set()
    return pd.DataFrame(records), dominant_queries


def _run_zeek_path(
    dns_df: pd.DataFrame,
    min_cluster_size: int,
    min_samples: int,
    *,
    thresh_high: float,
    scan_cfg: dict,
) -> pd.DataFrame | None:
    """Run the per-query Zeek clustering path.

    dns_df may carry was_blocked/block_ratio columns from pihole pre-enrichment
    (both-mode). _build_features ignores them; _enrich picks them up if present.

    After clustering, the noise-set candidates are unioned with any
    dense-cluster members surfaced by _surface_dense_clusters (the tunnel-shape
    scan; gated by scan_cfg). thresh_high is the high-entropy bar the scan reuses.

    Returns a candidate_df at the shared-seam contract, source='zeek', with no
    label-score threshold applied. Surfaced-dense rows carry dense_cluster_id,
    cluster_true_member_count, and cluster_true_query_total (absent/NaN on
    noise rows). Returns None only when neither noise nor a surfaced dense
    cluster yields a candidate.
    """
    if dns_df.empty or "query" not in dns_df.columns:
        return None

    # reset_index returns the owned working frame; the caller remains unchanged.
    working_df = dns_df.reset_index(drop=True)

    # Drop degenerate queries that break feature engineering.
    has_dot    = working_df["query"].str.count(r"\.") > 0
    queries = working_df["query"]
    has_domain_by_query = {
        query: _TLD_EXTRACT(query).domain != ""
        for query in queries.unique()
    }
    has_domain = queries.map(has_domain_by_query)
    dns_df = working_df[has_dot & has_domain].reset_index(drop=True)
    del working_df
    if dns_df.empty:
        return None

    feat_df = _build_features(dns_df)

    X = np.ascontiguousarray(feat_df.to_numpy(dtype=np.float64))
    del feat_df
    labels = fit_predict_interruptible(
        X, min_cluster_size=min_cluster_size, min_samples=min_samples,
    )
    del X

    noise_mask    = labels == -1
    noise_queries = np.unique(dns_df.loc[noise_mask, "query"].values)

    # Scan non-noise clusters for the tunnel shape - a self-clustering
    # high-volume tunnel never reaches the noise set. Surfaced dense members
    # union with the noise candidates below.
    dense_records, dense_dominant = _surface_dense_clusters(
        dns_df,
        labels,
        thresh_high=thresh_high,
        scan_cfg=scan_cfg,
        member_floor=scan_cfg["scan_min_cluster_members"],
    )

    # Pure-tunnel is zero noise but surfaced dense; return None only when BOTH
    # the noise set AND the surfaced-dense set are empty.
    if len(noise_queries) == 0 and dense_records.empty:
        return None

    # Drop noise queries that are counted dense-cluster members so a member is
    # never tallied twice - once as a noise row, once in cluster_true_member_count.
    noise_only = [q for q in noise_queries if q not in dense_dominant]

    all_queries = list(dict.fromkeys([*noise_only, *dense_records["query"].tolist()]))
    candidate_df = pd.DataFrame({"query": all_queries})
    if not dense_records.empty:
        # Left-merge attaches dense columns to surfaced rows; noise rows stay NaN.
        # dense_records holds one row per query (the claimed-set disjoint
        # attribution above), so drop_duplicates only guards the merge against a
        # row fan-out and is inert under that invariant.
        candidate_df = candidate_df.merge(
            dense_records.drop_duplicates("query"), on="query", how="left",
        )
    candidate_df["_ext"] = candidate_df["query"].apply(_TLD_EXTRACT)
    candidate_df["label_entropy"] = candidate_df.apply(
        lambda row: _max_subdomain_entropy(row["query"], row["_ext"]), axis=1
    )

    # Track whether block enrichment columns are present (both-mode only).
    has_block_enrichment = "was_blocked" in dns_df.columns
    # Precompute one grouping so per-candidate enrichment is O(group) rather than
    # an O(N) scan per candidate. groupby preserves within-group row order, so the
    # enrichment values and their ordering are unchanged.
    grouped = dns_df.groupby("query")

    def _enrich(domain: str) -> dict[str, Any]:
        sub = grouped.get_group(domain) if domain in grouped.groups else dns_df.iloc[0:0]
        srcs: list[str] = []
        if "src" in sub.columns:
            srcs = [s for s in sub["src"].dropna().unique().tolist() if isinstance(s, str)]
        rcode_dist: dict[Any, int] = {}
        if "rcode" in sub.columns:
            rcode_dist = sub["rcode"].value_counts().to_dict()
        first_ts, last_ts = _finite_ts_bounds(
            sub["ts"] if "ts" in sub.columns else None
        )
        result: dict[str, Any] = {
            "query_count":      len(sub),
            "unique_sources":   len(srcs),
            "querier_ips":      srcs,
            "rcode_distribution": rcode_dist,
            "first_ts":         first_ts,
            "last_ts":          last_ts,
        }
        if has_block_enrichment:
            result["was_blocked"] = bool(sub["was_blocked"].any())
            result["block_ratio"]  = float(sub["block_ratio"].max())
        return result

    enriched = candidate_df["query"].apply(_enrich)
    candidate_df["query_count"]       = enriched.apply(lambda e: e["query_count"])
    candidate_df["unique_sources"]    = enriched.apply(lambda e: e["unique_sources"])
    candidate_df["querier_ips"]       = enriched.apply(lambda e: e["querier_ips"])
    candidate_df["rcode_distribution"] = enriched.apply(lambda e: e["rcode_distribution"])
    candidate_df["first_ts"] = enriched.apply(lambda e: e["first_ts"])
    candidate_df["last_ts"] = enriched.apply(lambda e: e["last_ts"])
    if has_block_enrichment:
        candidate_df["was_blocked"] = enriched.apply(lambda e: e["was_blocked"])
        candidate_df["block_ratio"] = enriched.apply(lambda e: e["block_ratio"])

    candidate_df["registrable_domain"] = candidate_df.apply(
        lambda row: _registrable_key(row["query"], row["_ext"]), axis=1
    )
    candidate_df["has_public_suffix"] = candidate_df["_ext"].apply(
        _has_public_suffix
    )
    candidate_df.drop(columns=["_ext"], inplace=True)
    candidate_df["source"] = "zeek"

    return candidate_df


def _run_pihole_path(
    pihole_df: pd.DataFrame,
    pihole_cfg: dict,
    *,
    thresh_high: float,
    scan_cfg: dict,
) -> PiholeClusterResult | None:
    """Run the per-domain aggregate pihole clustering path.

    Returns noise candidates union any scan-surfaced dense aggregate rows at the
    shared-seam contract, plus counts for every non-noise aggregate row and the
    scan-attempt state. Returns None only when clustering did not run: the aggregate
    is empty or smaller than the configured min_cluster_size.
    """
    agg_df = _build_pihole_aggregate(pihole_df)
    if agg_df.empty:
        return None

    # Guard: HDBSCAN behaviour is undefined when the dataset is smaller than
    # min_cluster_size; common in tests and short time-window runs.
    min_cs = pihole_cfg["min_cluster_size"]
    if len(agg_df) < min_cs:
        return None

    feat_df = _build_pihole_features(agg_df)
    X = np.ascontiguousarray(feat_df.to_numpy(dtype=np.float64))
    labels = fit_predict_interruptible(
        X,
        min_cluster_size=min_cs,
        min_samples=pihole_cfg["min_samples"],
    )

    clustered_labels = labels[labels != -1]
    cluster_count = int(np.unique(clustered_labels).size)
    total_members = int(clustered_labels.size)
    scanned = bool(scan_cfg["scan_dense_clusters"])
    dense_records, dense_dominant = _surface_dense_clusters(
        agg_df,
        labels,
        thresh_high=thresh_high,
        scan_cfg=scan_cfg,
        member_floor=_PIHOLE_SCAN_MIN_CLUSTER_MEMBERS,
        query_weight=agg_df["query_count"],
    )

    noise_mask = labels == -1
    noise_df = agg_df.loc[
        noise_mask & ~agg_df["query"].isin(dense_dominant)
    ].copy()
    if dense_records.empty:
        candidate_df = noise_df.reset_index(drop=True)
    else:
        dense_df = agg_df.merge(
            dense_records.drop_duplicates("query"),
            on="query",
            how="inner",
            validate="one_to_one",
        )
        candidate_df = pd.concat(
            [noise_df, dense_df], ignore_index=True, sort=False,
        )
    if candidate_df.empty:
        return PiholeClusterResult(
            candidates=None,
            cluster_count=cluster_count,
            total_members=total_members,
            scanned=scanned,
        )

    candidate_df["_ext"] = candidate_df["query"].apply(_TLD_EXTRACT)
    candidate_df["label_entropy"] = candidate_df.apply(
        lambda row: _max_subdomain_entropy(row["query"], row["_ext"]), axis=1
    )
    candidate_df["registrable_domain"] = candidate_df.apply(
        lambda row: _registrable_key(row["query"], row["_ext"]), axis=1
    )
    candidate_df["has_public_suffix"] = candidate_df["_ext"].apply(
        _has_public_suffix
    )
    candidate_df.drop(columns=["_ext"], inplace=True)
    candidate_df["source"] = "pihole"

    return PiholeClusterResult(
        candidates=candidate_df,
        cluster_count=cluster_count,
        total_members=total_members,
        scanned=scanned,
    )


def _enrich_zeek_with_pihole(
    dns_df: pd.DataFrame,
    pihole_df: pd.DataFrame,
) -> pd.DataFrame:
    """Join per-domain block data from pihole_df onto dns_df (both-mode).

    Adds was_blocked (bool) and block_ratio (float) columns using the same
    denominator as _build_pihole_aggregate: block_count / clip(total_count, 1).
    Domains in dns_df with no pihole match default to was_blocked=False,
    block_ratio=0.0 - never NaN.
    """
    # Null/type guard consistent with _build_pihole_aggregate.
    valid_mask = pihole_df["query"].notna() & pihole_df["query"].apply(
        lambda x: isinstance(x, str)
    )
    ph = pihole_df[valid_mask]

    if ph.empty:
        dns_df["was_blocked"] = False
        dns_df["block_ratio"]  = 0.0
        return dns_df

    block_counts = (
        ph[ph["event_type"].isin(["gravity_blocked", "regex_blocked"])]
        .groupby("query").size()
    )
    total_counts = ph.groupby("query").size()

    domain_br = (
        block_counts.reindex(total_counts.index, fill_value=0)
        / total_counts.clip(lower=1)
    ).fillna(0.0)

    br_map      = domain_br.to_dict()
    blocked_set = set(domain_br.index[domain_br > 0])

    dns_df["block_ratio"]  = dns_df["query"].map(br_map).fillna(0.0)
    dns_df["was_blocked"]  = dns_df["query"].isin(blocked_set)

    return dns_df


def _make_below_gate_group_findings(
    dns_df: pd.DataFrame,
    *,
    threshold: float,
    min_subdomains: int,
    min_nxdomain_fraction: float,
    surfaced_parents: set[str],
    now: datetime,
    data_window: tuple[datetime, datetime],
) -> list[Finding]:
    """Promote resolution-dominated below-gate Zeek families from the full frame.

    This pass deliberately does not consume ``candidate_df``. A high-volume
    family can self-cluster, fail the dense high-score scan, and therefore be
    absent from both the noise and surfaced-dense candidate sets. Reading the
    full normalized frame keeps increased volume from making the family vanish.
    """
    if (
        dns_df.empty
        or "query" not in dns_df.columns
        or "rcode" not in dns_df.columns
    ):
        return []

    valid_query = dns_df["query"].notna() & dns_df["query"].apply(
        lambda value: isinstance(value, str)
    )
    full = dns_df[valid_query].copy()
    if full.empty:
        return []

    distinct = pd.DataFrame({"query": pd.unique(full["query"])})
    distinct["_ext"] = distinct["query"].apply(_TLD_EXTRACT)
    distinct["registrable_domain"] = distinct.apply(
        lambda row: _registrable_key(row["query"], row["_ext"]),
        axis=1,
    )
    distinct["has_public_suffix"] = distinct["_ext"].apply(_has_public_suffix)
    distinct["label_entropy"] = distinct.apply(
        lambda row: _max_subdomain_entropy(row["query"], row["_ext"]),
        axis=1,
    )
    # A registrable-domain apex is not a subdomain and cannot advance the
    # distinct-name floor.
    below = distinct[
        (distinct["query"] != distinct["registrable_domain"])
        & (distinct["label_entropy"] < threshold)
    ].copy()
    if below.empty:
        return []

    below_by_query = below.set_index("query")
    full = full[full["query"].isin(below_by_query.index)].copy()
    full["registrable_domain"] = full["query"].map(
        below_by_query["registrable_domain"]
    )
    full_groups = full.groupby("registrable_domain", sort=False)

    findings: list[Finding] = []
    for reg_domain, query_shapes in below.groupby("registrable_domain", sort=True):
        parent = str(reg_domain)
        if parent in surfaced_parents or len(query_shapes) < min_subdomains:
            continue

        query_names = query_shapes["query"].tolist()
        rows = full_groups.get_group(reg_domain)
        rcode_stats = _nxdomain_stats(rows["rcode"].value_counts().to_dict())
        if rcode_stats is None or rcode_stats[0] < min_nxdomain_fraction:
            continue

        sources: list[str] = []
        if "src" in rows.columns:
            sources = [
                source
                for source in rows["src"].dropna().unique().tolist()
                if isinstance(source, str)
            ]
        label_scores = query_shapes["label_entropy"].astype(float)
        first_ts, last_ts = _finite_ts_bounds(
            rows["ts"] if "ts" in rows.columns else None
        )
        # ``_severity_for`` remains the only severity-basis owner. Promotion is
        # INFO because the mandatory lexical leg did not clear; the behavior
        # that made it visible lives in tier + resolution evidence.
        _, severity_basis = _severity_for(
            None,
            dense_origin=False,
            has_public_suffix=False,
        )
        fraction, nxdomain_count = rcode_stats
        next_steps = [
            f"Review the queried names under {parent}",
            "Check whether the parent is expected in this environment",
        ]
        if sources:
            next_steps.insert(
                1, f"Pivot on querier IPs: {', '.join(sources[:5])}"
            )
        has_public_suffix = bool(query_shapes["has_public_suffix"].all())
        subdomain_count = int(len(query_shapes))
        if has_public_suffix:
            description = (
                f"{subdomain_count} {plural(subdomain_count, 'distinct name')} under "
                f"registrable domain {parent} failed to resolve in {fraction:.0%} of "
                "lookups. This pattern may resemble automated name generation."
            )
        else:
            description = (
                f"{subdomain_count} {plural(subdomain_count, 'distinct name')} under "
                f"private namespace {parent} failed to resolve in {fraction:.0%} of "
                "lookups. Names in a private namespace routinely fail to resolve "
                "outside their local zone."
            )
        findings.append(Finding(
            detector=DETECTOR_NAME,
            severity=Severity.INFO,
            title=parent,
            description=description,
            evidence={
                "tier": "below_gate_group",
                "source": "zeek",
                "registrable_domain": parent,
                "subdomain_count": subdomain_count,
                "max_label_score": round(float(label_scores.max()), 4),
                "min_label_score": round(float(label_scores.min()), 4),
                "total_queries": int(len(rows)),
                "unique_sources": len(sources),
                "sample_domains": query_names[:5],
                "querier_ips": sources,
                "nxdomain_fraction": round(fraction, 4),
                "nxdomain_count": nxdomain_count,
                "severity_basis": severity_basis,
                **_event_time_evidence(first_ts, last_ts),
            },
            next_steps=next_steps,
            ts_generated=now,
            data_window=data_window,
        ))

    return findings


# ---------------------------------------------------------------------------
# Shared back half
# ---------------------------------------------------------------------------

def _shared_back_half(
    candidate_df: pd.DataFrame,
    threshold: float,
    now: datetime,
    data_window: tuple[datetime, datetime],
) -> list[Finding]:
    """Label-score filter → group by registrable_domain → build and sort findings.

    Source-agnostic: operates on the shared candidate_df contract produced by
    _run_zeek_path or _run_pihole_path.
    """
    candidate_df = candidate_df[candidate_df["label_entropy"] >= threshold].copy()
    if candidate_df.empty:
        return []
    # Constructor precondition: every row reaching the constructors already
    # cleared label_entropy >= threshold; constructors must not repeat that gate.

    candidate_df = candidate_df.sort_values(
        "label_entropy", ascending=False
    ).reset_index(drop=True)

    group_findings: list[Finding]     = []
    singleton_findings: list[Finding] = []

    for reg_domain, grp in candidate_df.groupby("registrable_domain"):
        if len(grp) >= 2:
            group_findings.append(
                _make_group_finding(str(reg_domain), grp, now, data_window)
            )
        else:
            singleton_findings.append(
                _make_singleton_finding(grp.iloc[0], str(reg_domain), now, data_window)
            )

    group_findings.sort(key=lambda f: f.evidence["max_label_score"], reverse=True)
    singleton_findings.sort(key=lambda f: f.evidence["label_score"], reverse=True)

    return group_findings + singleton_findings


# ---------------------------------------------------------------------------
# Detector entry point
# ---------------------------------------------------------------------------

def run(context: DetectorContext) -> list[Finding]:
    """Cluster DNS query behavior and flag high-entropy noise domains."""
    cfg = context.config
    min_cluster_size: int  = cfg.get("min_cluster_size", DEFAULT_CONFIG["min_cluster_size"])
    min_samples: int       = cfg.get("min_samples",      DEFAULT_CONFIG["min_samples"])
    threshold: float       = cfg.get("threshold",        DEFAULT_CONFIG["threshold"])
    promote_below_gate: bool = cfg.get(
        "promote_below_gate", DEFAULT_CONFIG["promote_below_gate"]
    )
    promote_min_subdomains: int = cfg.get(
        "promote_min_subdomains", DEFAULT_CONFIG["promote_min_subdomains"]
    )
    promote_min_nxdomain_fraction: float = cfg.get(
        "promote_min_nxdomain_fraction",
        DEFAULT_CONFIG["promote_min_nxdomain_fraction"],
    )
    thresh_high: float     = cfg.get("thresh_high_entropy", DEFAULT_CONFIG["thresh_high_entropy"])
    pihole_cfg: dict       = {**DEFAULT_CONFIG["pihole"], **cfg.get("pihole", {})}
    scan_cfg: dict = {
        key: cfg.get(key, DEFAULT_CONFIG[key])
        for key in (
            "scan_dense_clusters",
            "scan_min_high_entropy_fraction",
            "scan_min_cluster_members",
            "scan_min_regdomain_share",
            "scan_max_members_per_cluster",
        )
    }

    zeek_df   = context.logs.get("dns*.log*")
    pihole_df = context.logs.get("pihole*.log*")

    has_zeek   = zeek_df is not None and not zeek_df.empty and "query" in zeek_df.columns
    has_pihole = pihole_df is not None and not pihole_df.empty

    if not has_zeek and not has_pihole:
        return []

    now = datetime.now(timezone.utc)
    zeek_full_df: pd.DataFrame | None = None
    pihole_result: PiholeClusterResult | None = None

    if has_zeek and has_pihole:
        # Enrich Zeek frame with pihole block data BEFORE clustering (evidence-only;
        # was_blocked/block_ratio never enter the Zeek feature matrix).
        dns_df = _enrich_zeek_with_pihole(zeek_df.copy(), pihole_df)
        zeek_full_df = dns_df
        candidate_df = _run_zeek_path(
            dns_df, min_cluster_size, min_samples, thresh_high=thresh_high, scan_cfg=scan_cfg,
        )
    elif has_zeek:
        zeek_full_df = zeek_df
        candidate_df = _run_zeek_path(
            zeek_df, min_cluster_size, min_samples, thresh_high=thresh_high, scan_cfg=scan_cfg,
        )
    else:
        pihole_result = _run_pihole_path(
            pihole_df,
            pihole_cfg,
            thresh_high=thresh_high,
            scan_cfg=scan_cfg,
        )
        candidate_df = (
            pihole_result.candidates if pihole_result is not None else None
        )

    findings: list[Finding] = []
    surfaced_parents: set[str] = set()
    if candidate_df is not None and not candidate_df.empty:
        findings = _shared_back_half(
            candidate_df, threshold, now, context.data_window
        )
        surfaced = candidate_df[candidate_df["label_entropy"] >= threshold]
        surfaced_parents = {
            str(parent)
            for parent in surfaced["registrable_domain"].dropna().tolist()
        }

        # Synthetic INFO disclosure when the dense-cluster scan produced findings -
        # gated on the SAME threshold, so it never discloses more than the report shows.
        summary = _make_scan_summary_finding(
            candidate_df, threshold, now, context.data_window
        )
        if summary is not None:
            findings.append(summary)

    # Scan-off returns standalone Pi-hole to the shipped disclosed state. Scan-on
    # uses the existing scan_summary route, so these two INFO tiers are mutually
    # exclusive by construction.
    if (
        pihole_result is not None
        and pihole_result.cluster_count > 0
        and not pihole_result.scanned
    ):
        findings.append(_make_pihole_unscanned_finding(
            pihole_result.cluster_count,
            pihole_result.total_members,
            now,
            context.data_window,
        ))

    if promote_below_gate and zeek_full_df is not None:
        findings.extend(_make_below_gate_group_findings(
            zeek_full_df,
            threshold=threshold,
            min_subdomains=promote_min_subdomains,
            min_nxdomain_fraction=promote_min_nxdomain_fraction,
            surfaced_parents=surfaced_parents,
            now=now,
            data_window=context.data_window,
        ))

    return findings


# ---------------------------------------------------------------------------
# Finding constructors
# ---------------------------------------------------------------------------

def _make_group_finding(
    reg_domain: str,
    grp: pd.DataFrame,
    now: datetime,
    data_window: tuple[datetime, datetime],
) -> Finding:
    source = str(grp.iloc[0]["source"])
    # label_entropy (the per-label suspicion score column) feeds the evidence
    # keys max_label_score / min_label_score / label_score.
    grp_sorted = grp.sort_values("label_entropy", ascending=False)
    max_ent = float(grp_sorted["label_entropy"].max())
    min_ent = float(grp_sorted["label_entropy"].min())
    # For a dense group, n_rows and rcode_stats are sample-relative because
    # only surfaced rows carry per-query outcome evidence; the true
    # dominant-domain member count lives in cluster_true_member_count below.
    n_rows = len(grp)

    # Honest counts. A dense-cluster group can mix noise rows with sampled rows
    # from one or more dense clusters; count noise rows individually but each
    # dense cluster ONCE via its true (dominant-domain) totals - never per
    # sampled row (overcounts under the per-cluster cap) nor per registrable
    # domain alone (undercounts two dense clusters under one parent).
    # cluster_true_* are DOMINANT-domain counts; never whole-cluster totals.
    has_dense = "dense_cluster_id" in grp.columns and grp["dense_cluster_id"].notna().any()
    dense_tunnel_supported = _group_supports_dense_tunnel(grp)
    if "dense_cluster_id" in grp.columns:
        noise_rows = grp[grp["dense_cluster_id"].isna()]
        per_cluster = grp.dropna(subset=["dense_cluster_id"]).groupby("dense_cluster_id")
        subdomain_count = int(len(noise_rows)
                              + per_cluster["cluster_true_member_count"].first().sum())
        total_queries   = int(noise_rows["query_count"].sum()
                              + per_cluster["cluster_true_query_total"].first().sum())
    else:
        subdomain_count = n_rows
        total_queries   = int(grp["query_count"].sum())

    all_ips: list[str] = []
    for ips in grp["querier_ips"]:
        if isinstance(ips, list):
            all_ips.extend(ips)
    unique_ips = list(dict.fromkeys(all_ips))

    sample_domains  = grp_sorted["query"].head(5).tolist()
    rcode_stats = (
        _nxdomain_stats(grp["rcode_distribution"])
        if "rcode_distribution" in grp.columns
        else None
    )
    first_ts, _ = _finite_ts_bounds(
        grp["first_ts"] if "first_ts" in grp.columns else None
    )
    _, last_ts = _finite_ts_bounds(
        grp["last_ts"] if "last_ts" in grp.columns else None
    )
    has_public_suffix = bool(grp["has_public_suffix"].all())
    severity, severity_basis = _severity_for(
        rcode_stats,
        dense_origin=dense_tunnel_supported and source == "zeek",
        has_public_suffix=has_public_suffix,
    )
    title    = reg_domain

    if has_dense and dense_tunnel_supported:
        # Deliberately surfaced dense cluster - the opposite of noise. {subdomain_count}
        # is the honest dominant-domain count, never the capped/sampled row count.
        namespace_kind = (
            "Registrable domain" if has_public_suffix else "Private namespace"
        )
        description = (
            f"{namespace_kind} {reg_domain} forms a dense, high-entropy cluster of "
            f"{subdomain_count} subdomains - the shape of DNS tunneling."
        )
        if _RESOLUTION_BASIS in severity_basis:
            description += _behavior_sentence(rcode_stats, severity_basis)
    elif has_dense:
        namespace_kind = (
            "Registrable domain" if has_public_suffix else "Private namespace"
        )
        description = (
            f"{namespace_kind} {reg_domain} has a repeated high-scoring name in "
            "a dense cluster that may reflect automated retry or rendezvous traffic."
            f"{_behavior_sentence(rcode_stats, severity_basis)}"
        )
    else:
        namespace_kind = (
            "Registrable domain" if has_public_suffix else "Private namespace"
        )
        description = (
            f"{namespace_kind} {reg_domain} has {subdomain_count} subdomains in the DNS noise cluster "
            f"with elevated label scores."
            f"{_behavior_sentence(rcode_stats, severity_basis)}"
        )
    if has_public_suffix:
        next_steps = [
            f"Check domain registration: whois {shlex.quote(str(reg_domain))}",
            f"Look up {reg_domain} on VirusTotal and Shodan",
            "Check conn.log for connections to IPs resolved from these queries",
            f"Pivot on querier IPs: {', '.join(unique_ips[:5])}",
        ]
    else:
        next_steps = [
            f"Check the local DNS zone or resolver that serves {reg_domain}",
            "Confirm these names are expected on the internal network",
            "Check conn.log for connections to IPs resolved from these queries",
            f"Pivot on querier IPs: {', '.join(unique_ips[:5])}",
        ]

    if source == "pihole":
        combined_qtypes: dict[str, int] = {}
        for qtype_dict in grp["qtype_counts"]:
            if isinstance(qtype_dict, dict):
                for k, v in qtype_dict.items():
                    combined_qtypes[k] = combined_qtypes.get(k, 0) + v
        evidence: dict[str, Any] = {
            "source":            "pihole",
            "registrable_domain": reg_domain,
            "subdomain_count":   subdomain_count,
            "max_label_score":   round(max_ent, 4),
            "min_label_score":   round(min_ent, 4),
            "total_queries":     total_queries,
            "unique_sources":    len(unique_ips),
            "sample_domains":    sample_domains,
            "querier_ips":       unique_ips,
            "was_blocked":       bool(grp["was_blocked"].any()),
            "block_ratio":       float(grp["block_ratio"].max()),
            "cache_ratio":       float(grp["cache_ratio"].mean()),
            "forward_ratio":     float(grp["forward_ratio"].mean()),
            "special_count":     int(grp["special_count"].sum()),
            "qtype_counts":      combined_qtypes,
            "severity_basis":    severity_basis,
        }
        if has_dense:
            evidence["origin"] = "dense_cluster"
    else:
        # Zeek findings carry resolution-outcome evidence when measurable; a
        # scan-surfaced dense finding additionally carries ``origin``.
        evidence = {
            "source":            "zeek",
            "registrable_domain": reg_domain,
            "subdomain_count":   subdomain_count,
            "max_label_score":   round(max_ent, 4),
            "min_label_score":   round(min_ent, 4),
            "total_queries":     total_queries,
            "unique_sources":    len(unique_ips),
            "sample_domains":    sample_domains,
            "querier_ips":       unique_ips,
            "severity_basis":    severity_basis,
        }
        if rcode_stats is not None:
            evidence["nxdomain_fraction"] = round(rcode_stats[0], 4)
            evidence["nxdomain_count"] = rcode_stats[1]
        # Both-mode enrichment fields (absent in zeek-only runs).
        if "was_blocked" in grp.columns:
            evidence["was_blocked"] = bool(grp["was_blocked"].any())
        if "block_ratio" in grp.columns:
            evidence["block_ratio"] = float(grp["block_ratio"].max())
        if has_dense:
            evidence["origin"] = "dense_cluster"

    evidence.update(_event_time_evidence(first_ts, last_ts))

    return Finding(
        detector=DETECTOR_NAME,
        severity=severity,
        title=title,
        description=description,
        evidence=evidence,
        next_steps=next_steps,
        ts_generated=now,
        data_window=data_window,
    )


def _make_singleton_finding(
    row: pd.Series,
    reg_domain: str,
    now: datetime,
    data_window: tuple[datetime, datetime],
) -> Finding:
    source = str(row["source"])
    domain = str(row["query"])
    ent    = float(row["label_entropy"])

    # A dense cluster of one repeated high-entropy query collapses to a single
    # distinct candidate and routes here. The defensive dense-origin branch keeps
    # the prose honest independent of the group/singleton routing invariant.
    dense_origin = "dense_cluster_id" in row.index and pd.notna(row.get("dense_cluster_id"))
    dense_tunnel_supported = (
        dense_origin
        and _meets_dense_child_floor(row.get("cluster_true_member_count"))
    )
    rcode_stats = (
        _nxdomain_stats(row["rcode_distribution"])
        if "rcode_distribution" in row.index
        else None
    )
    severity, severity_basis = _severity_for(
        rcode_stats,
        dense_origin=dense_tunnel_supported and source == "zeek",
        has_public_suffix=bool(row["has_public_suffix"]),
    )

    if dense_origin and dense_tunnel_supported:
        description = (
            f"Domain {domain} sits in a dense, high-entropy cluster (label score {ent:.4f}) "
            f"- the shape of DNS tunneling."
        )
        if _RESOLUTION_BASIS in severity_basis:
            description += _behavior_sentence(rcode_stats, severity_basis)
    elif dense_origin:
        description = (
            f"Domain {domain} repeats in a dense cluster with label score {ent:.4f}, "
            "a pattern that may reflect automated retry or rendezvous traffic."
            f"{_behavior_sentence(rcode_stats, severity_basis)}"
        )
    else:
        description = (
            f"Domain {domain} appears in the DNS noise cluster with label score {ent:.4f}."
            f"{_behavior_sentence(rcode_stats, severity_basis)}"
        )
    next_steps = [
        f"Check domain registration: whois {shlex.quote(str(reg_domain))}",
        f"Look up {domain} on VirusTotal and Shodan",
        "Check conn.log for connections to IPs resolved from this query",
        "Check ASN for resolved IPs",
    ]

    if source == "pihole":
        evidence: dict[str, Any] = {
            "source":        "pihole",
            "label_score":   round(ent, 4),
            "query_count":   int(row["query_count"]),
            "unique_sources": int(row["unique_sources"]),
            "querier_ips":   list(row["querier_ips"]),
            "was_blocked":   bool(row["was_blocked"]),
            "block_ratio":   float(row["block_ratio"]),
            "cache_ratio":   float(row["cache_ratio"]),
            "forward_ratio": float(row["forward_ratio"]),
            "qtype_counts":  dict(row["qtype_counts"]),
            "special_count": int(row.get("special_count", 0)),
            "severity_basis": severity_basis,
        }
        if dense_origin:
            evidence["origin"] = "dense_cluster"
    else:
        # Zeek findings carry resolution-outcome evidence when measurable; a
        # scan-surfaced dense finding additionally carries ``origin``.
        evidence = {
            "source":             "zeek",
            "label_score":        round(ent, 4),
            "query_count":        int(row["query_count"]),
            "unique_sources":     int(row["unique_sources"]),
            "querier_ips":        row["querier_ips"],
            "rcode_distribution": row["rcode_distribution"],
            "severity_basis":     severity_basis,
        }
        if rcode_stats is not None:
            evidence["nxdomain_fraction"] = round(rcode_stats[0], 4)
            evidence["nxdomain_count"] = rcode_stats[1]
        # Both-mode enrichment fields (absent in zeek-only runs).
        if "was_blocked" in row.index:
            evidence["was_blocked"] = bool(row["was_blocked"])
        if "block_ratio" in row.index:
            evidence["block_ratio"] = float(row["block_ratio"])
        if dense_origin:
            evidence["origin"] = "dense_cluster"

    evidence.update(_event_time_evidence(
        row.get("first_ts"),
        row.get("last_ts"),
    ))

    return Finding(
        detector=DETECTOR_NAME,
        severity=severity,
        title=domain,
        description=description,
        evidence=evidence,
        next_steps=next_steps,
        ts_generated=now,
        data_window=data_window,
    )


def _make_scan_summary_finding(
    candidate_df: pd.DataFrame,
    threshold: float,
    now: datetime,
    data_window: tuple[datetime, datetime],
) -> Finding | None:
    """One synthetic INFO Finding disclosing the dense-cluster scan aggregate.

    Counts ONCE PER CLUSTER from dense_cluster_id (never a sampled-row sum): the
    id is what lets the summary count clusters honestly. It counts only clusters
    that SURVIVE the same ``label_entropy >= threshold`` gate the dense findings
    pass, so the disclosure can never claim a cluster the report does not show -
    the gate can drop every surfaced dense row when ``threshold`` is set above
    ``thresh_high_entropy``. Returns None when candidate_df carries no
    dense_cluster_id column or no surviving dense rows (noise-only and gated-out
    paths), so those runs stay silent.
    """
    if "dense_cluster_id" not in candidate_df.columns:
        return None
    dense = candidate_df[candidate_df["label_entropy"] >= threshold].dropna(
        subset=["dense_cluster_id"]
    )
    if dense.empty:
        return None

    per_cluster = dense.groupby("dense_cluster_id")
    cluster_count = int(per_cluster.ngroups)
    member_counts = per_cluster["cluster_true_member_count"].first()
    total_members = int(member_counts.sum())
    reg_domains   = per_cluster["registrable_domain"].first().tolist()[:5]
    tunnel_supported = any(
        _meets_dense_child_floor(value) for value in member_counts
    )
    if tunnel_supported:
        description = (
            "The dense-cluster scan surfaced high-entropy clusters concentrated under a "
            "single registrable domain - the shape of DNS tunneling. A benign high-entropy "
            "service can produce the same shape and should be allowlisted."
        )
        next_steps = [
            "Review dense-cluster findings before treating as tunneling",
            "Allowlist known high-entropy services",
        ]
    else:
        description = (
            "The dense-cluster scan surfaced a repeated high-scoring DNS name "
            "concentrated under one registrable domain. This pattern may reflect "
            "automated retry or rendezvous traffic."
        )
        next_steps = [
            "Review the repeated name and its query source",
            "Allowlist known automated services",
        ]

    return Finding(
        detector=DETECTOR_NAME,
        severity=Severity.INFO,
        title="dense-cluster scan: high-entropy clusters surfaced",
        description=description,
        evidence={
            "tier":                "scan_summary",
            "cluster_count":       cluster_count,
            "total_members":       total_members,
            "registrable_domains": reg_domains,
        },
        next_steps=next_steps,
        ts_generated=now,
        data_window=data_window,
    )


def _make_pihole_unscanned_finding(
    cluster_count: int,
    total_members: int,
    now: datetime,
    data_window: tuple[datetime, datetime],
) -> Finding:
    """Counts-only disclosure for standalone Pi-hole dense clusters not scanned."""
    if cluster_count == 1:
        title = (
            f"{total_members} domains formed a dense cluster; Pi-hole dense-cluster "
            "scanning was disabled for this run - this cluster was not analyzed."
        )
    else:
        title = (
            f"{total_members} domains formed {cluster_count} dense clusters; Pi-hole "
            "dense-cluster scanning was disabled for this run - these clusters were "
            "not analyzed."
        )
    return Finding(
        detector=DETECTOR_NAME,
        severity=Severity.INFO,
        title=title,
        description=(
            "This is a coverage disclosure, not a detection. Pi-hole supplied the "
            "aggregate counts, but this run had dense-cluster scanning disabled and "
            "did not inspect the cluster members."
        ),
        evidence={
            "tier": "unscanned_clusters",
            "cluster_count": cluster_count,
            "total_members": total_members,
        },
        next_steps=[
            "Enable scan_dense_clusters to analyze Pi-hole dense clusters",
            "Re-run the detector after changing the DNS scan setting",
        ],
        ts_generated=now,
        data_window=data_window,
    )
