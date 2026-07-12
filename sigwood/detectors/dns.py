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

from dataclasses import dataclass
import math
from datetime import datetime, timezone
from typing import Any

import numpy as np
import pandas as pd
from sigwood.common.clustering import ACTIVE_BACKEND, fit_predict_interruptible
from sklearn.preprocessing import StandardScaler

from sigwood.common.finding import DetectorContext, Finding, MethodTag, Severity
from sigwood.common.tld import TLD_EXTRACT as _TLD_EXTRACT

DETECTOR_NAME = "dns"
STATUS = "available"

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
    "threshold": 1.5,
    # thresh_high_entropy / scan_min_high_entropy_fraction gate the per-label
    # suspicion score (dns.entropy() - a weighted lexical heuristic, NOT Shannon
    # entropy), not an information-theoretic measure.
    "thresh_high_entropy": 1.8,
    # Dense-cluster scan (Zeek path only). A sustained high-volume tunnel
    # self-clusters past min_cluster_size and escapes the noise-only label-score
    # gate; this scan surfaces the dominant-registrable-domain members of
    # clusters that are overwhelmingly high-entropy AND concentrated under one
    # eTLD+1 (the tunnel shape). Conservative by construction so a benign
    # high-entropy cluster does not flood. scan_dense_clusters=False is
    # byte-identical to the noise-only path.
    "scan_dense_clusters": True,
    "scan_min_high_entropy_fraction": 0.8,   # frac of members >= thresh_high_entropy
    "scan_min_cluster_members": 100,         # cluster-size floor (rows)
    "scan_min_regdomain_share": 0.8,         # concentration under one registrable domain
    "scan_max_members_per_cluster": 500,     # per-cluster surfaced-sample cap (perf)
    "pihole": {
        "min_cluster_size": 25,   # ~2K aggregated domain rows, not per-query
        "min_samples": 10,
    },
}

# Resolved at clustering import - accurate by read time. "fast-HDBSCAN" when
# the accelerator extra is installed, "HDBSCAN" otherwise. Both glow named -
# either way it's a published algorithm.
DETECTOR_METHOD = MethodTag(
    "fast-HDBSCAN" if ACTIVE_BACKEND == "fast_hdbscan" else "HDBSCAN",
    named=True,
)

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

    counts = {c: s.count(c) for c in set(s)}
    probs = [v / n for v in counts.values()]
    shannon = -sum(p * math.log2(p) for p in probs)

    digits = sum(c.isdigit() for c in s) / n
    vowels = sum(c in 'aeiou' for c in s) / n
    unique_ratio = len(set(s)) / n

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
    shapes = queries.apply(_query_shape)
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
    top_suffixes = suffixes.value_counts().nlargest(20).index
    suffix_col = suffixes.where(suffixes.isin(top_suffixes), "other")
    feat["TLD"] = suffix_col.values
    return pd.get_dummies(feat, columns=["TLD"], drop_first=True)


def summit(val: Any) -> float:
    """Sum TTL list or pass through scalar."""
    if isinstance(val, (int, float)):
        return float(val)
    return np.array(val, dtype=np.float32).sum()


def _max_subdomain_entropy(query: str, ext: Any) -> float:
    """Max entropy across the subdomain labels left of the registrable domain.

    For api-409632fc.example.com the registrable domain is example.com, so only
    ["api-409632fc"] is scored. For foo.bar.baz.example.com the labels ["foo",
    "bar", "baz"] are scored and the max is returned. When the query equals the
    registrable domain (no subdomain prefix), the domain label itself is scored
    as a fallback.
    """
    reg = ext.top_domain_under_public_suffix
    if reg:
        if query.endswith("." + reg):
            prefix = query[: -(len(reg) + 1)]
            labels = [lbl for lbl in prefix.split(".") if lbl]
        else:
            # query IS the registrable domain - score its domain label
            labels = [ext.domain] if ext.domain else []
    else:
        labels = [query.split(".")[0]]
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
        rtt_median = df["rtt"].median()
        rtt_fill = 0.0 if pd.isna(rtt_median) else float(rtt_median)
        feat["rtt"] = np.log1p(df["rtt"].fillna(rtt_fill))

    if "ttl" in df.columns:
        feat["ttl"] = np.log1p(df["ttl"].fillna(0).apply(summit))

    if "rcode" in df.columns:
        feat["rcode"] = df["rcode"].fillna(-1)

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

    query_counts    = query_events.groupby("query").size()
    client_nunique  = query_events.groupby("query")["src"].nunique()
    querier_ips_s   = query_events.groupby("query")["src"].apply(
        lambda x: sorted(x.dropna().unique().tolist())
    )
    unique_qtypes_s = query_events.groupby("query")["qtype"].nunique()
    qtype_counts_s  = query_events.groupby("query")["qtype"].apply(
        lambda x: x.value_counts().to_dict()
    )

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
) -> tuple[pd.DataFrame, set[str]]:
    """Scan non-noise clusters for the DNS-tunnel shape and surface their members.

    A sustained high-volume tunnel forms its own dense cluster (a real label),
    so the noise-only candidate set never sees it. For each non-noise cluster,
    over its member rows, gate on three signals:
      - the fraction of members whose _max_subdomain_entropy clears thresh_high,
      - the cluster size (rows),
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
        whole-cluster totals).
      - dominant_queries: every surfaced cluster's FULL (uncapped) dominant query
        set, which the caller removes from the noise set so a counted member is
        never also tallied as an independent noise row.

    Empty frame + empty set when disabled or nothing passes the gate. Cost is
    bounded: one _TLD_EXTRACT per DISTINCT member query, broadcast to rows.
    """
    empty_cols = [
        "query", "dense_cluster_id",
        "cluster_true_member_count", "cluster_true_query_total",
    ]
    if not scan_cfg["scan_dense_clusters"]:
        return pd.DataFrame(columns=empty_cols), set()

    frac_floor   = scan_cfg["scan_min_high_entropy_fraction"]
    member_floor = scan_cfg["scan_min_cluster_members"]
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
        member_q = dns_df.loc[labels == lbl, "query"]
        if len(member_q) < member_floor:
            continue  # size floor - cheap reject before any extract

        # One _TLD_EXTRACT per DISTINCT member query; broadcast to rows.
        ent_by_q: dict[str, float] = {}
        reg_by_q: dict[str, str] = {}
        for q in member_q.unique():
            ext = _TLD_EXTRACT(q)
            ent_by_q[q] = _max_subdomain_entropy(q, ext)
            reg_by_q[q] = ext.top_domain_under_public_suffix or q

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
        # Only dominant queries not already claimed by an earlier cluster.
        dominant_distinct = [q for q in dict.fromkeys(dom_q.tolist()) if q not in claimed]
        if not dominant_distinct:
            continue  # every dominant query already attributed elsewhere
        claimed.update(dominant_distinct)
        dominant_queries.update(dominant_distinct)

        owned = set(dominant_distinct)
        true_member_count = len(dominant_distinct)
        true_query_total  = int(dom_q.isin(owned).sum())  # query events for THIS cluster's owned subdomains

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

    dns_df = dns_df.copy().reset_index(drop=True)

    # Drop degenerate queries that break feature engineering.
    has_dot    = dns_df["query"].str.count(r"\.") > 0
    has_domain = dns_df["query"].apply(lambda q: _TLD_EXTRACT(q).domain != "")
    dns_df = dns_df[has_dot & has_domain].reset_index(drop=True)
    if dns_df.empty:
        return None

    feat_df = _build_features(dns_df)

    X = np.ascontiguousarray(feat_df.to_numpy(dtype=np.float64))
    labels = fit_predict_interruptible(
        X, min_cluster_size=min_cluster_size, min_samples=min_samples,
    )

    noise_mask    = labels == -1
    noise_queries = np.unique(dns_df.loc[noise_mask, "query"].values)

    # Scan non-noise clusters for the tunnel shape - a self-clustering
    # high-volume tunnel never reaches the noise set. Surfaced dense members
    # union with the noise candidates below.
    dense_records, dense_dominant = _surface_dense_clusters(
        dns_df, labels, thresh_high=thresh_high, scan_cfg=scan_cfg,
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
        result: dict[str, Any] = {
            "query_count":      len(sub),
            "unique_sources":   len(srcs),
            "querier_ips":      srcs,
            "rcode_distribution": rcode_dist,
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
    if has_block_enrichment:
        candidate_df["was_blocked"] = enriched.apply(lambda e: e["was_blocked"])
        candidate_df["block_ratio"] = enriched.apply(lambda e: e["block_ratio"])

    candidate_df["registrable_domain"] = candidate_df.apply(
        lambda row: row["_ext"].top_domain_under_public_suffix or row["query"], axis=1
    )
    candidate_df.drop(columns=["_ext"], inplace=True)
    candidate_df["source"] = "zeek"

    return candidate_df


def _run_pihole_path(
    pihole_df: pd.DataFrame,
    pihole_cfg: dict,
) -> pd.DataFrame | None:
    """Run the per-domain aggregate pihole clustering path.

    Returns a candidate_df at the shared-seam contract, source='pihole', with no
    label-score threshold applied. Returns None when the aggregate is empty or smaller
    than min_cluster_size (HDBSCAN is undefined on tiny datasets).
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

    noise_mask   = labels == -1
    candidate_df = agg_df[noise_mask].copy().reset_index(drop=True)
    if candidate_df.empty:
        return None

    candidate_df["_ext"] = candidate_df["query"].apply(_TLD_EXTRACT)
    candidate_df["label_entropy"] = candidate_df.apply(
        lambda row: _max_subdomain_entropy(row["query"], row["_ext"]), axis=1
    )
    candidate_df["registrable_domain"] = candidate_df.apply(
        lambda row: row["_ext"].top_domain_under_public_suffix or row["query"], axis=1
    )
    candidate_df.drop(columns=["_ext"], inplace=True)
    candidate_df["source"] = "pihole"

    return candidate_df


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


# ---------------------------------------------------------------------------
# Shared back half
# ---------------------------------------------------------------------------

def _shared_back_half(
    candidate_df: pd.DataFrame,
    threshold: float,
    thresh_high: float,
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

    candidate_df = candidate_df.sort_values(
        "label_entropy", ascending=False
    ).reset_index(drop=True)

    group_findings: list[Finding]     = []
    singleton_findings: list[Finding] = []

    for reg_domain, grp in candidate_df.groupby("registrable_domain"):
        if len(grp) >= 2:
            group_findings.append(
                _make_group_finding(str(reg_domain), grp, thresh_high, now, data_window)
            )
        else:
            singleton_findings.append(
                _make_singleton_finding(grp.iloc[0], str(reg_domain), thresh_high, now, data_window)
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

    if has_zeek and has_pihole:
        # Enrich Zeek frame with pihole block data BEFORE clustering (evidence-only;
        # was_blocked/block_ratio never enter the Zeek feature matrix).
        dns_df = _enrich_zeek_with_pihole(zeek_df.copy(), pihole_df)
        candidate_df = _run_zeek_path(
            dns_df, min_cluster_size, min_samples, thresh_high=thresh_high, scan_cfg=scan_cfg,
        )
    elif has_zeek:
        candidate_df = _run_zeek_path(
            zeek_df, min_cluster_size, min_samples, thresh_high=thresh_high, scan_cfg=scan_cfg,
        )
    else:
        candidate_df = _run_pihole_path(pihole_df, pihole_cfg)

    if candidate_df is None or candidate_df.empty:
        return []

    findings = _shared_back_half(candidate_df, threshold, thresh_high, now, context.data_window)

    # Synthetic INFO disclosure when the dense-cluster scan produced findings -
    # gated on the SAME threshold, so it never discloses more than the report shows.
    summary = _make_scan_summary_finding(candidate_df, threshold, now, context.data_window)
    if summary is not None:
        findings.append(summary)

    return findings


# ---------------------------------------------------------------------------
# Finding constructors
# ---------------------------------------------------------------------------

def _make_group_finding(
    reg_domain: str,
    grp: pd.DataFrame,
    thresh_high: float,
    now: datetime,
    data_window: tuple[datetime, datetime],
) -> Finding:
    source = str(grp.iloc[0]["source"])
    # label_entropy (the per-label suspicion score column) feeds the evidence
    # keys max_label_score / min_label_score / label_score.
    grp_sorted = grp.sort_values("label_entropy", ascending=False)
    max_ent = float(grp_sorted["label_entropy"].max())
    min_ent = float(grp_sorted["label_entropy"].min())
    n_rows = len(grp)  # candidate rows surfaced in this group (sample + noise)

    # Honest counts. A dense-cluster group can mix noise rows with sampled rows
    # from one or more dense clusters; count noise rows individually but each
    # dense cluster ONCE via its true (dominant-domain) totals - never per
    # sampled row (overcounts under the per-cluster cap) nor per registrable
    # domain alone (undercounts two dense clusters under one parent).
    # cluster_true_* are DOMINANT-domain counts; never whole-cluster totals.
    has_dense = "dense_cluster_id" in grp.columns and grp["dense_cluster_id"].notna().any()
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
    sample_entropy  = grp_sorted["label_entropy"].head(5).tolist()
    severity = Severity.HIGH if max_ent >= thresh_high else Severity.MEDIUM
    title    = reg_domain

    if has_dense:
        # Deliberately surfaced dense cluster - the opposite of noise. {subdomain_count}
        # is the honest dominant-domain count, never the capped/sampled row count.
        description = (
            f"Registrable domain {reg_domain} forms a dense, high-entropy cluster of "
            f"{subdomain_count} subdomains - the shape of DNS tunneling."
        )
    else:
        sample_desc = ", ".join(f"{d} ({e:.2f})" for d, e in zip(sample_domains, sample_entropy))
        extra_note  = f" (+{n_rows - 5} more)" if n_rows > 5 else ""
        description = (
            f"Registrable domain {reg_domain} has {subdomain_count} subdomains in the DNS noise cluster "
            f"with elevated label scores. Top subdomains: {sample_desc}{extra_note}."
        )
    next_steps = [
        f"Check domain registration: whois {reg_domain}",
        f"Look up {reg_domain} on VirusTotal and Shodan",
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
        }
    else:
        # zeek source - noise-path evidence carries only `source` as its additive
        # key; a scan-surfaced (dense-cluster) finding additionally carries `origin`.
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
        }
        # Both-mode enrichment fields (absent in zeek-only runs).
        if "was_blocked" in grp.columns:
            evidence["was_blocked"] = bool(grp["was_blocked"].any())
        if "block_ratio" in grp.columns:
            evidence["block_ratio"] = float(grp["block_ratio"].max())
        if has_dense:
            evidence["origin"] = "dense_cluster"

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
    thresh_high: float,
    now: datetime,
    data_window: tuple[datetime, datetime],
) -> Finding:
    source = str(row["source"])
    domain = str(row["query"])
    ent    = float(row["label_entropy"])
    severity = Severity.HIGH if ent >= thresh_high else Severity.MEDIUM

    # A dense cluster of one repeated high-entropy query collapses to a single
    # distinct candidate and routes here. The defensive dense-origin branch keeps
    # the prose honest independent of the group/singleton routing invariant.
    dense_origin = "dense_cluster_id" in row.index and pd.notna(row.get("dense_cluster_id"))

    if dense_origin:
        description = (
            f"Domain {domain} sits in a dense, high-entropy cluster (label score {ent:.4f}) "
            f"- the shape of DNS tunneling."
        )
    else:
        description = (
            f"Domain {domain} appears in the DNS noise cluster with label score {ent:.4f}. "
            f"Not clustered with any known-pattern group - warrants analyst review."
        )
    next_steps = [
        f"Check domain registration: whois {reg_domain}",
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
        }
    else:
        # zeek source - noise-path evidence carries only `source` as its additive
        # key; a scan-surfaced (dense-cluster) finding additionally carries `origin`.
        evidence = {
            "source":             "zeek",
            "label_score":        round(ent, 4),
            "query_count":        int(row["query_count"]),
            "unique_sources":     int(row["unique_sources"]),
            "querier_ips":        row["querier_ips"],
            "rcode_distribution": row["rcode_distribution"],
        }
        # Both-mode enrichment fields (absent in zeek-only runs).
        if "was_blocked" in row.index:
            evidence["was_blocked"] = bool(row["was_blocked"])
        if "block_ratio" in row.index:
            evidence["block_ratio"] = float(row["block_ratio"])
        if dense_origin:
            evidence["origin"] = "dense_cluster"

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
    dense_cluster_id column or no surviving dense rows (the pihole and
    zeek-only-noise paths, and the gated-out case), so those runs stay silent.
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
    total_members = int(per_cluster["cluster_true_member_count"].first().sum())
    reg_domains   = per_cluster["registrable_domain"].first().tolist()[:5]

    return Finding(
        detector=DETECTOR_NAME,
        severity=Severity.INFO,
        title="dense-cluster scan: high-entropy clusters surfaced",
        description=(
            "The dense-cluster scan surfaced high-entropy clusters concentrated under a "
            "single registrable domain - the shape of DNS tunneling. A benign high-entropy "
            "service can produce the same shape and should be allowlisted."
        ),
        evidence={
            "tier":                "scan_summary",
            "cluster_count":       cluster_count,
            "total_members":       total_members,
            "registrable_domains": reg_domains,
        },
        next_steps=[
            "Review dense-cluster findings before treating as tunneling",
            "Allowlist known high-entropy services",
        ],
        ts_generated=now,
        data_window=data_window,
    )
