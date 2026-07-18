"""Scan detector - port scan detection from Zeek conn.log.

Detects vertical (one→many ports), horizontal (one→many hosts), block
(many ports AND many hosts), and slow (temporally spread) port scanning.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime, timezone

import numpy as np
import pandas as pd

from sigwood.common.finding import DetectorContext, Finding, MethodTag, Severity

DETECTOR_NAME = "scan"
STATUS = "available"

REQUIRED_LOGS = [
    {"source": "zeek_dir", "pattern": "conn*.log*"},
]

OPTIONAL_LOGS: list[dict] = []

DEFAULT_CONFIG = {
    "vertical_threshold": 15,
    "horizontal_threshold": 15,
    "block_port_threshold": 20,
    "block_host_threshold": 20,
    "block_state_min": 0.30,
    "slow_state_min": 0.30,
    "window_secs": 3600,
    "slow_min_ports": 8,
    "slow_min_buckets": 4,
}

DETECTOR_METHOD = MethodTag("pattern", named=False)

# ── Domain-knowledge constants ────────────────────────────────────────────────

SCAN_STATES = {'S0', 'REJ', 'RSTO', 'RSTR', 'SH', 'OTH'}

BITTORRENT_PORTS_PEER    = {6881, 6882, 6883, 6884, 6885, 6886, 6887, 6888, 6889,
                             51413, 51414}
BITTORRENT_PORTS_TRACKER = {6969, 2710}

# IoT/smart device discovery ports - multicast/broadcast, structurally produce
# high S0/OTH rates that are not scanning
IOT_DISCOVERY_PORTS = {
    5353,   # mDNS
    1900,   # SSDP/UPnP
    5355,   # LLMNR
    137,    # NetBIOS Name Service
    138,    # NetBIOS Datagram
}

# IoT multicast/broadcast destination ranges - connections to these are never scans
IOT_MULTICAST_PREFIXES = ('224.', '239.', '255.255.255.255', 'ff0', 'ff1', 'ff2')

DARK_PORTS = {0, 1, 2, 3, 4, 6, 8}

SCAN_TYPE_DESCRIPTIONS = {
    'vertical'  : 'Port scan (one host, many ports)',
    'horizontal': 'Network sweep (many hosts, one port)',
    'block'     : 'Block scan (many hosts AND many ports)',
}

STATE_EXPLANATIONS = {
    'S0'  : 'SYN sent, no response (filtered/firewalled)',
    'REJ' : 'Port closed (RST received)',
    'RSTO': 'Connection reset by originator',
    'RSTR': 'Connection reset by responder',
    'SF'  : 'Normal established+closed connection',
    'SH'  : 'Half-open scan (SYN+FIN)',
    'OTH' : 'No SYN observed',
}


# ── Zone-label seam ───────────────────────────────────────────────────────────
#
# Standalone-callable fallback: when run() is invoked with a DetectorContext
# whose home_net is empty (e.g. from a notebook), this RFC1918 list is used.
# The runner is the normal supply path - it resolves [sigwood].home_net and
# passes it on every DetectorContext.
_DEFAULT_HOME_NET = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]


def _zone_of(ip: str, home_net: list[str]) -> str:
    """Return the zone label for an IP given the operator's home_net.

    Today returns "internal" or "external". The function body is the seam:
    adding a third zone (e.g. "dmz") is a single new if-check inside this
    function - signature and callers do not change. Zones are descriptive
    labels only; there is no trust-rank or numeric ordering at this stage.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "external"
    if any(addr in ipaddress.ip_network(n, strict=False) for n in home_net):
        return "internal"
    return "external"


def _classify_direction(src: str, dst: str, home_net: list[str]) -> tuple[str, str, str]:
    """Compute (src_zone, dst_zone, rendered) for a flow.

    The rendered direction string falls out of the zone pair via mechanical
    f-string interpolation - not a hardcoded 2×2 branch. For the two-zone case
    the four strings ("internal→internal", "internal→external",
    "external→internal", "external→external") are produced byte-identically;
    introducing additional zones would yield the new combinations without
    touching this function.
    """
    src_zone = _zone_of(src, home_net)
    dst_zone = _zone_of(dst, home_net)
    return src_zone, dst_zone, f"{src_zone}→{dst_zone}"


def _prefilter(df: pd.DataFrame, home_net: list[str]) -> pd.DataFrame:
    """Drop ICMP, IPv6 link-local, and IoT multicast rows; add direction columns.

    Normalizes expected columns to safe types first so downstream detection code
    does not crash on malformed-but-loadable conn logs. Rows with missing or
    unparseable values simply never meet scan thresholds and produce no findings.

    Adds three columns: ``direction`` (rendered string for evidence display),
    ``src_zone`` and ``dst_zone`` (raw zone labels, used by structural checks
    that would otherwise have to string-parse the rendered direction).
    """
    df = df.copy()

    # Ensure required string columns exist and contain no None/NaN values.
    for col in ("src", "dst", "proto", "conn_state"):
        if col not in df.columns:
            df[col] = ""
        else:
            df[col] = df[col].fillna("").astype(str)

    # Port and timestamp must be numeric for every scan mode. Malformed rows are
    # dropped here instead of letting lower-level pandas operations raise KeyError.
    for col in ("port", "ts"):
        if col not in df.columns:
            df[col] = np.nan
        else:
            df[col] = pd.to_numeric(df[col], errors="coerce")

    df = df[df["port"].notna() & df["ts"].notna()]
    if df.empty:
        return df

    df = df[df['proto'] != 'icmp']
    if df.empty:
        return df
    df = df[~(df['src'].str.startswith('fe80:') | df['dst'].str.startswith('fe80:'))]
    if df.empty:
        return df
    df = df[~df['dst'].map(lambda ip: any(ip.startswith(p) for p in IOT_MULTICAST_PREFIXES))]
    if df.empty:
        return df
    df = df.copy()  # break view chain before column assignment
    triples = [_classify_direction(s, d, home_net) for s, d in zip(df['src'], df['dst'])]
    df['src_zone']  = [t[0] for t in triples]
    df['dst_zone']  = [t[1] for t in triples]
    df['direction'] = [t[2] for t in triples]
    return df


def _detect_vertical(df: pd.DataFrame, cfg: dict) -> list[dict]:
    """Vertical scan: one src → many distinct ports on one dst."""
    threshold   = cfg['vertical_threshold']
    window_secs = cfg['window_secs']

    global_counts = (
        df.groupby(['src', 'dst'])['port']
        .nunique()
        .reset_index(name='global_distinct_ports')
    )
    candidates = global_counts[global_counts['global_distinct_ports'] >= threshold]

    if len(candidates) == 0:
        return []

    cand_keys = candidates[['src', 'dst']]
    df_cands  = df.merge(cand_keys, on=['src', 'dst'])

    results = []
    for (src, dst), grp in df_cands.groupby(['src', 'dst']):
        grp       = grp.sort_values('ts')
        ts_arr    = grp['ts'].values          # already float epoch seconds
        port_arr  = grp['port'].values
        state_arr = grp['conn_state'].values

        port_counts         = {}
        max_ports_in_window = 0
        best_left           = 0
        best_right          = 0
        left                = 0

        for right in range(len(ts_arr)):
            p = port_arr[right]
            if p is not None and not (isinstance(p, float) and np.isnan(p)):
                port_counts[p] = port_counts.get(p, 0) + 1
            while ts_arr[right] - ts_arr[left] > window_secs:
                lp = port_arr[left]
                if lp is not None and not (isinstance(lp, float) and np.isnan(lp)):
                    port_counts[lp] -= 1
                    if port_counts[lp] == 0:
                        del port_counts[lp]
                left += 1
            n = len(port_counts)
            if n > max_ports_in_window:
                max_ports_in_window = n
                # The winning window includes both endpoints: right was just
                # added, and left was advanced until the span fit.
                best_left  = left
                best_right = right

        if max_ports_in_window < threshold:
            continue

        window_states    = state_arr[best_left:best_right + 1]
        window_ports     = port_arr[best_left:best_right + 1]
        state_counts     = pd.Series(window_states).value_counts()
        total_conns      = len(window_states)
        scan_state_count = sum(state_counts.get(s, 0) for s in SCAN_STATES)
        scan_state_ratio = scan_state_count / total_conns

        port_series  = pd.Series(window_ports).dropna()
        port_buckets = pd.cut(port_series, bins=[0, 1023, 49151, 65535],
                              labels=['well-known', 'registered', 'ephemeral'])
        counts_arr   = (port_buckets.value_counts().values + 1).astype(float)
        probs        = counts_arr / counts_arr.sum()
        port_range_entropy = round(float(-np.sum(probs * np.log(probs))), 3)

        results.append({
            'scan_type'          : 'vertical',
            'src'                : src,
            'dst'                : dst,
            'port'               : None,
            'port_class'         : None,
            'distinct_ports'     : max_ports_in_window,
            'distinct_hosts'     : 1,
            'total_conns'        : total_conns,
            'scan_state_ratio'   : round(scan_state_ratio, 3),
            'top_states'         : ', '.join(state_counts.head(3).index.tolist()),
            'port_range_entropy' : port_range_entropy,
            'window_start'       : datetime.fromtimestamp(
                                       ts_arr[best_left], tz=timezone.utc
                                   ).strftime('%Y-%m-%d %H:%M:%S'),
            'window_secs'        : window_secs,
            'direction'          : grp['direction'].iloc[0],
        })

    return results


def _detect_horizontal(df: pd.DataFrame, cfg: dict) -> list[dict]:
    """Horizontal scan: one src → same port across many distinct hosts."""
    threshold   = cfg['horizontal_threshold']
    window_secs = cfg['window_secs']

    df_tcp_udp = df[df['port'].notna()].copy()

    global_counts = (
        df_tcp_udp.groupby(['src', 'port'])['dst']
        .nunique()
        .reset_index(name='global_distinct_hosts')
    )
    candidates = global_counts[global_counts['global_distinct_hosts'] >= threshold]

    if len(candidates) == 0:
        return []

    cand_keys = candidates[['src', 'port']]
    df_cands  = df_tcp_udp.merge(cand_keys, on=['src', 'port'])

    results = []
    for (src, port), grp in df_cands.groupby(['src', 'port']):
        grp       = grp.sort_values('ts')
        ts_arr    = grp['ts'].values          # already float epoch seconds
        host_arr  = grp['dst'].values
        state_arr = grp['conn_state'].values

        host_counts         = {}
        max_hosts_in_window = 0
        best_left           = 0
        best_right          = 0
        left                = 0

        for right in range(len(ts_arr)):
            h = host_arr[right]
            if h is not None:
                host_counts[h] = host_counts.get(h, 0) + 1
            while ts_arr[right] - ts_arr[left] > window_secs:
                lh = host_arr[left]
                if lh is not None:
                    host_counts[lh] -= 1
                    if host_counts[lh] == 0:
                        del host_counts[lh]
                left += 1
            n = len(host_counts)
            if n > max_hosts_in_window:
                max_hosts_in_window = n
                # The winning window includes both endpoints: right was just
                # added, and left was advanced until the span fit.
                best_left  = left
                best_right = right

        if max_hosts_in_window < threshold:
            continue

        window_ts        = ts_arr[best_left:best_right + 1]
        window_states    = state_arr[best_left:best_right + 1]
        state_counts     = pd.Series(window_states).value_counts()
        total_conns      = len(window_states)
        scan_state_ratio = sum(state_counts.get(s, 0) for s in SCAN_STATES) / total_conns
        velocity         = max_hosts_in_window / max(window_ts[-1] - window_ts[0], 1)

        port_int = int(port)
        if port_int <= 1023:
            port_class = 'well-known'
        elif port_int <= 49151:
            port_class = 'registered'
        else:
            port_class = 'ephemeral'

        results.append({
            'scan_type'              : 'horizontal',
            'src'                    : src,
            'dst'                    : None,
            'port'                   : port_int,
            'port_class'             : port_class,
            'distinct_ports'         : 1,
            'distinct_hosts'         : max_hosts_in_window,
            'total_conns'            : total_conns,
            'scan_state_ratio'       : round(scan_state_ratio, 3),
            'top_states'             : ', '.join(state_counts.head(3).index.tolist()),
            'velocity_hosts_per_sec' : round(velocity, 4),
            'window_start'           : datetime.fromtimestamp(
                                           ts_arr[best_left], tz=timezone.utc
                                       ).strftime('%Y-%m-%d %H:%M:%S'),
            'window_secs'            : window_secs,
            'direction'              : grp['direction'].iloc[0],
        })

    return results


def _detect_block(df: pd.DataFrame, cfg: dict) -> list[dict]:
    """Block scan: one src → many ports AND many hosts within a time window."""
    port_threshold       = cfg['block_port_threshold']
    host_threshold       = cfg['block_host_threshold']
    scan_state_ratio_min = cfg['block_state_min']
    window_secs          = cfg['window_secs']

    df_w = df[df['port'].notna()].copy()
    df_w['time_bucket']   = (df_w['ts'] // window_secs).astype(int)
    df_w['is_scan_state'] = df_w['conn_state'].isin(SCAN_STATES)

    global_agg = df_w.groupby('src').agg(
        global_distinct_ports=('port', 'nunique'),
        global_distinct_hosts=('dst',  'nunique'),
        scan_state_ratio=('is_scan_state', 'mean'),
    ).reset_index()

    candidates = global_agg[
        (global_agg['global_distinct_ports'] >= port_threshold) &
        (global_agg['global_distinct_hosts'] >= host_threshold) &
        (global_agg['scan_state_ratio']      >= scan_state_ratio_min)
    ]

    if len(candidates) == 0:
        return []

    df_cands   = df_w[df_w['src'].isin(candidates['src'])]
    bucket_agg = df_cands.groupby(['src', 'time_bucket']).agg(
        distinct_ports=('port', 'nunique'),
        distinct_hosts=('dst',  'nunique'),
        total_conns=('port', 'count'),
        scan_state_ratio=('is_scan_state', 'mean'),
        top_states=('conn_state',
                    lambda x: ', '.join(x.value_counts().head(3).index.tolist())),
        direction=('direction', 'first'),
        ports_well_known=('port', lambda x: (x <= 1023).sum()),
        ports_registered=('port', lambda x: ((x > 1023) & (x <= 49151)).sum()),
        ports_ephemeral=('port', lambda x: (x > 49151).sum()),
        window_start_ts=('ts', 'min'),
    ).reset_index()

    findings = bucket_agg[
        (bucket_agg['distinct_ports'] >= port_threshold) &
        (bucket_agg['distinct_hosts'] >= host_threshold) &
        (bucket_agg['scan_state_ratio'] >= scan_state_ratio_min)
    ].copy()

    if len(findings) == 0:
        return []

    findings['scan_type']    = 'block'
    findings['dst']          = None
    findings['port']         = None
    findings['port_class']   = None
    findings['window_secs']  = window_secs
    findings['window_start'] = findings['window_start_ts'].map(
        lambda ts: datetime.fromtimestamp(ts, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
    )
    findings['scan_state_ratio'] = findings['scan_state_ratio'].round(3)
    findings['breadth_score']    = findings['distinct_ports'] * findings['distinct_hosts']

    findings = (
        findings
        .sort_values('breadth_score', ascending=False)
        .drop_duplicates(subset=['src'], keep='first')
        .drop(columns=['time_bucket', 'window_start_ts', 'breadth_score'])
        .reset_index(drop=True)
    )

    return findings.to_dict('records')


def _detect_slow(df: pd.DataFrame, cfg: dict) -> list[dict]:
    """Slow scan: port diversity spread across many time buckets to evade per-window thresholds."""
    min_ports      = cfg['slow_min_ports']
    min_buckets    = cfg['slow_min_buckets']
    state_min      = cfg['slow_state_min']
    bucket_secs    = cfg['window_secs']
    vert_threshold = cfg['vertical_threshold']

    df_w = df[df['port'].notna()].copy()
    df_w['time_bucket'] = (df_w['ts'] // bucket_secs).astype(int)

    def is_iot_discovery(grp: pd.DataFrame) -> bool:
        port_counts = grp['port'].value_counts()
        top_ports   = set(port_counts.head(3).index.tolist())
        if top_ports.issubset(IOT_DISCOVERY_PORTS | {53, 443, 80}):
            # Benign local discovery stays on-LAN: fewer than 10% of this src's
            # connections reach non-internal DESTINATIONS. Keyed on dst_zone -
            # src_zone is constant within a per-src group, so it cannot measure a
            # destination fraction. != 'internal' stays robust to a future third zone.
            ext_conns = grp[grp['dst_zone'] != 'internal'].shape[0]
            if ext_conns / len(grp) < 0.1:
                return True
        return False

    results = []

    for src, grp in df_w.groupby('src'):
        n_buckets = grp['time_bucket'].nunique()
        if n_buckets < min_buckets:
            continue

        total_unique_ports = grp['port'].nunique()
        if total_unique_ports < min_ports:
            continue

        max_ports_in_bucket = grp.groupby('time_bucket')['port'].nunique().max()

        if max_ports_in_bucket >= vert_threshold:
            continue

        spread_score     = round(total_unique_ports / max(max_ports_in_bucket, 1), 2)
        state_counts     = grp['conn_state'].value_counts()
        scan_state_ratio = sum(state_counts.get(s, 0) for s in SCAN_STATES) / len(grp)

        if scan_state_ratio < state_min:
            continue

        iot_flag = is_iot_discovery(grp)

        if iot_flag:
            pattern_tag   = 'iot_discovery'
            pattern_notes = (
                "Traffic consistent with IoT device discovery (mDNS/SSDP/UPnP) - high "
                "temporal spread from repeated attach/detach cycles rather than "
                "deliberate scanning."
            )
        elif scan_state_ratio >= 0.60:
            pattern_tag   = 'slow_scan'
            pattern_notes = (
                f"Connection attempts paced across {n_buckets} time windows, below a "
                "per-window detection threshold - a cadence consistent with a "
                "deliberately slow scan."
            )
        else:
            pattern_tag   = 'slow_scan_candidate'
            pattern_notes = (
                "Connection attempts spread across several time windows with moderate "
                "scan-indicative behavior - short of a confident slow-scan call."
            )

        results.append({
            'scan_type'             : 'slow',
            'src'                   : src,
            'dst'                   : None,
            'port'                  : None,
            'port_class'            : None,
            'distinct_ports'        : total_unique_ports,
            'distinct_hosts'        : grp['dst'].nunique(),
            'max_ports_in_bucket'   : int(max_ports_in_bucket),
            'active_buckets'        : n_buckets,
            'temporal_spread_score' : spread_score,
            'total_conns'           : len(grp),
            'scan_state_ratio'      : round(scan_state_ratio, 3),
            'top_states'            : ', '.join(state_counts.head(3).index.tolist()),
            'window_start'          : datetime.fromtimestamp(
                                          float(grp['ts'].min()), tz=timezone.utc
                                      ).strftime('%Y-%m-%d %H:%M:%S'),
            'window_secs'           : bucket_secs,
            'direction'             : grp['direction'].iloc[0],
            'pattern_tag'           : pattern_tag,
            'pattern_notes'         : pattern_notes,
        })

    return results


def _classify(row: dict) -> tuple[str, str]:
    """Return (pattern_tag, explanation) for a finding dict."""
    port      = row.get('port')
    ratio     = row['scan_state_ratio']
    hosts     = row.get('distinct_hosts') or 0
    ports     = row.get('distinct_ports') or 0
    scan_type = row['scan_type']

    if scan_type == 'slow':
        return (row.get('pattern_tag', 'slow_scan_candidate'),
                row.get('pattern_notes', ''))

    if port in IOT_DISCOVERY_PORTS and ratio < 0.40:
        return ('iot_discovery',
                f"Port {port} is an IoT/device-discovery port (mDNS/SSDP/UPnP/NetBIOS); "
                "high host counts here are normal for discovery protocols rather than a "
                "port scan.")

    if port in BITTORRENT_PORTS_PEER and ratio >= 0.50:
        return ('bittorrent',
                f"BitTorrent peer connections on port {port} - peers contacted at a "
                "failure rate normal for peer discovery.")

    if port in BITTORRENT_PORTS_TRACKER and ratio >= 0.15:
        return ('bittorrent',
                f"BitTorrent tracker traffic on port {port} - trackers contacted at a "
                "failure rate normal for announce/scrape.")

    if port == 53 and ratio < 0.05 and hosts >= 15:
        return ('dns_resolver',
                "DNS recursive resolution to many external resolvers on port 53 - the "
                "pattern of a DNS server or resolver rather than a scanner.")

    if port == 443 and ratio < 0.10 and hosts >= 15:
        return ('https_browsing',
                "HTTPS to many external hosts - consistent with normal web browsing or "
                "cloud-service traffic.")

    if port == 80 and ratio < 0.10 and hosts >= 15:
        return ('http_browsing',
                "HTTP to many external hosts - consistent with normal web traffic.")

    if port == 443 and 0.10 <= ratio < 0.50 and hosts >= 20:
        return ('streaming_blocked',
                "Many HTTPS destinations with a moderate failure rate - on a "
                "media/streaming device, consistent with DNS-level blocking (Pi-hole, "
                "NextDNS) causing direct-connection fallbacks.")

    if port in DARK_PORTS and ratio >= 0.90:
        return ('dark_traffic',
                f"Port {port} is unassigned/reserved - likely a Zeek encoding artifact "
                "(e.g. ICMP type/code) or internet background radiation.")

    if scan_type == 'vertical' and ratio >= 0.60 and ports >= 1000:
        return ('confirmed_scan',
                "A full port-range sweep against a single target - the behavior of a "
                "deliberate port scan.")

    if ratio >= 0.60:
        return ('confirmed_scan',
                "A high share of scan-indicative connection states across the contacted "
                f"{'ports' if scan_type == 'vertical' else 'hosts'} - consistent with a "
                "deliberate scan.")

    return ('unknown', '')


def _to_severity(row: dict) -> Severity:
    """Return Severity based on scan_state_ratio, breadth, and pattern_tag."""
    ratio   = row['scan_state_ratio']
    breadth = max(row.get('distinct_ports') or 0, row.get('distinct_hosts') or 0)
    tag     = row['pattern_tag']

    if tag in ('dns_resolver', 'https_browsing', 'http_browsing',
               'iot_discovery', 'dark_traffic'):
        return Severity.LOW

    if row.get('scan_type') == 'slow':
        if tag == 'slow_scan':
            return Severity.HIGH if ratio >= 0.60 else Severity.MEDIUM
        return Severity.LOW

    if ratio >= 0.60:
        return Severity.HIGH
    if ratio >= 0.30 and breadth >= 50:
        return Severity.HIGH
    if ratio >= 0.20:
        return Severity.MEDIUM
    if ratio >= 0.10 and breadth >= 25:
        return Severity.MEDIUM
    return Severity.LOW


def _make_finding(row: dict, data_window: tuple) -> Finding:
    """Construct a Finding from a classified result dict."""
    scan_type      = row['scan_type']
    src            = row['src']
    dst            = row.get('dst')
    port           = row.get('port')
    distinct_ports = row.get('distinct_ports', 0)
    distinct_hosts = row.get('distinct_hosts', 0)
    active_buckets = row.get('active_buckets')

    if scan_type == 'vertical':
        title = f"{src} → {dst}"
    elif scan_type == 'horizontal':
        title = f"{src} → *:{port}"
    elif scan_type == 'block':
        title = f"{src} → *"
    else:
        title = f"{src}"

    description = row.get('pattern_notes') or (
        f"A {scan_type} scan pattern - repeated connection attempts consistent with "
        "port or host enumeration."
    )

    evidence: dict = {
        'scan_type'        : scan_type,
        'src'              : src,
        'dst'              : dst,
        'port'             : port,
        'distinct_ports'   : distinct_ports,
        'distinct_hosts'   : distinct_hosts,
        'total_conns'      : row.get('total_conns'),
        'scan_state_ratio' : row.get('scan_state_ratio'),
        'top_states'       : row.get('top_states'),
        'direction'        : row.get('direction'),
        'pattern_tag'      : row.get('pattern_tag'),
        'window_start'     : row.get('window_start'),
        'window_secs'      : row.get('window_secs'),
    }
    if scan_type == 'slow':
        evidence['temporal_spread_score'] = row.get('temporal_spread_score')
        evidence['active_buckets']        = active_buckets
        evidence['max_ports_in_bucket']   = row.get('max_ports_in_bucket')

    pattern_tag = row.get('pattern_tag', 'unknown')
    severity    = row['_severity']

    if pattern_tag == 'confirmed_scan' or severity == Severity.HIGH:
        next_steps = [
            "Pivot to conn.log to review full connection history for this source",
            "Check reverse DNS for the source host",
            "Look up source IP on Shodan for open services and prior reports",
        ]
    elif pattern_tag == 'bittorrent':
        next_steps = [
            f"Confirm whether {src} runs BitTorrent (expected P2P swarm behavior)",
            "Add source to allowlist to suppress if BitTorrent is authorized",
        ]
    elif pattern_tag in ('iot_discovery', 'dns_resolver', 'https_browsing',
                         'http_browsing', 'streaming_blocked'):
        next_steps = [
            "Add source to allowlist to suppress this known-benign pattern",
        ]
    elif pattern_tag == 'dark_traffic':
        next_steps = [
            "Check the proto field in conn.log - likely an ICMP type/code encoding",
        ]
    elif scan_type == 'slow' and pattern_tag == 'slow_scan':
        next_steps = [
            "Pivot to conn.log to review full connection history for this source",
            "Check reverse DNS for the source host",
            "Look up source IP on Shodan",
            f"Review the temporal spread - activity paced across {active_buckets} time windows",
        ]
    else:
        next_steps = [f"Review conn.log for {src} to assess scan intent"]

    return Finding(
        detector='scan',
        severity=severity,
        title=title,
        description=description,
        evidence=evidence,
        next_steps=next_steps,
        ts_generated=datetime.now(tz=timezone.utc),
        data_window=data_window,
    )


# ── Detector entry point ──────────────────────────────────────────────────────

def run(context: DetectorContext) -> list[Finding]:
    """Detect port scan activity: vertical, horizontal, block, and slow scans."""
    cfg: dict = {**DEFAULT_CONFIG, **context.config}
    home_net = list(context.home_net) if context.home_net else list(_DEFAULT_HOME_NET)

    df = context.logs.get('conn*.log*')
    if df is None or df.empty:
        return []

    df = _prefilter(df, home_net)
    if df.empty:
        return []

    all_rows: list[dict] = []
    all_rows.extend(_detect_vertical(df, cfg))
    all_rows.extend(_detect_horizontal(df, cfg))
    all_rows.extend(_detect_block(df, cfg))
    all_rows.extend(_detect_slow(df, cfg))

    if not all_rows:
        return []

    # Deduplicate: keep highest-breadth result per unique (scan_type, src, dst, port)
    seen: dict[tuple, dict] = {}
    for row in all_rows:
        key    = (row['scan_type'], row.get('src'), row.get('dst'), row.get('port'))
        breadth = max(row.get('distinct_ports') or 0, row.get('distinct_hosts') or 0)
        if key not in seen or breadth > max(
            seen[key].get('distinct_ports') or 0,
            seen[key].get('distinct_hosts') or 0,
        ):
            seen[key] = row

    deduped = list(seen.values())

    for row in deduped:
        if 'pattern_tag' not in row:
            row['pattern_tag'], row['pattern_notes'] = _classify(row)
        row['_severity'] = _to_severity(row)

    sev_order = {Severity.HIGH: 0, Severity.MEDIUM: 1, Severity.LOW: 2, Severity.INFO: 3}
    deduped.sort(
        key=lambda r: (sev_order[r['_severity']], -r.get('scan_state_ratio', 0))
    )

    return [_make_finding(row, context.data_window) for row in deduped]
