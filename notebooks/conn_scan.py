#!/usr/bin/env python3
"""
Port scan exploration over Zeek conn.log data.

A standalone prototype kept for the working-out behind the shipped `scan`
detector; run the detector itself with `sigwood scan`.

Scan types detected:
  vertical    one source → many ports on one target host
  horizontal  one source → same port across many hosts
  block       one source → many ports AND many hosts
  slow        activity spread across time windows to evade per-window thresholds

Usage:
  python3 notebooks/conn_scan.py conn.log
  python3 notebooks/conn_scan.py /path/to/logs/conn.*.log.gz
  python3 notebooks/conn_scan.py conn.log --output scan_results/
  python3 notebooks/conn_scan.py conn.log --format json
  python3 notebooks/conn_scan.py conn.log --min-severity MEDIUM
  python3 notebooks/conn_scan.py conn.log --vertical-threshold 20 --horizontal-threshold 20
"""

import argparse
import gzip
import glob
import json
import os
import sys
import warnings
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd
from scipy.stats import entropy as scipy_entropy
from tqdm import tqdm

warnings.filterwarnings('ignore')

# ── Version ───────────────────────────────────────────────────────────────────
VERSION = 'prototype'

# ── Defaults ──────────────────────────────────────────────────────────────────
DEFAULT_VERTICAL_PORT_THRESHOLD   = 15
DEFAULT_HORIZONTAL_HOST_THRESHOLD = 15
DEFAULT_BLOCK_PORT_THRESHOLD      = 20
DEFAULT_BLOCK_HOST_THRESHOLD      = 20
DEFAULT_BLOCK_SCAN_STATE_MIN      = 0.30
DEFAULT_SLOW_SCAN_STATE_MIN       = 0.30
DEFAULT_FAST_WINDOW_SECS          = 60
DEFAULT_SLOW_WINDOW_SECS          = 3600
DEFAULT_MIN_CONNECTIONS           = 3
DEFAULT_SLOW_MIN_PORTS            = 8
DEFAULT_SLOW_MIN_BUCKETS          = 4

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

REQUIRED_FIELDS = {'ts', 'id.orig_h', 'id.resp_h', 'id.resp_p', 'proto', 'conn_state'}
OPTIONAL_FIELDS = {'orig_bytes', 'resp_bytes', 'duration', 'orig_pkts', 'resp_pkts'}

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


# ══════════════════════════════════════════════════════════════════════════════
# Data loading
# ══════════════════════════════════════════════════════════════════════════════

def open_log(path: str):
    """Open a plain or gzipped log file."""
    if path.endswith('.gz'):
        return gzip.open(path, 'rt', encoding='utf-8', errors='replace')
    return open(path, 'r', encoding='utf-8', errors='replace')


def load_conn_log(pattern: str, verbose: bool = False) -> tuple[pd.DataFrame, int]:
    """
    Load one or more Zeek conn.log files matching a glob pattern.
    Handles plain and gzipped files transparently.
    Parses line-by-line with json.loads - avoids ujson issues with Zeek output.
    """
    paths = sorted(glob.glob(pattern)) if ('*' in pattern or '?' in pattern) else [pattern]
    if not paths:
        raise FileNotFoundError(f"No files matched: {pattern}")

    rows = []
    skipped = 0

    for path in paths:
        with open_log(path) as fh:
            for line in tqdm(fh, desc=f"  {Path(path).name}", unit=" lines",
                             leave=False, disable=not verbose):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    skipped += 1
                    continue
                if not REQUIRED_FIELDS.issubset(rec.keys()):
                    skipped += 1
                    continue
                row = {f: rec[f] for f in REQUIRED_FIELDS}
                for f in OPTIONAL_FIELDS:
                    row[f] = rec.get(f)
                rows.append(row)

    if not rows:
        raise ValueError(f"No valid conn.log records found in: {pattern}")

    df = pd.DataFrame(rows)
    df.rename(columns={
        'id.orig_h': 'src_ip',
        'id.resp_h': 'dst_ip',
        'id.resp_p': 'dst_port',
    }, inplace=True)
    df['ts'] = pd.to_datetime(df['ts'], unit='s', utc=True)
    df['dst_port'] = pd.to_numeric(df['dst_port'], errors='coerce').astype('Int32')
    df.sort_values('ts', inplace=True)
    df.reset_index(drop=True, inplace=True)
    return df, skipped


# ══════════════════════════════════════════════════════════════════════════════
# Pre-filtering
# ══════════════════════════════════════════════════════════════════════════════

def ip_in_nets(ip: str, nets: list) -> bool:
    """Return True if ip falls within any of the given CIDR strings."""
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in ipaddress.ip_network(n, strict=False) for n in nets)
    except ValueError:
        return False


def build_internal_mask(series: pd.Series, nets: list) -> pd.Series:
    """Vectorized internal IP classification."""
    return series.map(lambda ip: ip_in_nets(ip, nets))


def classify_direction(src_int: bool, dst_int: bool) -> str:
    if src_int and dst_int:
        return 'internal→internal'
    elif src_int:
        return 'internal→external'
    elif dst_int:
        return 'external→internal'
    return 'external→external'


def prefilter(df_raw: pd.DataFrame, args) -> pd.DataFrame:
    """
    Apply pre-filters to remove traffic that produces structural false positives:
      - ICMP: Zeek encodes type/code in port fields - not real port numbers
      - IPv6 link-local (fe80::/10): neighbor discovery, not scanning
      - IoT multicast/broadcast destinations: mDNS, SSDP, etc.
      - Allowlisted source IPs
    Then classify direction (internal/external) using home_nets.
    """
    n_raw = len(df_raw)
    df = df_raw.copy()

    # ICMP - port field semantics are different, not suitable for scan detection
    icmp_mask = df['proto'] == 'icmp'
    df = df[~icmp_mask].copy()
    n_icmp = icmp_mask.sum()

    # IPv6 link-local
    ipv6_ll_mask = (df['src_ip'].str.startswith('fe80:') |
                    df['dst_ip'].str.startswith('fe80:'))
    df = df[~ipv6_ll_mask].copy()
    n_ipv6 = ipv6_ll_mask.sum()

    # IoT multicast/broadcast destinations
    multicast_mask = df['dst_ip'].map(
        lambda ip: any(ip.startswith(p) for p in IOT_MULTICAST_PREFIXES)
    )
    df = df[~multicast_mask].copy()
    n_multicast = multicast_mask.sum()

    # Allowlisted source IPs
    n_allowlist = 0
    if args.allowlist_ips:
        al_mask = df['src_ip'].isin(args.allowlist_ips)
        n_allowlist = al_mask.sum()
        df = df[~al_mask].copy()

    # Direction classification
    home_nets = args.home_nets or []
    src_int = build_internal_mask(df['src_ip'], home_nets)
    dst_int = build_internal_mask(df['dst_ip'], home_nets)
    df['direction'] = [classify_direction(si, di)
                       for si, di in zip(src_int, dst_int)]

    if args.verbose:
        print(f"  Pre-filter summary:")
        print(f"    Raw rows      : {n_raw:,}")
        print(f"    ICMP excluded : {n_icmp:,}")
        print(f"    IPv6 LL excl. : {n_ipv6:,}")
        print(f"    Multicast excl: {n_multicast:,}")
        if n_allowlist:
            print(f"    Allowlist excl: {n_allowlist:,}")
        print(f"    Working rows  : {len(df):,}")

    return df


# ══════════════════════════════════════════════════════════════════════════════
# Detectors
# ══════════════════════════════════════════════════════════════════════════════

def detect_vertical_scans(df: pd.DataFrame, args) -> pd.DataFrame:
    """
    Vertical scan: one src → many distinct ports on one dst.
    Two-pass: global groupby filter → sliding window on candidates only.
    """
    threshold   = args.vertical_threshold
    window_secs = args.slow_window

    # Pass 1
    global_counts = (
        df.groupby(['src_ip', 'dst_ip'])['dst_port']
        .nunique()
        .reset_index(name='global_distinct_ports')
    )
    candidates = global_counts[global_counts['global_distinct_ports'] >= threshold]

    if args.verbose:
        print(f"  Vertical Pass 1: {len(candidates)} candidate pairs "
              f"(of {len(global_counts):,} total)")

    if len(candidates) == 0:
        return pd.DataFrame()

    # Pass 2: merge instead of apply() for scalability
    cand_keys = candidates[['src_ip', 'dst_ip']]
    df_cands  = df.merge(cand_keys, on=['src_ip', 'dst_ip'])

    results = []
    for (src, dst), grp in df_cands.groupby(['src_ip', 'dst_ip']):
        grp       = grp.sort_values('ts')
        ts_arr    = grp['ts'].values.astype('int64') / 1e9
        port_arr  = grp['dst_port'].values
        state_arr = grp['conn_state'].values

        port_counts         = {}
        max_ports_in_window = 0
        best_window_start   = ts_arr[0]
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
                best_window_start   = ts_arr[left]

        if max_ports_in_window < threshold:
            continue

        state_counts     = pd.Series(state_arr).value_counts()
        total_conns      = len(state_arr)
        scan_state_count = sum(state_counts.get(s, 0) for s in SCAN_STATES)
        scan_state_ratio = scan_state_count / total_conns

        port_series        = pd.Series(port_arr).dropna()
        port_buckets       = pd.cut(port_series, bins=[0, 1023, 49151, 65535],
                                    labels=['well-known', 'registered', 'ephemeral'])
        port_range_entropy = scipy_entropy(port_buckets.value_counts().values + 1)

        results.append({
            'scan_type'          : 'vertical',
            'src_ip'             : src,
            'dst_ip'             : dst,
            'dst_port'           : None,
            'port_class'         : None,
            'distinct_ports'     : max_ports_in_window,
            'distinct_hosts'     : 1,
            'total_conns'        : total_conns,
            'scan_state_ratio'   : round(scan_state_ratio, 3),
            'top_states'         : ', '.join(state_counts.head(3).index.tolist()),
            'port_range_entropy' : round(port_range_entropy, 3),
            'window_start'       : datetime.fromtimestamp(
                                       best_window_start, tz=timezone.utc
                                   ).strftime('%Y-%m-%d %H:%M:%S'),
            'window_secs'        : window_secs,
            'direction'          : grp['direction'].iloc[0],
        })

    return pd.DataFrame(results)


def detect_horizontal_scans(df: pd.DataFrame, args) -> pd.DataFrame:
    """
    Horizontal scan: one src → same port across many distinct hosts.
    Two-pass: global groupby filter → sliding window on candidates only.
    """
    threshold   = args.horizontal_threshold
    window_secs = args.slow_window

    df_tcp_udp = df[df['dst_port'].notna()].copy()

    # Pass 1
    global_counts = (
        df_tcp_udp.groupby(['src_ip', 'dst_port'])['dst_ip']
        .nunique()
        .reset_index(name='global_distinct_hosts')
    )
    candidates = global_counts[global_counts['global_distinct_hosts'] >= threshold]

    if args.verbose:
        print(f"  Horizontal Pass 1: {len(candidates)} candidate pairs "
              f"(of {len(global_counts):,} total)")

    if len(candidates) == 0:
        return pd.DataFrame()

    # Pass 2: merge for scalability
    cand_keys = candidates[['src_ip', 'dst_port']]
    df_cands  = df_tcp_udp.merge(cand_keys, on=['src_ip', 'dst_port'])

    results = []
    for (src, port), grp in df_cands.groupby(['src_ip', 'dst_port']):
        grp       = grp.sort_values('ts')
        ts_arr    = grp['ts'].values.astype('int64') / 1e9
        host_arr  = grp['dst_ip'].values
        state_arr = grp['conn_state'].values

        host_counts         = {}
        max_hosts_in_window = 0
        best_window_start   = ts_arr[0]
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
                best_window_start   = ts_arr[left]

        if max_hosts_in_window < threshold:
            continue

        state_counts     = pd.Series(state_arr).value_counts()
        total_conns      = len(state_arr)
        scan_state_ratio = sum(state_counts.get(s, 0) for s in SCAN_STATES) / total_conns
        velocity         = max_hosts_in_window / max(ts_arr[-1] - ts_arr[0], 1)

        port = int(port)
        if port <= 1023:
            port_class = 'well-known'
        elif port <= 49151:
            port_class = 'registered'
        else:
            port_class = 'ephemeral'

        results.append({
            'scan_type'              : 'horizontal',
            'src_ip'                 : src,
            'dst_ip'                 : None,
            'dst_port'               : port,
            'port_class'             : port_class,
            'distinct_ports'         : 1,
            'distinct_hosts'         : max_hosts_in_window,
            'total_conns'            : total_conns,
            'scan_state_ratio'       : round(scan_state_ratio, 3),
            'top_states'             : ', '.join(state_counts.head(3).index.tolist()),
            'velocity_hosts_per_sec' : round(velocity, 4),
            'window_start'           : datetime.fromtimestamp(
                                           best_window_start, tz=timezone.utc
                                       ).strftime('%Y-%m-%d %H:%M:%S'),
            'window_secs'            : window_secs,
            'direction'              : grp['direction'].iloc[0],
        })

    return pd.DataFrame(results)


def detect_block_scans(df: pd.DataFrame, args) -> pd.DataFrame:
    """
    Block scan: one src → many ports AND many hosts.
    scan_state_ratio_min is a hard gate - without it any active workstation fires.
    """
    port_threshold      = args.block_port_threshold
    host_threshold      = args.block_host_threshold
    scan_state_ratio_min = args.block_state_min
    window_secs         = args.slow_window

    df_w = df[df['dst_port'].notna()].copy()
    df_w['time_bucket'] = (
        df_w['ts'].values.astype('int64') / 1e9 // window_secs
    ).astype(int)
    df_w['is_scan_state'] = df_w['conn_state'].isin(SCAN_STATES)

    # Pass 1: global filter
    global_agg = df_w.groupby('src_ip').agg(
        global_distinct_ports=('dst_port', 'nunique'),
        global_distinct_hosts=('dst_ip', 'nunique'),
        scan_state_ratio=('is_scan_state', 'mean'),
    ).reset_index()

    candidates = global_agg[
        (global_agg['global_distinct_ports'] >= port_threshold) &
        (global_agg['global_distinct_hosts'] >= host_threshold) &
        (global_agg['scan_state_ratio'] >= scan_state_ratio_min)
    ]

    if args.verbose:
        print(f"  Block Pass 1: {len(candidates)} candidate src IPs "
              f"(of {global_agg['src_ip'].nunique():,} total)")

    if len(candidates) == 0:
        return pd.DataFrame()

    df_cands  = df_w[df_w['src_ip'].isin(candidates['src_ip'])]
    bucket_agg = df_cands.groupby(['src_ip', 'time_bucket']).agg(
        distinct_ports=('dst_port', 'nunique'),
        distinct_hosts=('dst_ip', 'nunique'),
        total_conns=('dst_port', 'count'),
        scan_state_ratio=('is_scan_state', 'mean'),
        top_states=('conn_state',
                    lambda x: ', '.join(x.value_counts().head(3).index.tolist())),
        direction=('direction', 'first'),
        ports_well_known=('dst_port', lambda x: (x <= 1023).sum()),
        ports_registered=('dst_port', lambda x: ((x > 1023) & (x <= 49151)).sum()),
        ports_ephemeral=('dst_port', lambda x: (x > 49151).sum()),
        window_start_ts=('ts', lambda x: x.values.astype('int64').min() / 1e9),
    ).reset_index()

    findings = bucket_agg[
        (bucket_agg['distinct_ports'] >= port_threshold) &
        (bucket_agg['distinct_hosts'] >= host_threshold) &
        (bucket_agg['scan_state_ratio'] >= scan_state_ratio_min)
    ].copy()

    if len(findings) == 0:
        return pd.DataFrame()

    findings['scan_type']    = 'block'
    findings['dst_ip']       = None
    findings['dst_port']     = None
    findings['port_class']   = None
    findings['window_secs']  = window_secs
    findings['window_start'] = findings['window_start_ts'].map(
        lambda ts: datetime.fromtimestamp(ts, tz=timezone.utc)
                           .strftime('%Y-%m-%d %H:%M:%S')
    )
    findings['scan_state_ratio'] = findings['scan_state_ratio'].round(3)
    findings['breadth_score']    = findings['distinct_ports'] * findings['distinct_hosts']

    findings = (
        findings
        .sort_values('breadth_score', ascending=False)
        .drop_duplicates(subset=['src_ip'], keep='first')
        .drop(columns=['time_bucket', 'window_start_ts', 'breadth_score'])
        .reset_index(drop=True)
    )

    return findings


def detect_slow_scans(df: pd.DataFrame, args) -> pd.DataFrame:
    """
    Slow scan / temporal spread detector.

    Finds hosts whose port diversity is spread across many time buckets,
    staying below per-window thresholds deliberately.

    temporal_spread_score = total_unique_ports / max_ports_in_any_single_bucket
    Score >> 1 = deliberately spread (slow scan pattern)
    Score ≈ 1  = clustered in time (normal behavior)

    scan_state_ratio gate filters out IoT/mobile devices whose spread comes
    from network attach/detach cycles rather than scanning activity.
    """
    min_ports       = args.slow_min_ports
    min_buckets     = args.slow_min_buckets
    state_min       = args.slow_state_min
    bucket_secs     = args.slow_window
    vert_threshold  = args.vertical_threshold

    df_w = df[df['dst_port'].notna()].copy()
    df_w['time_bucket'] = (
        df_w['ts'].values.astype('int64') / 1e9 // bucket_secs
    ).astype(int)

    # IoT pattern recognition helpers
    def is_iot_discovery(grp: pd.DataFrame) -> bool:
        """
        Return True if this src looks like IoT device discovery traffic rather
        than scanning. Signals:
          - Majority of traffic is to well-known IoT discovery ports (mDNS, SSDP)
          - Top destinations are DNS servers or multicast groups
          - Very low unique external routable destinations
        """
        port_counts = grp['dst_port'].value_counts()
        top_ports   = set(port_counts.head(3).index.tolist())
        # If top ports are dominated by discovery ports, likely IoT
        if top_ports.issubset(IOT_DISCOVERY_PORTS | {53, 443, 80}):
            # And the traffic is mostly to internal/multicast destinations
            ext_conns = grp[~grp['direction'].str.startswith('internal')].shape[0]
            if ext_conns / len(grp) < 0.1:
                return True
        return False

    results = []

    for src, grp in df_w.groupby('src_ip'):
        n_buckets = grp['time_bucket'].nunique()
        if n_buckets < min_buckets:
            continue

        total_unique_ports = grp['dst_port'].nunique()
        if total_unique_ports < min_ports:
            continue

        max_ports_in_bucket = grp.groupby('time_bucket')['dst_port'].nunique().max()

        # Already caught by vertical detector - skip
        if max_ports_in_bucket >= vert_threshold:
            continue

        spread_score     = round(total_unique_ports / max(max_ports_in_bucket, 1), 2)
        state_counts     = grp['conn_state'].value_counts()
        scan_state_ratio = sum(state_counts.get(s, 0) for s in SCAN_STATES) / len(grp)

        # State ratio gate - filters IoT/mobile network attach/detach patterns
        if scan_state_ratio < state_min:
            continue

        # IoT discovery pattern check
        iot_flag = is_iot_discovery(grp)

        # Pattern tag for slow scan findings
        if iot_flag:
            pattern_tag   = 'iot_discovery'
            pattern_notes = (
                f"Traffic pattern consistent with IoT device discovery (mDNS/SSDP/UPnP). "
                f"High temporal spread from repeated network attach/detach cycles rather "
                f"than deliberate scanning. Add to iot_devices in sigwood.conf to suppress."
            )
        elif scan_state_ratio >= 0.60:
            pattern_tag   = 'slow_scan'
            pattern_notes = (
                f"Temporal spread score {spread_score:.2f} with {scan_state_ratio:.1%} "
                f"scan-indicative states across {n_buckets} time windows. "
                f"Activity deliberately paced below per-window detection threshold. "
                f"Strong slow scan signature."
            )
        else:
            pattern_tag   = 'slow_scan_candidate'
            pattern_notes = (
                f"Temporal spread score {spread_score:.2f} with {scan_state_ratio:.1%} "
                f"scan-indicative states across {n_buckets} time windows. "
                f"Moderate confidence - review destination IPs and ports."
            )

        results.append({
            'scan_type'             : 'slow',
            'src_ip'                : src,
            'dst_ip'                : None,
            'dst_port'              : None,
            'port_class'            : None,
            'distinct_ports'        : total_unique_ports,
            'distinct_hosts'        : grp['dst_ip'].nunique(),
            'max_ports_in_bucket'   : int(max_ports_in_bucket),
            'active_buckets'        : n_buckets,
            'temporal_spread_score' : spread_score,
            'total_conns'           : len(grp),
            'scan_state_ratio'      : round(scan_state_ratio, 3),
            'top_states'            : ', '.join(state_counts.head(3).index.tolist()),
            'window_start'          : grp['ts'].min().strftime('%Y-%m-%d %H:%M:%S'),
            'window_secs'           : bucket_secs,
            'direction'             : grp['direction'].iloc[0],
            'pattern_tag'           : pattern_tag,
            'pattern_notes'         : pattern_notes,
        })

    if not results:
        return pd.DataFrame()

    return (
        pd.DataFrame(results)
        .sort_values('temporal_spread_score', ascending=False)
        .reset_index(drop=True)
    )


# ══════════════════════════════════════════════════════════════════════════════
# Fingerprinting
# ══════════════════════════════════════════════════════════════════════════════

def conn_state_fingerprints(df: pd.DataFrame, scanner_ips: list) -> dict:
    """Compute per-src connection state fingerprints for candidate scanner IPs."""
    fps = {}
    for ip in scanner_ips:
        src_df = df[df['src_ip'] == ip]
        if len(src_df) == 0:
            continue
        dist       = src_df['conn_state'].value_counts(normalize=True).round(3)
        scan_score = sum(dist.get(s, 0) for s in SCAN_STATES)
        fps[ip] = {
            'total_connections' : len(src_df),
            'state_distribution': dist.to_dict(),
            'scan_state_score'  : round(scan_score, 3),
            'dominant_state'    : dist.index[0] if len(dist) > 0 else None,
        }
    return fps


# ══════════════════════════════════════════════════════════════════════════════
# Pattern classification
# ══════════════════════════════════════════════════════════════════════════════

def classify_finding(row) -> tuple[str, str]:
    """
    Returns (pattern_tag, explanation) for a finding.
    Ordered from most specific to least specific.
    """
    src       = row['src_ip']
    port      = row.get('dst_port')
    ratio     = row['scan_state_ratio']
    hosts     = row.get('distinct_hosts') or 0
    ports     = row.get('distinct_ports') or 0
    scan_type = row['scan_type']

    # Slow scan findings are pre-tagged by detect_slow_scans()
    if scan_type == 'slow':
        return (row.get('pattern_tag', 'slow_scan_candidate'),
                row.get('pattern_notes', ''))

    # ── IoT discovery ports ──
    if port in IOT_DISCOVERY_PORTS and ratio < 0.40:
        return ('iot_discovery',
                f"Port {port} is an IoT/device discovery port (mDNS/SSDP/UPnP/NetBIOS). "
                f"High host counts on this port are normal for device discovery protocols. "
                f"Not a port scan. Add source to iot_devices in sigwood.conf to suppress.")

    # ── BitTorrent peer ports ──
    if port in BITTORRENT_PORTS_PEER and ratio >= 0.50:
        return ('bittorrent',
                f"BitTorrent peer connections on port {port} - {hosts} peers contacted, "
                f"{ratio:.1%} failed connections (normal for BT peer discovery). "
                f"If this host shouldn't run BitTorrent, investigate.")

    # ── BitTorrent tracker ports ──
    if port in BITTORRENT_PORTS_TRACKER and ratio >= 0.15:
        return ('bittorrent',
                f"BitTorrent tracker traffic on port {port} - {hosts} trackers contacted, "
                f"{ratio:.1%} failed connections (normal for tracker announce/scrape). "
                f"If this host shouldn't run BitTorrent, investigate.")

    # ── DNS recursive resolution ──
    if port == 53 and ratio < 0.05 and hosts >= 15:
        return ('dns_resolver',
                f"DNS recursive resolution - {hosts} external resolvers on port 53, "
                f"{ratio:.1%} failed. This is a DNS server or resolver, not a scanner. "
                f"Add to dns_servers in sigwood.conf to suppress.")

    # ── Normal HTTPS browsing / cloud services ──
    if port == 443 and ratio < 0.10 and hosts >= 15:
        return ('https_browsing',
                f"HTTPS to {hosts} external hosts, {ratio:.1%} failed - consistent with "
                f"normal web browsing or cloud service traffic. "
                f"Add to workstations or servers in sigwood.conf to suppress.")

    # ── Normal HTTP browsing ──
    if port == 80 and ratio < 0.10 and hosts >= 15:
        return ('http_browsing',
                f"HTTP to {hosts} external hosts, {ratio:.1%} failed - consistent with "
                f"normal web traffic.")

    # ── Streaming device / DNS-blocked HTTPS ──
    if port == 443 and 0.10 <= ratio < 0.50 and hosts >= 20:
        return ('streaming_blocked',
                f"{hosts} HTTPS destinations, {ratio:.1%} failed. On a media/streaming "
                f"device this pattern is consistent with DNS-level blocking (Pi-hole, "
                f"NextDNS) causing direct connection fallback attempts. "
                f"Add to media_devices in sigwood.conf to suppress.")

    # ── Dark / unassigned ports ──
    if port in DARK_PORTS and ratio >= 0.90:
        return ('dark_traffic',
                f"Port {port} is unassigned/reserved - likely a Zeek encoding artifact "
                f"(e.g. ICMP type/code) or internet background radiation. "
                f"Check proto field in conn.log.")

    # ── Strong scanner signature ──
    if scan_type == 'vertical' and ratio >= 0.60 and ports >= 1000:
        return ('confirmed_scan',
                f"Full port range scan - {ports} distinct ports on single target "
                f"with {ratio:.1%} scan-indicative states. Strong scanner signature.")

    if ratio >= 0.60:
        return ('confirmed_scan',
                f"{ratio:.1%} scan-indicative states "
                f"({'ports' if scan_type == 'vertical' else 'hosts'}: {max(ports, hosts)}). "
                f"Strong scanner signature.")

    return ('unknown', '')


def severity_label(row) -> str:
    """
    Severity driven by scan_state_ratio as primary signal.
    Breadth is a secondary escalator only - not sufficient on its own.
    Known benign patterns are always LOW regardless of breadth.
    """
    ratio   = row['scan_state_ratio']
    breadth = max(row.get('distinct_ports') or 0, row.get('distinct_hosts') or 0)
    tag     = row['pattern_tag']

    # Benign patterns - LOW regardless of breadth
    if tag in ('dns_resolver', 'https_browsing', 'http_browsing',
               'iot_discovery', 'dark_traffic'):
        return 'LOW'

    # Slow scan has its own severity logic
    if row.get('scan_type') == 'slow':
        if tag == 'slow_scan':
            return 'HIGH' if ratio >= 0.60 else 'MEDIUM'
        return 'LOW'

    if ratio >= 0.60:
        return 'HIGH'
    if ratio >= 0.30 and breadth >= 50:
        return 'HIGH'
    if ratio >= 0.20:
        return 'MEDIUM'
    if ratio >= 0.10 and breadth >= 25:
        return 'MEDIUM'
    return 'LOW'


# ══════════════════════════════════════════════════════════════════════════════
# Synthesis
# ══════════════════════════════════════════════════════════════════════════════

def synthesize(detector_outputs: list[pd.DataFrame],
               fingerprints: dict) -> pd.DataFrame:
    """
    Combine all detector outputs, attach fingerprints, classify, assign severity,
    deduplicate across fast/slow windows, and sort by severity.
    """
    all_dfs = [d for d in detector_outputs if len(d) > 0]
    if not all_dfs:
        return pd.DataFrame()

    df_all = pd.concat(all_dfs, ignore_index=True)

    # Attach global scan_state_score
    df_all['scan_state_score'] = df_all['src_ip'].map(
        lambda ip: fingerprints.get(ip, {}).get(
            'scan_state_score',
            df_all.loc[df_all['src_ip'] == ip, 'scan_state_ratio'].iloc[0]
        )
    )

    # Classify findings that don't already have a tag (slow scan findings are pre-tagged)
    needs_classification = ~df_all.get('pattern_tag', pd.Series(dtype=str)).notna()
    if 'pattern_tag' not in df_all.columns:
        classified          = df_all.apply(classify_finding, axis=1)
        df_all['pattern_tag']   = classified.map(lambda x: x[0])
        df_all['pattern_notes'] = classified.map(lambda x: x[1])
    else:
        # Fill in untagged rows (non-slow detectors)
        mask = df_all['pattern_tag'].isna()
        if mask.any():
            classified = df_all[mask].apply(classify_finding, axis=1)
            df_all.loc[mask, 'pattern_tag']   = classified.map(lambda x: x[0]).values
            df_all.loc[mask, 'pattern_notes'] = classified.map(lambda x: x[1]).values

    df_all['severity'] = df_all.apply(severity_label, axis=1)

    # Deduplicate across windows - keep largest breadth per unique event
    df_all['breadth'] = df_all[['distinct_ports', 'distinct_hosts']].fillna(0).max(axis=1)
    df_dedup = (
        df_all
        .sort_values('breadth', ascending=False)
        .drop_duplicates(subset=['scan_type', 'src_ip', 'dst_ip', 'dst_port'], keep='first')
        .reset_index(drop=True)
    )

    sev_order            = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2}
    df_dedup['_sev_ord'] = df_dedup['severity'].map(sev_order)
    df_dedup = (
        df_dedup
        .sort_values(['_sev_ord', 'scan_state_ratio', 'breadth'],
                     ascending=[True, False, False])
        .drop(columns='_sev_ord')
        .reset_index(drop=True)
    )

    return df_dedup


# ══════════════════════════════════════════════════════════════════════════════
# Reporting
# ══════════════════════════════════════════════════════════════════════════════

def print_report(df_dedup: pd.DataFrame, ts_min, ts_max, n_raw: int,
                 min_severity: str = 'LOW', file=sys.stdout):
    """
    Compact tabular report - one row per finding.

    All pattern analysis, notes, and next-steps logic is preserved in the
    DataFrame (pattern_tag, pattern_notes, scan_state_ratio, etc.) and
    in the JSON/CSV exports. The verbose block format will be re-enabled
    once pattern recognition is fully validated across diverse network types.
    """
    w = lambda s: print(s, file=file)

    sev_order   = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2}
    min_sev_ord = sev_order.get(min_severity, 2)

    report_df = df_dedup[
        df_dedup['severity'].map(sev_order) <= min_sev_ord
    ].copy()

    if len(report_df) == 0:
        w(f"No findings at or above {min_severity} severity.")
    else:
        # Summary counts
        counts = report_df['severity'].value_counts()
        w(f"Synthesized findings: {len(report_df)} unique scan events")
        w("severity")
        for sev in ['HIGH', 'MEDIUM', 'LOW']:
            n = counts.get(sev, 0)
            if n:
                w(f"{sev:>8s}    {n}")
        w("")

        # Build display columns - keep it to what fits a terminal cleanly
        display_cols = [
            'severity', 'pattern_tag', 'scan_type', 'src_ip', 'dst_ip',
            'dst_port', 'distinct_ports', 'distinct_hosts',
            'scan_state_ratio', 'window_start', 'direction',
        ]
        # Add spread score column for slow scan findings if present
        if 'temporal_spread_score' in report_df.columns:
            has_slow = report_df['scan_type'].eq('slow').any()
            if has_slow:
                display_cols.insert(display_cols.index('scan_state_ratio'),
                                    'temporal_spread_score')

        # Right-align severity for readability
        report_df['severity'] = report_df['severity'].map(
            lambda s: f"{s:>6s}"
        )

        w(report_df[display_cols].to_string(index=False))

    w("")
    w(f"Data: {ts_min.strftime('%Y-%m-%d %H:%M')} → "
      f"{ts_max.strftime('%Y-%m-%d %H:%M')} UTC  "
      f"({n_raw:,} connections)")


# ══════════════════════════════════════════════════════════════════════════════
# Export
# ══════════════════════════════════════════════════════════════════════════════

def export_results(df_dedup: pd.DataFrame, ts_min, ts_max, n_raw: int,
                   output_dir: Path, run_ts: str, args):
    output_dir.mkdir(parents=True, exist_ok=True)

    if args.format in ('text', 'both'):
        out_txt = output_dir / f"scan_findings_{run_ts}.txt"
        with open(out_txt, 'w') as f:
            print_report(df_dedup, ts_min, ts_max, n_raw,
                         min_severity=args.min_severity, file=f)
        print(f"Report         : {out_txt}")

    if args.format in ('json', 'both'):
        if len(df_dedup) > 0:
            out_json = output_dir / f"scan_findings_{run_ts}.json"
            with open(out_json, 'w') as jf:
                for _, row in df_dedup.iterrows():
                    event = row.to_dict()
                    event['_sourcetype']      = 'sigwood_scan_findings'
                    event['detector_version'] = VERSION
                    event = {k: ('' if v is None else v) for k, v in event.items()}
                    jf.write(json.dumps(event) + '\n')
            print(f"JSON (Splunk)  : {out_json}")

    if len(df_dedup) > 0:
        out_csv = output_dir / f"scan_findings_{run_ts}.csv"
        df_dedup.to_csv(out_csv, index=False)
        print(f"CSV            : {out_csv}")


# ══════════════════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════════════════

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog='conn_scan.py',
        description='Port scan detector - part of the sigwood suite.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    p.add_argument('log_path',
                   help='Path to Zeek conn.log or glob pattern (e.g. logs/conn.*.log.gz)')

    # Network context
    net = p.add_argument_group('network context')
    net.add_argument('--home-nets', nargs='+', metavar='CIDR',
                     default=['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'],
                     help='Internal network CIDRs (default: RFC1918)')
    net.add_argument('--allowlist-ips', nargs='+', metavar='IP',
                     default=[],
                     help='Source IPs to exclude from scan detection')

    # Detection thresholds
    thresh = p.add_argument_group('detection thresholds')
    thresh.add_argument('--vertical-threshold', type=int,
                        default=DEFAULT_VERTICAL_PORT_THRESHOLD,
                        help=f'Distinct ports to trigger vertical scan '
                             f'(default: {DEFAULT_VERTICAL_PORT_THRESHOLD})')
    thresh.add_argument('--horizontal-threshold', type=int,
                        default=DEFAULT_HORIZONTAL_HOST_THRESHOLD,
                        help=f'Distinct hosts to trigger horizontal scan '
                             f'(default: {DEFAULT_HORIZONTAL_HOST_THRESHOLD})')
    thresh.add_argument('--block-port-threshold', type=int,
                        default=DEFAULT_BLOCK_PORT_THRESHOLD,
                        help=f'Port threshold for block scan (default: {DEFAULT_BLOCK_PORT_THRESHOLD})')
    thresh.add_argument('--block-host-threshold', type=int,
                        default=DEFAULT_BLOCK_HOST_THRESHOLD,
                        help=f'Host threshold for block scan (default: {DEFAULT_BLOCK_HOST_THRESHOLD})')
    thresh.add_argument('--block-state-min', type=float,
                        default=DEFAULT_BLOCK_SCAN_STATE_MIN,
                        help=f'Min scan_state_ratio for block scan '
                             f'(default: {DEFAULT_BLOCK_SCAN_STATE_MIN})')
    thresh.add_argument('--slow-state-min', type=float,
                        default=DEFAULT_SLOW_SCAN_STATE_MIN,
                        help=f'Min scan_state_ratio for slow scan '
                             f'(default: {DEFAULT_SLOW_SCAN_STATE_MIN})')
    thresh.add_argument('--slow-min-ports', type=int,
                        default=DEFAULT_SLOW_MIN_PORTS,
                        help=f'Min unique ports for slow scan (default: {DEFAULT_SLOW_MIN_PORTS})')
    thresh.add_argument('--slow-min-buckets', type=int,
                        default=DEFAULT_SLOW_MIN_BUCKETS,
                        help=f'Min active time buckets for slow scan '
                             f'(default: {DEFAULT_SLOW_MIN_BUCKETS})')
    thresh.add_argument('--fast-window', type=int,
                        default=DEFAULT_FAST_WINDOW_SECS,
                        help=f'Fast detection window in seconds (default: {DEFAULT_FAST_WINDOW_SECS})')
    thresh.add_argument('--slow-window', type=int,
                        default=DEFAULT_SLOW_WINDOW_SECS,
                        help=f'Slow detection window in seconds (default: {DEFAULT_SLOW_WINDOW_SECS})')

    # Output
    out = p.add_argument_group('output')
    out.add_argument('--output', metavar='DIR', default=None,
                     help='Write results to this directory (default: print to stdout)')
    out.add_argument('--format', choices=['text', 'json', 'both'], default='text',
                     help='Output format (default: text)')
    out.add_argument('--min-severity', choices=['HIGH', 'MEDIUM', 'LOW'], default='LOW',
                     help='Minimum severity to report (default: LOW)')

    p.add_argument('--verbose', '-v', action='store_true',
                   help='Print progress and diagnostic detail')
    p.add_argument('--version', action='version', version=f'conn_scan.py {VERSION}')

    return p


def main():
    parser = build_parser()
    args   = parser.parse_args()

    run_ts = datetime.now().strftime('%Y%m%d_%H%M%S')

    # ── Load ──────────────────────────────────────────────────────────────────
    print(f"conn_scan.py {VERSION} - loading {args.log_path}")
    try:
        df_raw, n_skipped = load_conn_log(args.log_path, verbose=args.verbose)
    except (FileNotFoundError, ValueError) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    ts_min     = df_raw['ts'].min()
    ts_max     = df_raw['ts'].max()
    span_hours = (ts_max - ts_min).total_seconds() / 3600
    n_raw      = len(df_raw)

    print(f"Loaded {n_raw:,} connections  "
          f"({ts_min.strftime('%Y-%m-%d %H:%M')} → {ts_max.strftime('%Y-%m-%d %H:%M')} UTC, "
          f"{span_hours:.1f}h)")
    if n_skipped:
        print(f"  Skipped {n_skipped:,} malformed rows")

    # ── Pre-filter ────────────────────────────────────────────────────────────
    print("Pre-filtering...")
    df = prefilter(df_raw, args)

    # ── Detect ────────────────────────────────────────────────────────────────
    print("Running vertical scan detection...")
    df_vert_slow = detect_vertical_scans(df, args)
    # Fast window: temporarily override slow_window
    args_fast = argparse.Namespace(**vars(args))
    args_fast.slow_window = args.fast_window
    df_vert_fast = detect_vertical_scans(df, args_fast)

    print("Running horizontal scan detection...")
    df_horiz_slow = detect_horizontal_scans(df, args)
    df_horiz_fast = detect_horizontal_scans(df, args_fast)

    print("Running block scan detection...")
    df_block_slow = detect_block_scans(df, args)
    df_block_fast = detect_block_scans(df, args_fast)

    print("Running slow scan / temporal spread analysis...")
    df_slow = detect_slow_scans(df, args)

    # ── Fingerprint ───────────────────────────────────────────────────────────
    all_dfs     = [df_vert_slow, df_vert_fast, df_horiz_slow, df_horiz_fast,
                   df_block_slow, df_block_fast, df_slow]
    scanner_ips = list(set(
        ip for d in all_dfs if len(d) > 0
        for ip in d['src_ip'].unique()
    ))
    fingerprints = conn_state_fingerprints(df, scanner_ips)

    # ── Synthesize ────────────────────────────────────────────────────────────
    df_findings = synthesize(all_dfs, fingerprints)

    # ── Report ────────────────────────────────────────────────────────────────
    if args.output:
        output_dir = Path(args.output)
        export_results(df_findings, ts_min, ts_max, n_raw,
                       output_dir, run_ts, args)
        print_report(df_findings, ts_min, ts_max, n_raw,
                     min_severity=args.min_severity)
    else:
        print()
        print_report(df_findings, ts_min, ts_max, n_raw,
                     min_severity=args.min_severity)


if __name__ == '__main__':
    main()
