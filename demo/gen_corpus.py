#!/usr/bin/env python3
"""Generate the deterministic synthetic demo corpus for sigwood.

Writes a small Zeek + syslog corpus that exercises the real
loader -> allowlist -> detector -> renderer path, so a short terminal cast can
show sigwood finding a compromised host three ways: beacon (periodic C2),
dns (a high-entropy DGA lookup burst), and syslog (intrusion-narrative needles).

No real network data. Addresses are RFC 5737 documentation space
(192.0.2.x / 198.51.100.x / 203.0.113.x) and RFC 1918 private space
(192.168.x.x); readable domains are the RFC 2606 reserved example.{com,net,org}
family; the malware apex is a random high-entropy label under .xyz. The
generator makes zero network calls and is byte-for-byte deterministic for a
given seed, anchor, and timezone (syslog stamps render in the generating box's
local time), so it is safe to run offline or in CI.

Usage:
    python3 demo/gen_corpus.py [OUT_DIR] [--seed N] [--anchor ISO8601]

Defaults regenerate the exact corpus the demo config and README expect.
"""
from __future__ import annotations

import argparse
import json
import math
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

# The narrative host: one internal machine, compromised, visible three ways.
WEBHOST = "192.168.1.37"
# Two external C2 endpoints (RFC 5737 documentation space).
C2_PRIMARY = "198.51.100.20"      # 3-min beacon, also the SSH source in syslog
C2_SECONDARY = "203.0.113.61"     # 10-min beacon

# Per-channel decorrelation seeds (explicit table - never hash(), which is
# salted per process and would break determinism).
FLOW = {
    "primary_beacon": 0x01,
    "secondary_beacon": 0x02,
    "background_conn": 0x03,
    "dns_background": 0x04,
    "dga": 0x05,
    "dns_allowlist": 0x06,
    "syslog_background": 0x07,
    "syslog_needles": 0x08,
    "syslog_other": 0x0D,
    "reboot": 0x09,
    "apex": 0x0A,
    "dga_timing": 0x0B,
    "conn_bytes": 0x0C,
    "pihole_background": 0x0E,
    "pihole_dga": 0x0F,
    "pihole_blocks": 0x10,
    "pihole_clients": 0x11,
    "pihole_timing": 0x12,
}

WINDOW_SECONDS = 86_400  # a 24h corpus
PIHOLE_DGA_COUNT = 20    # below pihole min_cluster_size so the burst stays noise

# DGA alphabet: digits + consonants (no vowels) - consonant-heavy random labels
# are a realistic DGA shape and clear the detector's entropy gates cleanly.
DGA_ALPHABET = "0123456789bcdfghjklmnpqrstvwxyz"
BASE36 = "0123456789abcdefghijklmnopqrstuvwxyz"


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Generate the sigwood demo corpus.")
    p.add_argument(
        "out_dir", nargs="?", default="demo/corpus",
        help="output directory for the generated corpus (default: demo/corpus)",
    )
    p.add_argument(
        "--seed", type=int, default=3759,
        help="RNG seed (default: 3759 - the corpus the demo expects)",
    )
    p.add_argument(
        "--anchor", default="2026-06-01T00:00:00",
        help="ISO-8601 UTC start of the 24h window (default: 2026-06-01T00:00:00)",
    )
    return p


def main() -> None:
    args = build_parser().parse_args()

    # Anchor as tz-aware UTC so .timestamp() is identical across machines and
    # timezones - a naive .timestamp() is local-tz-dependent and would break
    # byte-for-byte determinism. Syslog stamps are rendered in local time
    # (_sysline_ts) to match the parser's host-local wall-clock interpretation.
    anchor = datetime.fromisoformat(args.anchor).replace(tzinfo=timezone.utc)
    epoch0 = anchor.timestamp()

    def rng_for(channel: str) -> random.Random:
        return random.Random(args.seed ^ FLOW[channel])

    conn_rows: list[dict] = []
    dns_rows: list[dict] = []
    syslog_lines: list[tuple[float, str]] = []
    pihole_lines: list[tuple[float, str]] = []

    _gen_conn(conn_rows, rng_for, epoch0)
    apex = _gen_dns(dns_rows, rng_for, epoch0)
    _gen_pihole(pihole_lines, rng_for, anchor, apex)
    _gen_syslog(syslog_lines, rng_for, anchor)

    out = Path(args.out_dir)
    zeek = out / "zeek"
    syslog = out / "syslog"
    pihole = out / "pihole"
    zeek.mkdir(parents=True, exist_ok=True)
    syslog.mkdir(parents=True, exist_ok=True)
    pihole.mkdir(parents=True, exist_ok=True)

    _write_ndjson(zeek / "conn.log", conn_rows)
    _write_ndjson(zeek / "dns.log", dns_rows)
    _write_syslog(syslog / "messages", syslog_lines)
    _write_pihole(pihole / "pihole.log", pihole_lines)

    print(f"wrote {len(conn_rows)} conn, {len(dns_rows)} dns, "
          f"{len(pihole_lines)} pihole, {len(syslog_lines)} syslog lines")
    print(f"  {zeek/'conn.log'}")
    print(f"  {zeek/'dns.log'}")
    print(f"  {pihole/'pihole.log'}")
    print(f"  {syslog/'messages'}")
    print(f"  DGA apex: {apex}")


# ---------------------------------------------------------------------------
# conn.log - two beacons + shaped background
# ---------------------------------------------------------------------------

def _conn_row(rows: list[dict], ts: float, src: str, dst: str, port: int,
              proto: str, orig_bytes: int, resp_bytes: int, state: str,
              duration: float) -> None:
    rows.append({
        "_path": "conn",
        "ts": round(ts, 6),
        "uid": f"C{len(rows):07d}",
        "id.orig_h": src,
        "id.resp_h": dst,
        "id.resp_p": port,
        "proto": proto,
        "orig_bytes": orig_bytes,
        "resp_bytes": resp_bytes,
        "conn_state": state,
        "local_orig": True,
        "duration": round(duration, 6),
    })


def _gen_conn(rows: list[dict], rng_for, epoch0: float) -> None:
    # Primary beacon - periodic 3-minute C2, the more prominent of the two.
    # A 60s cadence sits exactly at the 30s-bin Nyquist limit, where the score
    # is anchor-sensitive (identical flows score far apart by how arrivals fall
    # against bin edges); a cleanly-resolved 180s period is what the detector
    # reliably flags. Earns a solid MEDIUM.
    # resp/orig byte ratio varies per flow (a fixed multiple is an obvious tell);
    # drawn from its own channel so it never perturbs the beacon timing.
    bb = rng_for("conn_bytes")
    rb = rng_for("primary_beacon")
    for i in range(480):
        ts = epoch0 + i * 180 + rb.uniform(-3.5, 3.5)
        ob = rb.randint(200, 500)
        _conn_row(rows, ts, WEBHOST, C2_PRIMARY, 443, "tcp",
                  ob, int(ob * bb.uniform(2.4, 3.6)), "SF", rb.uniform(0.05, 0.4))

    # Secondary beacon - slower 10-minute C2. Scores MEDIUM, below the primary.
    rb = rng_for("secondary_beacon")
    for i in range(144):
        ts = epoch0 + i * 600 + rb.uniform(-12, 12)
        ob = rb.randint(300, 900)
        _conn_row(rows, ts, WEBHOST, C2_SECONDARY, 8443, "tcp",
                  ob, int(ob * bb.uniform(2.4, 3.6)), "SF", rb.uniform(0.1, 0.8))

    # Background - aperiodic internal traffic, shaped to trip NEITHER beacon
    # (no 4-tuple gets a periodic run of 20+), scan (no src fans many ports at
    # one host), NOR duration (every duration well under the 1800s floor).
    rb = rng_for("background_conn")
    internal = [f"192.168.1.{h}" for h in range(20, 31)]
    external = ([f"198.51.100.{n}" for n in range(30, 60)]
                + [f"203.0.113.{n}" for n in range(30, 60)]
                + [f"192.0.2.{n}" for n in range(30, 60)])
    dsts = internal + external
    for _ in range(2000):
        ts = epoch0 + rb.uniform(0, WINDOW_SECONDS)
        src = rb.choice(internal)
        dst = rb.choice(dsts)
        if dst == src:
            dst = rb.choice(external)
        port = rb.choice([80, 443, 443, 443, 22])
        ob = rb.randint(120, 8000)
        _conn_row(rows, ts, src, dst, port, "tcp",
                  ob, rb.randint(120, 40000),
                  rb.choice(["SF", "SF", "S1"]), rb.uniform(0.02, 5.0))

    rows.sort(key=lambda r: r["ts"])


# ---------------------------------------------------------------------------
# dns.log - DGA burst + readable background + allowlist-bite minority
# ---------------------------------------------------------------------------

def _dns_row(rows: list[dict], ts: float, src: str, query: str, qtype: int,
             rtt: float, rcode: int, ttls: list[int], answers: list[str]) -> None:
    rows.append({
        "_path": "dns",
        "ts": round(ts, 6),
        "id.orig_h": src,
        "query": query,
        "qtype": qtype,
        "rtt": round(rtt, 6),
        "rcode": rcode,
        "TTLs": ttls,
        "answers": answers,
        "TC": False,
    })


def _hour_weights(rng: random.Random) -> list[float]:
    """24 hourly weights = a two-bump envelope (a big morning peak + a smaller
    evening one) times a per-hour noise multiplier, so the digest histogram has
    real shape AND ragged bin-to-bin variation instead of a clean synthetic bell."""
    def bump(h: float, mu: float, sigma: float) -> float:
        return math.exp(-0.5 * ((h - mu) / sigma) ** 2)
    return [
        (0.68 * bump(h, 9.0, 2.4) + 0.32 * bump(h, 18.5, 1.5)) * rng.uniform(0.5, 1.5)
        + 0.03
        for h in range(24)
    ]


def _gen_dns(rows: list[dict], rng_for, epoch0: float) -> str:
    # Readable background - a handful of service names under the RFC 2606
    # reserved example family, resolving cleanly. High volume + regularity.
    rb = rng_for("dns_background")
    services = [
        "www.example.com", "api.example.com", "cdn.example.net",
        "mail.example.com", "update.example.net", "ntp.example.org",
        "auth.example.com", "assets.example.net",
    ]
    internal = [f"192.168.1.{h}" for h in range(20, 41)]
    # Sample each query's hour from the ragged two-bump envelope, then a uniform
    # offset within that hour - real activity with shape and high-frequency noise,
    # not a flat smear or a clean bell. Drawn from the seeded channel (determinism).
    hour_w = _hour_weights(rb)
    hours = list(range(24))
    for _ in range(3000):
        h = rb.choices(hours, weights=hour_w)[0]
        ts = epoch0 + h * 3600 + rb.uniform(0, 3600)
        query = rb.choice(services)
        qtype = rb.choice([1, 1, 1, 28])
        _dns_row(rows, ts, rb.choice(internal), query, qtype,
                 rb.uniform(0.005, 0.05), 0,
                 [rb.choice([300, 3600])],
                 [f"198.51.100.{rb.randint(10, 250)}"])

    # DGA - one high-entropy apex under .xyz, a burst of distinct random
    # subdomains from the compromised host, mostly NXDOMAIN. All share the
    # registrable domain -> ONE grouped finding.
    ra = rng_for("apex")
    apex_label = "".join(ra.choice(BASE36) for _ in range(ra.randint(10, 12)))
    apex = f"{apex_label}.xyz"
    rb = rng_for("dga")
    rt = rng_for("dga_timing")   # pacing on its own channel - labels stay fixed
    t = epoch0 + 43_200
    for i in range(14):
        label = "".join(rb.choice(DGA_ALPHABET)
                        for _ in range(rb.randint(12, 18)))
        # DGA probes cluster tightly - a few seconds apart, not minutes.
        t += rt.uniform(2, 8)
        ts = t + rb.uniform(-1.5, 1.5)
        nx = i >= 2  # first two resolve, the rest NXDOMAIN
        _dns_row(rows, ts, WEBHOST, f"{label}.{apex}", 1,
                 rb.uniform(0.02, 0.2),
                 3 if nx else 0,
                 [rb.choice([30, 45])],
                 [] if nx else [f"203.0.113.{rb.randint(10, 250)}"])

    # Allowlist bite - a minority of queries the shipped domains_common list
    # suppresses before the detector runs (reverse-PTR .arpa, mDNS .local,
    # DNS-SD _service). Kept small so real background still dominates.
    rb = rng_for("dns_allowlist")
    for _ in range(200):
        ts = epoch0 + rb.uniform(0, WINDOW_SECONDS)
        src = rb.choice(internal)
        kind = rb.choice(["arpa", "arpa", "local", "sd"])
        if kind == "arpa":
            o = rb.randint(10, 250)
            query = f"{o}.100.51.198.in-addr.arpa"
            qtype = 12
        elif kind == "local":
            query = rb.choice(["printer.local", "nas.local", "hub.local"])
            qtype = 1
        else:
            query = rb.choice(["_ipp._tcp.local", "_http._tcp.local",
                               "_workstation._tcp.local"])
            qtype = 12
        _dns_row(rows, ts, src, query, qtype,
                 rb.uniform(0.001, 0.01), 0, [120], [])

    rows.sort(key=lambda r: r["ts"])
    return apex


# ---------------------------------------------------------------------------
# pihole/pihole.log - dnsmasq background + modest DGA burst + blocks
# ---------------------------------------------------------------------------

def _pihole_emit(
    lines: list[tuple[float, str]],
    anchor: datetime,
    offset: float,
    message: str,
) -> None:
    stamp = _sysline_ts(anchor, offset)
    lines.append((offset, f"{stamp} pihole dnsmasq[1234]: {message}"))


def _pihole_answer(domain: str, qtype: str, rng: random.Random) -> str:
    if qtype == "AAAA":
        return f"2001:db8::{rng.randint(10, 999):x}"
    if qtype == "PTR":
        return rng.choice(["printer.local", "gateway.local", "nas.local"])
    if qtype == "HTTPS":
        return "svc 1 . alpn=h2"
    if qtype == "TXT":
        return '"v=spf1 -all"'
    return f"198.51.100.{rng.randint(10, 250)}"


def _pihole_query_type(domain: str, rng: random.Random) -> str:
    if domain.endswith(".in-addr.arpa") or domain.endswith(".local"):
        return "PTR"
    if domain.startswith("_"):
        return "PTR"
    return rng.choices(
        ["A", "AAAA", "HTTPS", "TXT", "SRV"],
        weights=[70, 14, 9, 4, 3],
    )[0]


def _pihole_query_exchange(
    lines: list[tuple[float, str]],
    anchor: datetime,
    offset: float,
    src: str,
    domain: str,
    qtype: str,
    rng: random.Random,
    *,
    cached: bool,
) -> None:
    _pihole_emit(lines, anchor, offset, f"query[{qtype}] {domain} from {src}")
    answer = _pihole_answer(domain, qtype, rng)
    if cached:
        _pihole_emit(lines, anchor, offset + 0.04, f"cached {domain} is {answer}")
        return
    upstream = rng.choice(["192.0.2.53", "198.51.100.53", "203.0.113.53"])
    _pihole_emit(lines, anchor, offset + 0.03, f"forwarded {domain} to {upstream}")
    _pihole_emit(lines, anchor, offset + 0.11, f"reply {domain} is {answer}")


def _gen_pihole(
    lines: list[tuple[float, str]],
    rng_for,
    anchor: datetime,
    apex: str,
) -> None:
    rb = rng_for("pihole_background")
    rc = rng_for("pihole_clients")
    rt = rng_for("pihole_timing")

    services = [
        "api.example.com", "www.example.com", "cdn.example.net",
        "mail.example.com", "update.example.net", "ntp.example.org",
        "auth.example.com", "assets.example.net", "vpn.example.com",
        "status.example.org",
    ]
    generated = (
        [
            f"{name}.example.com" for name in (
                "portal", "intranet", "calendar", "payroll", "helpdesk",
                "files", "docs", "search", "reports", "billing", "photos",
                "music", "video", "forms", "print", "backup", "inventory",
                "training", "directory", "welcome",
            )
        ]
        + [
            f"{name}.example.net" for name in (
                "relay", "resolver", "mirror", "updates", "packages",
                "time", "vpn", "auth", "cache", "proxy", "mail", "assets",
                "news", "monitor", "metrics",
            )
        ]
        + [
            f"{name}.example.org" for name in (
                "wiki", "forum", "donate", "events", "status", "docs",
                "library", "archive", "support", "alerts",
            )
        ]
    )
    reserved_chatter = [
        "10.100.51.198.in-addr.arpa", "42.100.51.198.in-addr.arpa",
        "printer.local", "gateway.local", "_ipp._tcp.local",
        "_workstation._tcp.local",
    ]
    domains = services + generated + reserved_chatter
    domain_weights = [
        300 if domain == "api.example.com" else
        45 if domain in services else
        10
        for domain in domains
    ]

    clients = [f"192.168.1.{h}" for h in range(20, 41)]
    client_weights = [80 if client == WEBHOST else 4 for client in clients]
    hour_w = _hour_weights(rb)
    hours = list(range(24))

    for _ in range(950):
        h = rb.choices(hours, weights=hour_w)[0]
        offset = h * 3600 + rt.uniform(0, 3600)
        src = rc.choices(clients, weights=client_weights)[0]
        domain = rb.choices(domains, weights=domain_weights)[0]
        qtype = _pihole_query_type(domain, rb)
        _pihole_query_exchange(
            lines, anchor, offset, src, domain, qtype, rb,
            cached=rb.random() < 0.34,
        )

    # A modest burst: below the pihole min_cluster_size so it remains noise,
    # while the long labels still make the digest query-length tail obvious.
    rd = rng_for("pihole_dga")
    t = 43_200.0
    for _ in range(PIHOLE_DGA_COUNT):
        label = "".join(rd.choice(DGA_ALPHABET)
                        for _ in range(rd.randint(42, 52)))
        domain = f"{label}.{apex}"
        t += rt.uniform(3, 9)
        _pihole_emit(lines, anchor, t, f"query[A] {domain} from {WEBHOST}")
        _pihole_emit(lines, anchor, t + 0.03,
                     f"forwarded {domain} to 198.51.100.53")
        _pihole_emit(lines, anchor, t + 0.10, f"reply {domain} is NXDOMAIN")

    block_rng = rng_for("pihole_blocks")
    block_domains = [
        "ads.bad.invalid", "telemetry.bad.test", "tracker.bad.invalid",
        "metrics.bad.test", "banner.bad.invalid",
    ]
    for i in range(110):
        offset = block_rng.uniform(0, WINDOW_SECONDS)
        src = rc.choices(clients, weights=client_weights)[0]
        domain = block_rng.choice(block_domains)
        _pihole_emit(lines, anchor, offset, f"query[A] {domain} from {src}")
        if i % 2 == 0:
            _pihole_emit(
                lines, anchor, offset + 0.04,
                f"gravity blocked (demo) {domain} is 0.0.0.0",
            )
        else:
            _pihole_emit(
                lines, anchor, offset + 0.04,
                f"regex denied {domain} is 0.0.0.0",
            )

    lines.sort(key=lambda x: x[0])


# ---------------------------------------------------------------------------
# syslog/messages - templated background + needles + reboot burst
# ---------------------------------------------------------------------------

def _sysline_ts(anchor: datetime, offset: float) -> str:
    dt = (anchor + timedelta(seconds=offset)).astimezone()
    # RFC 3164 header: space-padded day (not %e - portability/determinism).
    return f"{dt.strftime('%b')} {dt.day:2d} {dt.strftime('%H:%M:%S')}"


def _gen_syslog(lines: list[tuple[float, str]], rng_for, anchor: datetime) -> None:
    def emit(offset: float, host: str, body: str) -> None:
        # Traditional on-disk RFC 3164 format (RHEL/Fedora /var/log/messages):
        # no numeric <PRI> prefix - that is the network-wire form, stripped on
        # write. Header is `Mon DD HH:MM:SS host tag: message`.
        stamp = _sysline_ts(anchor, offset)
        lines.append((offset, f"{stamp} {host} {body}"))

    # Templated background - a few stable, high-count templates across three
    # hosts. Deliberately NO `Accepted ... for ...` sshd shape: at drain3
    # sim_thresh=0.5 it would merge with the root-login needle and steal its
    # rarity. Background sshd uses connection-close / session lines instead.
    rb = rng_for("syslog_background")
    hosts = ["webhost", "app01", "db01"]
    for _ in range(2000):
        offset = rb.uniform(0, WINDOW_SECONDS)
        host = rb.choice(hosts)
        pid = rb.randint(600, 9999)
        choice = rb.random()
        if choice < 0.30:
            emit(offset, host,
                 f"CRON[{pid}]: (root) CMD (/usr/bin/healthcheck)")
        elif choice < 0.55:
            sess = rb.randint(1000, 9999)
            emit(offset, host,
                 f"systemd[1]: Started Session {sess} of user deploy.")
        elif choice < 0.75:
            h = rb.randint(20, 40)
            emit(offset, host,
                 f"dhclient[{pid}]: DHCPACK of 192.168.1.{h} from 192.168.1.1")
        elif choice < 0.90:
            n = rb.randint(30, 59)
            emit(offset, host,
                 f"postfix/smtpd[{pid}]: connect from "
                 f"mail.example.com[198.51.100.{n}]")
        else:
            h = rb.randint(20, 40)
            port = rb.randint(30000, 60000)
            emit(offset, host,
                 f"sshd[{pid}]: Connection closed by 192.168.1.{h} port {port}")

    # The intrusion narrative on webhost, in TWO tight clusters (each a ~2-3 min
    # span) with ~an hour between them: break-in + privilege escalation, then
    # persistence. Each line is a structurally unique count-1 template -> MEDIUM.
    # Within-cluster gaps stay > burst_gap_seconds (60s) so the lines stay ISOLATED
    # rare events and never collapse into a burst (the burst split is >= 60s).
    rn = rng_for("syslog_needles")
    clusters = [
        [   # initial access + privilege escalation
            f"sshd[24815]: Accepted password for root from {C2_PRIMARY} port 44122 ssh2",
            "sudo: www-data : TTY=unknown ; PWD=/var/www/html ; USER=root ; COMMAND=/bin/bash",
            "useradd[24980]: new user: name=systemd-worker, UID=0, GID=0",
        ],
        [   # persistence, ~an hour later
            "crontab[25007]: (root) REPLACE (root)",
            "sshd[25120]: Server listening on 0.0.0.0 port 8443.",
        ],
    ]
    at = 3700.0 + rn.uniform(0, 400)
    for group in clusters:
        t = at
        for body in group:
            emit(t, "webhost", body)
            t += rn.uniform(70, 105)          # > 60s: stays isolated; ~2-3 min span
        at = t + rn.uniform(3300, 4200)       # ~an hour to the next cluster

    # A few benign-but-rare events on ANOTHER host (db01), spread across the day,
    # so the hunt surfaces believable noise AROUND the intrusion - not a corpus
    # where every rare line is the attack. Each is a unique count-1 template, well
    # separated in time (no burst), and interleaves chronologically with webhost.
    ro = rng_for("syslog_other")
    other = [
        "kernel: EXT4-fs (sda1): mounted filesystem with ordered data mode",
        "smartd[812]: Device: /dev/sda, SMART Prefailure Attribute: Reallocated_Sector_Ct",
        "named[1103]: network unreachable resolving './NS/IN'",
        "kernel: usb 2-1: new high-speed USB device number 7 using xhci_hcd",
    ]
    for i, body in enumerate(other):
        emit(i * 5400 + 2000 + ro.uniform(-600, 600), "db01", body)

    # Reboot burst on gateway - a wall of boot lines within ~10s. Distinct
    # messages stay count-1 (rare); the tight gaps collapse them into ONE INFO
    # burst, and the Linux-version banner labels it "rebooted". The kernel
    # ring-buffer clock advances by uneven per-subsystem gaps (real dmesg is
    # never a fixed step) but stays monotonic.
    rb = rng_for("reboot")
    base = 50_000.0
    subsystems = _reboot_subsystems()
    units = _reboot_units()
    emit(base, "gateway",
         "kernel: [    0.000000] Linux version 6.1.0-27-amd64 "
         "(debian-kernel@lists.debian.org) #1 SMP PREEMPT_DYNAMIC")
    boot = 0.0
    for word in subsystems:
        boot += rb.uniform(0.02, 0.35)
        emit(base + boot, "gateway",
             f"kernel: [{boot:11.6f}] bringing up {word}")
    for unit in units:
        boot += rb.uniform(0.05, 0.60)
        emit(base + boot, "gateway",
             f"systemd[1]: Started {unit}.")

    lines.sort(key=lambda x: x[0])


def _reboot_subsystems() -> list[str]:
    return [
        "ACPI subsystem", "PCI host bridge to bus 0000:00",
        "SCSI subsystem", "USB core support", "thermal management",
        "power management", "clocksource tsc", "RAPL PMU counters",
        "IOMMU DMA remapping", "virtio-net interface eth0",
        "ext4 journal recovery", "cgroup hierarchy v2", "netfilter conntrack",
        "cryptd worker pool", "random number generator", "watchdog nmi",
        "hugepage allocator", "ftrace ring buffer", "audit subsystem",
        "loop device driver", "bridge netfilter", "ipv6 addrconf",
        "software raid md0", "tpm chip tpm0", "serial 8250 ports",
        "hpet timer", " nvme controller nvme0", "sd card host mmc0",
        "gpio controller", "i2c adapter smbus", "rtc cmos clock",
        "efivars firmware", "cpu microcode loader", "smp boot secondary",
    ]


def _reboot_units() -> list[str]:
    return [
        "Journal Service", "udev Kernel Device Manager",
        "Network Time Synchronization", "D-Bus System Message Bus",
        "Login Service", "OpenSSH server daemon",
        "Regular background program processing daemon",
        "Permit User Sessions", "Network Manager",
        "Firewall nftables ruleset", "System Logging Service",
        "Docker Application Container Engine", "Prometheus node exporter",
        "Unattended Upgrades Shutdown", "Disk Manager", "Snap Daemon",
    ]


# ---------------------------------------------------------------------------
# writers
# ---------------------------------------------------------------------------

def _write_ndjson(path: Path, rows: list[dict]) -> None:
    with path.open("w") as f:
        for row in rows:
            f.write(json.dumps(row, sort_keys=True) + "\n")


def _write_syslog(path: Path, lines: list[tuple[float, str]]) -> None:
    with path.open("w") as f:
        for _, line in lines:
            f.write(line + "\n")


def _write_pihole(path: Path, lines: list[tuple[float, str]]) -> None:
    with path.open("w") as f:
        for _, line in lines:
            f.write(line + "\n")


if __name__ == "__main__":
    main()
