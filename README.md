<img src="https://raw.githubusercontent.com/helixmap/sigwood/main/docs/img/sigwood-logo.png"
     align="left" width="130" hspace="14" vspace="6"
     alt="sigwood - a cut log whose tree rings form a fingerprint">

*between grep and a SIEM*

[![CI](https://github.com/helixmap/sigwood/actions/workflows/ci.yml/badge.svg)](https://github.com/helixmap/sigwood/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/sigwood)](https://pypi.org/project/sigwood/) <br>
![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](#license)

<br><br clear="all">

**`sigwood`** is a local-first, command-line threat-hunting tool for self-hosters. Point it at
logs you already have - Zeek, Pi-hole/dnsmasq, syslog, or CloudTrail - and it profiles
what's in them, then runs a handful of detectors over them: beaconing, suspicious DNS, port
scans, bulk outbound transfers, out-of-character TLS setups, authentication structure, rare
syslog events, unusual CloudTrail activity, and behavioral patterns in names your Pi-hole
already blocked.

**Not a SIEM. Not an agent. Not magic.** Nothing to deploy - no database, no daemon, no network, 
no account. Install it, point it at a directory of logs, read the output. It runs on your own
box, over logs at rest, and your logs never have to leave your machine.

> **Status: early / pre-1.0 (`0.7.0`).** The nine detectors work and are covered by tests,
> but things may change before 1.0. Built with heavy AI assistance under human review;
> the [FAQ says how](https://github.com/helixmap/sigwood/blob/main/docs/FAQ.md#a-brand-new-repo-a-short-history-tidy-docs---was-this-written-by-ai),
> and the [evidence ledger](https://github.com/helixmap/sigwood/blob/main/docs/EVIDENCE.md)
> records what has and has not been measured. Feedback is welcome.

<p align="center">
  <b><a href="#quick-start">Install</a></b> ·
  <a href="https://github.com/helixmap/sigwood/blob/main/docs/MANUAL.md">Manual</a> ·
  <a href="https://github.com/helixmap/sigwood/blob/main/docs/FAQ.md">FAQ</a> ·
  <a href="https://github.com/helixmap/sigwood/blob/main/docs/CONTRACT.md">Contract</a> ·
  <a href="https://github.com/helixmap/sigwood/blob/main/docs/ROADMAP.md">Roadmap</a> ·
  <a href="https://github.com/helixmap/sigwood/blob/main/docs/KNOWN-ISSUES.md">Known issues</a> ·
  <a href="https://github.com/helixmap/sigwood/blob/main/docs/SCHEMA.md">Schemas</a> ·
  <a href="https://github.com/helixmap/sigwood/blob/main/SECURITY.md">Security</a>
</p>

## Quick start

```bash
pipx install sigwood        # or: pip install sigwood in a venv - see Installation

sigwood /var/log/           # point it at a directory
sigwood /opt/zeek/dns.log   # or a single file
```

That's it - no config required. Here is the kind of thing a run surfaces (illustrative
output, not real network data):

```
dns - 1 finding · 1 high
Finds domain names that stand apart from the rest, including
machine-generated-looking names of the sort malware uses for disposable
command domains, and large batches of related lookups. You decide how
machine-generated a name must look, and how large a batch of lookups counts.
────────────────────────────────────────────────────────────────────────────────
groups (1)
          names  entropy score  queries  clients
  high       16  2.10-1.85          418        1  k7x2p9qz3f.example

beacon - 2 findings · 2 medium
Finds outbound connections that keep a regular rhythm, a pattern worth checking
for automated check-ins. You decide how strict the rhythm has to be before it
surfaces.
────────────────────────────────────────────────────────────────────────────────
medium  192.168.1.37  →  198.51.100.20:443/tcp    period=3.0m    rhythm=0.624   480 conns
medium  192.168.1.37  →  203.0.113.50:8443/tcp    period=10.0m   rhythm=0.606   144 conns

syslog - 1 finding · 1 medium
Finds rare log patterns and recorded reboots or administrative runs, so changes
on a machine do not disappear into routine logs. You decide how seldom a
pattern must appear to count as rare.
────────────────────────────────────────────────────────────────────────────────
privileged (1)
  medium  Accepted password for root from 198.51.100.20 port 51900 ssh2

-v explains why each finding surfaced
```

Read top to bottom, that is a story: an internal host making high-entropy lookups under one
throwaway domain, calling out to two external IPs on a fixed schedule, and a root SSH login
from one of those same IPs. A finding means "unusual for **your** network," not "known-bad" -
it is a lead to look at, not a verdict. Add `-v` for the evidence behind each score and the
next steps to run it down.

**Only have a Pi-hole?** That is a complete setup on its own:

```bash
sigwood digest /var/log/pihole/pihole.log   # orient: what's in the log
sigwood /var/log/pihole/                    # hunt: DNS clustering over your queries
sigwood dnsblock /var/log/pihole/           # bonus: behavior in names Pi-hole blocked
```

The usual invocations:

```bash
sigwood digest /var/log/messages     # orient first - a fast, factual profile of a file
sigwood graph /opt/zeek              # replay the flows as a self-contained HTML artifact
sigwood syslog /var/log              # run a single detector
sigwood init                         # detection-driven setup, writes a config
sigwood hunt                         # run the curated default hunt
```

**No logs handy?** The repository includes a small synthetic corpus generator - one
compromised host, no real network data - so you can watch it work first:

```bash
git clone https://github.com/helixmap/sigwood
cd sigwood
python3 demo/gen_corpus.py                 # writes a synthetic corpus; no network calls
sigwood hunt --config=demo/sigwood.toml    # beacons, a DGA burst, a bulk transfer out, and the syslog trail
```

The generated logs live under `demo/corpus/` (gitignored); the full walkthrough is in
[`demo/README.md`](https://github.com/helixmap/sigwood/blob/main/demo/README.md). Here is a
full run against that corpus, followed by the same findings in HTML format:

<p align="center">
  <img src="https://raw.githubusercontent.com/helixmap/sigwood/main/docs/img/demo.svg" width="760" alt="sigwood hunting one compromised host across conn, DNS, and syslog - synthetic RFC 5737 data with random-label demo domains">
</p>
<p align="center">
  <img src="https://raw.githubusercontent.com/helixmap/sigwood/main/docs/img/report.png"
       width="760" alt="sigwood html report">
</p>

...and the same flows replayed by `sigwood graph`, one self-contained HTML file:

<p align="center">
  <img src="https://raw.githubusercontent.com/helixmap/sigwood/main/docs/img/graph.gif"
       width="760" alt="sigwood graph replaying conn.log flows as an animated Sankey - hosts, the services they reach, and destination hosts across a morning of traffic; scrambled sample data">
</p>


## Installation

One name everywhere: the PyPI distribution, the command, the import package, and the config
section are all `sigwood`. Requires **Python 3.11+**.

The recommended install is [pipx](https://pipx.pypa.io), which keeps sigwood in its own
isolated environment and on your PATH (and sidesteps the `externally-managed-environment`
refusal a bare `pip install` hits on modern distros):

```bash
# Debian / Raspberry Pi OS / Ubuntu:  sudo apt install pipx
# Fedora:                             sudo dnf install pipx
# macOS:                              brew install pipx

pipx ensurepath              # once - then reopen your shell
pipx install sigwood
sigwood --help
```

Prefer [uv](https://docs.astral.sh/uv/)? `uv tool install sigwood` does the same job, and a
plain virtualenv also works. Optional extras, upgrades, `sudo pip` recovery, and the on-disk
footprint are all in the
[manual](https://github.com/helixmap/sigwood/blob/main/docs/MANUAL.md#installing-and-upgrading).

## What it hunts

| Detector  | Surfaces                                            | Method                       | Source                         |
|-----------|-----------------------------------------------------|------------------------------|--------------------------------|
| `beacon`  | periodic C2-style callbacks                         | FFT over connection timing   | Zeek `conn.log`                |
| `dns`     | DGA / tunneling / anomalous lookups                 | HDBSCAN clustering           | Zeek `dns.log` **or** Pi-hole  |
| `dnsblock` \* | new blocked names, bursts & recurrence | pattern (bounded behavioral) | Pi-hole                        |
| `syslog`  | rare events & reboots                               | drain3 templating + rarity   | journal, syslog, **or** Zeek `syslog.log` |
| `auth` \* | failure concentration, volume, spread & landings    | heuristics                   | journal, syslog, **or** Zeek `syslog.log` |
| `scan`    | vertical / horizontal / block / slow port scans     | pattern (heuristic)          | Zeek `conn.log`                |
| `exfil`   | bulk outbound byte transfer                        | heuristics                   | Zeek `conn.log`                |
| `ssl` \*  | outbound TLS setup unlike your estate's norm         | heuristics                   | Zeek `ssl.log` (+ `x509.log`)  |
| `aws`     | per-principal anomalous CloudTrail behavior         | statistical (z-score composite) | CloudTrail `*.json*` (incl. `.gz`) |

\* opt-in: `dnsblock`, `auth`, and `ssl` are not in the curated default hunt. Run one by
name (`sigwood dnsblock /var/log/pihole/`), select it with `--detect`, or run everything with `--detect=all`.

`dns` and `syslog` each answer **one** question across several source families -
Zeek and Pi-hole for DNS; the live systemd journal, flat rsyslog, and Zeek's own
`syslog.log` for syslog - and adapt to whichever fidelity they're handed. On a
systemd host `syslog` prefers the live journal by default.

Run the curated default hunt (`sigwood hunt`), or just some (`sigwood hunt --detect=beacon,dns`). Each detector is also its own subcommand: `sigwood beacon ~/zeek`.

**And what it doesn't hunt.** sigwood watches up to three flanks - your network,
your system logs, and your cloud API activity - whichever of them you actually
have, and with no agent on your machines, so some attacker behavior stays out of
view however good the detectors get. The
[roadmap](https://github.com/helixmap/sigwood/blob/main/docs/ROADMAP.md) maps
both halves onto the [MITRE ATT&CK](https://attack.mitre.org/) matrix, tactic by
tactic: what sigwood sees today, what could narrow each gap, and which gaps it
will never close - some because closing them would mean shipping threat-intel
feeds or signature packs instead of behavior, others because they sit outside
its agentless, behavior-first design. sigwood aims for the top of the
[pyramid of pain](https://www.attackiq.com/glossary/pyramid-of-pain-2/) as a
design muse, and will not enumerate badness.

## Evidence and field validation

The [evidence ledger](https://github.com/helixmap/sigwood/blob/main/docs/EVIDENCE.md)
lists what has been measured for every detector, the limits of each result, and what is
still owed. To help test sigwood on an environment that did not shape it, use the
privacy-bounded
[field validation kit](https://github.com/helixmap/sigwood/blob/main/docs/FIELDKIT.md).

## Where it stands

sigwood's North Star is behavior: beacon uses an FFT over connection timing; dns uses
HDBSCAN clustering over per-query behavior; syslog uses drain3 log-templating plus rarity;
aws uses a per-principal z-score composite; auth uses authentication structure across failures,
services, sources, accounts, and hosts. Every run names the technique each detector used, and
`-v` shows the evidence behind a finding. A finding is a lead, not a verdict - severity marks
what deserves review first, and HIGH is deliberately scarce.

The curated default hunt is a short, reviewed list, and the
[evidence ledger](https://github.com/helixmap/sigwood/blob/main/docs/EVIDENCE.md) records what
each detector has and has not been measured on; `dnsblock` stays opt-in at 1.0. When it runs,
`dnsblock` reaches beyond the report window for history, extending file selection over
`default_window`. With the stock `7d` setting, that is a 28-day file-selection aperture - four
times the report span by duration, though the number of files depends on the rotation layout.

If you know [RITA](https://github.com/activecm/rita) (or AC-Hunter), the
beacon-hunting goal will look familiar - RITA is excellent at it. sigwood
differs in conception: frequency domain, no database, no import step, several
log families rather than conn/dns alone, and an orientation verb for logs you
have not met yet. If you already run RITA against a dedicated Zeek sensor, keep
it - sigwood is for the box where the logs already live.

## Digging deeper

The [manual](https://github.com/helixmap/sigwood/blob/main/docs/MANUAL.md) is the deep door:
verbs and exit codes, source discovery, windows and time, every detector in depth, output,
tuning, and exporters, in the order a hunt runs. The
[FAQ](https://github.com/helixmap/sigwood/blob/main/docs/FAQ.md) answers objections,
[known issues](https://github.com/helixmap/sigwood/blob/main/docs/KNOWN-ISSUES.md) quantifies
the rough edges, the [contract](https://github.com/helixmap/sigwood/blob/main/docs/CONTRACT.md)
says what stays stable through 1.x, and
[CONTRIBUTING](https://github.com/helixmap/sigwood/blob/main/CONTRIBUTING.md) covers building
from source and adding a detector.

## License

MIT. See the [MIT License](https://github.com/helixmap/sigwood/blob/main/LICENSE).
