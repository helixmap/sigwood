<!--
<p align="center">
  <img src="https://raw.githubusercontent.com/helixmap/sigwood/main/docs/img/sigwood-logo.png" width="300" alt="sigwood">
</p>
-->
[![CI](https://github.com/helixmap/sigwood/actions/workflows/ci.yml/badge.svg)](https://github.com/helixmap/sigwood/actions/workflows/ci.yml)

sigwood is a local-first, command-line threat-hunting tool for self-hosters. Point it at
logs you already have - Zeek, Pi-hole/dnsmasq, syslog, or CloudTrail - and it profiles
what's in them, then runs a handful of detectors over them: beaconing, suspicious DNS, port
scans, rare syslog events, over-long connections, and unusual CloudTrail activity.

**Not a SIEM. Not an agent. Not magic.** Nothing to deploy - no database, no daemon, no network, 
no account. Install it, point it at a directory of logs, read the output. It runs on your own
box, over logs at rest, and your logs never have to leave your machine.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](#license)
![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)

> **Status: early / pre-1.0 (`0.2.6`).** The six detectors work and are covered by tests,
> but things may change before 1.0. Feedback is welcome.

<p align="center">
  <b><a href="#quick-start">Install</a></b> ·
  <a href="https://github.com/helixmap/sigwood/blob/main/docs/FAQ.md">FAQ</a> ·
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
dns - 1 finding · 1 H
────────────────────────────────────────────────────────────────────────────────
groups (1)
  [H]   16 sub  score=2.10-1.85  418 qry  1 src  k7x2p9qz3f.example

beacon - 2 findings · 2 M
────────────────────────────────────────────────────────────────────────────────
[M]  192.168.1.37  →  198.51.100.20:443/tcp    period=3.0m    score=0.624   480 conns
[M]  192.168.1.37  →  203.0.113.50:8443/tcp    period=10.0m   score=0.606   144 conns

syslog - 1 finding · 1 M
────────────────────────────────────────────────────────────────────────────────
privileged (1)
  [M]   Accepted password for root from 198.51.100.20 port 51900 ssh2
```

Read top to bottom, that is a story: an internal host making high-entropy lookups under one
throwaway domain, calling out to two external IPs on a fixed schedule, and a root SSH login
from one of those same IPs. A finding means "unusual for **your** network," not "known-bad" -
it is a lead to look at, not a verdict. Add `-v` for the evidence behind each score and the
next steps to run it down.

The usual invocations:

```bash
sigwood digest /var/log/messages     # orient first - a fast, factual profile of a file
sigwood graph /opt/zeek              # replay the flows as a self-contained HTML artifact
sigwood syslog /var/log              # run a single detector
sigwood init                         # detection-driven setup, writes a config
sigwood hunt                         # run the curated default hunt
```

**No logs handy?** sigwood ships a small synthetic corpus - one compromised host, no real
network data - so you can watch it work first:

```bash
git clone https://github.com/helixmap/sigwood
cd sigwood
python3 demo/gen_corpus.py                 # writes a synthetic corpus; no network calls
sigwood hunt --config=demo/sigwood.toml    # beacons, a DGA burst, and the matching syslog trail
```

The generated logs live under `demo/corpus/` (gitignored); the full walkthrough is in
[`demo/README.md`](https://github.com/helixmap/sigwood/blob/main/demo/README.md). Here is a
full run against that corpus, and the same findings as an HTML report:

<p align="center">
  <img src="https://raw.githubusercontent.com/helixmap/sigwood/main/docs/img/demo.svg" width="760" alt="sigwood hunting one compromised host across conn, DNS, and syslog - synthetic RFC 5737 data with random-label demo domains">
</p>
<p align="center">
  <img src="https://raw.githubusercontent.com/helixmap/sigwood/main/docs/img/report.png"
       width="760" alt="sigwood html report">
</p>

## Why use sigwood?

- **It runs where your logs are.** No service, no database, no daemon, no agent to push.
  `pipx install sigwood`, point it at a directory, get output. The only setup step is
  optional: `sigwood init`, which just writes plain text files under `~/.sigwood/`.
- **Named methods.** beacon uses an FFT over connection timing; dns uses HDBSCAN clustering
  over per-query behavior; syslog uses drain3 log-templating plus rarity scoring; aws uses a
  per-principal z-score composite. Every run names the technique each detector used, and `-v`
  shows the evidence behind a finding.
- **Big-tent ingestion.** One tool reads Zeek (NDJSON *and* TSV, flat *or* date-partitioned
  directories), Pi-hole/dnsmasq, the live **systemd journal** (`journalctl`, no sudo), flat
  syslog (Debian *and* RHEL/Fedora layouts, RFC 3164 *and* ISO-8601), and CloudTrail. Rotation
  and `.gz`/`.bz2`/`.xz` compression are handled for you.
- **Orient before you hunt.** `sigwood digest FILE` reports facts about a log -
  time span, top talkers, the shape of the mix - so you know where to point the
  detectors. `sigwood graph FILE` creates a visual representation of the
  activity on a log. sigwood gives you facts, not verdicts.
- **Filter before analyze.** A curated allowlist of known-harmless infrastructure ships on and
  drops that noise *before* any detector sees the data - toggle a list off by name, or drop the
  whole thing with `--no-allowlist`. Every run reports how much it hid.
- **Pick the output for the job.** A **report** to read (`text`, `html`, `pdf`),
  a **lossless feed** to script against (`json`), or a **worklist** to triage
  from (`csv`), or a Sankey animation (`graph`).

## What it hunts

| Detector  | Surfaces                                            | Method                       | Source                         |
|-----------|-----------------------------------------------------|------------------------------|--------------------------------|
| `beacon`  | periodic C2-style callbacks                         | FFT over connection timing   | Zeek `conn.log`                |
| `dns`     | DGA / tunneling / anomalous lookups                 | HDBSCAN clustering           | Zeek `dns.log` **or** Pi-hole  |
| `syslog`  | rare events & reboots                               | drain3 templating + rarity   | systemd journal, flat syslog, **or** Zeek `syslog.log` |
| `scan`    | vertical / horizontal / block / slow port scans     | pattern (heuristic)          | Zeek `conn.log`                |
| `duration`| abnormally long-lived connections                   | heuristics                   | Zeek `conn.log`                |
| `aws`     | per-principal anomalous CloudTrail behavior         | statistical (z-score composite) | CloudTrail `*.json*` (incl. `.gz`) |

`dns` and `syslog` each answer **one** question across several source families - Zeek and
Pi-hole for DNS; the live systemd journal, flat rsyslog, and Zeek's own `syslog.log` for syslog -
and adapt to whichever fidelity they're handed. On a systemd host `syslog` prefers the live
journal by default (`--syslog-source=auto`); `--syslog-source=files` keeps the flat-file behavior.

Run the curated default hunt (`sigwood hunt`), run everything available
(`sigwood hunt --detect=all`), select some (`sigwood hunt --detect=beacon,dns`), or exclude
(`sigwood hunt --detect='all,!syslog'`). Each detector is also its own subcommand:
`sigwood beacon ~/zeek`.

## Orient before the hunt: `digest`

```bash
sigwood digest /var/log/messages
sigwood digest /var/log/pihole/pihole.log   # a great first move on a Pi-hole box
sigwood digest conn.log dns.log             # several files → several cards
```

`digest` content-sniffs each file, routes it to the right summarizer (conn, dns, syslog,
cloudtrail), and falls back to a fast byte-profiler - **blob** - for anything it doesn't
recognize. A card is flush-left and factual: the file's time window, line count and size, a
scale-anchored histogram, and a handful of plain-language insights ("one client accounts for
71% of queries") - facts and superlatives, never verdicts. It reads *before* the allowlist,
because everything in the file is part of "what's in here." The blob profiler samples a big
file rather than reading it, so a one-gigabyte mystery file costs the same as a one-kilobyte
one.

## See your logs: `graph`

```bash
sigwood graph /opt/zeek                       # a Zeek dir → a conn graph and a dns graph
sigwood graph /var/log/pihole/pihole.log      # a Pi-hole box → clients, domains, dispositions
sigwood graph --pihole-dir=/var/log/pihole    # same, from your configured directory
sigwood graph dns.log --out=~/graphs/         # choose where the artifact lands
```

`graph` builds a **self-contained HTML artifact** - one file, no server, no
external resources, no network calls - that *replays* the flows in a log as an
animated Sankey: who talked to whom, over the window, with time, speed, and filter
controls. Watch the flows form and dissolve as you quickly get a sense of what's going
on in the data.

<p align="center">
  <img src="https://raw.githubusercontent.com/helixmap/sigwood/main/docs/img/graph.gif"
       width="760" alt="sigwood graph replaying conn.log flows as an animated Sankey - hosts, the services they reach, and destination hosts over a two-day window; scrambled sample data">
</p>

A Zeek directory produces two graphs - a **conn** graph (hosts vs the services
they reach) and a **dns** graph (clients vs the domains they look up). Pi-hole
adds a **disposition lane**: alongside the domains each client queried, you can
switch on a column for what Pi-hole did with each query - `blocked`,
`forwarded`, `cached`, or `local`. Like `digest`, `graph` reads *before* the
allowlist, and it states facts, not verdicts: it shows you the fat ribbon
leaving your database server at 3 AM, and lets you decide if that's your backup
window or a nightmare exfil scenario. Every artifact includes the command to
hunt the data being visualized, for a quick pivot into analysis.

## sigwood and RITA / AC-Hunter

If you know [RITA](https://github.com/activecm/rita) (or its commercial sibling AC-Hunter),
the beacon-hunting goal will look familiar - both hunt C2 in Zeek logs, and RITA is excellent
at it. sigwood differs in conception: there is no database and no import step (it reads Zeek -
and Pi-hole, syslog, and CloudTrail - in place), it spans several log families rather than
conn/dns alone, and it ships an orientation verb (`digest`) for logs you haven't met yet. If
you already run RITA against a dedicated Zeek sensor, keep it - sigwood is for the box where
the logs already live and the analyst who wants one tool across all of them.

## How a run works

```
discover & parse  →  allowlist (suppress)  →  detect  →  render
```

The **loader** finds files, decompresses, and normalizes every connection source to one
canonical schema, absorbing storage variation (TSV vs. NDJSON, flat vs. dated directories,
rotation). The **allowlist** suppresses known-good traffic before analysis. **Detectors** only
analyze - they never open files, read config, or suppress. **Output handlers** only render.
The CLI turns errors into actionable messages and owns the exit code. Every detector is also
an importable Python function, handy in a notebook.

### Analysis window

Pointed at a **directory**, an unqualified run looks back over the last `default_window` (`7d`
out of the box) of *that source's own* data - a sensible default for a live log dir you don't
want to read in full every time. Pointed at a **single file**, it reads the whole file.
Override either way:

```bash
sigwood --since=7d ~/zeek            # last 7 days
sigwood --since=2026-05-01 --until=2026-05-08 ~/zeek
sigwood --days=2-4 ~/zeek            # 2 to 4 days ago
sigwood --all ~/zeek                 # the entire archive
```

CloudTrail opts out of the default window - novelty detection needs full history, so it always
loads in full unless you narrow it explicitly. Times render in your local timezone, labeled as
such; pass `--utc` or set `use_utc = true` for UTC. `json` output is always UTC. (Grouped
syslog rows are the one exception - they lead with a syslog-shaped stamp instead. See the
FAQ.)

## Installation

One name everywhere: the PyPI distribution, the command, the import package, and the config
section are all `sigwood`. Requires **Python 3.11+**.

The recommended install is [pipx](https://pipx.pypa.io), which gives sigwood its own isolated
environment, puts the command on your PATH, and sidesteps the `externally-managed-environment`
refusal (PEP 668) that a bare `pip install` hits on Debian 12+, Raspberry Pi OS, Ubuntu 23.04+,
and Fedora:

```bash
# Debian / Raspberry Pi OS / Ubuntu:  sudo apt install pipx
# Fedora:                             sudo dnf install pipx
# macOS:                              brew install pipx

pipx ensurepath              # once - then reopen your shell
pipx install sigwood
sigwood --help
```

Prefer [uv](https://docs.astral.sh/uv/)? `uv tool install sigwood` does the same
job. A plain virtualenv also works (`python3 -m venv venv && venv/bin/pip
install sigwood`; a minimal Debian may need `sudo apt install python3-venv`
first). Avoid `sudo pip install` - it will pollute your system Python and nobody
wants that.

Upgrade with `pipx upgrade sigwood`.

Optional extras (same spelling under pipx or pip):

```bash
pipx install 'sigwood[all]'           # fast + splunk + cloudtrail (recommended)
pipx install 'sigwood[splunk]'        # Splunk exporter
pipx install 'sigwood[cloudtrail]'    # CloudTrail (S3) exporter
pipx install 'sigwood[pdf]'           # PDF reports - opt-in, see note below
```

A bare install needs no C compiler on the platforms people run this on. On
64-bit machines, DNS clustering uses `fast-hdbscan`; on 32-bit ARM it uses stock
`hdbscan` which is a bit slower but still works fine. The **first** run on a
small box takes a minute or two while the scientific stack warms up (cached on
disk after that); every run after is fast.

`[pdf]` is separate from `[all]` because PDF also needs native text libraries `pip` can't
install - `brew install pango` on macOS, `apt install libpango-1.0-0` (or `dnf install pango`)
on Linux. Every other format works with no extra setup.

From source:

```bash
git clone https://github.com/helixmap/sigwood
cd sigwood
python3 -m venv .venv                # Python 3.11+
.venv/bin/pip install -e '.[all]'
```

## Configuration

Configuration is optional - sigwood will run against a path with no config. When you want it
repeatable, `sigwood init` looks at the conventional locations on your box, profiles what it
finds (which log families, rough size, freshness), and writes an annotated config under `~/.sigwood/` (or
`/etc/sigwood` for a system-wide install). Re-run it any time: it merges into an existing
config without clobbering settings you already have, and shows a summary of what will change
before it writes anything.

Config is loaded from the first of: `--config=FILE`, then `~/.sigwood/config.toml`, then
`/etc/sigwood/config.toml`. Everything sigwood owns lives under `~/.sigwood/` -
config, allowlists, exports, reports. A trimmed example:

```toml
[sigwood]
detect     = "default"             # "default" | "all" | "dns,beacon" | "all,!syslog"
zeek_dir   = "/var/log/zeek"
syslog_dir = "/var/log"
# pihole_dir     = "/var/log/pihole"
# cloudtrail_dir = "/var/log/cloudtrail"

home_net       = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
default_window = "7d"             # lookback for a directory; "" or "all" = full
output_format  = "text"           # text | json | csv | html | pdf
```

Findings print to your terminal by default (pipeable). Set `report_dir`
(or pass `--out=PATH`) to write report files instead. Every setting a detector
has is documented in a commented "engine room" section at the bottom of the
generated config (you rarely need to mess around in there). And `sigwood
<detector> --help` lists that command's flags.

Everything sigwood writes is private by default: directories it creates are mode
`0700` and files `0600`, whatever your umask, because reports and exports can carry
domains, client addresses, and evidence. If an existing sigwood home is group- or
world-readable, a run points that out on stderr with the `chmod 700` to close it -
sigwood never changes permissions on directories it didn't create. A system-wide
`/etc/sigwood` config keeps normal shared permissions.

## Log sources it speaks

- **Zeek** - `conn.log`, `dns.log`, `syslog.log`, in NDJSON or TSV, from a flat directory or
  date-partitioned subdirectories. Rotation and gzip/bzip2/xz compression are transparent.
- **Pi-hole / dnsmasq** - DNS event logs, aggregated per domain for clustering.
- **syslog** - flat RFC 3164 and ISO-8601 (the high-precision format stock rsyslog writes on
  Ubuntu/Pop 24.04 and newer). Discovery is content-sniffed, not filename-matched, so it handles
  both the Debian convention (`syslog`, `auth.log`, `kern.log`) and the RHEL/Fedora one
  (extensionless `messages`, `secure`, `maillog`) - and won't mistake `dnf.log` or a binary like
  `wtmp` for a log stream.
- **CloudTrail** - gzipped JSON event records, read locally or pulled from S3 (see exporters below).

## The allowlist

sigwood filters **before** it analyzes: known-harmless traffic is dropped before any detector
sees it, so signal isn't buried in plumbing. Two kinds of allowlist file:

- **Flat files = suppression.** One rule per line - an IP, a CIDR, a `:port/proto`, or a domain
  glob/regex. Matching traffic is dropped before any detector runs.
- **TOML stanzas = structured suppression.** The same drop, expressed as an entry that carries a
  comment and an optional per-detector scope (`detectors = ["duration"]`). A richer
  classification role - telling a detector *what* something is - is planned, but no shipped
  detector consumes it yet, so today a stanza suppresses.

sigwood ships three curated **domain** lists, toggled by name:

| list | default | covers |
|------|---------|--------|
| `common`  | on  | broad internet infrastructure - CDNs, cloud, NTP, certificate validation, public DNS, OS update channels |
| `devices` | on  | consumer IoT / smart-home phone-home |
| `homelab` | off | self-hosted tooling (Splunk, Proxmox, UniFi, …) - opt-in, since suppressing a product you run is a real blind spot |

Nothing ad-, tracking-, or destination-specific ships - opinions differ and you may want to see
those. sigwood never ships numeric connection suppressions (those depend on your hosts, and
shipping them could hide real findings).

```bash
sigwood allowlist                 # what's loaded, each list's on/off state and size
sigwood allowlist show common     # the patterns in a list
sigwood allowlist enable homelab  # turn a shipped list on
sigwood allowlist disable common  # …or off
sigwood allowlist copy common     # fork a shipped list into your allowlist.d to edit
```

Toggles can also be set under `[allowlist.lists]` in config; the whole allowlist turns off for
one run with `--no-allowlist` or permanently with `enabled = false`. Every detect run discloses
its coverage on the banner (`allowlist: suppressed 1,284 connections (12%) and 312 domains
(59%)` - the share of loaded rows suppressed, per kind), so a surprising suppression rate is
visible at a glance.

Add your own in any `domains_*` file under `~/.sigwood/allowlist.d/` (the shipped `domains_user`
is a starter). Drop-ins are additive and survive upgrades; to replace a shipped list, `disable`
it and add your own. A bare host IP with no port suppresses *all* traffic involving that host - powerful
but dangerous, and flagged as such wherever it appears.

## Pulling logs in: exporters

sigwood can fetch logs from external systems to local files, which it then analyzes like any
other source - the syslog detector can't tell whether the data came from rsyslog or a Splunk
export.

```bash
sigwood export splunk            # run the configured "default" query
sigwood export splunk auth       # run the configured named query: "auth"
sigwood export cloudtrail        # pull logs from S3
```

- **Splunk** - named SPL queries under `[export.splunk.query.<name>]`. Prefer the
  `SIGWOOD_SPLUNK_USER` / `SIGWOOD_SPLUNK_PASS` environment variables over plaintext credentials
  in config, but sigwood will not judge you.
- **CloudTrail** - pulls gzipped JSON from an S3 prefix. AWS authentication is *not* handled
  here: you authenticate your shell, and boto3 resolves the ambient credential chain. sigwood
  never reads, stores, or prompts for AWS credentials, and warns before a large egress.

## Output formats

Choose by what you're doing with the findings - `--format=NAME` (or set `output_format` in
config):

- **`text`** (default) - a grouped report for the terminal, with a per-detector table of the
  signals behind each finding.
- **`html`** - the same report as a self-contained styled file to open in a browser, print, or
  share. No extra dependencies; dark mode and print styles included.
- **`pdf`** - the html report rendered to PDF (one renderer, two outputs). Opt-in:
  `pip install 'sigwood[pdf]'` plus the native text libraries (see the install note above).
- **`json`** - the lossless machine feed: a single object with `run_summary` and `findings`,
  correctly typed for `jq` or a SIEM, always the full set. Carries a `schema_version`.
- **`csv`** - a remediation worklist: one row per finding with the next-steps, the "why", and
  empty `status`/`notes` columns to track as you knock items down.

`text`, `html`, and `pdf` are reading views - they honor `-v` (the curated "why it scored") and
`-vv` (raw debug). `json` and `csv` always carry the full set.

Every text format - including `html` - prints to stdout by default; redirect or pipe to save
(`sigwood dns -f=html > report.html`). `pdf` is binary, so it needs a destination: a pipe
(`-f=pdf > report.pdf`) or a file. Set `--out=PATH` or `report_dir` to write files; a directory
target auto-names the report and prints the path it wrote.

## Building from source & running tests

```bash
git clone https://github.com/helixmap/sigwood
cd sigwood
python3 -m venv .venv                # Python 3.11+
.venv/bin/pip install -e '.[dev]'
.venv/bin/python -m pytest
```

`main` is kept runnable. Architecture tests cover detector discovery, run
planning, loader metadata, allowlist suppression, output registration, and CLI
error formatting.

## License

sigwood is licensed under the [MIT License](https://github.com/helixmap/sigwood/blob/main/LICENSE).
