# Roadmap

Where sigwood is and where it's headed. This is direction, not a dated schedule -
some of it is committed, some is ideas worth chasing. sigwood is a single-maintainer
project, so it moves as time allows.

## Shipped

What sigwood does today:

- **Six detectors** - beacon (FFT periodicity), dns (density clustering over Zeek
  dns.log or Pi-hole/dnsmasq), syslog (drain3 templating with per-host burst collapse,
  over Zeek syslog.log or flat rsyslog), scan, duration, and aws (per-principal
  behavior over CloudTrail).
- **A `digest` verb** to orient before you hunt - a fast, honest profile of conn, DNS,
  syslog, or CloudTrail data, with a bytes-only fallback for anything it doesn't
  recognize.
- **A `graph` verb** to see a log move - a self-contained HTML artifact that replays
  conn, DNS, or Pi-hole flows as an animated Sankey, with the exact hunt command baked in.
- **Five output formats** - text, JSON, CSV, HTML, and PDF - and a setup wizard
  (`sigwood init`) that looks at your logs before it asks anything.
- **An allowlist** for suppressing known-good infrastructure, with curated starter
  lists and your own drop-ins.
- **Log ingestion** that absorbs the variety: Zeek NDJSON and TSV, flat and
  date-partitioned layouts, rotation, and gzip/bzip2/xz - so detectors never see the
  storage details.
- **Exporters** that pull from Splunk, and from CloudTrail in S3, into local files
  when your logs live somewhere else.

## Next up

Actively being worked on or thought through:

- **dnsblock** - a detector for behavioral patterns in blocked Pi-hole queries: who is
  reaching for known-bad domains, how persistently, and across how many clients.
- **Beacon and aws, sharper on real data.** Short analysis spans surface mostly
  benign monitoring traffic (the default directory window is beacon's 7-day
  reliability bar, but a short archive still under-fills it, and the run says so);
  the refinement is per-detector windowing plus seeding common monitoring ports
  into the allowlist. The aws detector similarly over-weights an admin's own
  console sessions on a single account. Both are precision refinements worked out
  against real logs, not guessed at.
- **Scan and duration** - flagging scans of internal space at higher severity, and
  collapsing a load-balanced service (many IPs, one logical destination) into a single
  finding.

## Later

Bigger pieces that need real experimentation first - sigwood's detectors are
prototyped in the open, as scripts and notebooks under `notebooks/` run against
real logs, before they ship (see [CONTRIBUTING.md](../CONTRIBUTING.md)):

- **More detectors** - authentication analysis from `auth.log`/`secure` (brute force,
  odd login times), TLS and certificate anomalies from Zeek `ssl.log`, and Zeek's own
  `weird.log`/`notice.log`. A future CloudTrail identity and privilege-escalation
  detector is its own thing, separate from the behavioral `aws` detector.
- **Exploratory ideas** - a protocol and application classifier over conn.log, a
  per-protocol anomaly model, and an emailed-report output.

## By design, not on the roadmap

sigwood is deliberately a local, batch tool - no daemon, no stream, no service;
the exporters pull on demand and that is the only network it touches. It won't
grow into any of these:

- No daemon, database, or agent - you install it, point it at logs, and get output.
- No real-time streaming or alerting pipeline - it runs over logs you already have.
- Not a SIEM, and not trying to be - it's a focused hunting tool that sits next to one.

---

Have a detector or format in mind? [CONTRIBUTING.md](../CONTRIBUTING.md) has the map,
and a notebook prototype is a genuinely welcome way to start.
