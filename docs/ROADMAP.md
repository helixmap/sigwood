# Roadmap

Where sigwood is and where it's headed. This is direction, not a dated schedule -
some of it is committed, some is ideas worth chasing. sigwood is a single-maintainer
project, so it moves as time allows.

## Shipped

What sigwood does today:

- **Six detectors** - beacon (FFT periodicity), dns (density clustering over Zeek
  dns.log or Pi-hole/dnsmasq), syslog (drain3 templating with per-host burst collapse,
  over the live systemd journal, flat rsyslog, or Zeek syslog.log), scan, duration, and
  aws (per-principal behavior over CloudTrail).
- **A curated default hunt** that narrows the routine review surface while every
  detector remains runnable by name; `--detect=all` still runs everything available.
  The run discloses detectors held opt-in while their evidence is rebuilt.
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

- **One detector at a time.** Each noisy detector gets its own measured pass - a
  pre-registered bar for what "better" means, data held back from tuning, and a simple
  baseline the change has to beat. The syslog pass shipped in 0.2.7 (rare-line rollups,
  recognized transactions, reboot reporting); the DNS pass is in progress
  (behavior-corroborated severity in place of score-only verdicts); duration's pass
  follows.

## Later

Bigger pieces that need real experimentation first - sigwood's detectors are
prototyped in the open, as scripts and notebooks under `notebooks/` run against
real logs, before they ship (see [CONTRIBUTING.md](../CONTRIBUTING.md)):

- **More detectors** - **dnsblock** (behavioral patterns in blocked Pi-hole queries:
  who reaches for known-bad domains, how persistently, across how many clients),
  authentication analysis from `auth.log`/`secure` (brute force, odd login times), TLS
  and certificate anomalies from Zeek `ssl.log`, and Zeek's own
  `weird.log`/`notice.log`. A future CloudTrail identity and privilege-escalation
  detector is its own thing, separate from the behavioral `aws` detector. New
  detectors join the default hunt only after the current defaults are reviewable.
- **DNS, beyond label shape** - research directions under active consideration for the
  DNS detector, each behavioral rather than list-driven: grouping generated-looking
  failed-lookup campaigns per client into one finding, then searching the same client's
  successful lookups for the structurally-related name that resolved (the rendezvous
  lead); a published lossless-compression bound on how much information a query stream
  could carry (catches fixed-codebook, record-type, and timing channels that no
  randomness score can see); joining DNS answers to connection-log behavior so a
  resolve-once lookup is corroborated by the flow that followed it; per-client union
  across Zeek and Pi-hole so adding a sensor never shrinks coverage; and richer
  per-transaction fidelity from dnsmasq's `--log-queries=extra` format. Each enters
  through the same measured discipline: a baseline to beat, held-back data, and results
  that earn the method its place.
- **Beacon and aws, deeper on real evidence** - beacon recalibration is a full
  research branch (public C2 captures, a plain periodicity baseline to beat, the
  aliasing edges), not a quick tune; aws stays scored on the evidence actually
  available to it. Ideas like per-detector windowing and seeding common monitoring
  ports into the allowlist wait for that measured pass.
- **Exploratory ideas** - flagging scans of internal space at higher severity, a
  protocol and application classifier over conn.log, a per-protocol anomaly model,
  and an emailed-report output.

## By design, not on the roadmap

sigwood is deliberately a local, batch tool - no daemon, no stream, no service;
the exporters pull on demand and that is the only network it touches. It won't
grow into any of these:

- No daemon, database, or agent - you install it, point it at logs, and get output.
- No real-time streaming or alerting pipeline - it runs over logs you already have.
- Not a SIEM, and not trying to be - it sits between grep and a SIEM, a focused hunting
  tool that lives next to one.

---

Have a detector or format in mind? [CONTRIBUTING.md](../CONTRIBUTING.md) has the map,
and a notebook prototype is a genuinely welcome way to start.
