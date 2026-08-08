# Roadmap

Where sigwood is and where it's headed. This is direction, not a dated schedule -
some of it is committed, some is ideas worth chasing. sigwood is a single-maintainer
project, so it moves as time allows.

The middle section maps what sigwood can and cannot see onto the
[MITRE ATT&CK](https://attack.mitre.org/) matrix, because that is the honest way to
answer "what does this actually catch?" - including the parts of the answer that are
"nothing, and here is why."

## Shipped

What sigwood does today:

- **Seven detectors** - beacon (FFT periodicity), dns (density clustering over Zeek
  dns.log or Pi-hole/dnsmasq), syslog (drain3 templating with per-host burst collapse,
  over the live systemd journal, flat rsyslog, or Zeek syslog.log), auth (five
  authentication-structure heuristics over that same system-log lane), scan, exfil
  (bulk outbound transfers over connection logs), and aws (per-principal behavior over
  CloudTrail).
- **A curated default hunt** that narrows the routine review surface while every
  detector remains runnable by name; `--detect=all` still runs everything available.
  The run discloses which available detectors were held out of the default hunt, so an
  opt-in detector is never silently absent.
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

## Coverage: what sigwood actually sees

sigwood can watch up to three flanks - your network (via Zeek), your system logs (the
systemd journal, flat rsyslog, or Zeek's own syslog.log), and your cloud API activity
(CloudTrail) - and it sees only the ones you actually have and point it at. It has no
agent on your machines and never inspects process memory, so some attacker behavior is
out of view however good the detectors get.

**How to read the table.** *Today* means a shipped capability **when the relevant source
is present**; where a row depends on a detector outside the default hunt, the cell names
it. Naming an ATT&CK technique is an *association*, not a claim of full coverage - a
signal can be the behavior itself, or merely consistent with it, or just a side effect of
it, and those are very different things. The per-detector limits that qualify these rows
- beacon's span and aliasing edges, DNS source fidelity, aws's window-relative
first-seen behavior, exfil's measured-population limits - are catalogued in
[Known issues](KNOWN-ISSUES.md) rather than repeated here. The mapping is pinned to
**ATT&CK Enterprise v19.1** (checked 2026-08-04); a later ATT&CK release means this table
needs re-checking.

| Tactic | Today | What could narrow the gap |
|---|---|---|
| Reconnaissance | Sweeps against your estate (`scan`) | Web server logs |
| Resource Development | Nothing - it happens on attacker infrastructure | Nothing in sigwood's own telemetry; only external intelligence, which it won't ship |
| Initial Access | A window-first burst of new actions by one principal - compatible with stolen-key use, not proof of it (`aws`); failed authentication attempts ending in a success (`auth`) | Web server logs |
| Execution | An occasional rare `sudo` line (`syslog`) | Linux audit records, where enabled |
| Persistence | Rare account-management lines - `useradd` and kin (`syslog`) | Recognizing the edit itself: a crontab change, a new unit, a new SSH key |
| Privilege Escalation | Rare `sudo`/`su`, by rarity not by meaning (`syslog`); failed attempts followed by a success (`auth`) | Linux audit records beyond authentication outcomes |
| Stealth | Very little - camouflage is a host-level behavior | Little. Endpoint territory, and we say so |
| Defense Impairment | Nothing dedicated - a logging change may surface only incidentally, inside a broader unusual API burst (`aws`) | Naming it directly; noticing a host go quiet |
| Credential Access | Failure concentration and volume, with success-after-failures reported alongside them (`auth`) | Host-native evidence beyond authentication logs |
| Discovery | LAN sweeps (`scan`), cloud enumeration bursts (`aws`) | Already the best-served here |
| Lateral Movement | Multi-host authentication failures for one source and account (`auth`) | Zeek SMB and SSH logs |
| Collection | Nothing claimed | Zeek SMB logs |
| Command and Control | Check-in timing (`beacon`); generated-looking domains (`dns`), with the dense tunnel path Zeek-only | TLS anomalies, odd ports, tunnel log |
| Exfiltration | DNS tunnelling shapes (`dns`, Zeek-only for the dense path); bulk outbound byte transfers (`exfil`) | Transfers below the byte floor or split across many destinations; exfiltration inside an allowed cloud service |
| Impact | No mining-specific verdict; generic check-ins (`beacon`) can be a downstream clue | Cloud destruction events; SMB file activity |

**The shape of it.** This roadmap weights one particular threat model - a self-hosted
estate facing opportunistic internet attacks, compromised IoT devices and routers,
cryptominers, info-stealers, and stolen cloud keys - and that weighting is an assumption,
not a measured fact about the world. Against *that* model, sigwood's coverage is
strongest at command and control, discovery, exfiltration, and initial access. It is weak,
and should stay weak, at the tactics that need an agent on
the host: credential dumping from memory, exploitation of a local vulnerability, file
encryption as it happens, and behavioral camouflage. Some of that darkness cannot be
fixed from these flanks at all. One structural advantage worth naming: when Zeek runs on
a separate sensor, an attacker with root on a machine can erase that machine's local logs
but cannot reach the network record.

## Next up

Actively being worked on or thought through:

- **One detector at a time.** Each noisy detector gets its own measured pass - a
  pre-registered bar for what "better" means, data held back from tuning, and a simple
  baseline the change has to beat. The syslog pass shipped in 0.2.7 (rare-line rollups,
  recognized transactions, reboot reporting); the DNS pass is in progress
  (behavior-corroborated severity in place of score-only verdicts).

## Later

Bigger pieces that need real experimentation first - sigwood's detectors are
prototyped in the open, as scripts and notebooks under `notebooks/` run against
real logs, before they ship (see [CONTRIBUTING.md](../CONTRIBUTING.md)). Grouped by
the gap each one could narrow:

- **Command and control** - TLS and certificate anomalies from Zeek `ssl.log`, judged
  against your own estate's norms rather than a fingerprint database; Zeek's
  `weird.log`/`notice.log`; and a protocol classifier that notices a service running
  somewhere it normally does not.
- **Exfiltration, beyond bulk volume** - `exfil` now answers "who is uploading, and to
  whom" for transfers large enough to clear its floor, complementing the tunnelling
  shapes `dns` already covers. The open ground is what volume alone cannot see: a
  trickle held under the floor, an upload spread thin across many destinations, and
  modest transfers inside a service the allowlist already trusts.
- **DNS, beyond label shape** - research directions under active consideration, each
  behavioral rather than list-driven: grouping generated-looking failed-lookup campaigns
  per client into one finding, then searching the same client's successful lookups for
  the structurally-related name that resolved (the rendezvous lead); a published
  lossless-compression bound on how much information a query stream could carry (catches
  fixed-codebook, record-type, and timing channels that no randomness score can see);
  joining DNS answers to connection-log behavior so a resolve-once lookup is corroborated
  by the flow that followed it; per-client union across Zeek and Pi-hole so adding a
  sensor never shrinks coverage; and richer per-transaction fidelity from dnsmasq's
  `--log-queries=extra` format.
- **Known-bad access patterns** - **dnsblock**, over the domains your own Pi-hole
  already blocks: who reaches for them, how persistently, across how many clients. It
  uses your blocklist's verdicts, not a feed sigwood ships.
- **Cloud identity and privilege** - a future CloudTrail identity and
  privilege-escalation detector, separate from the behavioral `aws` detector and named
  for its question.
- **Corroboration across detectors** - today each detector reasons alone, which is why
  beacon caps its own severity: regular timing is one kind of evidence, and severity
  should rise only when independent kinds agree. Doing that honestly takes two steps, not
  one. First, link records that refer to the same thing - a connection's destination to
  the domain that resolved to it - and carry how *certain* that link is, because shared
  hosting and stale answers make identity genuinely ambiguous. Only then, and only where
  the signals are independent rather than two views of one fact, can severity rise. Being
  confident that two records name the same host is not itself evidence of bad behavior.
- **Beacon and aws, deeper on real evidence** - beacon recalibration is a full
  research branch (public C2 captures, a plain periodicity baseline to beat, the
  aliasing edges), not a quick tune; aws stays scored on the evidence actually
  available to it.
- **Exploratory ideas** - flagging scans of internal space at higher severity, a
  per-protocol anomaly model, and an emailed-report output.

New detectors join the default hunt only after the current defaults are reviewable, and
none of the above is a promise - each has to earn its place against real data first.

## By design, not on the roadmap

sigwood is deliberately a local, batch tool - no daemon, no stream, no service;
the exporters pull on demand and that is the only network it touches. It won't
grow into any of these:

- No daemon, database, or agent - you install it, point it at logs, and get output.
- No real-time streaming or alerting pipeline - it runs over logs you already have.
- Not a SIEM, and not trying to be - it sits between grep and a SIEM, a focused hunting
  tool that lives next to one.
- **No threat-intel feeds, and no shipped lists of bad domains, IPs, or file hashes.**
  Those are the cheapest thing for an attacker to change, so detections built on them
  go stale quietly. sigwood looks for behavior instead - which is also why it will never
  cover the Resource Development tactic above.
- **No detector-per-event-ID catalogues.** A detector here answers one question
  behaviorally, and does not grow into a signature pack to maintain. Narrow recognition of
  stable, documented event semantics is fine - the `aws` work reads specific API verb
  names that way - but the question comes first and the vocabulary stays small. What
  sigwood rejects is signature-pack sprawl, not the use of semantic fields.

Some things are left out for a plainer reason - there is no honest way to test them yet.
Detections for Windows event logs, or for Active Directory protocols like Kerberos, are
not ruled out on principle, but sigwood's current telemetry and measured corpora are
Linux-heavy, and without real logs of that kind there is no way to measure whether a
detector works or just makes noise. That measurement, not the idea, is the blocker.

---

Have a detector or format in mind? [CONTRIBUTING.md](../CONTRIBUTING.md) has the map,
and a notebook prototype is a genuinely welcome way to start.
