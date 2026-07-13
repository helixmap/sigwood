# Changelog

All notable changes to sigwood are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and sigwood aims to follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.1] - 2026-07-13

### Added

- A `graph` verb (`sigwood graph <path>`) that writes a self-contained HTML artifact -
  one file, no server, no external resources, no network calls - replaying a log's flows
  as an animated Sankey with time, speed, and filter controls. A Zeek directory produces
  a conn graph (hosts vs the services they reach) and a dns graph (clients vs the domains
  they look up); Pi-hole adds a disposition lane showing what happened to each query
  (`blocked`, `forwarded`, `cached`, or `local`). Like `digest`, it reads before the
  allowlist and states facts, not verdicts, and every artifact ends with the exact
  `sigwood hunt` command for the same log.

### Changed

- The curated `common` domain allowlist now ships its generic UUID-label rule disabled
  (commented out). It suppressed any query embedding a UUID under any domain - a lexical
  shape an exfil or beacon labeling scheme can simply choose - so it could drop hostile
  queries before analysis. Devices that chatter with UUID labels are better suppressed by
  their vendor apex; some users may see new DNS findings from such devices after
  upgrading. The rule stays in the file, commented, for anyone who wants to re-enable it
  knowingly.
- A syslog burst finding without an observed reboot is no longer described as
  "resembling a boot or batch event" - the neutral description states the cluster and
  nothing more, and the reboot wording appears only on bursts a detected boot event
  actually claimed.
- TOML allowlist stanzas are now documented as what they do today - structured
  suppression with a comment and per-detector scope - rather than as a classification
  mechanism no shipped detector consumes yet. A stanza missing its `match` key (or a
  stanza file that isn't valid TOML) now fails with an actionable message naming the
  file instead of a raw `KeyError`.

### Fixed

- Pointing sigwood at a directory that holds a mix of log families no longer silently
  drops the minority families: the run now says on stderr which family won the routing
  vote and what was sampled, a detector skipped because the positional target routed
  elsewhere now says so (instead of the misleading "not configured"), and `digest`
  notes each directory it skips in a multi-file invocation instead of passing over it
  without a word.
- A detector that crashes mid-run no longer reads as a clean night. The run still
  continues past the crash (sibling detectors' findings are unaffected), but the failure
  is now disclosed everywhere a scheduled run looks: the process exits nonzero, the JSON
  feed carries it under `run_summary.detectors_failed` (name → reason; empty `{}` on a
  clean run), the HTML/PDF report header shows a failure row, and the text report ends
  with a `failed:` line so a saved report is honest too. The FAQ's cron alerting recipe
  now pages on failed detectors as well as findings.

## [0.1.1] - 2026-07-11

### Changed

- Source and development install instructions in the README now create a virtualenv
  first, so a `pip install -e` in a fresh clone doesn't hit the PEP 668
  `externally-managed-environment` refusal on Debian, Raspberry Pi OS, or Fedora.
- Splunk export now reports a TLS certificate-verification failure with an actionable
  message, naming the `verify_tls = false` setting under `[export.splunk]` for a
  self-signed certificate on a trusted network, instead of a generic connection error.
- Source distributions no longer bundle the test suite - it shipped without the support
  files needed to collect it, so it was unusable - and a release-time gate checks the
  sdist carries no tests.
- Package metadata now declares the license as the SPDX `license = "MIT"` expression with
  `license-files`, dropping the deprecated MIT license classifier, and sets the operating
  system classifier to POSIX.

### Fixed

- The beacon detector no longer silently drops a genuine beaconing flow to a unicast host
  whose IPv4 address ends in `.255` (a valid host in any network wider than a /24). Its
  pre-filter now classifies non-unicast destinations and sources with the standard-library
  `ipaddress` module rather than a string-prefix test, so multicast, link-local (including
  IPv4 `169.254.0.0/16`), and the `255.255.255.255` limited broadcast are still excluded
  before scoring while real unicast hosts are kept.
- Copy polish in the `init` wizard prompts.
- `sigwood init` no longer lets a source you explicitly skip during setup quietly come
  back. A skipped default source (Zeek or syslog) is now written as
  `<key> = ""  # disabled during setup`, so the config merge cannot silently re-enable it;
  removing a source still reverts it to the shipped default.
- The `--dry-run` preview now counts Zeek logs in dated `zeekctl` layouts (the
  `YYYY-MM-DD/` and `current/` subdirectories) the way a real run discovers them, and shows
  `(unreadable)` for a directory it cannot read instead of a misleading `(0 files)`.
- A closed downstream pipe (for example `sigwood hunt | head`) now exits quietly with
  Unix SIGPIPE semantics instead of printing a `BrokenPipeError` traceback.
- The loader no longer crashes at import on platforms without the POSIX `grp`/`pwd`
  modules; permission-denied diagnostics fall back to numeric owner and group ids there.

### Security

- Output now strips terminal control bytes through a single sanitizer - including the
  surrogate-escaped bytes a non-UTF-8 filename decodes to - so a hostile file or directory
  name in a scanned tree can no longer inject terminal escape sequences, whether it reaches
  the analyst through a stderr diagnostic or a text, html, or csv report.
- That sanitizer now also covers the remaining command-line surfaces - the error boundary,
  `digest` narration, the `--dry-run` banner, and loader and export status messages - so a
  hostile file, directory, or configured path name cannot inject terminal escapes through
  any of them.

## [0.1.0] - 2026-07-10

First public release. A local-first, offline command-line threat-hunting workbench:
point it at logs you already have and read the output. No database, no daemon, no
agent, no account.

### Added

- Six detectors, each naming its own technique on every run:
  - `beacon` - periodic C2-style callbacks, via an FFT over connection timing
    (Zeek `conn.log`).
  - `dns` - DGA, tunneling, and anomalous lookups, via HDBSCAN clustering
    (Zeek `dns.log` or Pi-hole/dnsmasq).
  - `syslog` - rare events and reboots, via drain3 log-templating plus rarity scoring
    (flat RFC 3164 syslog or Zeek `syslog.log`).
  - `scan` - vertical, horizontal, block, and slow port scans (Zeek `conn.log`).
  - `duration` - abnormally long-lived connections (Zeek `conn.log`).
  - `aws` - per-principal anomalous CloudTrail behavior, via a transparent per-principal
    z-score composite.
- `digest` verb - a fast, factual profile of a single file (time window, top talkers, a
  scale-anchored histogram, plain-language insights) that states facts, never verdicts,
  and falls back to a bounded byte-profiler for files it doesn't recognize.
- Log sources: Zeek (NDJSON and TSV, flat or date-partitioned directories),
  Pi-hole/dnsmasq, flat RFC 3164 syslog (Debian and RHEL/Fedora layouts), and CloudTrail.
  Rotation and gzip/bzip2/xz compression are handled transparently.
- Output formats: `text` (default), `html`, and `pdf` reading views (honoring `-v`/`-vv`),
  plus `json` (a lossless, typed machine feed) and `csv` (a remediation worklist).
- An allowlist that suppresses known-harmless traffic before any detector runs - three
  curated domain lists (`common`, `devices`, `homelab`), user drop-ins, and per-run
  coverage disclosure - managed with the `allowlist` verb.
- Exporters that pull logs from Splunk and CloudTrail (S3) into local files for analysis.
- `init` - a detection-driven first-run wizard that profiles what's on disk and writes an
  annotated config under `~/.sigwood/`.
- Analysis-window controls (`--since`/`--until`/`--days`/`--all`), a per-source default
  lookback window, and local-or-UTC time rendering.

[Unreleased]: https://github.com/helixmap/sigwood/compare/v0.2.1...HEAD
[0.2.1]: https://github.com/helixmap/sigwood/compare/v0.1.1...v0.2.1
[0.1.1]: https://github.com/helixmap/sigwood/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/helixmap/sigwood/releases/tag/v0.1.0
