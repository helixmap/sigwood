# Known issues

sigwood is young, and this is the honest ledger of what it doesn't do well yet -
the rough edges worth knowing before you lean on it. None of them lose or corrupt
data quietly: where sigwood can't do something well, it says so at run time where it
can, and in this file where it can't yet. Found something that isn't here? Open an issue.

## Detectors

**Beacon wants a week or more of data.** A jittered periodic beacon only clears the
FFT score threshold intermittently over a single day, so a short window tends to
surface the most machine-regular flows - which are often benign infrastructure (NTP,
monitoring agents, DNS) rather than C2. sigwood flags a short analysis span at run
time; give it a week or more of `conn.log`, and use the allowlist to suppress the
infrastructure you recognize. Reliability across diverse real-world networks is still
being characterized, and this is the honest state of the flagship beacon detector today.

**Beacon doesn't yet score beacons to dead or blocked hosts.** The pre-filter looks
at connections that reached an established state, so a periodic check-in to a host
that never answers - connections that all fail or get rejected - isn't analyzed.
sigwood discloses at run time when most of the loaded connections were
non-established and went unscored. Scoring that traffic as its own tier is planned; it
needs threshold and false-positive calibration first.

**A beacon faster than 60 seconds is reported with the wrong period.** The FFT runs
over 30-second bins, so the fastest cadence it can represent is 60 seconds. A faster
check-in is still detected, but its reported period aliases to a longer value (a true
45-second beacon reads as roughly 90 seconds). Truthful sub-60s reporting needs finer
bins and a re-tune of the scoring constants.

**High-volume DNS tunneling spread across many domains can slip the scan.** sigwood
surfaces sustained tunneling that concentrates under a single registered domain, but a
tunnel spread thin across many domains - or one below the conservative volume floor -
may not be flagged. The floor is deliberately cautious so a benign high-entropy
cluster (a CDN or a telemetry endpoint) doesn't flood the report; allowlist the ones
you recognize.

**On Pi-hole/dnsmasq data, high-volume DNS tunneling can vanish from the report as it
grows.** The dense-cluster tunnel scan runs on Zeek DNS only. Pi-hole queries are
clustered without it, so a burst of random lookups that becomes voluminous enough to
form its own cluster stops being "noise" and stops being reported - in testing, scaling
the same DGA burst from 15 to 400 lookups took the report from ten findings to zero,
with no disclosure that anything was set aside. Until the scan is extended to the
Pi-hole path, corroborate a quiet Pi-hole report with per-domain query volume
(`sigwood digest /var/log/pihole/pihole.log` shows the heaviest domains), or run the
same traffic through Zeek, where the scan closes this gap.

**Letter-only high-entropy DGA labels are under-reported.** The DNS suspicion score
leans heavily on digits, so a random no-digit label scores about one point below a
digit-bearing equivalent. That makes this class invisible to the HIGH/tunnel path,
and leaves it below the surface gate for the vast majority of realistic lengths. Pivot on
query volume, registrable-domain concentration, and allowlist review when no-digit
labels show up in noisy DNS traffic.

**Repeated reboots are caught every time, with a few grouping edges.** sigwood detects
reboot signals across the whole log regardless of how rare they are, so a machine that
reboots repeatedly is flagged on every boot, not just its first. Three grouping edges are
worth knowing: a host whose shutdown and subsequent boot are more than about ten minutes
apart is reported as two reboots rather than one; reboots whose log lines carry no parseable
timestamp are grouped into a single undated reboot per host; and when a reboot produces only
one or two other rare lines, those lines are listed individually rather than folded into the
reboot's summary. No data is lost in any of these cases.

## Ingestion and windows

**On daily-rotating Zeek trees, the default window can miss today's newest events.**
The default window is anchored on the newest dated log directory, so on a tree that
rotates once a day, events written since midnight - which live only in the live
`current/` spool - can fall just outside it. They're read, then filtered out by the
window. An explicit `--since` with no `--until` includes them, and `--all` reads the
whole archive.

**zstd-compressed logs aren't supported yet.** sigwood transparently reads `.gz`,
`.bz2`, and `.xz`. `.zst` needs a decoder that isn't in the Python standard library
before 3.14, so it's deferred for now - decompress those files first.

**Peak memory runs to a multiple of the largest log loaded.** sigwood reads each log fully
into memory (pandas) rather than streaming, so peak memory tracks the biggest single file it
opens, not the total on disk - a ~560 MB `conn.log` peaked near 6 GB in one measurement. The
default window keeps a live directory from being read end to end, but one very large file, or
`--all` over a big archive, can exhaust a small box before the run finishes. Narrow the window
(`--since`/`--days`), point at a single file, or run where there's headroom; streaming
ingestion for the large-single-file case is on the list.

## Digest and output

**Not every finding carries a machine-readable event timestamp.** `duration`, `scan`,
aws burst, and syslog burst/reboot findings carry event timestamps in their JSON
evidence; beacon, dns, and isolated syslog rare-event findings currently do not, so a
`jq` timeline can place some findings but not others. Every finding does carry the run's data window.
Converging on a representative event timestamp for every finding is planned.

**The conn digest is slow on very large frames.** The connection digest walks every
row to build its histogram and per-flow summary, so a multi-million-row `conn.log`
takes a while. It's correct, just not yet optimized; performance work is on the list.
