# Known issues

sigwood is young, and this is the honest ledger of what it doesn't do well yet -
the rough edges worth knowing before you lean on it. None of them lose or corrupt
data quietly: where sigwood can't do something well, it says so at run time where it
can, and in this file where it can't yet. Found something that isn't here? Open an issue.

## Detectors

**Cross-feed syslog arbitration keeps the local rows - two narrow edges remain.** The
syslog detector reads up to two feeds in one run: local system logs (files or the
journal) and Zeek's own `syslog.log`. A host present in the local feed keeps its
local rows only; Zeek contributes just the hosts the local feed lacks, and the run
summary discloses the arbitration in counts. Two edges to know: if the local feed has
a coverage gap for an arbitrated host (say, a rotation hole), Zeek lines that would
have filled it are set aside with the rest - the local feed is authoritative for its
hosts; and the two feeds must agree on the host's name - if Zeek records a host by IP
(a hostless line) while your files record its name, that host is treated as two and
its events still count twice. Hostless (`unknown`) lines are never arbitrated.

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

**A slow beacon can be reported at a fraction of its true period.** For longer cadences the
FFT's energy spreads into harmonics, and a harmonic peak can edge out the fundamental: in
testing, a clean two-hour beacon was reported with a period of about one hour (half the truth)
and a four-hour beacon as about eighty minutes (a third). The beacon is still detected and
flagged - it is the reported period that is wrong, not a silent miss - so treat a reported
period as approximate and confirm the real cadence against the raw connection timestamps.

**Duration overstates severity for ordinary long-lived connections.** The duration detector
assigns HIGH from elapsed wall-clock time alone, so CDN, streaming, and keepalive flows can
score HIGH without corroborating evidence. It is opt-in while that severity model is rebuilt:
run `sigwood duration` or `sigwood hunt --detect=all`. It returns to the default hunt when its
severity earns that place.

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
Pi-hole path, run the same traffic through Zeek, where the dense-cluster scan closes this
gap directly. Failing that, read the distinct-domain count on the digest card
(`sigwood digest /var/log/pihole/pihole.log` prints a `domains:` total): a DGA burst is many
names queried once each, so it inflates the distinct-domain count while never rising to a
heaviest-domain - which is why a per-domain-volume check does not surface it.

**Letter-only high-entropy DGA labels are under-reported.** The DNS suspicion score
leans heavily on digits, so a random no-digit label scores about one point below a
digit-bearing equivalent. That makes this class invisible to the HIGH/tunnel path,
and leaves it below the surface gate for the vast majority of realistic lengths. Pivot on
query volume, registrable-domain concentration, and allowlist review when no-digit
labels show up in noisy DNS traffic.

**Hex-encoded DNS tunneling can slip the high-volume scan.** A long hexadecimal label - the
shape of base16-encoded tunneling - scores just below the high-entropy bar the dense-cluster
scan requires: a 32-character hex label scores about 1.78 against a 1.8 bar, so a high-volume
hex tunnel that grows into its own cluster can pass the scan without tripping it. The bias cuts
both ways - a short hex ID scores higher and can read as high-entropy, while a long hex tunnel
reads as just under the bar. Pivot on the volume and registrable-domain concentration of
random-looking lookups when the scan is quiet.

**On a small DNS capture, no clusters form and the method label still names the algorithm.**
Zeek DNS analysis needs a substantial number of queries before HDBSCAN groups them (the default
minimum cluster size is 2000); on a smaller capture every query is treated as noise and the
findings come entirely from the per-label suspicion score, not from cluster shape. The
`dns (fast-HDBSCAN)` method label names the clustering backend that ran even when it formed no
clusters, so on a small capture the lexical score is doing the work.

**A fast sequence of unprivileged rare events folds into one informational burst.** Three or
more rare log lines outside the privileged program class within about a minute on one host
collapse into a single INFO "burst" finding rather than individual LOW findings - that
grouping catches boot storms and
batch jobs, but it also catches an attacker working quickly. Nothing is dropped: the
burst carries the line count, time span, program mix, and sampled lines. Treat burst
findings as worth a skim rather than reading INFO as ignorable; the collapse is tunable
(`burst_min_size`, `burst_gap_seconds` under `[detectors.syslog]`) if you'd rather see
tight clusters as individual findings.

**Rare syslog lines with no usable host and no program can share one review unit.** The
family grouping uses `unknown` when either field cannot be derived, so lines from different
physical hosts can be grouped together when both identifiers are absent. The sampled raw
lines and exact line count remain available in that family finding; review the samples as
potentially unrelated events rather than assuming they came from one machine.

**With both Zeek DNS and Pi-hole configured, Pi-hole is enrichment only.** In
both-source mode Zeek is the clustering source and Pi-hole data enriches those
findings with the block disposition; queries that appear only in the Pi-hole log
(clients whose DNS never crosses the Zeek sensor's view) are not separately
clustered on that run. Point sigwood at the Pi-hole log alone to cluster it in its
own right.

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

**A graph's entity count describes only the timeline it shows.** For bounded Zeek
files, graph can remove a very small but distant sparse edge so the dense body fills
the timeline. A host or service found only in that removed edge is therefore absent
from the entity count as well as the plotted rows; the header notes how many rows
were removed. This changes the shown-window census, not the underlying logs.

**A resolver-windowed graph does not receive a second sparse-edge trim.** A configured
Zeek directory already gets the normal default window, so graph deliberately
leaves any sparse edge inside that retained window alone. Shell-expanded bounded
files can receive the density trim when no timeframe or `--all` is supplied. This
one-window rule avoids silently stacking two automatic window selections.

**A windowed connection graph cannot recover connections that began before the load
window.** The loader selects conn rows by their recorded start time, so a connection
whose duration overlaps `--since`, a default window, or a date-named directory is absent
when its start falls before that boundary. The graph can retain overlapping duration
bands during its later sparse-edge trim, but it cannot draw rows the loader never
returned. Date-named conn directories call this out in their stored window note; use a
wider window or `--all` when the leading edge matters.

**The end of a connection graph is a lower bound on activity still in progress.** Zeek
writes a conn record when the connection ends. A connection still open at capture or
export time therefore has no row yet and cannot appear in the replay. Duration bands
can show and disclose clipping for recorded rows, but they cannot estimate unseen open
connections.

**RFC 3164 syslog and Pi-hole timestamps carry no year and no timezone, so sigwood
infers both.** The RFC 3164 / dnsmasq wall-clock format simply doesn't record them. sigwood
stamps each line with the analysis machine's current year (rolling back one year only
when that would place it more than a week in the future - a stamp a few hours or days
ahead stays future-dated in the current year) and reads the time in the analysis
machine's local timezone before converting to UTC. Two consequences: a syslog archive more than a year
old is silently re-dated into the last twelve months, and a log written on a host in a
different timezone (shipped or exported logs) stays offset by the timezone difference -
and those shifted dates flow into window filtering, digest timelines, and finding data
windows looking confident. Zeek (epoch), CloudTrail (zoned ISO-8601), and ISO-8601 /
RFC-3339 syslog (Ubuntu/Pop 24.04+, which carries an explicit year and offset) are unaffected.
Analyze wall-clock logs on a machine in the log's own timezone, and treat dates on
year-old syslog archives with suspicion; a per-source timezone setting is on the list
if a real deployment needs it.

**ISO-8601 syslog discovery keys on the line shape, so a syslog-shaped application log
can be picked up.** sigwood recognizes an ISO-8601 syslog line by its `<timestamp> <host>
<program>: <message>` shape - an explicit offset plus a colon-terminated program tag. An
ISO-timestamped application log that happens to share that shape and sits in the syslog
directory can be hunted as syslog; a differently-shaped one (like `dnf.log`) is correctly
skipped. If a non-syslog file is picked up, point sigwood at the specific syslog file
rather than the directory.

**`auto` uses one local system-log source per run - it does not combine the journal with
your flat archive.** On a systemd host `--syslog-source=auto` prefers the live journal and,
once it finds usable entries there, does not also read `syslog_dir`. So a historical window
that has rolled out of the journal but still exists in your rotated flat files is not covered
by an `auto` run - pass `--syslog-source=files` (or point at the files directly) to hunt the
on-disk archive. This is deliberate: reading both and reconciling them would double the I/O and
still could not prove which copy is more complete. A very large `journalctl` query (for example
`--all` on a big archive) can take a while and has no built-in timeout; press Ctrl-C to stop it.

**A directory positional is hunted as one log family.** When you pass a directory to
`sigwood hunt` (or to `dns`/`syslog`, the two-source detectors), sigwood samples up to
32 files, takes a majority vote on what family the directory is (Zeek, syslog, Pi-hole,
CloudTrail), and hunts it as that family - files of a losing family in the same
directory aren't hunted as their own kind on that run (sigwood says so at run time when
the sample is mixed). The other single-detector verbs (`beacon`, `scan`, `duration`,
`aws`) don't sample at all: the verb itself decides the family, with no mixed-content
notice. A parent directory whose log families live in subdirectories (`case/zeek/`,
`case/pihole/`) isn't recursively inventoried either. Pass the files themselves, one
directory per family, or set the per-family source dirs in config.

**zstd-compressed logs aren't supported yet.** sigwood transparently reads `.gz`,
`.bz2`, and `.xz`. `.zst` needs a decoder that isn't in the Python standard library
before 3.14, so it's deferred for now - decompress those files first.

**Peak memory runs to a multiple of the largest log loaded.** sigwood reads each log fully
into memory (pandas) rather than streaming, so peak memory tracks the biggest single file it
opens, not the total on disk - a ~560 MB `conn.log` peaked near 6 GB in one measurement. The
default window keeps a live directory from being read end to end, but one very large file, or
`--all` over a big archive, can exhaust a small box before the run finishes. Narrow the window
(`--since`/`--days`), point at a single file, or run where there's headroom; streaming
ingestion for the large-single-file case is on the list. The install has real weight too:
the scientific-Python stack underneath (pandas, numpy, the clustering backend) puts a fresh
virtualenv at roughly 450 MB on disk - light to operate, not light to install.

## Digest and output

**Not every finding carries a machine-readable event timestamp.** `duration`, `scan`,
aws burst, and syslog family/burst/reboot findings carry event timestamps in their JSON
evidence; beacon, dns, and isolated syslog rare-event findings currently do not, so a
`jq` timeline can place some findings but not others. Every finding does carry the run's data window.
Converging on a representative event timestamp for every finding is planned.

**The conn digest is slow on very large frames.** The connection digest walks every
row to build its histogram and per-flow summary, so a multi-million-row `conn.log`
takes a while. It's correct, just not yet optimized; performance work is on the list.

**A force-killed run can leave the terminal cursor hidden.** sigwood hides the cursor
while it narrates progress and restores it on every ordinary exit, including errors and
Ctrl-C. `kill -9` (and an unhandled SIGTERM) gives the process no chance to clean up, so
the cursor can stay hidden in that shell — the same trade every cursor-hiding CLI makes.
`tput cnorm` (or opening a new tab) brings it back.
