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

**A machine that changed its hostname is scored as two machines.** This one is about a
single feed, not the two-feed case above: syslog rarity is counted per host and program,
and the host is whatever the log line says. If a machine's name changed partway through
the logs - renamed, or the short name replaced by the fully qualified one during setup -
its earlier and later lines are counted separately. A line that is unremarkable under one
name can look rare under the other because each name has its own, smaller history, and
`sigwood digest` reports two hosts for the one box. sigwood has no way to know two names
are the same machine. If you recognize the rename, read the two sets together; if the
change was recent, a window that starts after it gives you one consistent name.

**Beacon wants a week or more of data.** A jittered periodic beacon only clears the
FFT score threshold intermittently over a single day, so a short window tends to
surface the most machine-regular flows - which are often benign infrastructure (NTP,
monitoring agents, DNS) rather than C2. sigwood flags a short analysis span at run
time; give it a week or more of `conn.log`, and use the allowlist to suppress the
infrastructure you recognize. Reliability across diverse real-world networks is still
being characterized, and this is the honest state of the flagship beacon detector today.

**Beacon only scores Zeek SF/S1 connection states.** The pre-filter looks
at Zeek SF/S1 connections with observed originator bytes. Other state families are
not analyzed, including established-but-reset or incomplete connections such as
RSTO/RSTR/S2/S3 and unanswered or rejected attempts such as S0/REJ. sigwood discloses
at run time when most loaded connections fall outside SF/S1 and go unscored. Scoring
those families as separate tiers is planned; it needs threshold and false-positive
calibration first.

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

**On Pi-hole/dnsmasq-only data, DNS findings cannot reach HIGH.** HIGH requires a name to
look generated *and* to be corroborated by something else - lookups that mostly fail to
resolve, or membership in a dense concentrated cluster. Pi-hole records no DNS response
code, so the first is unavailable, and the dense-cluster scan runs on Zeek only, so the
second is too. Pi-hole DNS findings therefore top out at MEDIUM. This is a fidelity limit
of the source, not a judgement that the traffic is benign - add Zeek for the same domains
if you need the distinction.

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

**Letter-only DGA labels never clear the suspicion score's bar.** The score leans on digit
density, so a random no-digit label scores roughly a third of a point below a digit-bearing
label of the same length, and the best possible all-letter label sits below the candidate
bar (1.8) by arithmetic: zero of 11,000 seeded samples cleared it, 1,000 per length across
eleven lengths from 6 to 63. The vowel-free digit-and-consonant shape the score is tuned
toward clears the bar about 19-36% of the time at typical DGA lengths (10-16 characters); a
uniformly random letter-digit label, 6.6-14.8%. Boosting the letter-only class was measured
and rejected - every length- or vowel-keyed boost rule tested either flagged real benign
names (the strictest still crossed 57 in a benign reference week) or caught under half of
its target. The compensating channel is behavioral and narrow: on Zeek data, five or more
low-scoring subdomains under one parent whose lookups fail to resolve at least 90% of the
time surface together as one INFO finding regardless of score; a family spread across many
registrable domains, or one whose names resolve, is not covered by it. Pivot on query
volume, registrable-domain concentration, and allowlist review when no-digit labels show up
in noisy DNS traffic.

**Hex-encoded DNS tunneling can slip the high-volume scan.** A long hexadecimal label - the
shape of base16-encoded tunneling - straddles the high-entropy bar (1.8) the dense-cluster
scan requires: measured on seeded random hex, roughly half of labels clear the bar (40-60%
across lengths 16-63), well short of the 80% of cluster members the scan demands, so a
high-volume hex tunnel that grows into its own cluster can pass the scan without tripping
it. Pivot on the volume and registrable-domain concentration of random-looking lookups when
the scan is quiet.

**On a small DNS capture, no clusters form and the method label still names the algorithm.**
Zeek DNS analysis needs a substantial number of queries before HDBSCAN groups them (the default
minimum cluster size is 2000); on a smaller capture every query is treated as noise and the
findings come entirely from the per-label suspicion score, not from cluster shape. The
`dns (fast-HDBSCAN)` method label names the clustering backend that ran even when it formed no
clusters, so on a small capture the lexical score is doing the work.

**DNS clustering cost rises with the volume of unsuppressed queries.** Measured on one frozen
seven-day corpus of about 2.2 million rows, on one machine. Running the DNS detector on its own,
a `--no-allowlist` pass over the full seven days completed in about eight minutes, and the
process was observed at about 8 GiB resident — holding near that level for most of the run rather
than spiking briefly. Running the whole default hunt over the same window, also unsuppressed, did
not finish within a nine-minute bound. With the shipped allowlist the same window completes
normally, and at a one-day window the unsuppressed run completes in about 50 seconds.

With an unusually thin allowlist, or `--no-allowlist` over a large window, the DNS path may be
impractically slow or may exceed the memory available to the process on a smaller machine. Narrow
the window, run the detector on its own (`--detect=dns`), or keep suppression enabled. These
figures come from one corpus and one machine. They are not a scaling law and do not explain why
clustering behaves this way.

**A fast sequence of unprivileged rare events folds into one informational burst.** Four or
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

**Every auth finding caps at MEDIUM.** Concentrated failures, source volume, account volume,
and multi-host spread each describe one category of authentication evidence, and none becomes
HIGH on magnitude alone. Failures followed by a success are reported as evidence on the
matching multi-host finding but do not raise severity: the detector counts plainly and does
not claim a corroborated verdict. Treat every auth finding as a review lead.

**Auth floors count decision records, not human attempts, and more than one source can record
the same event.** Each source that observed an authentication contributes its own records, and
no source's records are discarded to make room for another's — dropping them is how a real
attack can disappear. Two consequences. A host reporting through both its service log and the
audit system can record one event in each, so its magnitudes can run up to about double. And
where one physical authentication produces several distinct eligible audit types, each
contributes. Mirrored renderings of a single audit record are reconciled to one, but the
numeric floors have not been retuned for either effect, so a multi-source or audit-rich feed
can cross a floor with fewer human attempts than a single-source feed. Every run says so in
its notes.

**A same-time auth tie can drop a failures-then-success result.** Landing keeps each source's
rows coherent rather than mixing them, and among the sources that recorded a transition for an
episode, the best-placed one owns the whole episode — including an unresolved
failure-and-success tie at a single timestamp. Another source's otherwise clear transition is
not substituted in that case. (A source that recorded no transition at all does not block one:
it is skipped, and a lower-placed source's result stands.) The result is a conservative miss.
Where the same source and account also produced a multi-host finding, only that evidence line
is absent. Where they did not, the failures-then-success finding is absent altogether — the
failures are still counted and will surface on their own if a concentration, volume, or spread
floor is reached, but nothing guarantees one is. Because landing no longer affects severity,
this can never lower another finding's tier.

**Auth `first_seen` is window-relative.** It is the first qualifying event in the data loaded
for this run, not proof that the activity began then. A finding can touch the beginning and end
of the window, and its evidence says so, but sigwood cannot infer what happened before the
observation cut. Widen the window before treating first-seen timing as history.

**Remote source addresses in auth logs are not individually allowlist-suppressible.** The
canonical system-log frame exposes the host that wrote each record, so the host allowlist can
suppress that machine before analysis. A remote source address extracted from the message is
not a canonical allowlist field, so only whole-host suppression applies on this lane. Runs with
remote sources disclose that boundary; per-address suppression needs a future normalization and
allowlist change, not detector-local filtering.

**The only observed auth HIGH witness is synthetic.** The available real estate corpora contain
no exact multi-host-failure plus landing shape, so they cannot demonstrate HIGH. The positive
regression uses generated authentication traffic with known structure. That is valid evidence
that the rule recognizes its declared shape, but it is not a precision claim about real attacks.

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

**A recognized admin session or update run groups the lines that fall inside it, related or
not.** When sigwood recognizes a session or a package-update run, it claims the rare lines
inside that window - which is what turns one administrator's work into a single row instead of
nineteen, because the daemon noise their actions caused belongs in the same story. The same
rule cannot tell that noise apart from something unrelated that merely happened at the same
time, so an unrelated line inside the window is grouped too, and if it came from a privileged
program the whole unit is reported at that higher severity. Nothing is hidden - every grouped
line is listed under the unit with its own time and program - so read a unit as "these things
happened together", not as "these things are the same event". Narrowing the rule by program was
measured and rejected: it dissolved genuine sessions and dropped most of their content.

**An AWS event can still exclude itself from analysis by naming a role exactly like a service
role.** CloudTrail activity is split into automated service activity and interactive activity,
and only the interactive side is scored. One of the signals for "service" is a role whose name
begins with `AWSServiceRoleFor`, the convention AWS uses for roles its own services assume. A
role created with a name that begins the same way is read the same way, and its events are set
aside without being counted or mentioned. A name that merely contains that marker somewhere in
the middle no longer qualifies, and neither does a different capitalisation. Closing the
exact-name case too would mean also requiring the reserved role path AWS uses for these roles -
but the records carry that path in only one of the two places the role name appears, and the
handful of real examples available cannot establish that it is always present. If it is not,
genuine automated activity would start being reported as ordinary user activity. That trade is
not worth making without more evidence.

## Ingestion and windows

**A folder *inside* a CloudTrail tree that you lack permission to read is skipped without saying
so.** If permissions stop sigwood listing the CloudTrail directory you configured, it now
reports that and carries on. Native CloudTrail archives can use a nested tree, though -
`AWSLogs/<account>/CloudTrail/<region>/<year>/...` - and sigwood searches downward with a
recursive match that silently returns nothing for any folder it cannot open. So a permissions
problem on a folder *below* the one you configured produces no error and no note: those events
are simply missing, and the run looks normal. The permission check covers the directory you
configured, not the folders beneath it. If your CloudTrail results seem short, check that every
folder under the configured directory is readable by the user running sigwood.

**A deliberately malformed log file can still stop a single run.** sigwood reads whatever
you point it at, and a file crafted to be hostile rather than merely broken can exhaust
memory or CPU badly enough to end that one run: a compressed archive that expands enormously,
a single line of unbounded length, an XZ stream declaring a huge decoder dictionary, a
timestamp span that inflates the digest histogram, an unbounded journal capture, or a DNS
name long enough to make lexical scoring crawl. The bound each of those needs is a judgement
about real logs - how long a legitimate line can be, how far a real archive expands - and
guessing wrong would silently discard valid data, which is worse. So they are written down
here rather than half-fixed.

The scope is one local run on your own workstation: sigwood is batch, single-user, and
reads files you chose. There is no service to take down and no exposure of data, and every
case that produced a raw crash or an unbounded allocation has been fixed. If you are pointing
sigwood at logs from a source you do not trust, treat it like any other parser: run it
somewhere you don't mind restarting.

**An explicit conn log named outside `conn*.log*` silently skips the connection
detectors.** Pointing sigwood at a single Zeek connection log whose filename does not
match `conn*.log*` (say, `capture.ndjson`) reports `conn.log not found` and skips
beacon, scan, and duration, even though the file's content is a valid conn log -
single-file discovery still matches by filename. Rename the file to match the
pattern (`conn.capture.log` works), or point sigwood at its directory with the
standard names. Content-trusted explicit files are planned; the filename match is
the current rule.

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

**Findings carry an event timestamp in their JSON evidence, but the key name varies by
finding type.** Most of them - beacon, dns, duration, and syslog families, bursts and
single rare lines - use `first_seen`. aws burst findings use `start_time`; syslog reboot
findings use `reboot_ts`, which is the reboot instant rather than the first event of a
group; and `scan` uses `window_start`, whose value is UTC but written without a timezone
offset. Two summary findings that describe a whole scan rather than one entity - the aws
ranked summary and the dns scan summary - carry no event timestamp at all, by design. A
`jq` timeline therefore has to know which key a given finding type uses. Every finding
also carries the run's data window.

**Symbolic-link refusal covers only the final file name, not hard links or parent
directories.** sigwood checks, at the moment it opens the file, that
the final name it was asked to write is not a symbolic link, and refuses rather than
following it. Two shapes are outside that check. A **hard link** is not a link sigwood can
detect this way — it is a second name for the same file, so opening it is opening that
file, and its contents would be replaced. A **symbolic link among the parent directories**
is followed normally, which is deliberate: a reports directory pointing at another disk is
an ordinary thing to set up, and only the last component is checked.

Both need the same thing to matter: another account able to create or replace a name in one
of the directories along your output path. If every such directory is one only you can write
to, neither applies. They need different fixes, and neither is a small one. Avoiding a hard
link means not emptying the destination before knowing what it is — writing to a temporary
name and moving it into place. A symbolic link among the parent directories is not addressed
by that at all, because the temporary file would be created inside the substituted directory
too; it needs each directory along the path opened without following links.

**The conn digest is slow on very large frames.** The connection digest walks every
row to build its histogram and per-flow summary, so a multi-million-row `conn.log`
takes a while. It's correct, just not yet optimized; performance work is on the list.

**A force-killed run can leave the terminal cursor hidden.** sigwood hides the cursor
while it narrates progress and restores it on every ordinary exit, including errors and
Ctrl-C. `kill -9` (and an unhandled SIGTERM) gives the process no chance to clean up, so
the cursor can stay hidden in that shell — the same trade every cursor-hiding CLI makes.
`tput cnorm` (or opening a new tab) brings it back.
