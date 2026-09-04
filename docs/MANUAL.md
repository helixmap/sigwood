# The sigwood manual

This is the reference for the reader who is digging in: what each verb does, how sources
are discovered, how time and windows work, what every detector measures and refuses to
measure, how to read the output, and which knobs exist. It states behavior, with limits
beside capabilities. It is not the [FAQ](FAQ.md), which answers objections; not the
[contract](CONTRACT.md), which promises what stays stable; and not a substitute for
[known issues](KNOWN-ISSUES.md), which quantifies the rough edges. Everything here is
Ctrl-F-able on purpose - headings name the thing you would search for.

## What a run is

sigwood is one command with a handful of verbs. The default verb is the **hunt**: point it
at a log file or rely on your configured directories, and it loads, suppresses, analyzes,
and reports in one pass, leaving nothing resident.

```
sigwood hunt                    # hunt the configured sources
sigwood /var/log/zeek/conn.log  # a path is intent enough - same hunt, one file
sigwood digest /var/log/messages
sigwood graph /var/log/pihole/
```

The verbs divide by what they produce. `hunt` produces findings - things worth a second
look, each with a severity and its evidence. `digest` produces orientation - a factual
card about what is in a file, with zero verdicts. `graph` produces a replay - one
self-contained HTML artifact that animates a log's flows. `export` pulls logs toward you
from Splunk or an S3 CloudTrail bucket into local files. `era` measures a whole dated Zeek
archive as one historical deck. `init` is the setup wizard, and `allowlist` inspects and
manages suppression. Each verb explains itself: `sigwood <verb> --help` prints that verb's
flags and does nothing else - `init --help` does not start the wizard.

**A run needs intent.** A bare path is intent - a hunt on that file. The word `hunt` is
intent - a hunt on your configured sources. Flags alone are not: `sigwood -q` refuses with
`nothing to hunt - run 'sigwood hunt' or pass a log file`, because a flag is set dressing
and running every detector on your whole estate should never be an accident.

**Exit codes are a scheduling contract.** A hunt exits `0` when the run itself succeeded,
whether or not it found anything - finding nothing on a clean night is success. It exits
`1` when the run failed: a broken config value, no detector able to run, or a detector
that crashed mid-run (the report still renders, and the JSON feed names the casualty
under `run_summary.detectors_failed`, so a crashed detector never reads as a quiet
night). An interrupted run exits `130`, and a run whose downstream pipe closed early -
`sigwood ... | head` - exits `141` silently, which under `pipefail` reads as "downstream
closed", not an error. Schedule the hunt, check the exit code for run health, and inspect
the JSON to decide whether to alert; the two questions are deliberately separate.

**Errors speak in two voices.** A usage mistake - an unknown flag, a malformed value -
gets a one-line `sigwood:` message plus a pointer to `--help`:

```
sigwood: unknown flag --bogus
run 'sigwood --help' for usage
```

An operational problem - a config value that will not parse, a detector name that does
not exist - gets the same one-line `sigwood:` voice with no usage pointer, because the
fix is in your environment, not your typing. And skipped work is not an error at all: it
is narrated in plain unprefixed lines on stderr, as status rather than failure -

```
conn*.log* not found in /var/log/zeek - skipping beacon detection
no detectors could run - check required log source paths in config or CLI overrides
```

A detector whose log is missing says so and stays out of the report rather than
pretending to have run; when nothing at all could run, the run exits `1` - the narration
stays calm, and the exit code carries the verdict.

---

## Installing and upgrading

After this chapter you can install sigwood without changing the operating system's Python,
add the optional integrations you need, upgrade the same environment later, and recover from
an earlier root-owned installation without guessing at a destructive command. sigwood needs
Python 3.11 or newer and supports macOS and Linux, including Raspberry Pi. It is tested on
3.11 through 3.14, the versions its CI matrix runs; 3.15 is untested at this tag, and
installing there is permitted rather than verified. Windows is not a tested native target;
use WSL when Windows is the host.

An isolated tool environment is the simplest route. With pipx:

```bash
pipx ensurepath
pipx install sigwood
sigwood --version
```

Reopen the shell after `pipx ensurepath` if the command is not found. The equivalent uv
command is `uv tool install sigwood`. A conventional virtual environment also works:

```bash
python3 -m venv venv
venv/bin/pip install sigwood
venv/bin/sigwood --version
```

Use the installer that owns the environment when you upgrade: `pipx upgrade sigwood` or
`uv tool upgrade sigwood`. For an editable source checkout, update it through your normal
Git workflow and refresh the existing environment directly:

```bash
.venv/bin/pip install -e '.[all]'
.venv/bin/sigwood --version
```

Extras add integrations. `[splunk]` installs the Splunk exporter, `[cloudtrail]` installs
the S3 exporter, and `[all]` includes those integrations plus the accelerated clustering
dependencies. `[pdf]` is separate because PDF rendering also needs native text libraries:
Pango on macOS or Linux. Adding an extra to an existing pipx environment needs `--force`,
for example `pipx install --force 'sigwood[pdf]'`. A virtual environment can add the extra
in place.

On a 64-bit machine, the base installation already selects `fast-hdbscan`. The `[fast]`
extra exists for the 32-bit case, where the base installation selects stock `hdbscan`; it
forces the faster backend there. Adding `[fast]` on a 64-bit machine changes nothing. A
first run on a small box can take a minute or two while the scientific stack warms and
caches work on disk. This startup cost is different from the memory cost of clustering a
large DNS window, covered under [Windows, time, and scale](#windows-time-and-scale).

A clean macOS arm64 virtual environment is roughly half a gigabyte because the scientific
Python stack dominates the installation. The size is an environment cost, not a resident
service: nothing keeps running after the command exits. A bare installation needs no compiler
on the platforms the project targets.

Do not use `sudo pip install sigwood`. That changes a system Python as root and may collide
with packages owned by the operating system. If it already happened, remove or repair that
copy through the package-management path that owns the system Python; there is no safe
universal uninstall line. Then install a user-owned pipx or uv copy. Removing an isolated
copy is correspondingly direct: `pipx uninstall sigwood` or `uv tool uninstall sigwood`.
sigwood installs no daemon, service, or scheduled job. Its user data remains under
`~/.sigwood/` until you choose to remove it, so save reports or exports before deleting that
directory.

## Sources and discovery

After this chapter you can tell sigwood exactly which data to read, predict what an
unqualified run will discover, and understand which feed wins when the same system-log host
appears twice. An explicit positional path narrows the run to that file or directory. With no
path, sigwood uses the configured source directories. The source-specific command-line
overrides narrow a run without rewriting config:

```bash
sigwood hunt --zeek-dir=/srv/zeek
sigwood dns --pihole-dir=/var/log/pihole
sigwood syslog --syslog-source=files --syslog-dir=/var/log
sigwood aws --cloudtrail-dir=/srv/cloudtrail
```

A single named file is read in full unless you give an explicit time bound. A directory is
discovered by source family, rotation, and compression, then windowed as described in the
next chapter. Missing input does not become an empty successful analysis: the affected
detector prints a skip line, and a run where nothing can execute exits nonzero.

Discovery also reports files it cannot parse or read instead of silently counting them as
empty. If a configured directory and an explicit positional path disagree, the positional
path is the scope you asked for; use the source-specific override when you mean to replace a
configured family for that run.

### Zeek

Zeek connection, DNS, and system-log streams can be TSV or NDJSON. sigwood reads flat
directories and dated directory trees, recognizes rotated siblings, and transparently opens
gzip, bzip2, and xz files. The connection stream supplies flow timing, state, ports, and byte
counts to beacon, scan, and exfil. The DNS stream supplies names, clients, response outcomes,
and grouping evidence to dns. Zeek's system-log stream is another input to syslog and auth.
An SSL stream, with certificate data when available, supplies ssl.

For Zeek, filenames are meaningful because each log type has a stable family name such as
`conn.log`, `dns.log`, or `ssl.log`. Pointing at a Zeek directory therefore lets discovery
select the stream each requested detector declares. Pointing at an explicit file is stricter:
the file is the source you chose, and a nonexistent positional path fails immediately instead
of falling through to directory discovery.

### Pi-hole and dnsmasq

Pi-hole contributes the flat query log at `/var/log/pihole/pihole.log` and its rotated
siblings. Pi-hole v6 still uses that path; the `dns.queryLogging` Pi-hole setting controls
whether the file is populated. sigwood reads this flat log, not the FTL long-term database.
If it is missing or empty, enable query logging before treating a quiet analysis as evidence.

On a Pi-hole-only run, dns clusters the per-domain aggregate directly, while dnsblock reads
the blocked disposition and measures first activity, bursts, and recurrence. When Zeek DNS
and Pi-hole are both present, Zeek is the clustering source and Pi-hole enriches those Zeek
findings with block disposition. Names visible only to Pi-hole are not separately clustered
in that combined run. Point dns at the Pi-hole log alone when you want that population
clustered in its own right.

### Flat syslog and the systemd journal

System logs are content-sniffed rather than accepted by filename alone. This difference is
intentional: Debian-family systems commonly use names such as `syslog`, `auth.log`, and
`kern.log`, while RHEL-family systems use extensionless names such as `messages`, `secure`,
and `maillog`. Inspecting the content lets sigwood accept both layouts and reject lookalikes
such as a package-manager log or a binary accounting file. RFC 3164 and ISO-8601 lines are
normalized to the same minimal row of time, host, program, raw line, and message.

On a systemd host, `--syslog-source=auto` prefers the live journal and falls back to files.
`journal` requires the journal, `files` selects the flat directory, and `off` disables the
local lane. Journal capture calls `journalctl --output=json` as your current user: it does not
use sudo, leaves no export behind, and deletes its private temporary capture after loading.
The journal and flat files are alternative local providers, not inputs that are merged
together.

Zeek `syslog.log` can still accompany the selected local provider. Arbitration happens per
host. If a host appears locally, its local rows win and Zeek rows for that host are set aside;
Zeek contributes hosts absent from the local feed. The run summary reports the affected host
and row counts. This prevents double counting, but it has edges: a gap in the local history is
not filled from Zeek once that host is local, and a hostname in one feed plus an address in the
other can look like separate hosts. Hostless rows are not arbitrated.

### CloudTrail, digest, and source choice

CloudTrail input is local JSON, including compressed files. The exporter can first pull it
from S3, but detection reads the resulting local files. AWS credentials remain in the ambient
boto3 chain; the analysis path does not ask for or store them.

When you do not know what a file is, start with `sigwood digest PATH`. Digest content-sniffs
connection, DNS, system-log, and CloudTrail shapes. Unrecognized text falls back to a bounded
byte profile rather than being assigned a detector schema. Digest reads before suppression,
because its job is to describe the input population. That makes it a useful check before a
hunt whose source choice or row volume surprises you.

## Windows, time, and scale

After this chapter you can select an exact analysis interval, predict how a directory differs
from a file, line up displayed dates with your query bounds, and avoid loading more data than
your machine can hold.

An unqualified directory run uses the configured lookback for that source's own data. A
single file is read in full. `--all` widens to the complete available archive. Explicit
bounds override the ordinary directory lookback:

```bash
sigwood hunt --since=7d /srv/zeek
sigwood hunt --since=2026-05-01 --until=2026-05-08 /srv/zeek
sigwood hunt --days=2-4 /srv/zeek
sigwood hunt --hours=0-6 /srv/zeek
sigwood hunt --all /srv/zeek
```

The endpoints in `--days=N-M` and `--hours=N-M` are order-insensitive. A single-value form is
rejected because it does not state a range. For rotated flat logs, sigwood peeks
at each candidate file's first timestamp and can stop before decompressing older rotations.
An input it cannot peek is already loaded in full, so no later shortcut can recover that I/O.

dnsblock needs history to decide whether blocked activity is new or recurring. On a peekable
Pi-hole directory it may select 21 additional days of rotated files while keeping reported
rows inside the chosen report window. With the usual week-long report span, that creates a
28-day file-selection aperture. The history changes classification context, not the dates
shown as findings. Explicit bounds and `--all` retain their normal meanings. CloudTrail takes
the opposite special case: novelty needs its history, so an unqualified CloudTrail source
loads in full unless you narrow it explicitly.

Human-readable times use the machine's local timezone and carry a `local` label. `--utc`
makes the display UTC. Naive dates given to `--since`, `--until`, or day ranges are interpreted
in the same zone the report displays; a date with an explicit offset keeps that offset.
Auto-named report and digest dates follow the same setting. JSON is always ISO-8601 UTC so a
machine feed does not change with display preference. CSV uses ISO-8601 with the active display
offset. Grouped syslog rows are the human-output exception: they lead with a syslog-shaped
stamp while the report window still names its zone.

Before analyzing a very large loaded population, sigwood asks for confirmation at the
configured warning boundary. `--yes` accepts advisory prompts for unattended work; disabling
that boundary in config suppresses the prompt. The loader is not a streaming engine: each log
is represented in memory, so a very large file or a wide unsuppressed window can exhaust a
small host. Narrow the time range, select the needed detector, or run on a machine with more
headroom.

DNS clustering is the clearest measured example. On one seven-day estate containing about
1.7 million Zeek DNS rows and 3.8 million Pi-hole rows, a DNS-only pass without suppression
used 7.26-7.54 GiB in the main process and about 9.85 GiB across the process tree. The child
clustering process is why watching only the parent understates the requirement. Those figures
come from one corpus and machine; they are not a general scaling law. Large clustering runs
can also vary slightly in cluster membership because parallel work returns in different
orders. Reported findings were stable in the measured runs, but a domain at a boundary is not
guaranteed to repeat. Keep suppression enabled for ordinary work and inspect borderline cases
directly when repeatability matters.

Use `--dry-run` when you want to inspect source selection, detector eligibility, and window
planning without running analysis or writing output. It is especially useful before widening
a dated archive or changing several source overrides at once. `-q` suppresses runner-owned
progress and the ordinary window advisory, but it never suppresses warnings, prompts, errors,
or the report itself. In automation, combine explicit bounds with `--yes` only after you have
decided that the large-data advisory is expected; accepting a prompt does not change how much
memory the chosen source requires.

Window labels describe the rows that survived loading, not necessarily every file opened to
establish context. This distinction matters for dnsblock history, for a compressed rotation
whose leading timestamp had to be inspected, and for rows with missing timestamps. A run note
calls out important exclusions or degraded input. When you compare reports, compare their data
windows and source notes before comparing finding counts.

## The detectors, in depth

After this chapter you can choose the detector that answers your question, understand what
evidence can raise its severity, and recognize where a quiet result is only a source or method
limit. Severity orders review; it does not assign guilt. Operator-adjustable controls are
listed in [Tuning and suppression](#tuning-and-suppression). Measurement history and its
limits live in the [evidence ledger](EVIDENCE.md).

### auth: where did authentication pressure concentrate?

auth reads the normalized system-log lane and groups recognized authentication observations
by service, source, account namespace, account, and host. It surfaces concentrated failure
runs, unusually high source or account volume, the same source-account identity spreading
across hosts, and a success that follows sustained failures for the same service identity.
No log dialect deletes another's records: sigwood counts them together. A host that reports
through both sshd's own log and the audit system can therefore record one event twice, so
these counts are decision records rather than a count of human attempts.

Every auth finding tops out at MEDIUM. Failure volume, spread, and a later success are useful
structural signals, but the calibration work stopped before it had an independent population
for absolute thresholds or precision. auth is opt-in: run it directly or select it by name.
Host allowlisting suppresses the entire system-log story for that host, which can remove the
authentication evidence too. The published [auth measurement](evidence/auth.md) explains the
conservative structure, the severity ceiling, and what remains unmeasured.

### beacon: which connection tuple repeats on a cadence?

beacon groups Zeek connection rows by source, destination, port, and protocol, places arrivals
on a time grid, and uses an FFT-based score to find a dominant repeating interval. It reports
the strongest period, score components, connection count, byte shape, and time span so you can
pivot back to the process and destination. Only Zeek `SF` and `S1` rows with observed
originator bytes enter the scorer.

Timing is a single evidence category, so beacon caps at MEDIUM; with an operator-lowered
threshold, a lower score can surface as LOW. A week or more resolves a jittered cadence
better than a day. Gaps that occupy most of each day, destination rotation, rhythm changes,
or unrelated traffic sharing the exact tuple can dilute the signal. Cadences faster than 60
seconds can be detected but reported at an aliased longer period. Treat the period as a pivot,
not an exact clock. The published [beacon measurement](evidence/beacon.md) records the seeded
anchor, the ceiling, and the missing precision and transfer studies.

### dns: which names look generated, and what behavior backs that up?

dns combines a weighted lexical score with HDBSCAN grouping over per-query behavior. A name
that clears the spelling-shape bar is a candidate, normally MEDIUM. HIGH requires another
kind of evidence: a strong failure-to-resolve pattern on Zeek, or the eligible dense and
concentrated cluster route. The verbose evidence names that basis, so HIGH is never inferred
from the spelling score alone. A narrower Zeek-only route can also surface a family of
lower-scoring subdomains as INFO when they concentrate under a parent and overwhelmingly fail
to resolve.

sigwood's Pi-hole parser does not carry the resolution outcome. Its dense scan can find the
high-volume shape, but that same volume is not allowed to corroborate itself there, so
Pi-hole-only DNS findings stop at MEDIUM. Letter-only generated labels cannot reach the lexical bar by construction, and hex
labels can straddle it. Families spread across many registrable domains can escape the
concentration route. On small captures HDBSCAN may form no cluster and the lexical route does
the work even though the method label still names the backend. The published
[DNS measurement](evidence/dns.md) bounds these results to the measured estate and rule family;
it is not a universal catch rate.

### dnsblock: is blocked-name activity new, bursty, or recurring?

dnsblock reads Pi-hole blocked dispositions and compares the report population with bounded
history. It separates first activity, burst-shaped activity, and recurrence rather than
treating every blocked lookup as equivalent. The extra history can reach beyond the report
window, but findings remain inside that window. Because the tool stores no cross-run state, a
persistently blocked name can surface again while its onset remains in the lookback. Add the
exact expected name pattern to suppression after triage rather than treating one report as a
permanent acknowledgement.

The current findings are LOW or INFO; the method does not manufacture a high-severity verdict
from a blocklist hit. dnsblock is opt-in. Its one-estate threshold sweep and held-out interval
are recorded in the [evidence ledger](EVIDENCE.md#evidence-and-its-limits), but a full public
calibration record and independent-environment validation are still owed.

### syslog: which log patterns are rare, grouped, or reboot-related?

syslog mines message templates with drain3, counts template frequency across the loaded
population, and surfaces rare rows. Rare entries from a configured privileged-program class
take the MEDIUM lane; other isolated rare entries take LOW. Tight groups of unprivileged rare
rows on a host fold into an INFO burst, and repeated host-program families fold into review
units. Reboot signals are found independently of rarity and become INFO events or label a
nearby burst. Recognized administration sessions and update runs gather contemporaneous
findings into bounded review units while retaining the member evidence.

Rarity is corpus-relative. A stream where nearly every message is structurally unique can
over-trigger, and removing a noisy host changes the population used for everyone else.
Transactions group things that happened together; they do not prove every member has the same
cause. Cross-feed arbitration and hostname changes can also divide or omit history in the ways
described under sources. The published [syslog measurement](evidence/syslog.md) covers the
tested estate's masks and grouping thresholds, not every distribution or environment.

### scan: which source spread across ports, hosts, or time?

scan uses Zeek connection states and breadth counts to distinguish vertical activity against
many ports on one target, horizontal activity against many hosts on one port, block activity
across both dimensions, and slow activity spread over multiple time buckets. Findings from a
source fold by scan type so one sweep reads as one review row while member measurements remain
in evidence. Severity combines scan-indicative state share, breadth, and recognizable benign
shapes; deliberate broad sweeps can reach HIGH, while browsing, resolver, discovery, and dark
traffic shapes remain LOW.

Activity split across a fixed bucket boundary can be missed by the block arm or misclassified
by the slow arm. No calibration campaign has established
precision, recall, or transfer, as the [scan ledger row](EVIDENCE.md#evidence-and-its-limits)
states. Read a finding as threshold arithmetic over the loaded window and inspect the retained
targets before acting.

### exfil: where did a large measured outbound byte mass go?

exfil sums complete Zeek byte rows for each internal source and external destination, then
requires both a volume floor and a strongly outbound share. A surfaced pair is MEDIUM. When a
source reaches several addresses in the same fixed network block, the report can fold the pool
while retaining every destination's own totals in JSON and verbose evidence. This makes cloud
backup pools readable but can group unrelated neighboring services at a block edge.

The detector describes bulk transfer, not theft. Missing responder byte counts make a whole
log abstain or remove individual rows from the measurement; an unrecorded inbound mass can even
make a download look outbound. Transfers below the floor, split across destinations, or outside
the selected window remain invisible. The published [exfil measurement](evidence/exfil.md)
found destination-pool aggregation to be the dominant noise issue on its estate and bounds
noise, not malicious-transfer recall.

### ssl: which outbound TLS setup differs from the estate norm?

ssl is an opt-in Zeek analysis of source-destination pairs. One leg measures client behavior
around server-name use; the other uses server-infrastructure evidence such as certificate
validation context. A single leg is LOW. Both independent legs together are MEDIUM. HIGH is
unreachable because the detector has no third category that could support it. Certificate
facts describe only sessions where the needed SSL and certificate fields are present.

The calibration covered both legs and their eligibility funnel on one estate. That supports
an opt-in behavioral detector, not inclusion in the default hunt or transfer to another
environment. The [ssl ledger row](EVIDENCE.md#evidence-and-its-limits) is the current public
record; a full conclusion and cross-estate measurement remain open.

### aws: which CloudTrail principal stands out?

aws separates automated service activity from interactive principals. It uses a transparent
composite of per-principal error rate, distinct source addresses, distinct action names, and
action entropy. Absolute score bands produce MEDIUM or LOW findings; rank position alone never
creates a verdict, and a small scorable population makes the ranked tier abstain with an INFO
summary. A separate route groups several first-seen actions close together as a burst. That
burst is MEDIUM and reaches HIGH only when its error-rate condition also fires; size or service
spread alone does not escalate it.

Low-volume principals are set aside, and "first seen" means first inside the loaded window,
not first in the account's lifetime. The lane split is mechanical and can classify a
user-created role as automation. No calibration population was found, so
the [aws ledger row](EVIDENCE.md#evidence-and-its-limits) makes no efficacy or transfer claim.
Use the principal, event identifiers, source addresses, and regions as investigation pivots.

## Reading output

After this chapter you can tell run health from finding severity, choose the output surface
for a person or a machine, expand a finding without losing its context, and use digest or graph
as an entry point into the same data.

A hunt begins with a run summary: selected sources, data window, loaded record counts,
detectors run or skipped, suppression coverage, and notes about degraded or incomplete input.
Read that summary before the findings. A quiet report where a source was missing, a detector
abstained, or a detector failed does not mean the same thing as a successful run over complete
input. The process exit code reports run health; the finding list reports what the completed
analysis surfaced.

Each finding has a detector, severity, title, description, next steps, evidence, and a data
window. Severity is a review order tied to the detector's own ladder. HIGH often means that an
independent corroborator joined the base signal, not that the tool identified an attacker.
MEDIUM can be the ceiling for a method that holds only one evidence category. LOW and INFO can
still describe facts worth checking, especially grouped syslog bursts or a first activity.

Verbosity changes reading views. With no `-v`, text, HTML, and PDF emphasize the title and
compact finding row. `-v` adds the curated reason, practical pivots, and the evidence fields
that explain the severity. The data window comes last so the explanation stays together.
`-vv` exposes the full evidence dictionary for debugging and detailed review. A captured DNS
tail illustrates the middle tier:

```text
     next steps:
       · Check domain registration: whois relct5a6uig.xyz
       · Look up relct5a6uig.xyz on VirusTotal and Shodan
       · Check conn.log for connections to IPs resolved from these queries
       · Pivot on querier IPs: 192.168.1.37
     evidence:
       severity_basis: resolution-outcome
       sample_domains: 6d4ts10y9nl0vnm27t.relct5a6uig.xyz, 4t6d45ffn0766hm3.relct5a6uig.xyz, np9mr1h3xfw8.relct5a6uig.xyz
       unique_sources: 1
       min_label_score: 1.8485
       max_label_score: 1.9576
       nxdomain_fraction: 1.0
       nxdomain_count: 3
     data window: 2026-05-31 19:12 → 2026-06-01 18:57 local  (1d)
```

This is a contiguous excerpt from the captured demo output. Its basis says why the DNS row is
HIGH. At `-vv`, source, registrable domain, query counts, sample names, scores, timestamps, and
the remaining internal evidence are present too.

Choose a format by consumer:

- `text` is the terminal report, grouped by detector.
- `html` is a self-contained reading view with print and dark-mode styling.
- `pdf` renders the same report through the HTML path and needs an explicit destination or
  pipe plus the optional native dependencies.
- `json` is the lossless typed feed with `schema_version`, `run_summary`, and the full finding
  set. It always uses UTC and ignores display verbosity.
- `csv` is a remediation worklist with a row per finding plus status and notes columns. It also
  keeps the full set and ignores display verbosity.

The reading views can cap the number of rendered findings for each detector after severity
sorting and disclose when they do. JSON and CSV do not truncate. stdout is the default for
text and HTML, so either redirect it or use `--out=PATH`. A directory target produces an
automatic filename; a file target is literal.

Notes are part of the result, not decorative footer text. They disclose skipped source
families, eligibility loss, arbitration, capped displays, and detector-specific blind spots
that the renderer can observe at run time. Preserve them when copying a report into a ticket;
a finding without its run notes can imply coverage the run did not have.

### Digest anatomy

Digest is pre-hunt orientation and reads before suppression. A card names the file and schema,
shows its time span, line count, byte size, population-specific measurements, a scale-anchored
histogram with its peak, and a small set of factual insights. For a captured Zeek connection
file, those facts included host counts, outbound and inbound bytes, an hourly histogram, the
dominant receiving destination, and the densest tuple. Digest uses superlatives such as
"largest" or "more than 50x" but never assigns a threat label. Several input files produce
several cards. Unrecognized text becomes a sampled byte profile so a mystery file can still be
oriented without reading an arbitrarily large object end to end.

### Graph replay

Graph writes a self-contained HTML Sankey replay with no server, external resource, or network
call. Connection graphs place hosts against services and destinations; DNS graphs place clients
against domains; Pi-hole can add blocked, forwarded, cached, and local dispositions. It reads
before suppression and ends with the hunt command for the same input, making the artifact a
pivot rather than a verdict.

For Zeek connection data, a byte ribbon spreads the recorded total across the recorded
duration at a constant rate, while connection counts remain anchored at starts. Zeek does not
record when bytes moved inside a connection, so the ribbon is an explicit model and can smooth
a bursty transfer. The artifact notes byte mass clipped outside its displayed window. A valid
log still yields an artifact when it is busy: the player can cap smoothing, coarsen time bins,
or fold to the busiest hosts and services, and the header says which simplification occurred.
Graph is a replay of saved records, never a live monitor.

## Tuning and suppression

After this chapter you can inspect what suppression removed, add a narrow local exception, and
find every supported configuration route without copying a second set of defaults into this
manual. The annotated source of defaults is
[`sigwood/data/config_example.toml`](../sigwood/data/config_example.toml); generate a local
version with `sigwood init`, then change only the entries your evidence justifies.

### Suppression comes first

Flat allowlist files drop matching traffic before analysis. Domain patterns, numeric connection
rules, and system-log host patterns are different lanes. TOML stanzas perform the same drop
while carrying a comment and optional detector scope; no shipped method currently consumes a
classification-only role. `sigwood allowlist` shows whether suppression is active, the shipped
list states and sizes, user-list counts, and stanza count. `show`, `enable`, `disable`, and
`copy` inspect or manage a named shipped list. `--no-allowlist` bypasses suppression for one
run, and every detect run reports the suppressed share.

The drop-in filename is a type rule. An active flat list has no dot: `domains*` holds domain
globs, `connections*` holds numeric flow rules, and `hosts*` holds system-log host patterns.
A `.toml` file holds structured stanzas. Any other dot, or a trailing `~`, keeps a file from
loading; this lets you park a backup without accidentally treating it as policy. Drop-ins are
additive. To replace a shipped domain list, disable it and add your own.

A bare host address with no port suppresses all traffic involving that host. A pattern in the
`hosts` file suppresses that host's entire system-log story across flat files, the journal, and
Zeek system logs, including reboots and grouped administration or update activity. It also
changes the rarity population for the hosts that remain. Prefer narrow patterns, check the run
banner, and review local lists periodically.

### Configuration key map

The following map names the complete annotated surface. It describes purpose only; the example
file remains the owner of values.

| section | keys and purpose |
| --- | --- |
| `[sigwood]` | `root` resolves relative paths; `detect` selects analysis; `zeek_dir`, `syslog_source`, `syslog_dir`, `pihole_dir`, and `cloudtrail_dir` select inputs; `home_net` defines traffic direction; `report_dir` and `export_dir` select write roots; `output_format`, `quiet`, and `use_utc` select presentation; `default_window` and `warn_above` bound ordinary loading; `max_findings_per_detector` caps reading views. |
| `[graph]` | `target_bins` bounds time detail; `top_hosts` and `top_services` bound visible categories; `domain_level` selects name aggregation. |
| `[allowlist]` | `enabled` controls the entire suppression pass; `domain_patterns` and `connection_rules` point outside the drop-in directory; `allowlist_dir` locates drop-ins. Under `[allowlist.lists]`, `common`, `devices`, and `homelab` toggle the shipped domain sets. |
| `[export.splunk]` | `host` and `port` locate Splunk; `verify_tls` controls certificate verification; the backend-qualified `export_dir` selects its literal destination. Each `[export.splunk.query.<name>]` uses `spl`, `output_basename`, and the query-qualified `export_dir`. |
| `[export.cloudtrail]` | `path` names the S3 prefix, `egress_warn_gb` sets the advisory boundary, and the CloudTrail-qualified `export_dir` selects its literal destination. |
| `[detectors.beacon]` | `threshold` is the reporting score and `min_connections` is the eligible-flow floor. |
| `[detectors.scan]` | `vertical_threshold`, `horizontal_threshold`, `block_port_threshold`, and `block_host_threshold` set breadth gates; `block_state_min` and `slow_state_min` set state-share gates; `window_secs`, `slow_min_ports`, and `slow_min_buckets` define the time buckets and slow route. |
| `[detectors.exfil]` | `min_outbound_bytes` is the measured-volume floor and `min_orig_share` is the outbound-direction gate. |
| `[detectors.ssl]` | `min_connections` is the surfaced pair floor. |
| `[detectors.dns]` | `min_cluster_size` and `min_samples` shape clustering; `threshold`, `promote_below_gate`, `promote_min_subdomains`, `promote_min_nxdomain_fraction`, and `thresh_high_entropy` control lexical and promoted routes; `scan_dense_clusters`, `scan_min_high_entropy_fraction`, `scan_min_cluster_members`, `scan_min_regdomain_share`, and `scan_max_members_per_cluster` control dense-cluster inspection. The nested `[detectors.dns.pihole]` has its own `min_cluster_size` and `min_samples`. |
| `[detectors.syslog]` | `rarity_pct` and `max_count` define rarity; `burst_gap_seconds`, `burst_min_size`, and `family_min_size` define folds; `privileged_programs` defines the elevated program class; `reboot_cluster_seconds` groups boot signals; `recognize_transactions` controls administration and update review units. |
| `[detectors.aws]` | `min_events` and `min_scorable_principals` bound the ranked population; `burst_gap_seconds` and `burst_min_firsts` form first-activity bursts; `burst_high_error_rate` is the burst escalation gate; `composite_medium_threshold` and `composite_low_threshold` set absolute score bands. `burst_window_edge_margin_seconds` and `burst_high_service_count` remain accepted for compatibility but are unused. |

`sigwood init` discovers conventional inputs, previews changes, and merges into an existing file
without overwriting settings you already chose. Config lookup uses `--config=FILE` first, then
the user file, then the system-wide file. Command-line source, time, detector, output, and UTC
choices override the corresponding run behavior without editing the file.

Unknown entries are ignored with a `config:` warning and a nearby-name suggestion when one is
available. A malformed supported value is an operational error and stops before analysis, so a
mistyped setting does not quietly become a different hunt.

## Exporters

After this chapter you can pull a bounded local copy from Splunk or S3, know where credentials
come from, and hand the resulting files to the ordinary analysis path. Export is ingestion,
not a detector: it writes local logs, and later runs read those files exactly like logs that
arrived through rsyslog or another collector.

```bash
sigwood export splunk
sigwood export splunk auth
sigwood export cloudtrail
sigwood export cloudtrail --since=7d
```

For Splunk, configure named SPL queries. A bare Splunk export runs the only configured query;
when several exist, supply the query name. Prefer the `SIGWOOD_SPLUNK_USER` and
`SIGWOOD_SPLUNK_PASS` environment variables to credentials written in a file. The exporter
talks to the configured management endpoint and writes the selected query result locally.

For CloudTrail, configure an S3 prefix. Authenticate the shell through the normal AWS route;
boto3 resolves the ambient credential chain. sigwood does not read, store, or prompt for AWS
credentials. Before a large estimated download it asks for confirmation, and `--yes` accepts
that advisory in an unattended job. A time range narrows the pull; without one, export uses its
documented date-window behavior rather than promising a live stream.

The global export destination is a base that segments output by source. A backend or query can
instead choose a literal final directory, and `--out=PATH` is always literal for that run.
Directories and files created by sigwood use user-only permissions because exports can contain
identifiers and evidence. Exporter integrations are optional installation extras. If the
needed extra is absent, install it into the same isolated environment that owns the command.
No sample success transcript appears here because a real Splunk or S3 backend was not driven
for this manual; the supported commands and credential behavior come from the public surface.

Export does not schedule itself, retain a remote cursor, or start continuous collection. If
you want a recurring pull, schedule the explicit command in your own job runner and check its
exit code. Keep the exported directory separate from report output so a later hunt cannot
mistake a rendered artifact for input. A narrow query or S3 prefix is also a cost control: it
reduces local storage, transfer, and the population the later loader must hold.

## Where the other documents are

After this chapter you can choose the shortest source that answers the question in front of
you. The [README](../README.md) is the front door and quick start. The
[public contract](CONTRACT.md) defines stable command, configuration, Python, JSON, CSV, and
exit-code surfaces. [Known issues](KNOWN-ISSUES.md) lists measured limitations and silent
edges. The [FAQ](FAQ.md) answers objections and common operational questions.

For detector support, the [evidence ledger](EVIDENCE.md) says what has been measured and what
is still owed, while the [field validation kit](FIELDKIT.md) explains how to contribute
privacy-bounded aggregate results from another environment. [Contributing](../CONTRIBUTING.md) covers a
source checkout, tests, and project workflow. When this manual and a stability promise appear
to differ, use the contract for the promise and open an issue for the documentation mismatch.

The [roadmap](ROADMAP.md) separates shipped coverage from possible future work. The repository's
[security policy](../SECURITY.md) explains how to report a vulnerability. Release history lives
in the [changelog](../CHANGELOG.md), while the license itself remains at the repository root.
These pages answer project questions; they do not replace the run summary or evidence attached
to the data you are reviewing.
