# sigwood FAQ

Questions people might very well ask, and a deeper look at the ideas under the detectors.

- [The basics](#the-basics)
- [Running it](#running-it)
- [How the detectors work](#how-the-detectors-work)
- [The project](#the-project)

---

## The basics

### What is sigwood, in one sentence?

A local-first command-line workbench for hunting through the logs you already have - Zeek,
Pi-hole/dnsmasq, syslog, CloudTrail - using transparent, named methods rather than a black
box, enumerated badness, or a rulebook.

### Is any of my data sent anywhere?

No. sigwood runs on your box, over files on your disk, and talks to no one. There is no
telemetry, no account, no cloud, no phone-home. The exporters move data *toward* you - they 
pull logs *in* from Splunk or an S3 CloudTrail bucket to local files - and they never push 
your data out. (For S3, you authenticate your own shell; sigwood never sees your AWS 
credentials.)

### Who can read the files it writes?

Only you, by default. Reports, digests, graph artifacts, exports, and the config can
carry domains, client addresses, and evidence, so every directory sigwood creates is
mode 0700 and every file it writes is 0600 - regardless of your umask, and re-applied
when a report is overwritten on a re-run. Sharing is a deliberate act: `chmod` the
file you actually mean to hand out. If your sigwood home predates this and is group-
or world-accessible, each run prints a one-line stderr reminder until you
`chmod 700` it; sigwood never changes permissions on a directory it didn't create.
The one exception is a system-wide `/etc/sigwood` config, which keeps ordinary
shared permissions so non-root users can read it.

### Do I need Zeek?

No. Pi-hole/dnsmasq, syslog, and CloudTrail each stand on their own. Zeek is simply where
the tool has the most to work with - it carries connection-level context (RTT, TTL, byte
counts, the full 5-tuple) that a DNS-only or host-log source can't. If you run on Pi-hole
alone, sigwood tells you so and keeps working; you just get DNS analysis without the
connection correlation. Point it at whatever you have. That said, Zeek is awesome and you 
*should* get it: https://zeek.org/

### What about Pi-hole?

Also not required and for the same reason: the detectors are independent of each
other and of their log formats. The dns detector works just fine on Zeek's dns.log.
If you do have a Pi-hole, however, sigwood offers rich support, incorporating
the `was-blocked` disposition of a query in its findings. It needs the flat
query log (pihole.log), so query logging has to be on; it doesn't read the FTL
database (yet). One thing to know when you run Zeek and Pi-hole together: Zeek
is the clustering source and Pi-hole enriches those findings - queries that only
the Pi-hole log saw aren't separately clustered on that run (run the Pi-hole log
on its own to cluster it directly; details in
[KNOWN-ISSUES.md](KNOWN-ISSUES.md)). Pi-hole is a great project and is worth a look: https://pi-hole.net/

### How is this different from a SIEM? From an IDS?

A SIEM is an always-on platform: it ingests continuously, stores everything, and alerts in
real time. sigwood is the opposite shape on purpose - it runs in batches, over logs at
rest, when *you* run it. There's nothing to deploy and nothing running in the background.
No database, no daemon. This is the sigwood promise.

It's also not an IDS. It doesn't sit inline, it doesn't match signatures, and it doesn't
block anything. It *surfaces behavior* for a human to triage. Think of it as the tool you
reach for to go hunting through a few days of logs, not the tool that watches the wire.

### What's the difference between the hunt and `digest`?

The **hunt** (the default - `sigwood <path>`, or `sigwood hunt`) runs the curated default
detector set and produces findings: things worth a second look, with a severity and the
evidence behind them. Detectors outside that set stay runnable by name; use
`--detect=all` to run every available detector.

`digest` (`sigwood digest <file>`) is orientation *before* the hunt. It reads a log and
tells you what's in it - time span, top talkers, the shape of the mix, a histogram - and
renders **zero verdicts**. No "suspicious," no "anomalous," just facts and superlatives.
It's sonar, not an X-ray machine: it tells you what's there so you know where to point the
detectors. (It also reads your data *before* the allowlist, because everything in the file
is part of "what's in here.")

### What's the `graph` verb for?

`graph` (`sigwood graph <path>`) is the third way to look at a log, alongside the hunt and
`digest`. It writes a self-contained HTML file that *replays* the log's flows as an animated
Sankey - clients, the domains or services they reached, and, for Pi-hole, what happened to each
query. Think of the three as orient, see, analyze: `digest` tells you what's in a file, `graph`
lets you watch it move, and the hunt tells you what stands out.

For Zeek connection logs, byte ribbons use the recorded total and duration to draw a
constant-rate band across each connection; connection counts remain anchored at starts.
Zeek does not record the timing of bytes inside a connection, so this is an explicit model,
not a claim that a bursty transfer was uniform. The artifact names the assumption and notes
any recorded byte mass clipped outside its shown window.

It is deliberately a **replay, not a monitor** - it plays back a saved record and never tails a
live one, so it keeps sigwood daemon-free and dashboard-free. Like `digest` it reads *before*
the allowlist and renders facts rather than verdicts: it shows you a flow, never a label like
"exfil" or "suspicious." The artifact is one file with no external resources and no network
calls, and it ends with the exact `sigwood hunt` command for the same log - so a graph is a
hook into the hunt, not a replacement for it.

A valid log always yields a graph. A very busy one that is too dense to animate smoothly
degrades rather than failing - it caps the smoothing, coarsens the time bins, or folds to the
busiest hosts and services, and notes what it did in the header - so you always get an artifact
to look at instead of an error.

### What log sources can it read?

Zeek (`conn.log`, `dns.log`, `syslog.log`, in NDJSON or TSV, flat or date-partitioned
directories), Pi-hole/dnsmasq, the live **systemd journal** (via `journalctl`, no sudo), flat
syslog in RFC 3164 or ISO-8601 form (both the Debian `*.log` convention and the extensionless
RHEL/Fedora one), and CloudTrail JSON. Rotation and `.gz`/`.bz2`/`.xz` compression are handled
for you. Forthcoming, possibly: more.

### Does it read the systemd journal?

Yes. On a systemd host `sigwood syslog` (and `sigwood hunt`) read the live system journal
directly - it runs `journalctl --output=json` for the journal *your* user can already read, with
**no sudo, no export step, and no file left behind** (the capture is a private temporary file
removed as soon as the data is loaded). Every entry becomes the same five-column row as flat
syslog, so the detector treats journal and file logs identically.

`--syslog-source` picks the local source: `auto` (the default) prefers the journal and falls back
to your `syslog_dir` files if journalctl is missing or the journal has nothing usable; `journal`
requires it; `files` uses the flat directory only; `off` turns the local lane off. sigwood uses
**one** local source per run - it never merges the journal with flat files (choose `files`
explicitly if you want the on-disk archive). It needs systemd 236 or newer, and a single journal
entry larger than 1 MiB fails the run visibly rather than being silently truncated.

Zeek's own `syslog.log` can load alongside the local source, and the same rule extends per host:
a host present in the local feed keeps its local rows only, and Zeek contributes just the hosts
the local feed lacks - otherwise a doubly-carried line would count twice and stop looking rare.
The run summary discloses it in counts when it happens (`system logs: 1 host carried by both the
local feed and Zeek syslog.log - kept the local rows (16,094 Zeek rows set aside)`).

**Existing configs migrate to `auto`.** If you never set `syslog_source`, sigwood now prefers the
journal on a systemd host and tells you which source it used; set `syslog_source = "files"` to keep
the old file-only behavior.

---

## Running it

### Why did a detector get skipped?

It needs a log it couldn't find. Each detector declares the log type it reads; if that file
isn't in the configured directory, the detector is skipped with a one-line note on stderr
(`conn.log not found in /var/log/zeek - skipping beacon detection`) and is left out of the
report rather than pretended-run. Point it at the right directory, or `--detect` only the
ones you have data for.

### Why did it flag something I know is fine?

Tell it once and it'll stop. sigwood filters **before** it analyzes: a flat-file allowlist
suppresses known-good traffic before any detector sees the data. Add the host, CIDR,
`:port/proto`, or domain pattern to your allowlist and that traffic never reaches the
detector - so it can't be flagged, and your noise floor is yours to set. (There's a second,
structured form - TOML stanzas - which suppress the same way but let a rule carry a
comment and a per-detector scope. A future classification role, where a detector is told
what a thing *is* - a nameserver, a backup client - rather than dropping it, is planned
but not consumed by any shipped detector yet.)

### What does it suppress out of the box?

A curated allowlist of known-harmless infrastructure - CDNs, cloud platforms, NTP, certificate
validation (OCSP/CRL), public DNS, OS update channels - plus common consumer-device telemetry,
all dropped before analysis so signal isn't buried in plumbing. These are the shipped `common`
and `devices` lists, both on by default; a third `homelab` list (Splunk, Proxmox, UniFi, …)
ships off, since suppressing a product you run is a real blind spot - turn it on with
`sigwood allowlist enable homelab`. Nothing ad-, tracking-, or destination-specific is on the
list - opinions differ and you may want to see those.

### How do I see or change what's suppressed?

`sigwood allowlist` prints what's loaded, which lists are on, and - on every detect run - how
much got suppressed (the `allowlist:` line on the run-summary banner, e.g. `suppressed 1,284
connections (12%) and 312 domains (59%)` - the parenthetical is the share of loaded rows each
covered, so an unexpectedly high rate rings a bell). `sigwood allowlist show <name>` prints a
list's patterns;
`enable`/`disable <name>` toggle a shipped list; `copy <name>` forks one into your
`~/.sigwood/allowlist.d/` to edit. Add your own names in any `domains_*` there (always
additive - to replace a shipped list, disable it). Names carry no extension, so a dotted copy
like `domains_user.bak` won't load (the readout nudges a rename); park a retired list with a
trailing `~` or by dropping the prefix. Turn suppression off for one run with
`--no-allowlist`, or permanently with `enabled = false`.

### How do I silence one noisy host?

Put a pattern in the `hosts` file under `~/.sigwood/allowlist.d/` (seeded blank by
`sigwood init`) - one fnmatch glob or `re:` regex per line, matched case-insensitively
against the system-log host column (`lab-*`, `re:^kiosk-[0-9]+$`). It applies to every
syslog feed - flat files, the system journal, and Zeek `syslog.log` - before analysis, and
the run banner discloses it (`suppressed 9,412 rows from 1 host`). Two things to know
before you reach for it: suppression removes that host's *entire* system-log story - rare
lines, bursts, reboots, admin-session and update-run units - and removing a chatty host
shifts what counts as rare for the remaining hosts, because rarity is relative to the
loaded corpus. Prefer narrow patterns, and review the file periodically. Host lists are
local-only: sigwood never ships one.

### What does the shipped allowlist not protect you from seeing?

Treat it as a discovery aid, not a fence. The shipped lists quiet DNS queries to known-good
domains so real signal isn't buried in plumbing - but they trust a domain by its **name**, so
a channel that fronts through an allowlisted CDN, or hosts its payload on a big cloud
provider's domain, gets its DNS name quieted along with the legitimate traffic. Two things keep
that from being a silent hole. First, the shipped lists are **domain-only**: connection
analysis (`beacon`, `scan`, `duration`, all reading `conn.log` by IP) never consults them, so a
periodic beacon to a fronted host is still scored on its *timing*, whatever name it used.
Second, every run prints how much it suppressed (the `allowlist:` line), and `--no-allowlist`
turns suppression off entirely for one run. Numeric IP/CIDR suppression never ships - that's
yours to set, locally. When a destination matters, read the connection findings and the
suppression rate, not just the DNS view.

### It surfaced a huge number of findings. Now what?

Two things are usually going on. First, real noise you haven't allowlisted yet - start
there. Second, on very high-volume host logs the syslog templating can over-trigger
(when almost every line looks structurally unique, "rare" stops meaning much); the reading
views (`text`/`html`/`pdf`) cap how many findings they show per detector and tell you they
did, while `json` and `csv` keep everything. Tightening that high-volume behavior is an honest
area of ongoing work - see [KNOWN-ISSUES.md](KNOWN-ISSUES.md). When in doubt, `digest` the file first to see
whether the volume is the story.

### How much data can it handle?

Pointed at a directory, an unqualified run looks back over the last `default_window` (`7d`
out of the box), so a live log directory isn't read end-to-end every time; widen with
`--since` / `--days` or read it all with `--all`. For rotated flat logs it peeks each
rotation file's first timestamp and stops early instead of decompressing the whole archive.
And it prompts before chewing through more than `warn_above` records (default 10,000,000).
Very large single pulls (tens of millions of CloudTrail events) are the current scaling
edge.

Memory is the other edge worth knowing. sigwood reads each log fully into memory (pandas)
rather than streaming it, so peak memory scales with the *largest single file* it opens, not
the total on disk - a ~560 MB `conn.log` peaked near 6 GB in one measurement. The default
window keeps a live directory from being read end to end, but one very large file, or `--all`
over a big archive, can OOM a small box. Narrow the window with `--since`/`--days`, point at a
single file, or run where there's headroom.

### What timezone are the times in?

Your machine's local timezone, labeled `local` on human-readable timestamps. Pass
`--utc` (or set `use_utc = true` in config) to render everything in UTC with a `UTC` label
instead - handy when you correlate across hosts or pivot into raw logs that carry UTC
stamps. The setting is consistent end to end: an offset-less `--since`/`--until` date and
the day boundaries of `--days` are read in the same timezone it displays (a date with an
explicit offset is always honored as written), export's no-timeframe default window
anchors on the same midnights, and the date in an auto-named report or digest filename
follows it too. `json` output is the exception by design - it is always ISO-8601 UTC, so
feeds into other tooling never shift with a display preference.

One display exception, on syslog's grouped rows: the leading stamp on a review unit, a burst
or a reboot is written in syslog's own wall-clock shape - `Jul 12 21:57:33` - rather than the
labeled form, so it reads like the log itself. It carries no `local` word, and it is the same
converted time as every other timestamp. Under `--utc` it picks up a ` UTC` suffix, because
there it no longer matches the clock the log was written in.

Two things to know when reading those rows. Syslog lines carry no year, so neither does this
stamp; the report header names the window, and `-v` shows each row's first timestamp in full.
And a raw log line's own stamp is the clock of the host that wrote it, which need not be
yours - a log shipped in from another timezone, or one carrying its own offset, can show
different digits from the grouped row above it even in local mode.

### Can I run it on a schedule?

Yes - it's batch, stateless, and built for unattended use. `-q` quiets the progress
narration, `-y` auto-accepts the large-dataset prompt, and `--out=<dir>/` (or `report_dir` in
config) writes a collision-safe named report. A hunt exits `0` whether or not it finds
anything - a clean Unix contract, where nonzero means the *run itself* failed, not that a
threat was found - so schedule it and inspect the JSON to decide whether to alert. That
contract covers a detector that crashes mid-run too: the run continues past it, but the
exit code goes nonzero and the JSON feed names it under `run_summary.detectors_failed`
(empty `{}` on a clean run) - a crashed detector never reads as a quiet night. A nightly
cron line:

```
0 3 * * *  sigwood hunt -q -y --format=json --out=~/.sigwood/reports/
```

and, to page yourself when a run found something - or when a detector failed and the
night's coverage is incomplete:

```
sigwood hunt -q -y --format=json | jq -e '(.findings | length > 0) or (.run_summary.detectors_failed | length > 0)' && your-alert-here
```

No daemon and no state between runs - each run stands on its own.

### Can I use it as a Python library?

Yes. Detectors are pure functions - they take loaded data and return findings, and never
open files, read config, or render output (the one caveat: syslog shows a terminal-only
progress bar while templating, silent when piped). You can import one and call it on a DataFrame in a
notebook, which is exactly how the clustering work is prototyped.

---

## How the detectors work

The thread running through all of them: **package sound methods so a self-hoster gets them
for free, and make the method visible.** sigwood is not a rule engine wearing an ML
costume. Each detector below names the actual idea it runs on, and every run tells you which
one ran.

### `beacon` - why an FFT?

A beacon - malware checking in with its controller on a schedule - is *periodic*. Periodicity
is nearly invisible in a list of timestamps but obvious in the **frequency domain**. An FFT
turns "connections over time" into "how much energy lives at each frequency," and a regular
beacon shows up as a sharp spike at its check-in frequency - even when jitter and missed
check-ins smear it out in the raw timeline.

A couple of choices matter. The timestamps are binned into **30-second buckets** and the FFT
runs over the bucket counts, which is resilient to gaps - a host that sleeps for an hour
breaks a raw inter-arrival series but barely dents a binned grid. The bin size also sets the
detector's floor: the fastest representable cadence is twice the bin (60 seconds), anything
faster shows up aliased as a slower period, and a beacon sitting exactly at that edge scores
less reliably than one comfortably above it - the sweet spot is the minutes-to-hours range
where real C2 check-ins live. The bin size is a calibrated constant; the scoring thresholds
and period band are tuned against it. The score is a composite - 40% how dominant the spectral peak is, 40% how
far that peak stands above the local noise floor, and 20% how regular the timing is (inverted
jitter) - over flows of at least 20 connections.

The detector measures *periodicity*, not maliciousness: a benign MRTG poller hitting SSH
every 60 seconds lights up too. That's the right mental model - beaconing is a *shape*, and a
finding is a flow with that shape, for you to explain or allowlist. The calibration reference
is the demo corpus's seeded 180-second beacon (480 connections over 24 hours), which scores
~0.62 with a dominant period of exactly 180.0s - one favorable *single-day* realization, not a
typical number; a 60-second cadence sits at the edge of what 30-second bins can represent, so
its score varies with how arrivals fall against bin boundaries.

One caveat rides on all of this: the FFT needs enough span to resolve a jittered beacon.
Resolving a jittered periodic check-in takes about a week of data - on a single day the same
beacon clears the score threshold only occasionally, so a short window surfaces mainly the most
machine-regular flows (often benign infrastructure, per the MRTG note above). Over a full week
the FFT has the resolution to hold that beacon in a tight band a little below its lucky
single-day peak - more span buys resolution, not a higher score. sigwood's default
directory window is `7d` - exactly the reliability bar - and it discloses a short analysis
span at run time, so widen with `--all` when your archive holds less than a week, and lean
on the allowlist to set aside your own infrastructure.

### `dns` - why HDBSCAN, and why is "noise" the interesting part?

Normal DNS is repetitive and clusters tightly. Your machines hit the same CDNs, update
servers, and mail hosts over and over, with similar round-trip times, TTLs, and query
lengths. Low-volume domain-generation-algorithm (DGA) traffic and DNS tunneling don't fit
those dense, boring clusters - they land in the noise HDBSCAN sets aside.

HDBSCAN is a **density-based clusterer**: it groups points where they're densely packed and
labels everything that belongs to no cluster as *noise*. The move that makes this work for
hunting is to flip the usual intent - **the noise is the signal.** The clusters are the
normal you don't care about; the points that fit nothing are the candidates.

Why HDBSCAN and not something simpler? k-means makes you declare the number of clusters up
front and assumes round, equal-sized blobs - DNS behavior is neither. Plain DBSCAN needs a
single global density threshold, which fails when some normal patterns are dense and others
sparse. HDBSCAN discovers the cluster count itself and tolerates varying density, which is
what real traffic looks like.

The features are per-query RTT, TTL, query length/depth, and TLD distribution. The noise
domains are then ranked by a per-label **suspicion score** - sigwood's own weighted lexical
heuristic, not Shannon entropy - computed on the highest-scoring label across all subdomains,
then grouped by registrable domain (eTLD+1), so fourteen random subdomains of one parent read
as one finding instead of fourteen. The score leans on digit density, so it has three related
biases: benign digit-heavy labels such as short hex IDs or versioned hostnames can score high;
dictionary-word DGAs can score low; and genuinely random letter-only, no-digit labels can also
score low (as can a long hexadecimal label, which sits just under the tunnel bar - see
[KNOWN-ISSUES.md](KNOWN-ISSUES.md)). A digit-bearing random-looking label such as `x7f2k9q1` scores much higher than a
letter-only label of similar length, so letter-only labels cannot reach HIGH severity or trip
the dense-cluster tunnel scan, and they fall below the surface gate for the vast majority of
realistic lengths. "High-entropy cluster" elsewhere is a colloquial name for that random-looking
query shape (the cluster topology), not a claim that the score is Shannon entropy. A finding is
a starting point, not a verdict; the intended pivots are `dns.log` → `conn.log` → whois →
reputation → ASN.

There is one place "noise is the signal" leaks: a *sustained, high-volume* tunnel is thousands
of structurally-similar high-entropy queries, so past a size threshold it forms its own dense
cluster and never reaches the noise set - the loudest exfil would be the one that hides.
On Zeek DNS, sigwood closes this by also scanning the dense clusters: a cluster whose
members are overwhelmingly high-entropy *and* concentrated under one registrable domain has
that shape surfaced into the same suspicion-score ranking, and the run discloses that the
scan fired. The gate is deliberately conservative, so a benign high-entropy cluster - a CDN
or telemetry endpoint that happens to look the same - does not flood the report; allowlist
those you recognize. **The dense-cluster scan runs on Zeek data only.** On Pi-hole/dnsmasq
data the same blind spot is open: a high-volume tunnel can self-cluster and drop out of the
report exactly as it grows louder - see [Known issues](KNOWN-ISSUES.md) for the honest
detail.

### `syslog` - why drain3, and what's a "rare template"?

Host logs are mostly *templated*. `Accepted password for alice from 192.0.2.10 port 22` and
`Accepted password for bob from 198.51.100.7 port 22` are the same sentence with different
blanks filled in. drain3 learns those templates online - it maintains a parse tree and
discovers, without a single regex from you, that both lines share the structure
`Accepted password for <*> from <*> port <*>`.

Once every line carries a template, you can ask a question keyword lists can't answer: **which
lines are structurally rare?** Count how often each template appears across every host; the ones at the bottom
of the distribution - the lines that look like almost nothing else in the log - get surfaced,
and a template seen exactly once is the strongest signal. The point of rarity over a
signature list is that the interesting event is usually the one you didn't think to name. A
keyword search only finds what you already anticipated; rarity finds the line that doesn't fit
its neighbors, whatever it happens to say.

One wrinkle dominates real logs: when a host does a lot at once - a reboot, a package
upgrade, a service restart - it spits out a burst of one-off lines (init chatter, services
starting in a fresh order, kernel ring-buffer dumps) that would *all* read as rare. A single
boot can be hundreds of "rare" lines. So rather than flood you, sigwood folds each per-host
burst of rare lines into a single summary - `Jul  1 03:12:47 · webhost · 187 rare
lines · 12s · mostly kernel, systemd` - and tags it `rebooted` directly after the host
when a boot signal lands in the same window. Reboots
themselves are detected on a separate full-frame pass, independent of rarity, so a machine
that reboots over and over is flagged **every** time - not just on its first, still-unique
boot.

The remaining rare lines use two deliberately modest tiers. The everyday **rare events**
sieve is LOW and remains visible in the default report: rarity concentrates things worth
skimming, but does not by itself claim danger. An exact, case-sensitive match on the parsed
program name against a small shipped class of authentication, privilege, account, audit,
and crash programs moves the finding into the MEDIUM **privileged** section. Membership is
never inferred from message text. Privileged rows also stay out of INFO burst collapse, so
a lone `useradd` cannot vanish into nearby routine chatter.

Within either rarity channel, isolated lines that share one host and one program fold into
a single review unit - `Jul  1 03:12:47 · webhost · sshd · 2 rare lines · 1h` -
because "this program produced
N one-offs" is one decision, not N; a lone rare line still stands on its own. Family and
burst rows show their first timestamp, `-v` includes up to three sampled lines, and an HTML
report has a closed expansion for the full bounded sample. Long identifier-like hexadecimal
runs (queue ids, session tokens) are normalized during template mining, so a message that
differs only by such an identifier counts as repetition rather than a parade of one-offs.

The shipped class is configuration, not a hidden rule. Copy the commented
`privileged_programs = [...]` block under `[detectors.syslog]` from
`config_example.toml` into your config, then add or remove exact program tokens; an operator
list replaces the shipped roster. A restart should not bury the day's real signal, and
rarity alone should not overstate it.

On top of rarity, sigwood recognizes two routine *transactions* the same way it recognizes
reboots: an **admin session** (a login through its logout, anchored on the session
open/close lines the system itself writes) and an **update run** (package-manager,
kernel-module, and policy-reload activity). When several findings on one host fall inside
one recognized transaction, they fold into a single labeled review unit - `Jul 12
22:11:11 · webhost · update run · 4 member findings · 1m · mostly kernel, systemd` - with
every member preserved behind it (`-v` in text, an expandable row in HTML, complete in
JSON). One admin doing one system update reads as one line, not nineteen. Recognition only
groups; it never decides severity - a unit is MEDIUM exactly when one of its members is
from the privileged class, and a rare line that matches no transaction is left exactly as
it was. If the pattern isn't there - an unfamiliar distro, a log that rotates mid-session -
findings simply stay ungrouped, and `recognize_transactions = false` turns the whole thing
off.

### `aws` - why a plain z-score instead of a fancy model?

Because you have to be able to read *why* a principal was surfaced. The CloudTrail detector is
**model-free on purpose**: a transparent z-score composite over intuitive danger signals -
error rate, distinct source IPs, distinct action names, action entropy - each a number you
can look at and explain. Reaching for an opaque model would betray the whole point; a score
you can't account for is worse than no score in a tool a humble operator is meant to trust.

It works in two tiers. **Burst sweeps** catch first-seen actions clumped together within a
sliding time gap - the shape of someone enumerating an account - and they're glanceable on one
line. **Ranked principals** get the composite. Only the *interactive* lane is scored: AWS's
own service-lane background activity is supposed to be broad and repetitive, so scoring it just
makes noise.

It's **batch and stateless** - "first-seen" means first in the window you loaded, not first in 
all of history, and the run says so rather than implying a baseline it doesn't keep. And it knows 
its blind spot: a low-volume principal doing a few high-impact things isn't reliably caught by 
volume-shaped signals, so principals below the event floor are set aside and their count is 
disclosed up front, not hidden.

### `scan` and `duration` - why are these labeled "just heuristics"?

Because that's what they are. `scan` counts distinct destination ports and hosts against thresholds 
to separate vertical (one host, many ports), horizontal (one port, many hosts), block (many of both), 
and slow (the same spread out over time) scanning. `duration` groups connections by flow and flags 
the long-lived tail - the keep-alive sessions and tunnels that stay open far longer than a normal 
request.

### Why isn't the top-ranked finding automatically the most severe?

Because that would manufacture verdicts. The tempting design is "sort by score, crown the top
one HIGH" - but run that against a perfectly clean log and it still crowns *something*. The
most-normal thing in a normal dataset gets a severity it didn't earn.

So severity is by **absolute gates, never rank position**. A finding is HIGH because it crossed
a real bar, not because it won a relative race against its neighbors. When nothing crosses the
bar, the tool says nothing stood out - which on a clean corpus is the most useful answer.
This is most visible in the CloudTrail detector, where a quiet account genuinely returns "nothing
stood out" instead of a top-of-the-list scare.

### Where do these detection methods come from?

The signal-processing and unsupervised-ML approaches - FFT for periodic-beacon detection and
density-based clustering for DNS behavior - are established techniques in mathematics-based
threat hunting, taught notably in David Hoelzer's SANS SEC595. sigwood applies them to local
logs with open-source libraries (numpy for the FFT, hdbscan / fast_hdbscan for clustering,
drain3 for syslog templating). The implementations are original, and no course material is
reproduced.

---

## The project

### A brand-new repo, a short history, tidy docs - was this written by AI?

Um yep, development was AI-assisted, no point being coy about it. The rest has a less exciting explanation than you might hope. sigwood was built over a few months against one homelab with Zeek, Pi-hole, syslog, a small CloudTrail corpus, and only opened up once it did something useful. The history starts at a single squashed commit because the real history was full of explorations that included that homelab's own IPs, hostnames, and other assets. Squashing was the cleanest way to get every example into line with RFC 5737 (the 192.0.2.x ranges throughout) with nothing real left in the tree. So a repo that looks like it appeared fully formed from Zeus's forehead is really just one person's ordinary, messy iteration, compressed behind that first squashed commit, with the mess kept private for a reason.

You don't have to take any of this on faith, though - most of it is checkable. The detection methods are named, published techniques you can look up: FFT for periodicity, HDBSCAN for clustering, drain3 for templating, a plain z-score composite, credited elsewhere in this FAQ. The privacy claim you can verify yourself: tldextract is pinned to run offline, so the tool talks to no one. The test suite is deterministic and passes on a cold install. And [KNOWN-ISSUES.md](KNOWN-ISSUES.md) names and quantifies the tool's own flaws rather than burying them. Read the code, run the tests, point it at your own logs - that will tell you more than this paragraph can.

### How do I know the sigwood I installed is genuine?

Every `sigwood` release on PyPI is published by a tag-triggered CI pipeline that authenticates
over OpenID Connect - there is no long-lived upload token sitting on anyone's laptop that could
leak and let someone publish a malicious release under our name. Each published file also carries
a [PEP 740](https://peps.python.org/pep-0740/) publish attestation: a Sigstore-backed, verifiable
record that the file was uploaded by this project's release pipeline (`helixmap/sigwood`'s
`release.yml`). PyPI shows it on each file's page. The precise claim matters - an attestation
proves *where a file came from*, this pipeline, not that the code is safe; for that, the rest of
this section applies: read the code, run the tests.

### What state is sigwood in?

Early, pre-1.0. The six detectors above work and are covered by tests. Five more -
`dnsblock`, `auth`, `ssl`, `protocol`, and `weird` - are planned but not built. Interfaces may still move before
1.0. The current roadmap and the running list of known rough edges are public, in
[ROADMAP.md](ROADMAP.md) and [KNOWN-ISSUES.md](KNOWN-ISSUES.md).

### How would I add a new log format, or a new detector?

sigwood is built "big-tent": a new log *format* joins an existing source family by adding a
parser front-end and a single loader strategy entry - the detector logic doesn't change,
because the loader normalizes every source to one canonical schema. A new *detector* is a
self-contained module that declares the log it needs and a `run()` that takes loaded data and
returns findings; discovery is automatic, with no registry to edit. The detector contract is
spelled out in [CONTRIBUTING.md](../CONTRIBUTING.md) ("Adding a detector"); the canonical
column schemas live in [SCHEMA.md](SCHEMA.md).

A guiding rule: a detector's identity is the *question it asks*, not the source it reads.
A second CloudTrail detector for privilege escalation would be its own detector named for that
question.

### Where do I report a bug or check what's planned?

To report a bug or float an idea, [open an issue](https://github.com/helixmap/sigwood/issues)
on GitHub - a clear description of what sigwood got wrong, ideally with a scrubbed log sample,
helps more than you'd expect. Known rough edges live in [KNOWN-ISSUES.md](KNOWN-ISSUES.md), and the
roadmap in [ROADMAP.md](ROADMAP.md).

### What's the license?

MIT. See [LICENSE](../LICENSE).
