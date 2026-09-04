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

### Why "sigwood"?

Signals in logs. That's the whole tweet. The name is short, memorable, and
sounds a bit chipper, which suits the tool. The namespace around "log" is
impossibly overcrowded, so it's off to the forest.

### Is any of my data sent anywhere?

No. sigwood runs on your box, over files on your disk, and talks to no one. There is no
telemetry, no account, no cloud, no phone-home. tldextract has no suffix-list URLs and no
cache, so it cannot fetch or retain a suffix list. The exporters move data *toward* you - they
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

### How do I upgrade, or recover from a `sudo pip install`?
*Full detail: [the manual](MANUAL.md#installing-and-upgrading).*

Use `pipx upgrade sigwood` or `uv tool upgrade sigwood`, matching the tool that installed it,
then run `sigwood --version` to confirm which command your shell finds. Do not repair an isolated
pipx, uv, or virtualenv install by rerunning it with `sudo`: a prior `sudo pip install` modified
a system Python, so cleanup must follow the package-management path that owns it. Install a
user-owned copy instead. Complete commands are in [Installation](../README.md#installation).

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

### I'm on Pi-hole v6 - where is the log sigwood reads?
*Full detail: [the manual](MANUAL.md#sources-and-discovery).*

Same place as v5: the flat query log at `/var/log/pihole/pihole.log`, plus its rotated
siblings, which sigwood picks up automatically. Pi-hole v6 controls it with
`dns.queryLogging`; if the log is missing or empty, turn query logging on. sigwood reads
this flat log, not FTL's long-term database. See [Quick start](../README.md#quick-start).

### How is this different from a SIEM? From an IDS?

sigwood sits between grep and a SIEM - more structure than grep, none of the platform.
A SIEM is an always-on platform: it ingests continuously, stores everything, and alerts in
real time. sigwood is the opposite shape on purpose - it runs in batches, over logs at
rest, when *you* run it. There's nothing to deploy and nothing running in the background.
No database, no daemon. This is the sigwood promise.

It's also not an IDS. It doesn't sit inline, it doesn't match signatures, and it doesn't
block anything. It *surfaces behavior* for a human to triage. Think of it as the tool you
reach for to go hunting through a few days of logs, not the tool that watches the wire.

### How does it relate to RITA, Security Onion, Malcolm, Suricata, or Slips?

All good projects, and if one of them already fits your stack, use it. Roughly: **Suricata**
is a rule-driven IDS engine that watches traffic and matches signatures in real time.
**Security Onion** and **Malcolm** are full monitoring platforms - they bundle sensors,
storage, and dashboards into something you deploy and operate. **Slips** is a behavioral
analysis engine with a machine-learning module set, run over flows or captures.
**RITA** is the closest relative in spirit: batch beacon-and-threat-hunting analysis over
Zeek logs.

sigwood's lane is the stack that has logs but no pipeline: a box with Zeek output, a
Pi-hole, a pile of syslog, or a CloudTrail export, and nobody running a platform over it.
One command over the files at rest, several detector families in one pass, a report, and
nothing left resident. It also runs happily as a batch second opinion *beside* any of the
above, since it only reads logs the sensors already wrote.

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
*Full detail: [the manual](MANUAL.md#reading-output).*

`graph` (`sigwood graph`, or `sigwood graph <path>` to narrow to one log) is the third way
to look at a log, alongside the hunt and `digest`. It writes one self-contained HTML artifact
that replays the log's flows as an animated Sankey - clients, the domains or services they
reached, and, for Pi-hole, what happened to each query. It is a **replay, not a monitor**: it
never tails a live log. Like `digest`, it reads before the allowlist and renders facts rather
than verdicts, so it shows a flow without calling it suspicious or exfiltration. The artifact
uses no external resources or network calls and ends with the exact `sigwood hunt` command for
the same log. A valid log always yields an artifact, even when a busy one must be simplified.

### What is `era`?

`era` measures a complete dated Zeek archive as one ten-card historical deck. It is not a
hunt and intentionally does not apply the allowlist, so its traffic counts include known
infrastructure that a hunt suppresses. Long-horizon cards need at least twelve eligible weeks;
a short archive still runs, but those cards may abstain. `sigwood era --dry-run` shows
the planner calendar and work estimate without loading the archive.

### What does the `ssl` detector actually claim?

It asks one question of every outbound TLS session: does the setup look unlike your own
estate's norm? Two measured legs answer it. **No server name** - the session completed,
was not a resumption, and carried no SNI. **A certificate that did not validate** - a
certificate was presented and its validation status was something other than `ok`.
One leg is LOW; both on the same host-and-destination pair is MEDIUM, because client
behavior and server infrastructure are independent kinds of evidence.

It does **not** claim the destination is malicious, look anything up in a reputation
feed, or compute a JA3 fingerprint. A hash fingerprint is a feed you would have to keep
current; sigwood measures your estate against itself instead, which is the whole point.

The certificate legs have a real limit and the finding says so: **TLS 1.3 encrypts the
certificate**, so a session that presented a visible certificate negotiated something
older. On the estate the detector was calibrated against, that was about a quarter of
outbound sessions - your mix will differ, and the run's own summary tells you what
yours was rather than assuming.

`ssl` is **opt-in**: run `sigwood ssl`, or include it with `--detect=all`. It stays out
of the default hunt until its calibration rests on more than one estate.

### What log sources can it read?

Zeek (`conn.log`, `dns.log`, `syslog.log`, in NDJSON or TSV, flat or date-partitioned
directories), Pi-hole/dnsmasq, the live **systemd journal** (via `journalctl`, no sudo), flat
syslog in RFC 3164 or ISO-8601 form (both the Debian `*.log` convention and the extensionless
RHEL/Fedora one), and CloudTrail JSON. Rotation and `.gz`/`.bz2`/`.xz` compression are handled
for you. Forthcoming, possibly: more.

### Does it read the systemd journal?
*Full detail: [the manual](MANUAL.md#sources-and-discovery).*

Yes. On a systemd host `sigwood syslog` (and `sigwood hunt`) read the live system journal
directly - it runs `journalctl --output=json` for the journal *your* user can already read, with
**no sudo, no export step, and no file left behind** (the capture is a private temporary file
removed as soon as the data is loaded). Every entry becomes the same five-column row as flat
syslog, so the detector treats journal and file logs identically.

`--syslog-source` selects `auto` (prefer the journal, then fall back to files), `journal`
(require it), `files` (use the flat directory), or `off` (disable the local lane). Existing
configs migrate to `auto`; set `syslog_source = "files"` to keep the old file-only behavior.

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
structured form - TOML stanzas - that suppresses the same way while carrying a comment and
per-detector scope.)

### What does it suppress out of the box?

A curated allowlist of known-harmless infrastructure - CDNs, cloud platforms, NTP, certificate
validation (OCSP/CRL), public DNS, OS update channels - plus common consumer-device telemetry,
all dropped before analysis so signal isn't buried in plumbing. These are the shipped `common`
and `devices` lists, both on by default; a third `homelab` list (Splunk, Proxmox, UniFi, …)
ships off, since suppressing a product you run is a real blind spot - turn it on with
`sigwood allowlist enable homelab`. Nothing ad-, tracking-, or destination-specific is on the
list - opinions differ and you may want to see those.

### How do I see or change what's suppressed?
*Full detail: [the manual](MANUAL.md#tuning-and-suppression).*

`sigwood allowlist` prints what is loaded and which lists are on. Every detect run also shows
an `allowlist:` banner line such as `suppressed 1,284 connections (12%) and 312 domains
(59%)`; the percentages are shares of the loaded rows, so an unexpectedly high rate is worth
checking. Use `sigwood allowlist show <name>` for one list. Turn suppression off for one run
with `--no-allowlist`.

### How do I silence one noisy host?
*Full detail: [the manual](MANUAL.md#tuning-and-suppression).*

Put a pattern in the `hosts` file under `~/.sigwood/allowlist.d/` (seeded blank by
`sigwood init`), one pattern per line; for example, `lab-*` matches those hostnames
case-insensitively. Suppression removes that host's *entire* system-log story - rare lines,
bursts, reboots, admin-session and update-run units - and removing a chatty host shifts what
counts as rare for the remaining hosts. Prefer narrow patterns.

### What does the shipped allowlist not protect you from seeing?

Treat it as a discovery aid, not a fence. The shipped lists quiet DNS queries to known-good
domains so real signal isn't buried in plumbing - but they trust a domain by its **name**, so
a channel that fronts through an allowlisted CDN, or hosts its payload on a big cloud
provider's domain, gets its DNS name quieted along with the legitimate traffic. Two things keep
that from being a silent hole. First, the shipped lists are **domain-only**: connection
analysis (`beacon`, `scan`, `exfil`, all reading `conn.log` by IP) never consults them, so a
periodic beacon to a fronted host is still scored on its *timing*, whatever name it used -
though if the same client also talks to that host legitimately on the same port, the blended
flow scores lower than the beacon alone (measured; see KNOWN-ISSUES).
Second, every run prints how much it suppressed (the `allowlist:` line), and `--no-allowlist`
turns suppression off entirely for one run. Numeric IP/CIDR suppression never ships - that's
yours to set, locally. When a destination matters, read the connection findings and the
suppression rate, not just the DNS view.

### It surfaced a huge number of findings. Now what?

Two things are usually going on. First, real noise you haven't allowlisted yet - start
there. Second, on very high-volume host logs the syslog templating can over-trigger
(when almost every line looks structurally unique, "rare" stops meaning much); the reading
views (`text`/`html`/`pdf`) cap how many findings they show per detector and tell you they
did, while `json` and `csv` keep everything. Tightening that high-volume behavior is
ongoing work - see [KNOWN-ISSUES.md](KNOWN-ISSUES.md). When in doubt, `digest` the file first to see
whether the volume is the story.

### How much data can it handle?
*Full detail: [the manual](MANUAL.md#windows-time-and-scale).*

Pointed at a directory, an unqualified run looks back over the last `default_window` (`7d`
out of the box), so a live log directory isn't read end-to-end every time; widen with
`--since` / `--days` or read it all with `--all`. For rotated flat logs it peeks each
rotation file's first timestamp and stops early instead of decompressing the whole archive.
The opt-in `dnsblock` detector may select 21 additional days of rotated files for its
28-day selection aperture while keeping reported rows inside the configured window.
An unpeekable source already loads in full; explicit time bounds and `--all` keep their normal
meanings. sigwood prompts before reading more than `warn_above` records (default 10,000,000),
and `warn_above = 0` turns that prompt off. It reads each log fully into memory rather than
streaming it, so one very large file can exhaust a small machine; narrow the window, point at
a single file, or run where there is headroom.

### What timezone are the times in?
*Full detail: [the manual](MANUAL.md#reading-output).*

Your machine's local timezone, labeled `local` on human-readable timestamps. Pass
`--utc` (or set `use_utc = true` in config) to render everything in UTC with a `UTC` label
instead - handy when you correlate across hosts or pivot into raw logs that carry UTC
stamps. The setting is consistent end to end: an offset-less `--since`/`--until` date and
the day boundaries of `--days` are read in the same timezone it displays (a date with an
explicit offset is always honored as written), export's no-timeframe default window
anchors on the same midnights, and the date in an auto-named report or digest filename
follows it too. `json` output is the exception by design - it is always ISO-8601 UTC, so
feeds into other tooling never shift with a display preference.

Syslog's grouped rows are the display exception: their leading stamp keeps syslog's own
wall-clock shape, adding a ` UTC` suffix under `--utc`.

### Can I run it on a schedule?

Yes - it's batch, stateless, and built for unattended use. `-q` quiets the progress
narration, `warn_above = 0` in config disables the large-dataset prompt for unattended runs
(`-y` still answers it for a one-off run, and covers the CloudTrail egress prompt), and
`--out=<dir>/` (or `report_dir` in config) writes a collision-safe named report. A hunt exits `0` whether or not it finds
anything - a clean Unix contract, where nonzero means the *run itself* failed, not that a
threat was found - so schedule it and inspect the JSON to decide whether to alert. That
contract covers a detector that crashes mid-run too: the run continues past it, but the
exit code goes nonzero and the JSON feed names it under `run_summary.detectors_failed`
(empty `{}` on a clean run) - a crashed detector never reads as a quiet night. A nightly
cron line (with `warn_above = 0` set in config):

```
0 3 * * *  sigwood hunt -q --format=json --out=~/.sigwood/reports/
```

and, to page yourself when a run found something - or when a detector failed and the
night's coverage is incomplete:

```
sigwood hunt -q --format=json | jq -e '(.findings | length > 0) or (.run_summary.detectors_failed | length > 0)' && your-alert-here
```

No daemon and no state between runs - each run stands on its own.

### Can I use it as a Python library?

Yes. Detectors are pure functions - they take loaded data and return findings, and never
open files, read config, or render output (the one caveat: syslog shows a terminal-only
progress bar while templating, silent when piped). You can import one and call it on a DataFrame in a
notebook, which is exactly how the clustering work is prototyped.

The [public contract](CONTRACT.md#calling-sigwood-from-python) shows the supported
entry point and the other scripting surfaces that stay stable throughout 1.x.

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
runs over the bucket counts, which is resilient to hour-scale gaps - a host that sleeps for an
hour breaks a raw inter-arrival series but barely dents a binned grid (measured: a nightly
one-hour outage leaves a week-long beacon's score essentially unchanged). That resilience has
limits: a beacon silent for most of each day, or one sharing its exact connection tuple with
comparable unrelated traffic, scores well below a clean continuous one - the measured numbers
are in KNOWN-ISSUES. The bin size also sets the
detector's floor: the fastest representable cadence is twice the bin (60 seconds), anything
faster shows up aliased as a slower period, and a beacon sitting exactly at that edge scores
less reliably than one comfortably above it - the sweet spot is the minutes-to-hours range
where real C2 check-ins live. The bin size is a calibrated constant; the scoring thresholds
and period band are tuned against it. The score is a composite - 40% how dominant the spectral peak is, 40% how
far that peak stands above the local noise floor, and 20% how regular the timing is (inverted
jitter) - over flows of at least 20 connections. The report shows it as `rhythm=`, because
what it measures is how regular a flow's cadence is.

The detector measures *periodicity*, not maliciousness: a benign MRTG poller hitting SSH
every 60 seconds lights up too. That's the right mental model - beaconing is a *shape*, and a
finding is a flow with that shape, for you to explain or allowlist. That is also why a beacon
finding on its own never rises above MEDIUM severity: timing is one category of evidence, and
HIGH is reserved for findings corroborated by evidence of a different kind - which timing
analysis alone cannot supply. The calibration reference
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

### If beacon can't prove malice, why does it run by default?

Because recurring automated connections are worth seeing, they are close to invisible in
`grep`, and finding them needs no lookup, no list, and no service - which is the whole
shape of this tool. That is the claim, and it stops there.

What the detector actually does: it reads the connection log you supplied, on your
machine, and reports connection groups whose rhythm score clears the configured
threshold. It does not identify malware from timing, so a finding tops out at MEDIUM and
its text reports where the strongest periodic component fell and what the rhythm score
combines, rather than naming a threat. The first steps it suggests are local - the process
on the source host, the DNS lookups that resolved to that destination, that destination's
history in `conn.log` - because the evidence lives in your own logs. Each
finding carries when the pattern started, when it was last seen, and how long it ran, so
you can judge it without leaving the report.

What it does not see: cadences
faster than 60 seconds are reported at the wrong period; only Zeek `SF`/`S1` connections
with observed originator bytes are scored, so retries to a host that never answers are
not analyzed; a jittered beacon needs about a week of span to resolve reliably; and a
callback that rotates destinations or changes its rhythm can stay under the bar. sigwood
discloses these at run time when they apply, in known-issues, and here.

Two caveats about the evidence behind all that. Its effect has been measured on
one home network, on synthetic cases, and against published method literature - not
across many real deployments, so it carries no precision claim. And the allowlist is
yours to set your own infrastructure aside; it is operator policy, not a substitute for
the detector being right.

If wider evidence later shows the lane earns less attention than it costs, narrowing it -
or moving it out of the default hunt - is a legitimate outcome, and one this project
would report rather than bury. Today the trade reads well: one bounded, inspectable,
local question, answered without overclaiming.

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
as one finding instead of fourteen. The report shows it in an `entropy score` column - **score**, because the number
carries no units and is not a count of bits, and **entropy** naming what the heuristic
is tuned to recognize rather than claiming a name was generated. The score
leans on digit density, and its biases are
measured (1,000 seeded samples per label length against the live scorer, eleven lengths from
6 to 63): benign digit-heavy labels such as short hex IDs or versioned hostnames can score
high; dictionary-word DGAs never cleared the candidate bar (a score of 1.8) in measurement;
and random letter-only labels never clear it at any length - zero of 11,000 samples, and the
best possible all-letter label sits below the bar by arithmetic - so a letter-only name can
never reach HIGH severity or trip the dense-cluster tunnel scan on its score. Measured
single-name catch rates vary by label shape and length (see
[KNOWN-ISSUES.md](KNOWN-ISSUES.md)). Those are single-name rates, not the detector's -
what one name's score does and does not decide is two paragraphs down. "High-entropy
cluster" elsewhere is a colloquial name for that random-looking
query shape (the cluster topology), not a claim that the score is Shannon entropy. A finding is
a starting point, not a verdict; the intended pivots are `dns.log` → `conn.log` → whois →
reputation → ASN.

**The score decides what gets looked at; behaviour decides how loudly.** Clearing the
suspicion-score bar makes a name a candidate and is worth a MEDIUM: it says the name *looks*
generated, nothing more. HIGH additionally requires corroboration of a different kind: either
the name's lookups mostly failed to resolve (a name that looks generated *and* does not
exist), or it sits in a dense, concentrated cluster of similar names. A name that merely
scores high is never crowned on that alone, which is why a clean capture can produce a page of
MEDIUMs and no HIGH at all.

That division of labor is why the measured catch rates above are one leg's recall, not the
detector's. A DGA family rarely appears as one name: at typical lengths a fifty-name family
under one registrable domain is very likely to put at least two members over the bar, and two
is all it takes to fold the parent into one group finding - though a family spread across
many registrable domains surfaces only as the individual names that clear. Below the bar
there is a second, narrower net, on Zeek data only: five or more low-scoring subdomains under
one parent, nearly all of whose lookups fail to resolve (at least 90%), surface together as
one INFO finding with no help from the score - a family spread across parents, or one whose
names resolve, is outside it. The bar itself is also not a free lever: the benign score curve
decays smoothly through the whole region around it - there is no gap between generated and
benign names in which to place a threshold - and boosting low-vowel or letter-only shapes was
measured and rejected for the same reason: every boost rule tested either flagged real benign
names (the strictest still crossed 57 in a benign reference week) or caught under half of its
target. Corroboration carries severity because no spelling rule tested could.

Two consequences worth knowing. On **Pi-hole/dnsmasq-only** data, HIGH is effectively out of
reach: sigwood's Pi-hole parser does not carry the resolution outcome, so it cannot corroborate,
and the dense-cluster scan, which does run on Pi-hole, is not allowed to corroborate on its own
there.
The below-gate family net above needs response codes too, so it is also Zeek-only: on Pi-hole a
name is reached either by its own score or by the dense scan's concentration test, and nothing
else.
Findings there top out at MEDIUM by design rather than by accident. For a **private namespace**,
such as names under a local-only suffix like `.lan` or `.internal`, a failed lookup is not evidence
of anything: failing to resolve outside its own
zone is simply what a private namespace does. Those names are grouped as one family and
reported, but their failures never count as corroboration.

There is one place "noise is the signal" leaks: a *sustained, high-volume* tunnel is thousands
of structurally-similar high-entropy queries, so past a size threshold it forms its own dense
cluster and never reaches the noise set - the loudest exfil would be the one that hides.
sigwood closes this by also scanning the dense clusters: a cluster whose members are
overwhelmingly high-entropy *and* concentrated under one registrable domain has that shape
surfaced into the same suspicion-score ranking, and the run discloses that the scan fired.
The gate is deliberately conservative, so a benign high-entropy cluster - a CDN or telemetry
endpoint that happens to look the same - does not flood the report; allowlist those you
recognize. The scan runs on Pi-hole/dnsmasq data as well as Zeek, with the same two bars, so
a family that concentrates under one parent is recovered on either source. What it does not
reach is a family spread across many separate parents, on either source - see
[Known issues](KNOWN-ISSUES.md) for that bound and the others.

### `syslog` - why drain3, and what's a "rare template"?

Host logs are mostly *templated*. `Accepted password for alice from 192.0.2.10 port 22` and
`Accepted password for bob from 198.51.100.7 port 22` are the same sentence with different
blanks filled in. drain3 learns those templates online - it maintains a parse tree and
discovers, without a single regex from you, that both lines share the structure
`Accepted password for <*> from <*> port <*>`.

Once every line carries a template, you can ask a question keyword lists can't answer: **which
lines are structurally rare?** Count how often each template appears across every host; the ones at the bottom
of the distribution - the lines that look like almost nothing else in the log - get surfaced,
and at the shipped default, every template that clears the rarity bar has been seen exactly
once. What separates one of those lines from another is the program that produced it, not the
count. The point of rarity over a
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
a single review unit - `Jul  1 03:12:47 · webhost · sshd · 4 rare lines · 1h` -
because "this program produced
N one-offs" is one decision, not N. The fold starts at four lines: below that, a summary
row plus its expansion costs as much space as the lines themselves, so one to three rare
lines simply stand on their own. Family and
burst rows show their first timestamp, `-v` includes up to three sampled lines, and an HTML
report has a closed expansion for the full bounded sample. Long identifier-like hexadecimal
runs (queue ids, session tokens) and space-separated hex-byte dumps (a FIDO2 security-key
debug dump at every login, a kernel `Code:` line) are normalized during template mining, so
a message that differs only by such an identifier counts as repetition rather than a parade
of one-offs. Ordinary short numbers, dates, and colon-joined MAC addresses are never
normalized, and the raw log line is always displayed exactly as written.

The privileged program class is configurable: copy the commented
`privileged_programs = [...]` block from `config_example.toml`, then add or remove exact
program tokens.

On top of rarity, sigwood recognizes two routine *transactions* the same way it recognizes
reboots: an **admin session** (a login through its logout, anchored on the session
open/close lines the system itself writes) and an **update run** (package-manager,
kernel-module, and policy-reload activity). When several findings on one host fall inside
one recognized transaction, they fold into a single labeled review unit - `Jul 12
22:11:11 · webhost · update run · 19 rare lines · 1m · mostly kernel, systemd` - with
every member preserved behind it (`-v` in text, complete in JSON; in HTML the row expands
straight to the members' raw log lines, grouped under thin per-member separators). One admin doing one system update reads as one line, not nineteen. Recognition replaces the findings it
groups with one unit and rates that unit from its members. A unit is MEDIUM exactly when one
of its members is from the privileged class; otherwise it is INFO and appears in the bursts
section. A rare line that matches no transaction is left exactly as it was. If the pattern
isn't there - an unfamiliar distro, a log that rotates mid-session -
findings simply stay ungrouped, and the same is true when the pattern is there but too big
to be one session: recognition declines any candidate longer than eight hours (periodic
privileged automation, like a frequent sudo cron, would otherwise chain into one
enormous false "session"), so those findings keep their own shapes too.
`recognize_transactions = false` turns the whole thing off.

### What does the auth detector look for?

`auth` asks how authentication activity is distributed inside the window you loaded. It can
surface five single-category signals at MEDIUM: **concentrated failures** against one service,
unusual **source volume**, unusual **account volume**, **multi-host failures** for one source and
account combination, and **failures followed by a success** for the same service identity.
Counting failures alone never proves an intrusion; these are review leads with the measured
eligible-record, failure, host, and time-span facts attached. An eligible-record count is not a
claim about the number of human login attempts.

Every `auth` finding caps at MEDIUM. Failures followed by a success still ride along as
evidence on the multi-host finding that covers the same source and account, so the report
does not print one event twice. That corroboration does not raise a severity today, and no
rule promotes an auth finding to HIGH. That tier is held back for corroboration between
different detectors, which sigwood does not do yet.

Counts are decision records as each source logged them. A host that reports through more than
one source, such as sshd's own log and the audit system, can record one event in each, so a
magnitude here is what the logs contain rather than a count of human attempts.

`auth` is opt-in rather than part of the curated default hunt: run `sigwood auth PATH`, name it in
`--detect`, or use `--detect=all`.

### What does the dnsblock detector look for?

`dnsblock` reads the blocked outcomes already present in Pi-hole/dnsmasq logs. It does not
ship a reputation feed or decide that a blocked name is malicious. It asks three bounded
behavioral questions: whether a client is reaching for a qualifying blocked-name family for
the first time in the available history, whether its blocked queries form a large burst
against its other active periods, and whether otherwise-unsurfaced blocked activity recurs
across at least four fully covered report periods. Run it directly with
`sigwood dnsblock /var/log/pihole`, name it in `--detect`, or include it with
`--detect=all`.

The detector is opt-in rather than part of the curated default hunt. First-activity findings
are LOW, while prior-handling and recurring rows are INFO context. Cadence is supporting
evidence only; it never changes routing or severity. The run says how much history it actually
consulted and distinguishes strong historical coverage from the weaker claim "first observed
in the available rows." It is stateless between runs, so a persistently blocked name can be
reported again while its onset remains in the lookback; suppress only the exact patterns you
have triaged as expected.

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

### `scan` and `exfil` - why are these labeled "just heuristics"?

Because that's what they are. `scan` counts distinct destination ports and hosts against thresholds
to separate vertical (one host, many ports), horizontal (one port, many hosts), block (many of both),
and slow (the same spread out over time) scanning; findings from one source fold into one row per
scan type, so a single sweep reads as one story instead of a hundred rows, with every per-target
measurement kept in the row's evidence. `exfil` sums the bytes each internal host sent to
each external destination and reports the pairs that clear a volume floor while running strongly
outbound. Both are arithmetic against thresholds you can read off the page - no model, nothing
learned, no published algorithm underneath - and the bracketed label says so instead of dressing
them up.

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

Yes: development was AI-assisted (Claude & Codex working together in a harness
built for the purpose), and the repository's public history begins with a single
squashed commit because earlier work contained private homelab identifiers that
were removed before publication.

Judge the result in the repository: the detection methods and their sources are named above,
the code is open, the test suite is deterministic,
[KNOWN-ISSUES.md](KNOWN-ISSUES.md) names and quantifies known flaws, and you can run sigwood
on your own logs.

### How do I know the sigwood I installed is genuine?

Every `sigwood` release on PyPI is published by a tag-triggered CI pipeline that authenticates
over OpenID Connect, so no upload token exists to leak. The tag that starts it is signed with a
hardware key that needs a physical touch, `main` and the release tags refuse unsigned pushes,
and the upload waits for the maintainer's approval in the browser, which the maintainer's
command-line token cannot give. [SECURITY.md](../SECURITY.md) walks the chain and shows how to
verify a checkout. Each published file also carries
a [PEP 740](https://peps.python.org/pep-0740/) publish attestation: a Sigstore-backed, verifiable
record that the file was uploaded by this project's release pipeline (`helixmap/sigwood`'s
`release.yml`). PyPI shows it on each file's page. The precise claim matters - an attestation
proves *where a file came from*, this pipeline, not that the code is safe; for that, the rest of
this section applies: read the code, run the tests.

### What state is sigwood in?

Stable, at 1.0. The nine detectors above work and are covered by tests. A protocol
classifier remains a roadmap future. Zeek's `weird.log` has a `digest` card, which
reports the shape of that log and reaches no verdict; that card is the shipped form
of weird analysis rather than a promise of a future detector. The interfaces listed under
[what 1.0 means](../README.md#what-10-means) are fixed from here; detection keeps moving,
and the reasoning for that split is in the same place. The current roadmap and the running
list of known rough edges are public, in
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
