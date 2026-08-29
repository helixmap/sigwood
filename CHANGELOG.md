# Changelog

All notable changes to sigwood are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and sigwood aims to follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **The dense-cluster tunnel scan now runs on Pi-hole data, not only Zeek.** A family of
  generated-looking names used to stop being identifiable in a Pi-hole report once it grew
  large enough to form its own cluster: below that size its domains surfaced individually,
  above it no finding named them and only a counts-only row remained, reporting how many
  domains had formed how many clusters. Such a family is now recovered when its names concentrate under a single
  registrable domain. Recovery is bounded and the bounds are measured: a family sprayed
  across many domains is still outside the scan, an encoding whose labels only sometimes
  look generated can still slip the member-fraction bar, and a cluster the scan inspects
  and rejects produces no row. Pi-hole findings stay capped at MEDIUM, because the volume
  evidence is not permitted to corroborate on a source that records no resolution outcome.
  Disabling the scan returns Pi-hole to its previous aggregate disclosure, which now says
  the scan was disabled rather than claiming a source limitation. The calibration record is
  published in the DNS evidence page.

### Changed

- **Reports are written to be read.** A first-time reader described sigwood's output as mostly
  cryptic, and the pass below answers that verdict rather than a lint. None of it changes what
  sigwood finds: the detectors and their thresholds are untouched, and the same run produces the
  same findings, with the same evidence, that it did before. What changed is how those findings
  are put on the page. Two qualifications, so the sentence above is not read wider than it
  holds: the wording of some human-facing notes changed, which `json` carries verbatim in
  `run_summary.notes` and has always documented as prose rather than contract; and one dns
  display cell was renamed, which is projection and never reached `json` or `csv`. The
  individual changes follow.

- **Severity is spelled out, everywhere a person reads it.** The text report showed `[H]`,
  `[M]`, `[L]` and `[I]`; a novice reader took those for magnitudes, times and sizes in a single
  sitting, while the spelled word decoded unaided. Text now reads `high`, `medium`, `low` and
  `info`, padded so mixed rows keep their columns; the html report spells and capitalizes the
  same words in its summary cards, its row pills and its group headers. `json` keeps its
  lowercase token and `csv` its column, both unchanged.

- **Verbose reports put the prose before the machine facts.** At `-v` and `-vv` the order is now
  description, then next steps, then evidence, with the data window last. Previously the
  imperative advice sat below the evidence block, and a reader who bounced off the evidence
  never reached the part telling them what to do. Adjacent findings are separated by one blank
  line, which the dense default view still does without.

- **Each detector group says what that detector looks for.** A one-line mission renders beneath
  the group header on both reading surfaces, so a reader meeting `beacon` or `dnsblock` for the
  first time is told what question it asks before being shown its answers. A report also carries
  one pointer, once, to the tier that explains why each finding surfaced, and it appears only
  when a group actually rendered.

- **Level-zero rows name what they hold.** dns counts read as `names`, `queries` and `clients`;
  beacon's composite reads as `rhythm`. The dns tables now carry their labels once as column
  headers rather than repeating them on every row, which is what the html tables already did.
  The dns lexical score is labelled `entropy score`, and the word `score` is doing work: the
  number is a weighted lexical measure with no units, so a bare `entropy` heading invites a
  reader to take it as a count of bits, which it is not.

- **Evidence timestamps are readable and unambiguous.** Instants inside the evidence block used
  to render as raw machine strings in UTC while the report's own window was shown in local time,
  so two lines of one block could describe the same moment and appear to disagree. Accepted
  instants now follow the report's display timezone, carry their `local` or `UTC` label, and
  include seconds where a distinction depends on them, such as an authentication failure and the
  success that followed it.

- **ssl and dnsblock findings explain themselves in plain language.** An ssl row said which
  internal signals fired; it now says that no server name was offered, or that a certificate did
  not validate, and it keeps the measured validation status that separates an expired
  certificate from a self-signed one. dnsblock descriptions say in words what its counts mean,
  keeping the distinction between complete daily coverage and coverage that cannot be confirmed.
  Both are rendering only: the machine payloads under them are unchanged.

- **The html report carries sigwood's own identity, and dns entities are one click to copy.**
  Detector names in group headers wear the wordmark's serif and colour, so the page reads as
  sigwood's document at every section boundary rather than only in the corner. A dns domain cell
  selects whole on one click, with no visual marking, and that convenience is absent from print.

- **`[detectors.beacon].bin_seconds` is no longer a configuration key.** The beacon detector bins a
  flow's connection times before looking for a rhythm, and every other number in that scorer - the
  score threshold, the period band it will consider, the peak-prominence normalization, and the
  reference score quoted in the documentation - was tuned against a 30-second bin. Changing the bin
  therefore did not adjust sensitivity; it produced scores that could not be compared with any of
  those numbers, including the threshold deciding whether a finding appeared at all. The value is
  now fixed in the detector. A configuration file still carrying the key keeps working: sigwood
  reports `config: ignoring unknown setting [detectors.beacon].bin_seconds` and continues with the
  calibrated value.

### Added

- **An evidence ledger: what has actually been measured, and what has not.**
  [docs/EVIDENCE.md](https://github.com/helixmap/sigwood/blob/main/docs/EVIDENCE.md) carries one
  row for **every** detector, not only the ones with results behind them: what was measured and
  on what population, what that supports and does not, and what is still owed. Five detectors
  now have published calibration conclusions under `docs/evidence/`; two are measured with the
  write-up still owed; and two have no calibration campaign at all, which the ledger says
  plainly. Nearly all of it rests on one estate, and each record says so itself. If you want to
  help change that, [FIELDKIT.md](https://github.com/helixmap/sigwood/blob/main/docs/FIELDKIT.md)
  is the door.

### Fixed

- **sigwood now tells you when a syslog archive's dates look re-dated.** RFC 3164 and Pi-hole
  logs carry no year, so sigwood stamps them with the current one. That silently moves an
  archive more than a year old into the last twelve months, and those dates then flow into
  windows, timelines and finding data windows looking entirely confident. Where the file still
  carries its original modification time, sigwood now says so once per file: `timestamps parse
  730 days newer than the file itself was last written`. It explains rather than repairs: the
  dates are still wrong. It is deliberately conservative: the two-day threshold exists
  because a log shipped from a distant timezone legitimately parses up to 26 hours ahead, and a
  copy made without preserving the modification time cannot be flagged at all. See
  **RFC 3164 syslog and Pi-hole timestamps carry no year** in
  [KNOWN-ISSUES.md](https://github.com/helixmap/sigwood/blob/main/docs/KNOWN-ISSUES.md) for
  what it can and cannot see.

- **On a daily-rotating Zeek tree, a default run now includes today's events.** sigwood anchored
  its default window on the newest dated log directory and stopped at that day's last second, so
  anything written since midnight - which lives only in the live `current/` spool - was read from
  disk and then filtered back out. A plain `sigwood /opt/zeek/logs` at three in the afternoon
  showed you nothing from that afternoon. The window's lower bound still selects the last N dated
  days; the upper bound is now open, so the live spool is included. Two consequences worth knowing:
  a 7-day default can now span eight calendar dates, because it covers seven archived days plus
  today so far; and a log line stamped in the future - clock skew, a misconfigured sensor - is now
  admitted rather than silently dropped, which is how every other source already behaved.

- **A large group of Pi-hole domains no longer disappears without a word.** On Pi-hole data,
  domains that clustered together produced no findings and nothing was said about them, so a burst
  of random lookups that grew large enough to form its own cluster stopped being identifiable - and
  where every domain clustered, the run reported no findings at all. A run now adds one
  informational row saying how many domains formed how many clusters. That row carries counts only,
  and no domain name reaches it. This shipped first as a disclosure over unexamined clusters; the
  Added entry above then extended the scan itself to Pi-hole, so in this release the row appears
  when dense-cluster scanning is switched off.

- **Detectors skipped for the same reason are now reported on one line.** Pointing sigwood at a
  single source - `sigwood /var/log/pihole/` - previously printed one warning per skipped detector
  and repeated all of them in the report, so a first run could spend ten lines on sources you do
  not have. Detectors sharing an identical reason are now grouped, and the reason text is unchanged:
  a source that is configured but outside the paths you named still says so, rather than being
  described as unconfigured. Machine output is unaffected - the JSON report still carries a
  separate reason for every skipped detector.

- **A malformed `[sigwood].home_net` now stops the run at startup instead of quietly disabling your
  topology.** Written as a bare string - `home_net = "10.0.0.0/8"` rather than
  `home_net = ["10.0.0.0/8"]` - the value was read as a list of single characters, none of which is
  a network. Depending on which detectors ran, that either silently left sigwood with no internal
  networks at all, so every address was treated as external and direction-aware analysis lost its
  meaning, or surfaced as an unhelpful error from the `scan` detector. sigwood now checks the value
  when it loads your configuration, names the offending entry, and shows the array form.

## [0.5.1] - 2026-08-25

### Changed

- **`beacon` now declines to score a flow whose timestamps span more than about a year.** It bins a
  flow's connection times before looking for a rhythm, so a very wide span asks for a very large
  number of bins, and a ceiling has always refused the extreme cases. That ceiling was set on an
  estimate of what the work costs; measured, the real cost is up to five times higher, because the
  dominant consumer is the Fourier transform's own scratch space rather than the arrays being
  transformed - and how much it needs depends on how the bin count happens to factor, which nothing
  chooses. The ceiling is lowered so it delivers the bound it always claimed. The practical effect
  is that a flow spanning roughly one to five years is no longer scored; such a span is not a
  beaconing candidate in any case, and a year remains far wider than any hunt window.

- **The package no longer carries detector modules that were only placeholders.** The planned
  `protocol` and `weird` detectors were never available to run, and the `weird` digest card is
  unchanged. An unused email-output module is gone with them. The shipped detector roster is now
  checked against discovery and the public documentation so dead placeholders cannot make those
  surfaces drift apart again.

- **Truncated digest mixes now say how much traffic their named categories leave out.** DNS query
  types, Zeek weird names and analyzers, and CloudTrail regions still name their three largest
  categories, followed by `(other) N%` when a positive share remains. A share below one percent is
  shown as `(other) <1%` rather than rounded away; a complete mix is rendered exactly as before.

- **`sigwood init` gives permission advice for the home it is actually writing.** A user or custom
  home now says to make the location writable as that user or choose another location, avoiding
  root-owned files from an unnecessary `sudo`. The deliberately shared `/etc/sigwood` home still
  permits elevation and says that `sudo` needs the executable's full path.

### Fixed

- **Relay-forwarded syslog now reports the originating program instead of a relay timestamp
  token.** sigwood looks through up to eight stacked RFC 3164 or ISO-8601 headers for program
  identity while retaining the outer relay host and the existing one-header message view. On a
  forwarding fleet, a program column that previously read a token such as `Jul` now names the
  service that emitted the event; estates without relay-forwarded logs see no change.

- **The shared exfil evidence slicer now enforces the quiet default reading level itself.** Level
  zero returns no destination-pool members even when the slicer is called directly, while level one
  remains capped at ten with a truthful remainder note and level two remains complete. Existing
  text, HTML, PDF, JSON, and CSV output is unchanged.

- **A single malformed log file no longer ends a whole hunt or export.** Four containment sites
  named a narrower set of errors than the code could raise, missing seven exception shapes between
  them, so one bad input destroyed work that had nothing to do with it. The outcomes now differ by
  input, as they should: a Zeek log whose `_path` is a list or object is profiled as an
  unrecognized source instead of ending the run; a syslog line carrying a far-future timestamp is
  treated as having no parseable timestamp instead of aborting **directory discovery** - which
  matters most, because that path meant a hostile file merely sitting in the configured log
  directory could stop a hunt it was never pointed at; and a malformed CloudTrail object is skipped
  by name with the rest of the export intact, where before one such object ended the export and
  discarded every valid object already fetched.

  The CloudTrail failures also reported themselves badly, in two different ways. A truncated
  archive member surfaced as `unexpected end of input` - a message that means end-of-input at a
  prompt, so it named a false cause - while deeply nested JSON produced a raw error trace. Both now
  report the object by name.

- **A syslog line dated 29 February keeps its date.** The parser reads a timestamp more than a week
  in the future as belonging to the previous year, but the previous year has no 29 February. In
  early 2028, while that date was still more than a week ahead, the assumption would have raised
  and dropped the line. When the previous-year candidate cannot represent 29 February, the parser
  now retains the literal current-year date.

## [0.5.0] - 2026-08-23

### Added

- **An opt-in `ssl` detector for outbound TLS sessions.** It asks one question: does a session's
  setup look unlike this estate's own norm? It measures two legs: a completed, non-resumed
  handshake that sent no server name, and a certificate that did not validate. One leg is LOW, both
  on the same source-and-destination pair is MEDIUM. It is **not** part of the default hunt: run it
  with `sigwood ssl` or `--detect=all`, because its calibration rests on a single estate and
  default-hunt membership asks for more than that. Because TLS 1.3 encrypts the certificate
  exchange, the certificate facts cover only the sessions that presented one, and the finding says
  so rather than implying whole coverage.

- **A `weird` digest card** over Zeek's own protocol-anomaly log, reporting the shape of what the
  sensor flagged without reaching a verdict. A weird name is a fact about parsing, and the same
  name that matters on one network is ordinary noise on another. The `weird` DETECTOR remains
  planned; this is orientation only.

- **Zeek `ssl.log`, `x509.log` and `weird.log` are ingested** through bounded canonical schemas.
  Recognition is by Zeek's own `_path`/`#path` directive rather than by guessing from field names,
  and a log carrying both a Zeek field and its canonical rename target is contained rather than
  loaded into a malformed frame.

### Security

- **The bundled DNS allowlist no longer hides names an attacker can register.** Its cloud entries
  matched whole namespaces such as `*.amazonaws.com`, `*.cloudfront.net`,
  `*.azurewebsites.net`, `*.googleusercontent.com` and others. Anyone can create a name inside
  those namespaces. Because
  allowlisting happens before detection, a DNS query to an attacker's own S3 bucket, CloudFront
  distribution or Azure web app was removed from the data before any detector saw it. Those entries
  now cover only the vendors' own control-plane endpoints, so customer-nameable addresses reach the
  detectors. A `nameservers` entry that matched any name beginning `ns` followed by digits,
  including `ns1.<any-domain>`, is likewise replaced with per-vendor entries, and the mDNS
  service-discovery entry, previously any name starting with an underscore, now requires the actual
  `_service._tcp.` structure. **Expect more DNS findings than before**, particularly for cloud
  storage, CDN and app-hosting names: that traffic was always there and was being filtered out.
  Some LEGITIMATE vendor control-plane traffic surfaces too. For example,
  `management.azure.com` is no longer
  suppressed, because the entry covering it also covered every customer-nameable address under
  `azure.com`; allowlist it locally if it is noise on your network.
  The scoping rule behind the change is written at the top of the list file: an entry may cover
  names a vendor operates, never a namespace in which anyone can register one.

### Changed

- **`auth` no longer slows down disproportionately as an account's history grows.** The landing
  analysis re-read an identity's whole decision history once for every established
  failure-then-success transition it found, so work grew with the square of that history: the
  measured cost roughly quadrupled each time the input doubled. It now reads the two facts it
  actually needs, the latest denial per identity and the latest activity per host, and grows in
  step with the input instead. This matters most on exactly the data `auth` exists to read, since a
  brute-force campaign is repeated failure-then-success cycles against one identity. **Findings are
  unchanged**: the same runs produce byte-identical results, which was the gate this change had to
  pass before speed counted for anything.

### Fixed

- **A directory whose first 32 files are all one log family no longer hides the rest in
  silence.** When you pass a directory to `sigwood hunt` (or to `dns`/`syslog`), sigwood
  samples up to 32 files and hunts the whole directory as whichever family wins that vote.
  It said so when the sample itself held more than one family. When the first 32 files were all
  Zeek while syslog files sat further down, sigwood routed the directory as Zeek and reported
  nothing, so logs of the other family were quietly never hunted as their own kind. sigwood
  now also says when the vote was taken on a sample rather than the whole directory:
  `<dir>: routing sampled the first 32 files (zeek 32) - hunting it as zeek; files beyond
  the sample were not examined, so pass other log types directly to include them`. A
  directory that is both mixed and truncated reports both facts. The existing mixed-sample
  message is unchanged, and which 32 files are sampled is unchanged: the first 32 by name,
  the same on every run and every host. Reading the directory no longer loads the whole
  listing into memory first, which matters on a directory holding very many files.

- **A Zeek TSV file whose `#separator` line carries no value no longer stops sigwood.**
  Such a header previously raised an unhandled error: `sigwood digest` failed instead of
  profiling the file, and on a hunt it ended the whole run, including every other log
  source in that run, before any findings were reported. `digest` now describes the file
  as an unrecognized source and exits normally, and a hunt skips just that file with
  `<name> could not be parsed - Zeek TSV header has an empty #separator value; skipping`
  and carries on with the remaining sources. Zeek headers that declare a separator
  normally are read exactly as before.

- **One malformed CloudTrail object no longer ends an export and discards every other
  object in the window.** An object whose JSON was not a CloudTrail envelope, such as a bare
  list or number at the root, a `Records` value that was not a list, an entry inside
  `Records` that was not an event, or an event carrying an `eventTime` that was not text
  but still held a value, such as a number, previously raised an unhandled error partway
  through the export, so a single small object cost every valid object already fetched.
  `sigwood export` now skips just that object with the existing
  `skipped unreadable object: <key>` warning naming its reason, and continues with the
  rest of the window. The object still counts toward the export's object total, so a
  skipped object stays visible rather than quietly reducing the count. Events with no
  usable `eventTime` (absent, empty, or a value such as `null` or `0`) are dropped
  individually exactly as they always have been, and their sibling events in the same
  object are exported unchanged.

- **An `--out` target that is not an ordinary file is now refused, instead of hanging,
  silently destroying it, or failing with an unreadable error.** Pointing a report at a
  named pipe used to hang the run indefinitely with no error, no timeout and no
  diagnostic on `text`, `json` and `csv`; on `html` and `pdf` it did something worse,
  replacing the pipe with a regular file and reporting success. A device such as
  `/dev/null` failed with a bare `[Errno 1] Operation not permitted` that named no path
  and suggested nothing, and a symbolic link under `html` or `pdf` ended the run with a
  raw Python traceback. Every one of these now stops with a message naming the target
  and what to do, and the target is left exactly as it was. Where sigwood could examine
  the destination it says `<path> is not a regular file - refusing to write to it; choose
  a regular file or directory`. Where the destination could not be opened at all, such as a named
  pipe with nothing reading it, it explains that the path could not be opened safely instead,
  because in that case sigwood has not established what the target is. Writing to an ordinary
  file, creating a new one, and writing into a directory are unchanged, including a
  destination the tool cannot itself read, which stays replaceable as before.

- **A Zeek `conn.log` or `dns.log` that carries both a Zeek field and its canonical name no
  longer loses rows silently.** Such a file, whether a `notice`-style export or a log rewritten to
  add a `src` column beside Zeek's own `id.orig_h`, used to be renamed into duplicate
  columns, after which every row was quietly dropped from analysis while the run summary
  still reported them as loaded, and four Python `FutureWarning`s appeared in the output. On
  a hunt, sigwood now skips that file with a single message naming the skipped row and the
  canonical-name collision. It carries on
  with the other sources. `sigwood digest` reports the collision and then states that the
  recognized log had no parseable records. Ordinary Zeek logs are read exactly as before,
  which was confirmed by re-running the full detector suite over a frozen seven-source
  archive and comparing every finding against the previous result.

- **`sigwood digest` now explains when a recognized log falls back to a byte profile because
  its summary could not be built.** That fallback was previously silent at the default level
  and explained only under `--verbose`, so the output looked like an ordinary profile of an
  unrecognized file. The explanation is now always shown, while the underlying error detail
  remains reserved for `--verbose`. A related fix stops sigwood suggesting you widen the
  time window when a file was read but produced no usable rows. Widening cannot help there,
  and the advice sent people looking in the wrong place.

## [0.4.0] - 2026-08-21

### Added

- **`dnsblock` is now available as an opt-in detector for Pi-hole blocked-name
  activity.** `sigwood dnsblock PATH` and `--detect=all` run it through normal public
  discovery; the curated default hunt remains unchanged. It reports bounded first-activity
  and query-burst findings plus recurring-activity context, states how much history the run
  actually consulted, and treats the operator's own blocklist outcomes as input rather than
  shipping a reputation verdict or feed.

- **`sigwood era` measures a whole dated Zeek archive as an allowlist-blind
  retrospective.** It reads traffic before hunt suppression so the report includes traffic
  that an allowlist would hide. The ten-card report writes to stdout unless `--out=PATH` is
  given and does not use the configured report directory; it has no timeframe flags because
  it covers the archive as a whole. It prints plain text by default, and `--format=html` or
  `--format=pdf` presents the same measured cards as a self-contained page for reading in a
  browser or handing to someone - the page fetches nothing from the network and carries no
  scripts, and a PDF aimed at a terminal is refused rather than written as binary. Short or gappy archives still
  produce an honest short report: cards that lack enough usable history abstain and explain
  why, while an archive with no usable dated data is refused. Large archives ask for
  confirmation before a long run.
- **A bounded streaming foundation in the loader** for detectors that need to analyze a
  large archive without holding it in memory. The streaming path is opt-in per run and no
  shipped detector binds it yet: an ordinary hunt takes the same single-pass read path as
  before and never pays the new snapshot hashing; records within the new 1 MiB limit load
  exactly as they did. On the streaming path, input is processed in bounded chunks (at
  most 65,536 rows and 32 MiB of decoded text at a time) from a content-stable snapshot
  of the selected files: a file replaced, truncated, or rewritten mid-run is detected and
  refused rather than silently misread, while a plain log that merely grows mid-run is
  read to its captured boundary and the appended tail waits for the next run. Per-file
  results commit only when the whole file read cleanly. Measured on the same 3.2 GB
  Pi-hole archive: a full-archive streaming pass completed with a peak under 150 MB of
  memory, where the previous release's whole-frame path was stopped at an 8 GB memory
  safety ceiling without completing.
- **Exports now carry content-bound availability provenance.** Each completed export
  directory gains a private `.sigwood-export-provenance.json` manifest that binds the
  written files to their requested half-open UTC interval, size, and SHA-256. Export
  commits stage private data and serialize the manifest-last replacement with a directory
  lock, so a write interrupted after data replacement but before manifest replacement
  leaves a torn pair that reads as unknown instead of claiming coverage it cannot prove;
  interruption before any replacement preserves the prior state untouched. The manifest, lock, and private staging namespace are reserved product
  artifacts: log discovery excludes them, and explicitly selecting one reports how to
  choose the exported data instead.

### Changed

- **The release workflow now drafts the GitHub Release itself** after a successful PyPI
  upload, with the tag's own changelog section as the notes. It creates a *draft* only;
  publishing it remains a maintainer's step after reading the rendered notes. Previously
  the Release was created entirely by hand as the step after the irreversible PyPI
  approval, and a release could reach PyPI while the repository's Releases page kept
  advertising the prior version - which is what happened with 0.3.0 for ten days. The
  maintainer checklist (`docs/RELEASING.md`) now verifies that the published Release is
  the repository's latest.

- **A single log record larger than 1 MiB of decoded text is now skipped and disclosed**
  with a per-file warning naming the file and the skipped count, instead of being passed
  whole into parsing and analysis. Real log lines are thousands of times smaller; the
  limit keeps an oversized record out of every parser, frame, and analysis result and
  makes the omission visible. The count also appears in the load's quality accounting.

### Fixed

- **Graph help now presents source-kind and source-path forms as alternatives, matching the
  parser's exclusive choice.**

## [0.3.0] - 2026-08-08

### Added

- **`exfil` - a new detector for bulk outbound transfers over Zeek connection logs.** It
  sums the bytes each internal host sent to each external destination and reports the pairs
  that move a large volume while running strongly outbound. It delivers a fact - a large
  outbound transfer to an external endpoint exists between these two hosts - and leaves the
  judgement to you; it never claims theft. Findings are MEDIUM; there is no severity ladder
  to climb and no baseline to learn, just two absolute thresholds you can read and change.
  It runs in the **default hunt**, so `sigwood hunt` includes it. `auth` is now the only
  opt-in detector.

  The two thresholds - one gibibyte of outbound bytes to a single endpoint, and at least
  60% of that pair's measured bytes flowing outbound - were swept against 121 days of real
  traffic and both hold up. The floor sits in a region where moving it either way by a factor
  of two barely changes what surfaces. The direction bar is what keeps ordinary downloads out
  of an upload worklist; it is the safe side of a real boundary rather than a precision-tuned
  value, and the difference between 60% and 50% was worth a single finding across those four
  months.

  **A rotating destination pool reports as one finding, not one per address.** Cloud services
  answer on pools, so a single backup run can touch a hundred addresses and would otherwise
  produce a hundred findings for one event - measured at its worst, 138 findings describing
  two things happening. Four or more surfaced destinations that share a network block **and
  the same sending host** now fold into a single finding that keeps every destination's own
  byte totals inside it: complete in
  JSON, the ten largest with a count of the rest under `-v`, and a single aggregate row in CSV
  with no destination list buried in a cell. On the same traffic, a typical week goes from nine
  findings to two and the worst week from 138 to two. Fewer than four destinations in a block
  report exactly as before.

  Byte figures cover only the connections where **both** byte counts were recorded; rows
  missing either count leave the measurement rather than being counted as zero, and a
  connection log with no responder byte counts at all makes the detector abstain and say so
  instead of guessing. Where those omissions could have changed the answer, the run summary
  reports how many pairs and how much outbound volume were affected. See
  [Known issues](docs/KNOWN-ISSUES.md) for what this detector cannot see, including the one
  case where an unrecorded responder count can make a download look like an upload.

- **Authentication analysis is now available as the opt-in `sigwood auth` detector.** It
  examines the system-log lane for five measured shapes: concentrated failures, source volume,
  account volume, multi-host failures, and failures followed by a success. Each single category
  caps at MEDIUM; the only HIGH path combines exact multi-host spread with a matching landing.
  Text and HTML share a designed severity-first row grammar, `-v` keeps untrusted identities out
  of ordinary evidence, and every run reports count-only extraction magnitudes plus honest
  evaluated-versus-abstained notes. The known-issues page also records four pre-existing
  limitations: the corroboration requirement, window-relative first-seen time, whole-host-only
  allowlist coverage for this lane, and the synthetic-only HIGH witness.
- **A misspelled setting name now warns instead of being silently ignored - at every
  config scope.** A typo like `zeek_dri`, a mistyped `[detectors.beacn]` table, an unknown
  `[export.splnk]` backend, or a wrong key nested as deep as `[detectors.dns.pihole]` now
  prints one plain warning on stderr - `config: ignoring unknown setting [sigwood].zeek_dri
  (did you mean zeek_dir?)` - and the run continues on what it understood. Nothing stops,
  no value is validated, and `-q` does not hide it (a warning is not progress narration).
  The `allowlist` command's read paths disclose the same way. The suggestion appears only
  when a close match exists.
- **A written contract for what sigwood keeps stable.** `docs/CONTRACT.md` states, in one
  place, what will not change across 1.x releases: the thirteen verbs, the flag spellings and
  their `=`-only value grammar, the five output-format tokens, the documented config key
  paths, the JSON envelope and its field types, the CSV column set, and the exit codes.
  Linked from the README and the FAQ. Detection itself is explicitly outside that promise -
  thresholds and calibration move when measurement says they should.
- **Every detector is now importable and callable from Python**, which the README and FAQ
  already described. `from sigwood import DetectorContext, Finding, Severity` works, as does
  `from sigwood.detectors.<name> import run` for all seven detectors.
  `DetectorContext.unsuppressed(...)` builds a context for that use with allowlist
  suppression **off**, and says so in its name and docstring, because results can be noisier
  than the same detector run through the CLI. Importing the package stays lightweight - it
  does not pull in pandas.
- **Tests that hold the contract to its word.** The published inventory is pinned by
  executable tests rather than prose alone, including a check that a consumer tolerating new
  fields keeps working, and an event-time matrix asserted against the real finding producers.
  The installed-wheel smoke in CI now exercises the documented Python example end to end.

### Changed

- **The demo corpus now shows data leaving.** The synthetic demo could not trip `exfil` at
  any threshold - it simply contained no bulk transfer - so the detector that now runs in
  the default hunt had nothing to demonstrate. The compromised host now uploads about 1.9 GB
  to an external drop host late in the day, hours after the intrusion, completing the arc
  from break-in to data leaving; `exfil` is in the demo's detector list, and the walkthrough
  covers what it reports. The transfer is deliberately a single destination, so it renders
  as a plain pair finding rather than the grouped form used for a rotating cloud pool. The
  corpus stays byte-for-byte deterministic at a given seed, and every pre-existing signal is
  unchanged. `demo/gen_corpus.py --scenario bench` also drops one leftover connection that
  existed only for the retired `duration` detector.

  The walkthrough's expected-output section has been corrected against a real run at the
  default seed. Three of its claims had gone stale as the DNS and syslog detectors evolved:
  the hunt reports three DNS findings rather than one, the syslog section reports ten rather
  than eight, and the Pi-hole-only DNS run reports MEDIUM rather than HIGH - the last of
  those is the severity ladder working as intended, since a Pi-hole feed carries no
  resolution outcome and so cannot supply the corroboration that would raise it.

- **The DNS detector is faster on large captures, with identical findings.** Domain parsing
  and label-shape analysis now run once per distinct query instead of once per row, character
  counting inside the label score is single-pass, and working tables are released as soon as
  clustering no longer needs them. On the seven-day reference capture the detector-only run
  dropped from about 8 minutes to about 7 (roughly 12% faster), with findings byte-for-byte
  identical before and after. Peak memory was not improved by this change; the detector
  process measured a few percent higher at its peak on macOS while the machine-wide peak was
  unchanged. (The Pi-hole change below is what moves peak memory.)

- **Pi-hole captures use substantially less memory to analyze, with identical results.** When
  sigwood reads a Pi-hole or dnsmasq log it no longer keeps five values that nothing in the
  tool reads: the answer payload, the upstream resolver address, the DNSSEC or block
  disposition phrase, the original log line, and the parsed message portion of that line. The
  grammars still recognize all of it because that is how each line's event type is decided, but the
  values are no longer carried on every row, which on a multi-million-line capture is
  gigabytes held for no reader. On the seven-day reference capture the detector process peaked
  roughly 2 GiB lower, about a quarter less than before, and the peak across sigwood and its
  helper process together fell by about the same amount. Results were unchanged on both
  reference captures: findings and graph data matched apart from the timestamp each run
  stamps on itself, and digest cards matched byte for byte. **One consequence to know about:**
  a log line that no grammar recognizes is still kept and still counted, but the row no longer
  carries the line's text. On the reference capture that is about one line in 650. Reading
  those lines means going to the source log rather than the loaded table.

- **Every `auth` finding now caps at MEDIUM.** Failures followed by a success are still reported,
  as evidence attached to the multi-host finding covering the same source and account, but they no
  longer raise a finding to HIGH. The counting this detector does is deliberately plain, and a
  higher tier has to earn its way back on evidence. `auth` remains opt-in.
- **Auth findings that describe the same activity from different angles now say so.** Source
  volume, account volume, and multi-host spread continue to report separately because they answer
  different questions. Each now names the related findings, with a count shown in the report
  row, so three rows are not read as three separate incidents.
- **The "working" spinner now uses the braille animation common to modern command-line
  tools.** On a terminal that can encode it, the indicator beside a running phase cycles
  through braille dots instead of `| / ─ \`. A terminal that cannot encode those
  characters, and `TERM=dumb`, keep the ASCII spinner unchanged. The spin rate, the line
  layout, and every other line of output are untouched. Encoding support is not the same
  as font coverage, so a terminal missing braille glyphs may show placeholder boxes.
- **A saved search named `default` no longer silently wins a bare `sigwood export`.**
  With several saved searches configured, `sigwood export` (or `sigwood export splunk`)
  now stops with the existing error naming them and the exact command to run instead of
  quietly picking the one called `default`. A single configured search still runs bare,
  whatever its name, and `default` remains a valid name to ask for explicitly. CloudTrail
  exports are unaffected. The example config and README no longer teach the old behavior.
- **Two `--syslog-source` errors now name the requirement rather than one detector.** Asking
  for an active system-log mode (`auto`, `journal`, `files`) when the final detector selection
  contains no system-log detector reports `requires a system-log detector` - from the usage
  error at the command line and from source resolution alike. For the shipped detector set,
  no run behavior changes beyond the reworded errors.

### Removed

- **BREAKING: the `duration` detector is retired; `exfil` replaces it.** `sigwood duration`
  is no longer a command, `[detectors.duration]` is no longer read (sigwood tells you so, and
  names the successor, if it finds one in your config), and the `detector` value in JSON and
  CSV output is now `exfil`. There is no alias.

  The reason is that its premise had expired. `duration` treated a long-lived connection as
  inherently suspicious and assigned severity from elapsed wall-clock time alone, so on any
  modern network its high-severity findings were by-design persistence - mobile push
  channels, mail clients holding a connection open, CDN keep-alives, interactive SSH - and
  the tool narrated a phone's push socket in the language of a command-and-control channel.
  Worse, the statistic missed the thing that actually matters in this space: a fast bulk
  upload never stays open long enough to trip a duration floor at all, and speed is exactly
  what an exfiltration channel wants. `exfil` asks the question that was worth asking, and
  duration survives as context on its findings rather than as the trigger.

### Fixed

- **An export given one end of a window no longer silently exports the wrong period.**
  Passing `--since` without `--until` still used midnight at the start of today as the
  unqualified default's end, so an export asked for "the last day" quietly stopped hours ago and wrote
  a plausible, complete-looking file that was missing its newest data. The two ends of that
  default are one window and now apply as one: with neither end given the default is unchanged,
  `--since` alone runs to now, `--until` alone keeps the same one-day width ending where you
  asked, and giving both is honoured as supplied. This is fixed for every export backend, not
  just Splunk. (One narrow compatibility exception is unchanged: an end of `23:59:58` or
  `23:59:59` (what `--days` produces) is still read as the following midnight.)
- **A Splunk export no longer silently under-fetches the newest hour, and timestamped results
  are trimmed to exactly the window you asked for.** Requests were fetched in whole hours with
  both ends rounded *down*, so any window not starting and ending on the hour lost up to an hour
  of its newest data and silently included data from before its start, while the filename named
  the window you asked for. Whole-hour fetching stays (it is how the query is chunked), but it
  now rounds outward to cover the request, and results carrying a usable timestamp are trimmed
  back to the exact period. `--days`, which was already correct, is unchanged. A saved search
  whose rows carry no usable timestamp keeps them rather than having a working export discarded,
  and the run says the file covers the wider whole-hour period; where only some rows lack one,
  those are dropped and the count is reported.
- **An export whose window ends before it starts is refused instead of writing an empty file.**
  A `--since` set in the future, a `--since`/`--until` pair given the wrong way round, and
  `--hours=N-N` (which asks for a window of no width at all) each produced a window ending at or
  before its start. Nothing can fall inside such a window, so the export fetched nothing, wrote an
  empty file, described the span as `1h`, and exited as though it had succeeded. An empty file
  is easy to miss when the run gives no reason to look at it. sigwood now stops before contacting
  the backend or creating a file, shows the window it worked out, and says the start must be earlier
  than the end. Spans that are not a whole number of days are also described through sigwood's
  shared format now, so a 30-minute window reads `30m` instead of being rounded up to `1h`, and
  `36h` reads `1.5d`; whole-day windows still read `1 day` and `2 days` as before.
- **Authentication counting no longer discards one log source's records in favour of another's.**
  Every source that observed an authentication now contributes its records: a benign SSH login can
  no longer hide audit-only failures for the same service, and a source that saw failures no other
  source recorded can no longer be dropped for being the smaller witness. Either behaviour could
  make a real brute force vanish from the report. `sshd` and `sshd-session` share one service
  identity, and named and numeric renderings of the same audit record are reconciled to one
  without collapsing genuine repetition. Reports label the magnitude as decision records rather
  than implying a count of human attempts, and every run discloses that a host reporting through
  more than one source can record one event in each. The numeric floors are unchanged.

- **A Pi-hole or CloudTrail directory you lack permission to read is no longer silently empty.**
  Permission problems were already reported for Zeek and syslog. These two search their
  directories a different way, one that returns no matches rather than reporting the problem, so
  a folder the running user could not open looked exactly like a folder holding no logs - no
  error, no note, and a detector reporting nothing at all. Both now check that they can list the
  configured directory before searching it, and report a permission denial by naming the source
  and the directory while the rest of the hunt continues. Only permission denials are reported
  this way: a configured path that does not exist keeps its existing `not found` message, and
  other listing failures keep their existing handling rather than being relabeled as a
  permissions problem they are not. One limit remains and is written down in the known-issues
  list: for CloudTrail this checks the directory you configured, not folders nested beneath it.
- **A DNS run with a single query left to analyze no longer fails the whole run.** When the DNS
  data reaching the detector came down to one row, the clustering step raised and the run reported
  DNS as failed and exited 1 - a clean night reported as a broken one, which matters if you run
  sigwood on a schedule and watch the exit code. One row can arrive through ordinary paths: a
  quiet feed under the default window, a narrow `--since`, a new sensor, or a busy feed whose
  queries are nearly all covered by the allowlist, since suppression happens before
  analysis. That single query is now examined the same way two would be, and can still be
  reported if it stands out. Nothing about how findings are scored has changed.
- **The PDF error now names a command that works.** Asking for `--format=pdf` without the
  optional extra installed pointed at `pip install 'sigwood[pdf]'`. That fails twice over for
  anyone who followed the recommended install: a stock Ubuntu server may not have a `pip`
  command at all, and
  pipx declines a plain `install` for a package you already have - which you always do, since you
  just ran sigwood to get the error. It now names `pipx install --force 'sigwood[pdf]'` with the
  virtualenv form alongside, and the README says how to add an extra to an install you already
  have.
- **sigwood no longer suggests widening access to your failed-login database.** When scanning
  a log directory, sigwood tried to read every file in it - including `btmp`, the binary record
  of failed logins, which on most Linux systems an ordinary user cannot read. It then advised
  granting that access, which is both a security downgrade and pointless: sigwood discards the
  file as binary the moment it can read it. The utmp-family databases - `btmp`, `wtmp`, `utmp`,
  `lastlog`, `faillog`, and their rotated copies - are now skipped when scanning a directory.
  Naming one of them directly still reads it, and an unreadable file with an ordinary log name
  still reports the permission problem exactly as before.
- **`sigwood init` no longer reports flat syslog files on a machine that has none.** On a system
  that logs only to the journal, the unreadable `btmp` above was by itself enough for setup to
  detect a syslog directory - which the hunt then found empty. Detection and the file counts it
  shows you now apply the same rule.
- **An unreadable Zeek or syslog directory no longer costs you the whole hunt.** If sigwood
  could not list one of those source directories - a permissions problem on a single folder -
  the run stopped with a bare `Permission denied` and produced nothing at all, discarding every
  other source it could read perfectly well. That directory is now skipped and the rest of the
  hunt runs. The report carries a note naming the source and up to three of the directories it
  could not list, with a count of any remainder, and saying their contents are absent from the
  run. A detector with another readable source keeps running; a detector left with no readable
  source is reported as skipped, and its reason names the permission problem instead of only
  the generic advice to check your source paths. A run where nothing at all could be read still
  stops, as before.
- **A log source sigwood could not read now says so in the report, not only on the
  terminal.** When some files are unreadable but other data still loads - a whole source
  denied, or part of one - the run completes and still exits 0; that tolerance is
  deliberate and unchanged. What was missing is the disclosure: the affected detector
  appeared in the report as having run and found nothing, which reads exactly like a clean
  result. The denial now appears as a note naming the source, how many of its files were
  unreadable, and up to three of their paths, with a count of any remainder. It rides the
  same channel as every other run note, so it reaches the text, html and pdf reports and
  the json feed; csv is a fixed worklist and carries no notes, as before. A run where
  nothing at all could be read still stops with the existing error.
- **A pipeline reading the merged stream now gets the promised broken-pipe exit code.**
  `sigwood ... 2>&1 | head` exited 120 when the reader closed early - the closed-pipe
  handler quieted stdout but not stderr, so the interpreter's final flush crashed on the
  same closed pipe. Both streams are now quieted and the exit code is 141 as documented,
  matching the plain `| head` case. Nothing is printed either way; a closed pipe is not
  an error.
- **A crafted log value can no longer execute when a finding's suggested command is
  pasted.** The literal commands some findings offer - `whois <domain>` on DNS findings,
  `grep <address>` and `whois <address>` on duration findings - now shell-quote the
  log-derived value. Ordinary addresses and domains render exactly as before; a value
  carrying shell metacharacters arrives visibly quoted and inert. Verified unchanged
  byte-for-byte on the frozen benign corpora.

- The known-issues entry on event timestamps said `beacon` and `dns` findings carried none.
  They have carried one for some time; the real wrinkle is that the key name varies by
  finding type, which is now stated plainly and tabulated in the contract page.

### Security

- **sigwood no longer writes through a symbolic link at its output path.** If the file sigwood
  was about to write turned out to be a symbolic link, it followed the link and wrote to
  whatever the link pointed at: that file was emptied, replaced with the run's findings, and had
  its permissions tightened to owner-only - and sigwood reported success. On a directory another
  account can write to, a symbolic link planted ahead of time therefore let someone else choose
  where a report landed, which is a way of taking the contents as much as destroying the file
  already there. sigwood now refuses at the moment it opens the file, leaves the existing file
  untouched, and reports the target it declined to write to. Ordinary use is unaffected,
  including a reports directory that is itself a symbolic link to another disk - only the final
  file name is checked. Two limits are written down in the known-issues list: a hard link is not
  covered, and neither is a symbolic link among the parent directories.

## [0.2.9] - 2026-08-01

### Added

- **The DNS suspicion score's measured catch rates are now written down.** The FAQ and the
  known-issues list state what the score actually catches, from a seeded measurement against
  the live scorer (1,000 samples per label length, eleven lengths from 6 to 63): the
  vowel-free digit-and-consonant shape the score is tuned toward clears the candidate bar
  about 19-36% of the time at typical DGA lengths (10-16 characters); a uniformly random
  letter-digit label, 6.6-14.8% at the same lengths; and random all-letter labels never clear
  it at any length - zero of 11,000 samples, with the best possible all-letter label below
  the bar by arithmetic. Boosting the letter-only class lexically was measured and rejected:
  every boost rule tested either flagged real benign names - the strictest still crossed 57
  in a benign reference week - or caught under half of its target, because the benign score
  curve decays smoothly through the region with no gap to put a threshold in. The docs pair
  the numbers with what one name's score does and does not decide: a score over the bar makes
  a candidate, families group by parent, and the below-gate family check - five or more
  low-scoring subdomains under one parent on Zeek data, nearly all of whose lookups fail to
  resolve - surfaces as one INFO finding regardless of score, while a family spread across
  many parents, or one whose names resolve, is outside it. The hex-tunneling entry is
  corrected by the same measurement: a long hex label straddles the bar - roughly half of
  samples clear it - rather than sitting just under it; the conclusion that a high-volume hex
  tunnel can slip the dense-cluster scan is unchanged, since half is well short of the member
  share the scan requires.

- **Every expandable system-log finding now shows its vocabulary above the fold.** The short
  `tokens:` line that previews what a capsule contains was reaching grouped families and
  bursts but not recognized administrative sessions or update runs - so the most structured
  finding sigwood produces was the one row on the page with nothing under it until you opened
  it. Recognized sessions now carry the same preview, distilled from the lines they group,
  and it appears on both the plain-text and HTML reports. A capsule whose content is entirely
  opaque identifiers still shows no preview rather than an empty one.

- **A field-validation kit for independent testers.** `tools/fieldkit.py` is one standalone
  script a collaborator can download and run wherever the `sigwood` command is installed: it
  proves the install with a small synthetic canary, runs exactly one ordinary default hunt,
  offers an optional local triage pass, and writes one reviewable Markdown report. The
  automated projection never copies a log-derived string - it keeps enumerated numeric
  measurements, counts, and fixed tokens, and groups anything unexpected under `other`; the
  three typed answers are the sole free-text exception, and the file is created privately and
  reviewed before the collaborator chooses to email it. `docs/FIELDKIT.md` states the complete
  field list and the exact privacy boundary. The kit is a repository tool, not a sigwood
  command, and nothing about the product changes. A quiet network now reads as a quiet
  network: a hunt that completes and reports nothing says so in its own words, distinct from
  a run where sigwood produced no readable report at all. The collaborator page also names
  pipx as a precondition, since several distributions do not ship it and block the
  pip-install alternative.

- **Families of low-scoring names whose lookups nearly all fail to resolve are now visible.** A single
  odd-looking domain that scores below the detector's bar stays quiet, as before - but when
  one parent domain carries several such names and nearly all of their lookups come back
  NXDOMAIN, sigwood now reports the family as one INFO finding. That is the shape of a
  rotating rendezvous or a subdomain generator whose infrastructure is dead, and it was
  previously invisible no matter how many names were involved. It reads the whole log rather
  than the clustered subset, so a busy family cannot hide by being big. Zeek only - Pi-hole
  logs carry no response code, so the check stays silent there rather than guessing. Tunable
  under `[detectors.dns]` (`promote_below_gate`, `promote_min_subdomains`,
  `promote_min_nxdomain_fraction`), and off by one setting if you would rather not see them.

- **The known-issues list now records what a very thin allowlist costs the DNS path.** Turning
  suppression off, or running with an unusually short allowlist over a large window, makes DNS
  clustering markedly more expensive - on one seven-day corpus of about 2.2 million rows the DNS
  detector on its own took about eight minutes unsuppressed and sat near 8 GiB of memory, and
  running the whole default hunt over that same window unsuppressed did not finish inside a
  nine-minute bound. The entry gives the measured figures, says plainly that they come from one
  corpus on one machine, and offers the three things that reliably help: narrow the window, run
  the detector on its own, or leave suppression on. Nothing about detection changed - this is a
  limitation that was always there and is now written down.

- **The known-issues list now records how a recognized admin session or update run groups
  lines.** Grouping claims the rare lines that fall inside the session's window - that is what
  turns one administrator's work into a single row instead of nineteen - and it means a line
  that merely happened at the same time is grouped too, and can set the unit's severity if it
  came from a privileged program. Every grouped line is still listed under the unit with its own
  time and program, so the entry tells you to read a unit as "these things happened together"
  rather than "these things are the same event". Nothing about detection changed; narrowing the
  grouping by program was measured and rejected because it dissolved genuine sessions.

- **Beacon findings carry their own event times.** Each finding now records when the
  periodic flow was first and last seen, how long it ran, and roughly how many cycles
  that span covers - so a ten-minute cadence that ran for an hour reads differently
  from one that ran all week, without leaving the finding. The first-seen time and the
  span show at `--verbose` and in the CSV worklist; the full set is in `-vv` and the
  JSON feed. Detection is unchanged.

- **Every grouped syslog finding now says what it is a fraction of.** Bursts, reboots,
  and recognized transactions carry the host's full analyzed line count beside their own,
  so "12 rare lines" can be read against the 40 lines that host produced or the 400,000
  it produced. Rare-line and per-program findings already carried the equivalent figure.
  Visible with `-v` and in the CSV worklist; the default one-line rows are unchanged.

### Changed

- **DNS clustering now treats response outcomes as evidence, not geometry.** Response
  codes no longer act like ordered numbers in the clustering matrix, suffix categories
  keep stable identities when counts tie, and a missing round-trip time stays
  distinguishable from a median observation without overpowering the other features.
  Cluster membership near the candidate bar can shift slightly as a result: on a benign
  reference week this meant four fewer barely-over-the-bar findings, with every
  corroborated and grouped finding unchanged.
- **DNS severity is earned by behaviour now, not by the label score alone.** A
  high-scoring domain name on its own is a lead, not a verdict, so it reports
  MEDIUM. HIGH additionally requires corroboration from what the queries actually
  did: most lookups under the name failing to resolve (a majority of responses,
  and at least two failures), or the name belonging to a dense high-entropy
  cluster - the shape of tunneling. One failed lookup is an event, not a pattern,
  so a single dead or mistyped hostname no longer reaches HIGH. Every DNS finding
  now records which corroboration applied, and says plainly when none did.
- **DNS findings carry their resolution evidence.** Where it can be measured,
  findings report the share of lookups that failed to resolve and how many failed.
  Pi-hole logs carry no response code, so on a Pi-hole-only run that corroboration
  is unavailable and DNS findings top out at MEDIUM - add Zeek DNS logs for the
  fuller picture. Whether a domain was blocked remains evidence you can read; it
  never decides severity.
- **Beacon severity follows the same rule: timing alone tops out at MEDIUM.** A
  periodic connection train is one category of evidence - a shape worth review,
  not a corroborated verdict - so a beacon finding on its own no longer reaches
  HIGH, whatever its score. The finding's prose now says what was measured (the
  regular cadence of an automated check-in) instead of asserting a C2 beacon,
  and its suggested next steps lead with local evidence - the process, dns.log,
  and conn.log history - before any external reputation lookup. Detection is
  unchanged: the same flows surface with the same scores.

### Fixed

- **Imitating a service role name no longer excludes a CloudTrail event from analysis.**
  Events are treated as automated service activity - and so left out of the per-principal
  scoring - when a role name in the record carries the `AWSServiceRoleFor` marker AWS uses
  for its own service roles. That marker was matched anywhere in the name, so a role called
  `MyAWSServiceRoleForSomething` qualified and its events were set aside with no note and no
  count. The marker must now begin a path segment of the role's identifier, and the
  comparison is case-sensitive; anything else is treated as interactive and is analyzed.
  Genuine service roles are unaffected. A role named exactly like a service role still
  qualifies, which is recorded in the known-issues list with the reason it is not closed.

- **A CloudTrail record can no longer exclude itself from analysis by imitating an AWS
  service name.** An event is treated as automated service activity - and so left out of
  the per-principal scoring entirely - when the field naming what invoked it ends in
  `amazonaws.com`. That test had no boundary, so a value such as `not-a-host/amazonaws.com`
  satisfied it and the event was set aside with no note and no count. The field must now be
  exactly `amazonaws.com` or end with `.amazonaws.com`, and the comparison is
  case-sensitive; anything else is treated as interactive and is analyzed. Genuine service
  activity is unaffected, because every value AWS writes there has the form
  `<service>.amazonaws.com`.

- **A malformed log file can no longer stop a run in two specific ways.** A connection log
  whose timestamps span an implausible range - ten lines dated years apart - made the beacon
  detector ask for billions of memory slots before it scored anything, which ended the
  process. It now declines to score that flow and carries on, which is what it already did
  for every other thing it cannot measure. Separately, a CloudTrail file containing a number
  with thousands of digits, or JSON nested thousands of levels deep, produced a raw Python
  error instead of a warning; both are now reported as an unreadable file and skipped, and a
  single bad line in a newline-delimited file no longer discards the good lines around it.
  A Zeek TSV log whose column-type header declares a container nested thousands of levels
  deep did the same thing; that line is now skipped and counted with the file's other
  malformed lines, and the rest of the file still loads. A column with an unusual type that
  never carries a value keeps parsing exactly as before - the limit applies to values, not to
  the header. None of these change what sigwood reports on ordinary logs.

- **A system-log capsule that shows a sample now says so.** Opening a finding that reported
  97 rare lines showed twenty of them and gave no sign the rest existed, which reads as a
  miscount or a broken control. The capsule now closes with `showing 20 of 97 rare lines`
  whenever the lines on screen are fewer than the lines counted, and says nothing at all when
  the capsule is complete. A grouped administrative session or update run discloses per
  grouped entry rather than once at the top, using the same count that entry already prints.
  The twenty-line sample itself is unchanged: those are the lines sigwood carries, so the
  disclosure states the shortfall rather than offering a switch that cannot recover it.

- **A Zeek `syslog.log` line with no message no longer becomes a finding about text
  that never existed.** A row whose `message` field is empty of content - JSON `null`,
  or `-` in TSV - was turned into the literal words `None` or `nan`, which then read as
  a program name, templated like any other line, and could surface as a rare finding.
  Those rows are now dropped before that can happen, and the count is reported:
  `syslog.log: skipped 3 rows with a missing or non-text message`. A genuinely empty
  message is kept, and so is a real log line whose text happens to read `None` - the
  check is on the field's type, not on how it prints.

- **A mistyped syslog setting now says which setting is wrong, instead of failing
  strangely later.** `[detectors.syslog]` values are checked before the detector
  runs: an out-of-range `rarity_pct` used to crash mid-run with an unhelpful
  message, `max_count = 0` silently switched rare-line detection off entirely, and
  writing `privileged_programs = "useradd"` instead of a list quietly emptied the
  privileged tier - a string is a sequence of letters, so the roster became `a`,
  `d`, `e`, `r`, `s`, `u`. Each is now reported against the setting that caused it,
  the other detectors still run, and no traceback reaches the terminal. This
  repairs crash and silent-disable shapes; it does not change detection on a valid
  configuration, and `rarity_pct` remains inert at the shipped `max_count = 1`.
- **Beacon says why it scored nothing, instead of just reporting nothing.** When the
  connection log is missing a column beacon needs, when every eligible connection
  lacks byte counts, or when rows carry no source, destination, port or protocol,
  the run summary now says so and names the cause - previously the detector
  returned an empty result that read exactly like "nothing was periodic." The
  counts describe the connections beacon actually received, after allowlist
  suppression, so a note never blames missing bytes for rows your allowlist
  removed. A configured `min_connections` below the scorer's own floor is now
  disclosed as well, rather than quietly having no effect.
- **A malformed `[detectors.beacon]` setting fails with a message that names the
  key.** A zero `bin_seconds`, a non-numeric threshold, or a text value where a
  number belongs used to surface as an opaque detector crash partway through a
  run; it is now reported against the setting that caused it, the other detectors
  still run, and no traceback reaches the terminal.
- **A connection log missing an optional column no longer crashes beacon.** Absent
  `bytes`, `conn_state`, `port` or `proto` columns are a fidelity limitation of the
  source, so beacon now abstains and says which columns were missing.
- **The beacon run-time disclosure describes the excluded connections truthfully.**
  It now says unscored connections were outside the Zeek SF/S1 states beacon
  analyzes, rather than calling them all "not established" - reset and
  half-closed connections are established states, and the old wording misfiled
  them. The known-issues entry carries the same correction, and the eligibility
  it states now matches the code exactly.
- **Beacon's suggested history pivot no longer prints a command that hangs.** The
  old `zeek-cut` suggestion piped nothing into `zeek-cut` and assumed a TSV file
  in the current directory; the step is now a plain instruction to review the
  destination's history in `conn.log`.

## [0.2.8] - 2026-07-24

### Added

- **The graph player shows byte flow as moving grain.** Ribbons carry small
  particles drifting from source to destination - density and speed follow
  each flow's current rate, inside the same frozen layout. On by default for
  byte-active conn replays (where rate is a measured claim), off for
  count-only graphs, always toggleable (`flow on|off`), and the default
  respects reduced-motion preferences. Filter clicks now snap the scale
  instantly instead of gliding.
- **The graph player carries a scale gauge.** A small bottom-left bracket shows
  what a ribbon's height is worth (`200 B/s`, `5k/s`), reading the exact scale
  the ribbons are drawn with - so the gauge can never disagree with the
  picture. It breathes with the scale in `fill`, sits still in `absolute`,
  follows the bytes/conns metric, and rides into saved clips.
- **`sigwood init` offers to skip detectors you have no logs for.** Decline a
  source during setup and the wizard now names the default-hunt detectors that
  would have read it and offers a one-keystroke `detect` exclusion (e.g.
  `detect = "default, !beacon, !scan"`) - so a box without Zeek stops seeing
  per-run "conn.log not found" notes it can do nothing about. Re-running init
  after adding the source offers to lift the exclusion; a hand-written custom
  `detect` value is never touched, and declining the offer writes nothing.

- **Pick a graph by name: `sigwood graph conn` (also `dns`, `pihole`).** Kind
  names select just those artifacts from configured sources; names compose
  (`sigwood graph conn dns`) and a single selected kind may stream to stdout or
  an exact `--out` file. Kind names and paths don't mix - a file literally named
  `conn` is reached as `./conn`. With kinds selected, only those families are
  probed, so a broken or unreadable unselected source no longer fails the run.
- **Graph flow grain is bidirectional.** Byte-active conn replays now show
  responder traffic as reverse grain - particles drifting destination-to-source
  in the source's color - split from forward grain by each flow's true
  responder-byte share (Zeek's `resp_bytes`, newly carried in the canonical
  connection schema). Ratios are exact at every aggregation tier - server
  folds and in-player rollups both sum bytes before dividing - so a
  download-heavy flow honestly shows mostly reverse grain. Ribbon shapes,
  counts, and saved-artifact geometry are unchanged; the optional direction
  ratio travels with clips, and graphs without responder data simply show
  forward grain as before.
- **The report says how it was made.** Text and HTML/PDF reports now carry a
  provenance row - `generated: <timestamp>  ·  sigwood <version>` - and, for CLI
  runs, `as: <the exact command line>` - so a saved report answers "which tool,
  which version, when, invoked how" by itself. The JSON feed carries both facts
  as `run_summary.generated_at` (ISO UTC) and `run_summary.invocation`
  (additive; no schema bump).

### Changed

- **An "admin session" can no longer span days.** Hosts with periodic privileged
  automation (a sudo cron under 45 minutes) used to chain their session
  open/close lines into one enormous "admin session" review unit - up to two
  weeks wide on long lookbacks - hiding unrelated findings under a wrong label.
  Session recognition now declines any candidate longer than 8 hours (measured:
  real interactive sessions top out well under 2 hours, automation chains start
  near a day), and the affected findings simply keep their own shapes. Genuine
  sessions, update runs, and reboot handling are unchanged.
- **Hardware-key logins and kernel dumps no longer flood the syslog report.**
  A second calibrated drain3 mask recognizes space-separated hex-pair runs (four
  or more pairs - FIDO2/CBOR debug dumps, kernel oops `Code:` lines), so a dump
  that repeats at every login shares one template instead of minting a fresh
  "rare" burst each time. Measured on a month of real fleet logs: the per-login
  burst class disappears while every MEDIUM finding and every genuinely
  once-ever event is preserved. Colon-joined MAC addresses and ordinary
  two-pair text (dates, `port 22 80`) are never masked; raw log lines are
  displayed byte-for-byte as always.
- **Syslog rows share one grammar.** Burst spans render through the same compact form
  as family and transaction rows (with a new honest seconds tier below one minute -
  `45s`, not `0m`), burst counts pluralize properly, and a transaction row now leads
  with its rare-line magnitude (`19 rare lines`) instead of the internal
  "member findings" phrase; the member count remains in evidence and JSON. Program
  mixes de-duplicate case variants for display (`CRON, cron` reads once, first
  spelling kept) - counts and machine output keep both.
- **The report header names sources, not glob patterns.** The `records:` line reads
  `12,345 syslog · 90,000 Zeek conn` instead of `12,345 *.log* · 90,000 conn*.log*`.
  The JSON feed additively carries the mapping as `run_summary.record_labels`
  (no schema bump); `record_counts` keys are unchanged.
- **Syslog review units roll up only when it pays.** Family and burst folding now
  starts at four rare lines (previously two and three): below that, a summary row plus
  its expansion costs as much space as the lines themselves, so one to three rare
  lines surface individually. Recognized transactions still group from two findings -
  their label carries meaning beyond compression. Tunable as before via
  `family_min_size` / `burst_min_size` under `[detectors.syslog]`.
- **Capsule summaries are tokens-only.** The per-template digest lines inside family
  and burst rows are gone; the `tokens:` scent line may now span up to two lines, and
  opening a row's sample always reveals something new (the raw lines). rsyslog's
  `#011`/`#012`/`#015` whitespace escapes read as separators while distilling tokens,
  so multi-line commands no longer render as glued tokens; raw lines stay verbatim.
- **Transaction rows in HTML expand straight to their raw log lines.** The
  severity-pill toggle on an admin-session or update-run row now opens the members'
  sampled raw lines under thin per-member separators instead of one-line member
  summaries; JSON member records additively carry the same bounded samples, in
  chronological member order. Separators name severity, program, and line count
  only - internal grouping vocabulary no longer appears in any output - and a JSON
  member record carries a `tier` key only when the member really is a family or
  burst rollup (a plain rare line omits it). Log content is never rewritten:
  whatever words an operator's own lines contain render verbatim.
- **Graph artifacts open in the full three-column view.** The player's view
  segment now lands with the middle tier on - services for conn, resolvers or
  query types for dns, dispositions for Pi-hole - matching how the graph is
  actually read; one click on `hosts` collapses it. The segment labels name the
  view states plainly. Clips inherit the new default; previously saved artifacts
  are unchanged (they are self-contained).
- **`graph` windows a directory like the hunt does.** A bare `sigwood graph`
  against a Pi-hole (or any flat) directory now reads the last `default_window`
  of available data - peeking rotation files' first timestamps and skipping the
  rest instead of decompressing the whole archive - and the artifact discloses
  the window. `--all`, explicit timeframes, and single named files behave
  exactly as before.
- **`warn_above = 0` now disables the large-dataset prompt.** Previously 0 meant
  prompt before analyzing any amount of data; it now switches the advisory prompt
  off entirely - the config-side equivalent of passing `-y` every run, suited to
  cron and other unattended schedules. Set a small positive value to keep an
  aggressive prompt.
- **The report wordmark matches the graph player's brand mark.** The `sigwood`
  token in the HTML/PDF report header now renders in the same serif face and
  light/dark color pair as the graph player's wordmark; the `· threat hunt`
  tagline keeps its bold sans treatment. A parity test pins both artifacts to one
  identical font stack and color pair so the two marks cannot drift apart.

### Fixed

- **A reboot is never mislabeled an "update run", and its `rebooted` marker can
  no longer vanish from the report.** On RHEL-family hosts a normal boot emits
  lines that satisfy the update-run grammar (dracut, the auditd stop/start pair,
  SELinux policy load), so a routine reboot could form a medium "update run"
  review unit that swallowed the reboot itself. Update-run recognition now
  ignores anchors inside a detected boot window (measured bounds), and a
  `rebooted` burst is never claimed by any review unit - the reboot always
  stays a visible row, including after a genuine update-then-reboot.
- **Graph flow particles read as streams, not stripes.** Same-moment spawns used
  to move in lockstep and bunch into vertical bands that marched across a
  ribbon, most visibly after a filter click. Each particle now carries its own
  slight speed variation, a restarting ribbon fills uniformly along its length,
  and the round dots are replaced by short motion streaks that follow the
  ribbon's curve - longer for faster flow - with a gentle brightness shimmer
  lifted off the ribbon color. Particles now pause with playback: a paused
  frame is fully still, and a filter click while paused recomposes the grain
  without motion. Flow direction, the toggle and its defaults, and saved
  artifacts are unchanged.
- **The graph header now counts the files that fed the graph, not the archive it
  scanned.** The source cell used to report every file discovered under the
  source directory (`+ 294 others` on a large rotation archive) even when the
  rendered window drew from a handful of them. The loader now records each
  file's kept time span and the header names only the files whose data
  overlaps the final rendered window; saved clips keep the parent artifact's
  set. The live system journal never records file paths.
- **The HTML report now discloses an underfilled window like the text report.**
  The HTML header's window row carries the same span parenthetical the text
  banner always had - the bare data span normally, and the
  `(Xh data span in Yd window)` disclosure when the loaded data underfills the
  requested lookback. The two surfaces share one formatter so they cannot drift.
- **Progress lines name the directory when file names repeat.** A dated Zeek archive
  loads several files that share one rotation name, and the load narration used to
  render identical `loaded conn.00:00:00-00:00:00.log.gz` lines for all of them. When
  any file names in one load collide, every line now carries one parent-directory
  component (`loaded 2026-05-01/conn.00:00:00-00:00:00.log.gz`), and a corrupt-file
  warning names the same disambiguated file. Loads without repeated names render
  exactly as before.

## [0.2.7] - 2026-07-21

### Added

- **Recognized syslog transactions.** The syslog detector now folds an administrative
  session (login through logout) or a system update run (package, kernel-module, and
  policy activity) into one labeled review unit per host - for example `update run ·
  4 member findings · 1m` - with every member finding preserved behind it: a compact
  drill-down at `-v` in text, an expandable row in HTML, and complete member evidence
  in JSON. Severity still comes only from the privileged program class; recognition
  groups findings, it never grades them. Default on; `recognize_transactions = false`
  under `[detectors.syslog]` restores the previous behavior exactly.
- **Host suppression allowlist.** A third flat-list kind silences a chatty machine's
  system logs whole-host: dot-free `hosts*` drop-ins in `allowlist.d/` (one fnmatch glob
  or `re:` regex per line, matched case-insensitively against the syslog host column),
  applied before analysis across all three syslog feeds - flat files, the system journal,
  and Zeek `syslog.log`. DNS and connection logs are untouched. The run banner gains a
  third coverage clause (`suppressed 9,412 rows from 2 hosts`), JSON carries the new
  `host_rows` / `host_total` / `hosts_matched` suppression fields, and `sigwood init`
  seeds a blank `hosts` template whose header warns that host suppression removes the
  whole host's story and shifts relative rarity. Host lists are local-only - sigwood
  never ships one.

### Changed

- **Steadier terminal narration.** The terminal cursor is hidden during narrated
  analyze, digest, graph, and export runs and restored across clean exits, failures,
  and interrupts; interactive prompts show it while you type. Quiet runs,
  dumb terminals, and redirected output see no cursor-control bytes at all.

### Fixed

- **Cross-feed syslog duplication no longer hides unique lines.** When the same
  host's messages reach both the local system-log feed (files or the journal) and
  Zeek's `syslog.log`, the duplicate coverage doubled that host's template counts, so
  a line that should have surfaced as a unique rare event silently left the rare set.
  sigwood now arbitrates per host: a host present in the local feed keeps its local
  rows only, and Zeek contributes just the hosts the local feed lacks. The run
  summary discloses it in counts (`system logs: 1 host carried by both the local
  feed and Zeek syslog.log - kept the local rows (16,094 Zeek rows set aside)`);
  loaded record counts are unchanged. Hosts only Zeek can see are unaffected, and
  hostless (`unknown`) lines are never arbitrated.

### Security

- **Artifacts are private by default.** Every directory sigwood creates is now mode
  0700 and every file it writes is 0600 - reports, digests, graph artifacts, exports,
  config and its backups, and allowlist seeds - independent of the process umask, and
  re-applied when an artifact is overwritten in place. The CLI also sets a 077 umask
  backstop for every command except `init`.
- **Loose-home advisory.** When an existing sigwood home is group- or world-accessible,
  each run prints a one-line stderr reminder with the exact `chmod 700` to close it.
  sigwood never changes permissions on a directory it did not create.
- A system-wide `/etc/sigwood` config keeps ordinary umask-governed permissions so
  non-root users can still read it.

## [0.2.6] - 2026-07-20

### Changed

- **Syslog capsule detail lines distill harder and fill the row.** A capsule whose
  sampled content fits on one line now shows a single `tokens:` line: the members'
  words in order, duplicates removed, complete. Larger capsules keep up to three
  per-pattern lines, now allowed 200 characters instead of 80. Opaque identifiers are
  filtered more precisely: audit record ids such as `msg=audit(...)` and kernel
  ring-buffer stamps no longer crowd out readable content, while IP addresses, ports,
  sizes, dates, and version strings are always kept.
- **The severity pill is the sample expander in HTML reports.** The separate
  "sampled log lines" control is gone; the `[M]`/`[L]`/`[I]` pill toggles it instead
  (a muted `+` beside the pill marks expandable rows; the colored pill itself keeps
  one constant width everywhere), and opening a capsule swaps its distilled lines for
  the raw sample. Sampled lines are syntax-highlighted: timestamp bright, host and
  program each in their own color, in both light and dark themes. The report remains
  JavaScript-free, and printed or PDF output carries no interactive control.
- **The HTML timestamp column hugs its content.** The leading stamp column is sized
  to the stamp itself (wider only under `--utc`, whose stamps carry a zone suffix),
  removing the fixed dead gap that previously sat between a capsule's timestamp and
  its hostname.

### Fixed

- **No more stray `|` above the report.** The render spinner no longer runs while the
  report itself streams to the same terminal, which previously stranded an orphaned
  spinner frame above the findings on every interactive run.
- **Capsule detail lines align with the timestamp column** in text reports; they
  previously sat one column to the left.
- **`[detectors.syslog].line_trim_limit` now works.** The published config key was
  read by nothing; it now trims lone rare-line titles as documented.
- **Severity pill text is readable in both themes.** White-on-color pill text
  measured as low as 2.1:1 contrast in dark mode; each severity now carries a
  per-theme ink color, every pairing clears the 4.5:1 accessibility bar, and a test
  pins the bar so future palette changes cannot regress it. One background moved
  slightly to reach the bar: the light-theme low-severity blue.

## [0.2.5] - 2026-07-20

### Fixed

- **A lone rare line read from the systemd journal now leads with its timestamp.** Journal
  entries carry their time as a separate field rather than inside the message text, so these
  rows previously rendered as bare message text in an otherwise time-ordered section - the
  common case on a modern Linux install, where sigwood prefers the journal. The row now
  starts with the same syslog-shaped stamp the grouped rows use. Lines from syslog files are
  unchanged: they already begin with their own wall clock, and sigwood never adds a second
  stamp to a line that has one.

### Changed

- **Grouped syslog rows now show a few distilled lines from what they group, and stay on one
  line each in HTML reports.** A review unit, burst, or reboot row is followed by up to three
  short fragments drawn from distinct message shapes inside it, so the row invites a closer
  look instead of only counting one. Fragments keep addresses, ports, process ids, exit codes
  and sizes, and drop only long opaque identifiers such as hashes and session tokens. On
  screen, syslog rows are clipped with a trailing ellipsis rather than wrapped or scrolled -
  widen the window to see more; printed reports still wrap so nothing is cut from a PDF. The
  leading stamp on those rows is now written in syslog's own wall-clock shape
  (`Jul 12 21:57:33`), so it reads in the same grammar as the log lines beside it. On a 7-day
  measurement corpus every grouped row carried fragments, with none empty.

- **Rare syslog findings now separate a privileged program channel from the routine
  rarity sieve.** Exact program membership in a shipped, operator-replaceable roster keeps
  security-critical families and singletons at MEDIUM; other rare families and singletons
  render as default-visible LOW, while bursts and reboots remain INFO. Family and burst rows
  now lead with their first timestamp, `-v` shows a three-line member sample, and HTML
  reports provide a closed full-sample expansion without leaking that body into printed
  reports. On the same 7-day measurement corpus, the report reads 12 privileged + 16
  routine + 10 info findings (38 total, under a minute to scan) - the increase over the
  prior 29 is privileged rows formerly buried inside info bursts, now independently
  reviewable.

- **Syslog rare-event output now groups isolated lines into per-host, per-program review
  units and normalizes long identifier-like hexadecimal-character runs during template
  mining.** Temporal bursts and reboot handling remain separate, while raw log text stays
  intact in evidence. On the measurement corpus, a 7-day multi-host run that previously
  reported 44 isolated rare-line findings now reports 19 review units (29 findings in
  total, from 56); a single quiet day reports about a dozen. Grouping changes how the
  findings are presented and counted, not what the detector observes - every rare line is
  still present in exactly one burst, family, or standalone finding.

## [0.2.4] - 2026-07-18

### Fixed

- **`scan` vertical and horizontal findings now describe the time window that actually
  triggered them**, not the whole loaded span. These scans fire when enough distinct ports
  or hosts appear inside a sliding window, but the reported evidence - connection count,
  scan-state ratio, top states, port-range entropy, and host velocity - was previously
  computed over every connection the pair exchanged across the entire log. A short scan
  burst buried in a long benign baseline between the same two hosts was therefore diluted:
  because severity and ranking are driven by the scan-state ratio, a real burst could be
  under-severitied and pushed down the report by the surrounding benign traffic. Evidence,
  severity, and rank now all reflect the triggering window. Block and slow scans are
  unchanged (their evidence was already window- and span-correct by design).

### Changed

- **The DNS detector's default surface threshold now matches its 1.8 high-entropy bar.**
  On the measurement corpus, 87 of 105 DNS findings scored from 1.5 up to but not
  including 1.8; the 18 findings at or above 1.8 remain under the new default.
- **The default hunt is now a curated set rather than every available detector.** Fresh
  installs, omitted selection, `--detect=`, and `--detect=default` select aws, beacon, dns,
  scan, and syslog; duration remains runnable by name while its severity evidence is rebuilt.
  Reports and dry runs disclose that opt-in remainder. Explicit `--detect=all` and existing
  configs with `detect = "all"` are unchanged and continue to run everything. This is a
  quieter default, not a claim that detector logic became smarter.

## [0.2.3] - 2026-07-16

### Added

- **The syslog detector now reads the live systemd journal directly** - no `sudo`, no export
  step, no durable capture file. On a systemd host `sigwood syslog` (and `sigwood hunt`) invoke
  `journalctl --output=json` for the invoking user's readable system journal, normalize every
  entry into the same five columns as flat syslog, and analyze them identically. A new
  `--syslog-source=auto|journal|files|off` flag (and `[sigwood].syslog_source`, default `auto`)
  chooses the local carrier: `auto` prefers the journal and falls back to the configured
  `syslog_dir` files when journalctl is absent/unusable or the journal has no usable entries;
  `journal` requires it; `files` uses the flat directory only; `off` disables the local lane.
  Exactly one local carrier is used per run - sigwood never merges the journal and flat files.
  Journal access depends entirely on the invoking user's permissions; sigwood never invokes sudo.
  Requires systemd 236+ (for `--output-fields`); a single journal entry over 1 MiB fails the run
  visibly rather than being silently truncated. `sigwood init` gains a compound "system logs"
  choice that detects and recommends the best local source.
- syslog ingestion now reads **ISO-8601 / RFC-3339 timestamps** in addition to RFC 3164 - the
  high-precision format stock rsyslog writes on Ubuntu/Pop 24.04 and newer. ISO stamps carry an
  explicit year and offset, so they convert directly to UTC and are not subject to the RFC 3164
  year-guess. Discovery accepts an ISO line only when it also carries a host and a colon-terminated
  program tag, so an ISO-timestamped application log (such as `dnf.log`) is not mistaken for syslog.

### Changed

- **A connection graph now replays bytes across each connection's lifetime.** `sigwood graph` on a
  Zeek conn log previously drew a connection's entire byte total in the single bin where it started,
  so one long transfer landed as a spike at its start and the rest of its life looked idle. Byte
  ribbons now spread that recorded total at a constant rate across the connection's recorded
  duration, while connection counts stay anchored at starts (those surfaces read `conn starts`).
  Zeek records a connection's total and duration but not the timing of bytes within it, so the even
  spread is an explicit model, not a claim that a bursty transfer was uniform - the artifact names
  the assumption, and discloses any recorded byte mass clipped outside the window it shows. Bands
  engage only where a row carries both positive bytes and a positive duration; zero-duration rows,
  DNS, and Pi-hole graphs are unchanged.
- **Existing installs migrate from files-only to journal-preferred `auto`.** A config that never
  set `syslog_source` now defaults to `auto` on a systemd host, so `sigwood syslog` prefers the
  live journal (falling back to your `syslog_dir` files if the journal is unavailable or empty).
  The run discloses which source it used. To keep the previous file-only behavior, set
  `syslog_source = "files"`. A config with an explicitly-empty `syslog_dir` continues to disable
  the local lane unchanged.
- The "permission denied" message for an unreadable log now gives correct, least-privilege advice:
  it suggests `usermod -aG` only for a group-readable file owned by a known log-reader group
  (`adm`); for a root-only (`0600`) log, or one owned by a privileged group, it points at adjusting
  group ownership or an ACL instead of recommending a group join that would not help or would
  over-grant.

## [0.2.2] - 2026-07-15

### Changed

- The `graph` verb is now resilient on real-world data: a valid log always produces a graph.
  Instead of failing on a dense or very large source, the builder degrades within the player -
  adapting host and service rankings, bin width, and smoothing - until it fits. Timelines with
  a long, sparse lead-in are trimmed to the active window, so a handful of long-lived flows no
  longer stretch the axis. The player's header is now a labeled provenance readout - source,
  window, entity counts, bin size, and the exact `sigwood hunt` command for the same log - and a
  Zeek directory that lacks byte or service detail still renders a connection-count graph.

### Fixed

- `sigwood graph` no longer aborts with a "too dense for smooth interaction" error on an
  ordinary day of dense logs; an oversized graph degrades to fit the animation instead of
  failing.

### Security

- Releases are now published through **PyPI Trusted Publishing**: each distribution is built and
  uploaded by a tag-triggered CI workflow that authenticates to PyPI over OIDC, with no
  long-lived upload token stored anywhere. Every published file carries a **PEP 740 publish
  attestation** - a Sigstore-backed, verifiable record that it was uploaded by this project's
  release pipeline. This is publication provenance (which pipeline uploaded the file), not a
  claim about how the code was built or that the code is safe.

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

[Unreleased]: https://github.com/helixmap/sigwood/compare/v0.5.1...HEAD
[0.5.1]: https://github.com/helixmap/sigwood/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/helixmap/sigwood/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/helixmap/sigwood/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/helixmap/sigwood/compare/v0.2.9...v0.3.0
[0.2.9]: https://github.com/helixmap/sigwood/compare/v0.2.8...v0.2.9
[0.2.8]: https://github.com/helixmap/sigwood/compare/v0.2.7...v0.2.8
[0.2.7]: https://github.com/helixmap/sigwood/compare/v0.2.6...v0.2.7
[0.2.6]: https://github.com/helixmap/sigwood/compare/v0.2.5...v0.2.6
[0.2.5]: https://github.com/helixmap/sigwood/compare/v0.2.4...v0.2.5
[0.2.4]: https://github.com/helixmap/sigwood/compare/v0.2.3...v0.2.4
[0.2.3]: https://github.com/helixmap/sigwood/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/helixmap/sigwood/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/helixmap/sigwood/compare/v0.1.1...v0.2.1
[0.1.1]: https://github.com/helixmap/sigwood/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/helixmap/sigwood/releases/tag/v0.1.0
