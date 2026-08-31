# sigwood - Schemas & the Parser/Detector Interface

This file is the canonical record of the column contracts that cross the
boundary between `parsers/` (which normalize) and `detectors/` (which analyze).
It captures both *what* each schema is and *why* we draw the lines where we do.

This file is the human-facing companion for the one interface that matters most
here: the normalized DataFrame a parser hands a detector. The code is the binding
authority - when this document and the implementation disagree, the implementation
wins and this file is wrong and should be fixed.

---

## Why this interface is special

Separation of powers means parsers and detectors never reach across into each
other. The only thing that crosses between them is a DataFrame with agreed-upon
columns. That column contract is therefore the single most load-bearing interface
in the codebase: get it right and a detector can be written, tested, and reasoned
about as a pure function of its input frame; get it wrong and detection policy
leaks into parsers or parsing leaks into detectors.

Two principles govern every schema below.

**Parsers normalize faithfully; they do not decide what matters.** A parser's job
is to turn a wire format into canonical columns. Deciding which columns are
*interesting* is detection policy and lives in detectors. This is why we resist
lossy projections that silently discard fields a parser saw - dropping a field is
a quiet detection-policy decision wearing a parser's coat.

**Schemas are minimal but never assume comprehensiveness.** We add a canonical
column when a real detector consumes it, not before - the same discipline that
governed dnsmasq event-type promotion (the taxonomy deliberately stops at twelve
named event types plus an `unknown` residual - the residual is the point, not a gap). But "minimal today" must never mean "hard to
extend tomorrow." Every parser is written so that adding a field later is a
one-line, obvious change, and every source that carries more than we currently
surface keeps an escape hatch (see below) so the unused richness is preserved
rather than thrown away at the door.

---

## The escape-hatch pattern

Some sources are far richer than any current detector consumes. CloudTrail is the
archetype: the v1 behavioral signals read ~10 fields, but the raw event carries
dozens, and those dozens are exactly where future detectors (privilege
escalation, exfiltration) will find their signal. Discarding them would betray
the "parsing is free, spend the saved effort on analysis" thesis; pre-building
columns for detectors that don't exist yet would betray the no-overengineering
discipline.

The escape hatch threads this. A parser may carry a single `raw` column holding
the original record (as a dict). The rules that keep it from rotting into a junk
drawer:

- **No shipped detector reads `raw` at runtime.** It is experimentation substrate
  and future-detector raw material, nothing more.
- **Promote, don't grep.** When a new detector needs a field that lives in `raw`,
  it promotes that field to a real, typed, documented canonical column - at that
  time, with real knowledge of what it needs. Detectors never reach into `raw`
  mid-analysis.
- **One hatch, clearly named.** `raw` is a deliberate, documented exception in an
  otherwise disciplined schema - not a habit and not a license for other open
  blobs.

The faint smell of a punt here is acceptable and intentional. We will catch the
punt downstream when a real detector gives us real requirements, and run with it.

---

## Derived keys vs. carried fields

Most canonical columns are *carried*: a wire field, renamed and type-normalized.
A few are *derived*: the parser computes them from one or more raw fields by a
rule. Derived keys are where parser logic legitimately concentrates, and they get
specified as **tested behavior** rather than as a single schema-table row,
because the rule is the substance.

The CloudTrail `principal` key is the first major derived key (see below). The
rule for collapsing the `userIdentity` variants into one stable actor key is the
heart of the CloudTrail parser, and it is verified by test cases per identity
type - not captured as a one-liner here. The schema table states the column
exists and what it represents; the parser spec and its tests state precisely how
it is computed. This keeps the schema clean while putting the complexity where it
is checkable.

---

## Schema registry

### Canonical connection schema (Zeek conn / dns transport)

Source: `parsers/zeek.py`, `parsers/zeek_tsv.py`. Consumers: beacon, scan,
exfil, digest (conn card), graph (conn replay). (The Zeek dns feed shares the
`src`/`ts` naming but has its own minimal schema, below.)

```
src        - source IP (str)
dst        - destination IP (str)
port       - destination port (int, nullable)
proto      - tcp / udp / icmp (str, nullable)
ts         - unix epoch timestamp (float)
bytes      - originator bytes (int, nullable)
resp_bytes - responder bytes (int, nullable; graph byte-direction shares and exfil)
duration   - connection duration in seconds (float, nullable)
conn_state - connection state (str, nullable)
local_orig - bool (nullable)
```

### Exfil evidence population

The `exfil` detector requires both `bytes` and `resp_bytes`. Its
`orig_bytes_total`, `resp_bytes_total`, `orig_share`, and `connection_count`
evidence describe only complete-byte measured rows for the pair; they do not
claim totals or byte share for rows whose responder bytes were unavailable.

Zeek-specific names (`id.orig_h`, etc.) never appear outside `parsers/zeek.py`.

### Fidelity-aware DNS schema (Zeek dns + dnsmasq)

Source: `parsers/zeek.py` (Zeek dns), `parsers/dnsmasq.py` (Pi-hole). Consumers:
dns detector, digest (dns card - fidelity-aware, reads both feeds). This is the canonical example of one detection question spanning
two source formats at different fidelities.

Minimal (both sources produce):
```
ts        - unix epoch float
src       - client IP (str)
query     - queried domain (str)
```

Extended (Zeek only):
```
resolver, rtt, ttl, rcode, answer, tc
```

`resolver` is Zeek's DNS responder address, normalized from `id.resp_h`.

dnsmasq enrichment (Pi-hole only) - computed by the dns detector's per-domain
aggregation (`_build_pihole_aggregate`), *not* emitted by the parser. Same
parser-emits-fragments / detector-aggregates split as CloudTrail below: the
dnsmasq parser emits one row per event (`ts, src, query, event_type, qtype,
host`); the enrichment appears only after the detector rolls those events up per
domain.

The parser retains only the fields shipped consumers read. Answer payloads,
upstream resolver addresses, DNSSEC and block-disposition phrases, and the
original line text are recognized by the grammars - they decide the `event_type`
- but are not carried on the row, because holding them costs gigabytes on a
multi-million-line capture and nothing reads them. A future consumer promotes
what it needs at its own planning seam and recovers the values by re-parsing the
source log, the same promote-don't-grep discipline the CloudTrail `raw` column
describes below.

One consequence worth stating plainly: a line no grammar recognizes is still
kept, and still counts, as an `unknown` row - but the row no longer carries the
line's text. Extending the grammar means reading the source log, not the loaded
frame.
```
was_blocked, block_ratio, unique_clients, qtype_counts, cache_ratio, forward_ratio
```

Both feeds carry `qtype` (so it is not listed under "Zeek only" above):
dnsmasq as a string mnemonic (e.g. `"A"`, `"AAAA"`); Zeek as the source's native
numeric type code (e.g. `1`, `28`). Each parser surfaces its source's native
form - no translation in the parser; a fidelity-aware consumer can map between
them if it wants a unified view. `qtype` exists on both feeds because the digest
dns `qtype-mix` slot consumes it on both - the same consumer-motivated,
govern-don't-grep promotion discipline as `program` on syslog.

`was_blocked` / `block_ratio` are evidence-only for DNS clustering - never feature
-matrix inputs.

### Fidelity-aware syslog schema (systemd journal + flat rsyslog + Zeek syslog.log)

Source: `parsers/syslog.py` (flat RFC 3164 or ISO-8601 rsyslog), `parsers/journal.py`
(the live systemd journal via `journalctl --output=json`), `parsers/zeek.py`
(`_normalize_zeek_syslog_df` - Zeek `syslog.log`, TSV + NDJSON front-ends).
Consumers: syslog detector (source-blind - reads only the minimal-5), digest
(syslog card - fidelity-aware, reads both flat/Zeek feeds), and the shipped `auth` detector.
The second
source-spanning detector after dns; same question (rare events / reboots)
over three physical feeds of one logical lane. Exactly ONE local carrier (the live
journal OR flat files) is selected per run; Zeek `syslog.log` remains independent.

Minimal (both feeds produce, v1-required):
```
ts        - unix epoch float
host      - hostname (str)
program   - program/process token from the message head (str)
raw       - original transport-layer line (str) - drives finding titles
message   - header-stripped, pid-normalised body (str) - drain3-aligned
```

Extended (Zeek only, nullable):
```
facility  - RFC 5424 facility, uppercase enum string ("DAEMON", "KERN", …)
severity  - RFC 5424 severity, uppercase enum string ("EMERG", "ERR", "INFO", …)
```

`program` is the leading token before the first `[` or `:` (e.g. `sshd`,
`postfix/smtpd`, `kernel`); `"unknown"` when absent. drain3 operates on
`message` directly. `program` is a govern-don't-grep promotion: surfaced as
a canonical column so downstream consumers (e.g. the digest verb) do not
re-parse it out of `message`.

Derivation rules - Zeek `syslog.log`:
- `raw     = Zeek 'message' verbatim`
- `host    = embedded RFC 3164 hostname via parse_host(raw); falls back to
             Zeek 'id.orig_h' when parse_host returns "unknown"`
- `program = parse_program_from_line(raw)` - looks through at most eight stacked
             transport headers, so a relay-forwarded line reports the originating
             program rather than the relay header's first token
- `message = normalize_pids(strip_header(raw))`
- `ts      = Zeek 'ts' (already canonical epoch float)`
- `facility/severity` carried as-is, uppercase enum strings; consumer
  interprets. The strip-header pipeline is shared with the flat path
  (parsers/syslog.py helpers), and `program` and `message` deliberately strip to
  different depths. `message` strips exactly ONE header, so the doubled-timestamp
  invariant holds - `strip_header` is `^`-anchored and removes only the leading
  transport header, leaving an inner application timestamp in the body. `program`
  instead looks through up to eight stacked headers, because a forwarded line's
  first token is the relay's own timestamp rather than a program name. Both feeds
  behave the same way. The eight-header bound means one large record cannot drive
  unbounded repeated parsing; a line relayed more times than that reports the
  token reached at the bound rather than failing.

Derivation rules - systemd journal (one compact-JSON object per entry):
- `ts      = __REALTIME_TIMESTAMP / 1_000_000` - the journal receipt time only
             (the clock journalctl seeks and windows on); `_SOURCE_REALTIME_TIMESTAMP`
             is ignored, an unparseable/absent timestamp drops the row
- `raw     = the decoded MESSAGE exactly` (a byte-array MESSAGE is strict-UTF-8
             decoded; embedded newlines/controls preserved - render sanitizers
             own line discipline)
- `host    = _HOSTNAME` when it is one non-whitespace token, else "unknown"
- `program = SYSLOG_IDENTIFIER, else _COMM`, through the shared `parse_program` rule
- `message = normalize_pids("<program>[pid]: <MESSAGE>")` when program is known,
             else `normalize_pids(MESSAGE)` - so a bare journal MESSAGE gains the
             program tag drain3 (and reboot matching) rely on
Journal rows carry no `facility`/`severity`. The journal is a loader-owned producer
(`journalctl --output=json`, no sudo, a bounded private transient capture removed
after load).

Ownership: parser/loader carry `facility` and `severity`; the detector
receives them in the frame but never reads or assumes them - minimal-5 only.
The digest consumes `severity` to define the error-rate kind on the Zeek
feed (error-set `{EMERG, ALERT, CRIT, ERR}`); the flat feed retains the
keyword-token heuristic, and the digest's insight wording forks with the feed.

### Access-decision projection (auth extraction)

Source: `parsers/auth.py` (shipped). Consumer: the shipped `auth` detector. The
projection stays a grammar-only boundary; aggregation and severity remain detector work.

A pure, grammar-only extractor over the canonical syslog lane: it consumes the
`message` and `program` columns above and returns grammar-derived facts alone.
Row timestamp, host, aggregation, and every scoring or severity decision live
outside it. `extract_decision(message, *, program)` returns one `AuthDecision`
or `None`.

```
outcome          - granted | denied | indeterminate (never absent)
gate             - deciding mechanism (never absent); see the domain below
actor            - the party whose attempt this is (str, nullable)
actor_namespace  - unix_user | unix_auid | preauth_username (nullable)
target           - the account being assumed, when a distinct one is named (nullable)
source           - remote address, address only (nullable)
auid             - audit login uid, verbatim (nullable)
terminal         - tty / terminal, verbatim (nullable)
exe              - executable path, verbatim (nullable)
audit_type       - audit record type, verbatim (nullable)
res              - audit result field, verbatim (nullable)
session          - audit session id, verbatim (nullable)
serial           - audit event serial, verbatim (nullable)
```

Every nullable field is textual. Audit carries unset markers and placeholders that
are meaningful as written, so no value is coerced to an integer.

`gate` domain, exactly six values: `sshd` · `dropbear` · `sudo` · `su` ·
`runuser` · `audit`. The gate is the deciding mechanism, not the emitting process,
so `sshd` and `sshd-session` share `sshd`, and both audit serializations share
`audit`. A PAM line's gate is the service named inside its parentheses; a service
outside the six returns `None` rather than minting a token.

`outcome` is three-valued and the third value is load-bearing. `indeterminate`
marks a line emitted by an authentication service during an authentication
exchange where no grant or denial was reached - a preauth disconnect, a
key-exchange failure, a session close. Such an observation is recorded but is
never an eligible access decision: `is_eligible_decision` is False, and consumers
must keep it out of attempt and denial denominators. Distinguishing it from `None`
(no access-decision grammar present at all) is what makes extraction coverage
measurable.

Identity rules:
- **At least one of `actor`, `target`, or `source` is always present.** A grammar
  that names no party returns `None` rather than an unattributable decision. In
  particular, a session opened *for* an account with no initiator named yields
  `actor=None, target=<account>` - the extractor does not invent an initiator.
- **Namespaces never merge.** A unix account name, an audit login uid, and an
  unauthenticated pre-authentication username occupy different identifier spaces;
  `actor_namespace` travels with the value and aggregates are never taken across
  it. `target` is a unix-account identifier in every current grammar.
- **Audit unset markers are not identities.** A bare `?` and the unset login-uid
  marker are refused as `actor`, `target`, and `source` while still being carried
  verbatim in their own fields - carrying a value and treating it as an identity
  are separate questions.
- **`source` is an address, never an endpoint.** A port is discarded, so two
  connections from one address share one source identity. A whole valid address is
  preserved before any port handling, so an unbracketed IPv6 literal is never
  truncated.

Extraction is dispatched on `program` over a fixed set - `sshd`, `sshd-session`,
`dropbear`, `sudo`, `su`, `runuser`, and the two audit serializations. A line whose
program is outside that set returns `None` before any grammar runs. A line whose
program token is absent (canonical `"unknown"`) is matched only against anchored
grammars, never a broad keyword scan; no such grammar ships today, so an untagged
line currently returns `None`.

Scope: this extractor recognises access-decision grammar and reports the outcome
a line states. It does not decide which record types own a gate, does not collapse
duplicate records of one attempt, and does not read command vocabulary - a sudo
record contributes its decision, never the command it ran.

### Canonical TLS-session schema (Zeek ssl.log)

Source: `parsers/zeek.py` (`_normalize_ssl_df`), `parsers/zeek_tsv.py`.
Consumer: the `ssl` detector. Every column has a named reader; a Zeek field
with no reader is dropped at normalization rather than carried, and a future
consumer promotes what it needs through the normalizer instead of reading Zeek
names downstream.

```
ts                - unix epoch timestamp (float)          - flow identity, event time
src               - originating IP (str)                  - flow identity, direction
dst               - responding IP (str)                   - flow identity, direction
port              - responder port (int, nullable)        - flow identity, evidence
version           - negotiated TLS version (str, nullable)      - tuple evidence
cipher            - negotiated cipher suite (str, nullable)     - tuple evidence
curve             - negotiated key-exchange curve (str, nullable) - tuple evidence
alpn              - negotiated next protocol (str, nullable)    - tuple evidence
sni               - server name indication (str, nullable)      - the sni_absent leg
resumed           - session resumption (bool, nullable)         - the sni_absent leg
established       - handshake completed (bool, nullable)        - the sni_absent leg
validation_status - chain validation outcome (str, nullable)    - the validation leg
cert_fp           - server certificate fingerprint (str, nullable) - the x509 join
```

`ts/src/dst/port` are the required flow identity; everything after them is
nullable. That is a fidelity fact, not a defect: TLS 1.3 encrypts the
certificate message, so `validation_status` and `cert_fp` are routinely absent,
and a handshake that never completed carries no negotiated parameters.

`cert_fp` is DERIVED from Zeek's `cert_chain_fps` vector - the leaf (first
element) is the server certificate. An empty chain, a non-sequence, or a
non-string leaf yields null; an absent chain column yields no `cert_fp` column
at all.

Dropped at normalization, having no reader: `uid`, `id.orig_p`, `ssl_history`,
`sni_matches_cert`, `chain_len`, `last_alert`, `client_cert_chain_fps`, and the
`cert_chain_fps` vector itself once its leaf is taken.

ssl.log carries no `local_orig`; direction is decided by the consumer against
`home_net`.

### Canonical certificate-fact schema (Zeek x509.log)

Source: `parsers/zeek.py` (`_normalize_x509_df`), `parsers/zeek_tsv.py`.
Consumer: the `ssl` detector's evidence join, keyed `ssl.cert_fp` →
`x509.fingerprint`.

```
ts               - unix epoch timestamp (float)             - representative-row order
fingerprint      - certificate fingerprint (str)            - the join key
not_valid_before - validity start (float epoch, nullable)   - validity/age evidence
not_valid_after  - validity end (float epoch, nullable)     - validity evidence
self_signed      - subject equals issuer (bool, nullable)   - evidence
key_alg          - public key algorithm (str, nullable)     - evidence
key_length       - public key length (int, nullable)        - evidence
```

`self_signed` is DERIVED from subject/issuer equality, and both identity
strings are then dropped: they have no reader, and their equality is the only
fact a consumer needs. The derivation requires BOTH values to be measured
strings - anything else yields null rather than `false`, because `false` would
assert "not self-signed" about a certificate whose identities were never read.

Dropped at normalization, having no reader: `certificate.subject`,
`certificate.issuer`, `certificate.sig_alg`, `certificate.serial`,
`certificate.version`, `certificate.exponent`, `certificate.curve`, the `san.*`
family, `basic_constraints.*`, `host_cert`, and `client_cert`.

### Rename-collision containment (ssl / x509)

A source carrying BOTH a Zeek field and the canonical name it renames to (for
example `id.orig_h` alongside a native `src`) cannot be renamed without
producing a duplicate column. The normalizer does not raise - normalization runs
after the per-file concatenation, outside the loader's per-file parse
containment, so raising would abort the whole run on one malformed file.
Instead the frame is emptied to its declared columns and one warning names the
pattern and the row count. The NDJSON recognizer declines to claim such a
record for the same reason.

### Canonical weird schema (Zeek weird.log)

Source: `parsers/zeek.py` (`_normalize_weird_df`), `parsers/zeek_tsv.py`.
Consumer: the `weird` digest card. As with the TLS schemas, every column has a
named reader and a Zeek field with no reader is dropped at normalization.

```
ts     - unix epoch timestamp (float)        - the histogram and the card window
name   - the weird name (str)                - name-volume cliff, name-mix
src    - originating host (str, nullable)    - host-volume cliff
source - the analyzer raising it (str, nullable) - analyzer-mix
```

Renames `id.orig_h` to `src`. `ts` and `name` are the required identity; `src`
and `source` are nullable, and both absences are ORDINARY rather than
defective: a weird raised below the connection layer names no host, and one
raised outside a protocol analyzer names no analyzer. The card renders a
missing analyzer as `(no analyzer)` in the analyzer mix and discloses missing
origin hosts as an ambient row count rather than inventing a host category.

Dropped at normalization, having no reader: `uid`, `id.orig_p`, `id.resp_h`,
`id.resp_p`, `peer`, `addl`, and `notice` - the last because Zeek sets it per
policy and a slot reading a value that never varies would be a constant cell.

### Canonical CloudTrail event schema (v1)

Source: `parsers/cloudtrail.py` (shipped). Consumers: `aws` detector (shipped),
digest (cloudtrail card - the aws front-half rollup without scoring).
**One row per event.** Aggregation to per-principal is the detector's job, not the
parser's - the same parser-emits-fragments / detector-aggregates split proven by
dnsmasq (`_build_pihole_aggregate` lives in the detector, not the parser). The
detector aggregates the interactive lane only; service-lane events are excluded
from all signals (AWS-run background activity is supposed to be broad and
repetitive - scoring it produces noise).

Carried fields:
```
ts            - eventTime parsed to unix epoch float
event_source  - eventSource (e.g. "s3.amazonaws.com")
event_name    - eventName (e.g. "ListBuckets")
identity_type - userIdentity.type, carried verbatim (IAMUser, AssumedRole, …)
source_ip     - sourceIPAddress (str, nullable)
error_code    - errorCode (str, nullable; null = no error)
aws_region    - awsRegion (str, nullable) - human-triage pivot, promoted from raw
event_id      - eventID - drill-back anchor, the analyst's key to the full event
```

Derived fields:
```
principal     - stable per-actor key derived from userIdentity (see below)
lane          - "interactive" | "service". Service iff any of: userIdentity.type
                in {AWSService, AWSAccount}; invokedBy is exactly
                "amazonaws.com" or ends with ".amazonaws.com"; or a path
                segment of the userIdentity or sessionIssuer arn starts with
                "AWSServiceRoleFor". Otherwise interactive. Both string tests
                are case-sensitive and require their boundary - a dot for
                invokedBy, a segment start for the role marker - so anything
                else stays interactive and is analyzed. No hardcoded
                principal-name list.
read_write    - "read" | "write". From top-level readOnly when present (bool or
                "true"/"false" string); else inferred from the action verb
                (Get/List/Describe/Head/Lookup/Search/BatchGet/Select/Query/Scan
                → read, else write). Unknown/empty eventName → write.
```

Escape hatch:
```
raw           - original event dict; no v1 detector reads it; promote-don't-grep
```

Deliberately **not** surfaced in v1 (available in `raw`, promote when a signal
needs them): `recipient_account_id` (only meaningful in cross-account setups our
target audience mostly lacks), `user_agent` (the one place drain3 template mining
might earn a role; promote if a UA-based signal materializes),
`request_parameters`, `response_elements`, `resources` (the substrate for future
privilege-escalation / exfil detectors - exactly what the hatch is for).

#### The `principal` derivation (tested behavior, not a one-liner)

`principal` collapses the `userIdentity` variants into one stable string so that
per-principal aggregation groups an actor's activity together rather than
fragmenting it. The governing intent: **a role assumed many times is one actor,
not many.** As shipped, the parser keys by `userIdentity.type` with a defined
precedence ladder per type (each step falls through to the next when absent or
empty):

- `AssumedRole`: the session *issuer*, never the per-assumption session name -
  `sessionContext.sessionIssuer.userName` → last slash-segment of
  `sessionContext.sessionIssuer.arn` → `sessionContext.sessionIssuer.principalId`
  → generic fallback. Every session of one role aggregates together. This is the
  load-bearing property and is asserted directly in tests (two sessions of one
  role → one principal; the session name is never the principal).
- `IAMUser`: `userName` → last slash-segment of `arn` → `principalId` → fallback.
- `AWSService`: `invokedBy` → fallback.
- `Root`: the literal marker `root`.
- All other types (FederatedUser, SAMLUser, WebIdentityUser, IdentityCenterUser,
  AWSAccount, future unknowns) and any event whose `userIdentity` is missing,
  empty, or not a dict: the **generic fallback** - `principalId` → `type` → the
  literal `unknown`. Stable, never crashes, never collapses distinct
  `principalId`s into one bucket.

The rule is tested per identity type, and validated against two corpora - a
quiet single-principal account and a multi-principal public CloudTrail corpus -
which between them exercise the full `userIdentity` variety.

---

## Export availability provenance (v1)

Every directory holding a successfully committed `sigwood export` carries a reserved
`.sigwood-export-provenance.json` manifest. It binds each completed data object
to the exact requested half-open UTC interval and to the bytes that were
written. The manifest itself is not log input.

```json
{
  "schema_version": 1,
  "generation": 1,
  "written_at": "2026-08-09T20:00:00Z",
  "entries": {
    "pihole_dnsblock_20260801_to_20260808.log": {
      "schema_version": 1,
      "content_sha256": "<64 lowercase hexadecimal characters>",
      "size_bytes": 123,
      "requested_start_utc": "2026-08-01T00:00:00Z",
      "requested_end_utc": "2026-08-08T00:00:00Z",
      "request_zone": "America/Chicago",
      "tzdata_version": "2026a",
      "exporter": "sigwood",
      "backend": "splunk",
      "completion": "success"
    }
  }
}
```

The manifest is canonical UTF-8 JSON with a trailing LF. Object keys are
unique, `generation` is positive, entry names are safe basenames, and every
interval is positive, UTC, and half-open: `[requested_start_utc,
requested_end_utc)`. `request_zone` and `tzdata_version` may be `null`. They
describe how the request was interpreted on the exporting host; they never
claim the source device's wall-clock zone and never establish completeness.
Manifest input is capped at 256 MiB and 100,000 entries; a selected population
above 100,000 objects is downgraded as one unit without partial trusted facts.

The loader publishes one typed availability fact for every selected data file.
A fact is `TRUSTED` only when a unique `completion: "success"` entry binds the
whole file's exact size and SHA-256. Missing, malformed, incomplete, unreadable,
or mismatched evidence yields `UNKNOWN`; it never aborts parsing solely because
provenance could not be established. Entries for files outside the selected
population create no fact. Trust is prospective: existing files do not become
trusted merely because a later manifest exists.

The reserved manifest, `.sigwood-export-provenance.lock`, and every path below
the exact `.sigwood-export-stage-` prefix are excluded before discovery,
sniffing, parsing, snapshots, and byte accounting. Explicitly naming a reserved
artifact is rejected with guidance to select the exported data file or its
containing directory.

The runner selects a strong coverage lane only for an exact bounded report
interval when every participating object is trusted and the merged union of
their manifest intervals covers that interval without a gap. Overlap counts
once. Filenames (`_to_`, `_Nd`, date-shaped names), loaded event extrema, and
request-zone context are never availability evidence. Implicit or unbounded
report intervals remain weak until a later contract supplies an authoritative
interval.

---

## Loader & data_sources wiring

Every source family loads through **one uniform pipeline**, not a per-source
branch. `loader.load_required_logs()` looks up a family's strategy with
`_SOURCE_LOADERS.get(source)` and hands it to `run_load()`, which owns everything
identical across families - the progress bar, coverage tracking, the timeframe
window filter, the read-corruption rail, and the verbose-gated wrong-family skip. A family is one `SourceLoader` entry in the `_SOURCE_LOADERS` registry,
declaring only what actually varies: how it discovers files, whether it parses to
a stream of row dicts or a whole DataFrame, its timestamp policy, and how it
resolves a default window. Adding a format is adding a registry entry, which
inherits the uniform treatment by construction - there is no `if source == …`
chain to extend, no `can_parse()` sniffing, and no parser base class.

CloudTrail is one such entry, keyed `cloudtrail_dir`. Its shape is structurally
its own - JSON events, neither Zeek NDJSON nor flat syslog text - so its
`stream`-mode `parse` sniffs each file from a single line iterator: a first line
parsing to a dict containing `Records` is an envelope (the whole document is
accumulated and parsed); a first line parsing to a bare event dict is NDJSON (the
exporter format, streamed line by line); anything else - a JSON list, or a non-JSON
first line from a pretty-printed envelope - is read as a whole document.
`discover_cloudtrail_files()` walks recursively (`rglob`) so a native
`AWSLogs/<acct>/CloudTrail/<region>/YYYY/MM/DD/*.json.gz` tree works when pointed
at any level, excluding `CloudTrail-Digest` integrity manifests. Corrupt or
undecodable files warn and skip; one bad file never kills a load. There is no
flatten-to-syslog path - the parser emits per-event canonical rows the `aws`
detector consumes directly. `load_cloudtrail()` itself is a thin wrapper that
selects the strategy and calls `run_load`.

The `cloudtrail_raw` label in `data_sources` is derived in
`runner._derive_data_sources()` from the source key, so a non-empty CloudTrail
load lights it up for free.

---

## Era archive observation facts

Era's archive planner consumes loader-owned discovery and exposes typed planning
facts; it is not a parser or a detector. Its source calendar consists of UTC
date groups: only a directory named exactly `YYYY-MM-DD` is a date group, and a
suffixed name never becomes a date by prefix accident.

The planner's work estimate is the sum of compressed on-disk file sizes from
`stat()`. Gzip trailer sizes, decoded-byte probes, and row counts are not work
estimates: trailers are advisory and the latter two require reading data.

For each source family and date, era keeps three independent observation layers:

- **availability**: whether the source was available for inventory;
- **parse usability**: whether the loaded source produced usable timestamps;
- **sensor completeness**: what the sensor's own capture-loss telemetry can
  support.

Missing capture-loss data is `completeness-unknown`, not proof that capture was
complete. Thin telemetry is a distinct quality state. Capture-loss intervals
remain attributed to their stable peer or stream. Weighted loss is calculated
within that peer from its reported gaps and acknowledgements; overlapping peers
are never combined into a made-up denominator.

Source partitions are UTC half-open intervals. Era projects their availability
and usable-timestamp floors onto display-calendar days: every overlapping UTC
partition must clear its floor and a committed usable timestamp must land in
the display day. A non-UTC display day can overlap two partitions, so failure of
either makes that display day ineligible. Sensor-loss intervals project by their
timestamps and peer but do not decide day eligibility.

Era report reducers consume only loader-selected rows and retain aggregate facts.
Their shards are complete UTC-midnight, half-open intervals wholly inside the
absolute report interval and bound to the planner's canonical source groups;
planned empty shards remain visible aggregate facts. Display timezone changes
labels and projections, not source membership or committed totals. Card 2 publishes committed connection
records and DNS-query rows independently. Its distinct destination-address count
is exact only for classifiable, routable addresses outside the configured
`home_net`; an address-cap or classification failure is displayed as an explicit
non-measurement, never as a partial exact count.

The canonical report identity contains archive content identity, resolved
configuration, CLI options, display timezone, partition zone, tldextract version,
the effective PSL snapshot SHA-256, and sigwood version. Generated-at and output
name are rendering metadata rather than identity inputs. Resource-measurement
receipts are `PASS`, `COMPLETED_RSS_OVER_LIMIT`, or `NOT_MEASURED`; a
non-measurement names whether the corpus, route, or measurement harness was
unavailable.
