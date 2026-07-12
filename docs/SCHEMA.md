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
duration, digest (conn card). (The Zeek dns feed shares the `src`/`ts` naming but
has its own minimal schema, below.)

```
src        - source IP (str)
dst        - destination IP (str)
port       - destination port (int)
proto      - tcp / udp / icmp (str)
ts         - unix epoch timestamp (float)
bytes      - originator bytes (int, nullable)
conn_state - connection state (str, nullable)
local_orig - bool (nullable)
```

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
dnsmasq parser emits one row per event (`ts, src, query, event_type, qtype, dst,
answer, validation, host, raw, message`); the enrichment appears only after the
detector rolls those events up per domain.
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

### Fidelity-aware syslog schema (flat rsyslog + Zeek syslog.log)

Source: `parsers/syslog.py` (flat RFC 3164 rsyslog), `parsers/zeek.py`
(`_normalize_zeek_syslog_df` - Zeek `syslog.log`, TSV + NDJSON front-ends).
Consumers: syslog detector (source-blind - reads only the minimal-5), digest
(syslog card - fidelity-aware, reads both feeds), future auth. The second
source-spanning detector after dns; same question (rare events / reboots)
over two source families.

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
- `program = parse_program(strip_header(raw))`
- `message = normalize_pids(strip_header(raw))`
- `ts      = Zeek 'ts' (already canonical epoch float)`
- `facility/severity` carried as-is, uppercase enum strings; consumer
  interprets. The strip-header pipeline is shared with the flat path
  (parsers/syslog.py helpers), so the doubled-timestamp invariant -
  `strip_header` is `^`-anchored, only strips the leading transport header -
  holds for both feeds.

Ownership: parser/loader carry `facility` and `severity`; the detector
receives them in the frame but never reads or assumes them - minimal-5 only.
The digest consumes `severity` to define the error-rate kind on the Zeek
feed (error-set `{EMERG, ALERT, CRIT, ERR}`); the flat feed retains the
keyword-token heuristic, and the digest's insight wording forks with the feed.

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
                in {AWSService, AWSAccount}; invokedBy ends "amazonaws.com"; or
                "AWSServiceRoleFor" appears in the userIdentity or sessionIssuer
                arn. Otherwise interactive. No hardcoded principal-name list.
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
