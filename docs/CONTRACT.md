# What sigwood keeps stable

This page is for anyone scripting against sigwood: what you can rely on across every
1.x release, what is deliberately free to change, and where the machine-readable
surfaces are.

The README carries a short version of this promise. This is the same promise in full.

## The rule

Existing documented verb names, flag spellings and their value/no-value shape, format
tokens, and config key paths remain recognized throughout 1.x. A rename requires an
accepted alias and a deprecation path; new names may be added at any time. Defaults,
thresholds, calibration, and human-facing wording may change.

A documented key path staying *recognized* is separate from its *value* staying put.
`[detectors.beacon].threshold` will keep being read; what it defaults to may change.

Breaking any of the above means 2.0.

## Verbs

Sixteen, all of which stay recognized:

`hunt` · `auth` · `beacon` · `dns` · `dnsblock` · `syslog` · `scan` · `exfil` · `ssl` ·
`aws` · `digest` · `graph` · `export` · `init` · `allowlist` · `era`

`era` measures a complete dated Zeek archive. It accepts `[DIR]` as an archive-root
override (otherwise `[sigwood].zeek_dir`), and only `--help`, `--config`, `--out`,
`--format`, `--utc`, `--quiet`, `--yes`, `--verbose`, and `--dry-run`. Era does
not accept timeframe, detector, allowlist, or source-directory flags. `--format`
accepts `text` (the default), `html`, and `pdf`; all three present the same measured
cards, and an unaccepted value is refused before the archive is read. Era writes to
stdout unless `--out` is explicit, and never uses `report_dir`. A PDF to a terminal is
refused rather than written as binary.

## Flags

One value syntax everywhere: `--flag=value`, and `-f=value` for the short forms.
There is no space-separated form (`--out report.txt`), no attached short form
(`-oreport.txt`), and no boolean bundling (`-vy`).

Eleven flags carry a single-letter short: `-h` `-V` `-v` `-y` `-a` `-q` `-o` `-c`
`-s` `-d` `-f`. `-V` is the only capital and it is `--version`; `-v` is `--verbose`.

The full inventory, with whether each takes a value:

| Flag | Short | Takes a value |
|---|---|---|
| `--help` | `-h` | no |
| `--version` | `-V` | no |
| `--verbose` | `-v` | no |
| `--yes` | `-y` | no |
| `--all` | `-a` | no |
| `--quiet` | `-q` | no |
| `--dry-run` | | no |
| `--no-allowlist` | | no |
| `--utc` | | no |
| `--out` | `-o` | yes (`PATH`) |
| `--config` | `-c` | yes (`FILE`) |
| `--since` | `-s` | yes (`DURATION\|DATE`) |
| `--until` | | yes (`DATE`) |
| `--days` | | yes (`N-M`) |
| `--hours` | | yes (`N-M`) |
| `--detect` | `-d` | yes (`LIST`) |
| `--format` | `-f` | yes (`FORMAT`) |
| `--syslog-source` | | yes (`MODE`) |
| `--zeek-dir` | | yes (`PATH`) |
| `--pihole-dir` | | yes (`PATH`) |
| `--syslog-dir` | | yes (`PATH`) |
| `--cloudtrail-dir` | | yes (`PATH`) |

`--syslog-source` is accepted by `hunt`, `auth`, and `syslog`; among the
single-detector verbs, exactly `auth` and `syslog` own the local system-log lane.

If an ordinary single-valued flag is repeated, the last occurrence wins. `-vv` is the
exception: it is its own registered token rather than two `-v`s, and it selects the
fullest reading level whichever order you write it in: `-v -vv` and `-vv -v` both
behave as `-vv`.

## Output formats

Five tokens stay available and selectable: `text`, `json`, `csv`, `html`, `pdf`.

Two carry machine contracts: `json` and `csv`. The other three are for reading and
their layout may change. Parse the first two.

`pdf` is always a valid token, but *rendering* one additionally needs the optional
native stack (`pip install "sigwood[pdf]"` plus system Pango/HarfBuzz/fontconfig).
Without it the token is still accepted and you get an actionable message, not an
unknown-format error.

## Calling sigwood from Python

Every detector is importable and callable without the CLI:

```python
from sigwood import DetectorContext, Finding, Severity
from sigwood.detectors.beacon import run

context = DetectorContext.unsuppressed(
    logs={"conn*.log*": frame},
    data_window=(start, end),
)
findings: list[Finding] = run(context)
```

`DetectorContext.unsuppressed(logs, *, data_window, config=None, data_sources=(),
home_net=())` builds a context with **suppression off**. Your allowlist is not
applied, so results can be noisier than the same detector run through the CLI. The
name says so on purpose.

The nine callable detectors are `auth`, `aws`, `beacon`, `dns`, `dnsblock`, `exfil`,
`scan`, `ssl`, `syslog`; each exposes `run(context) -> list[Finding]`.

A `Finding` has eight public attributes: `detector`, `severity`, `title`,
`description`, `evidence`, `next_steps`, `ts_generated`, `data_window`.

`Severity` has four members: `HIGH` (`"H"`), `MEDIUM` (`"M"`), `LOW` (`"L"`),
`INFO` (`"I"`).

`import sigwood` stays light; importing the package does not pull pandas.

## The json feed

A single JSON object, not one object per line:

```json
{
  "sigwood_version": "1.0.0",
  "schema_version": 1,
  "run_summary": {
    "data_window": ["2026-08-01T00:00:00+00:00", "2026-08-01T06:00:00+00:00"],
    "record_counts": {"conn*.log*": 12345},
    "record_labels": {"conn*.log*": "connections"},
    "data_size_bytes": 480000,
    "detectors_run": ["beacon"],
    "detectors_skipped": {},
    "detectors_failed": {},
    "notes": [],
    "data_sources": ["zeek_conn"],
    "detector_methods": {"beacon": {"label": "FFT", "named": true}},
    "requested_span": 604800.0,
    "invocation": "sigwood hunt --format=json",
    "generated_at": "2026-08-01T06:00:01+00:00",
    "suppression": {
      "enabled": true,
      "connections": 0,
      "domains": 0,
      "connection_total": 12345,
      "domain_total": 0,
      "host_rows": 0,
      "host_total": 0,
      "hosts_matched": 0
    }
  },
  "findings": [
    {
      "detector": "beacon",
      "severity": "medium",
      "title": "192.0.2.10 \u2192 192.0.2.20:443/tcp",
      "description": "The strongest periodic component in these connections falls at 10.0m. The rhythm score combines that component's spectral share and prominence with the steadiness of the gaps between connections.",
      "next_steps": ["Check whether this destination is expected infrastructure"],
      "evidence": {"first_seen": "2026-08-01T00:03:00+00:00", "conn_count": 480},
      "ts_generated": "2026-08-01T06:00:01+00:00",
      "data_window": ["2026-08-01T00:00:00+00:00", "2026-08-01T06:00:00+00:00"]
    }
  ]
}
```

That is the complete shape: every run and every finding carries all of these keys.

**Note the case.** `severity` is written **lowercase** in json: `"high"`, `"medium"`,
`"low"`, `"info"`. The Python `Severity` members are uppercase.

### run_summary fields

All fourteen are always present. Five can be `null`:

| Field | Type | Nullable |
|---|---|---|
| `data_window` | two UTC ISO strings | **yes** |
| `record_counts` | object of string to integer | no |
| `record_labels` | object of string to string | no |
| `data_size_bytes` | integer | no |
| `detectors_run` | array of strings | no |
| `detectors_skipped` | object of string to string | no |
| `detectors_failed` | object of string to string | no |
| `notes` | array of strings | no |
| `data_sources` | array of strings | no |
| `detector_methods` | object of detector name to `{"label": string, "named": boolean}` | no; an individual detector's **value** can be `null` |
| `requested_span` | number, seconds | **yes** |
| `suppression` | object of eight fields: `enabled` (boolean) plus `connections`, `domains`, `connection_total`, `domain_total`, `host_rows`, `host_total`, `hosts_matched` (integers) | **yes** |
| `invocation` | string | **yes** |
| `generated_at` | UTC ISO string | **yes** |

Both nested shapes are part of the contract: `detector_methods` values are either
`null` or carry exactly `label` and `named`, and a non-null `suppression` carries all
eight fields. Tests pin both.

`detector_methods` is the one to read carefully: the object itself is always there,
but an individual detector's entry may be `null`.

### finding fields

All eight are always present:

| Field | Type |
|---|---|
| `detector` | string |
| `severity` | lowercase string: `high`, `medium`, `low`, `info` |
| `title` | string |
| `description` | string |
| `next_steps` | array of strings |
| `evidence` | object |
| `ts_generated` | UTC ISO string |
| `data_window` | two UTC ISO strings |

- `schema_version` is currently **1** and bumps only on a breaking change.
- Existing envelope and field names, and their types, do not break within 1.x.
- `run_summary` carries fourteen fields, listed with their types and null arms in
  the table below. Read the nullable ones defensively.
- **Tolerate new fields.** New keys appear in `run_summary`, in `evidence`, and in
  findings without a schema bump. A consumer that rejects unknown keys will break on
  an ordinary release; that is the consumer's bug, not a contract violation.
- Timestamps in `json` are ISO-8601 **UTC**, always, regardless of display settings.
- Diagnostics and report prose are not parsing contracts even inside a
  machine-readable container. `notes` is a list of human sentences. Read it; do not
  pattern-match it.

### Which evidence keys are promised

`evidence` is an open dictionary and most of what it carries is detector-specific
detail that may change as detectors improve. **The keys promised stable are the ones
this page names**: the event-time keys in the table below. Anything else in
`evidence` is informational: useful, but not a contract, and it may be renamed or
dropped without a schema bump.

We would rather promise a small set and keep it than promise everything and quietly
break it.

### Exfil measured evidence

When an `exfil` finding contains `orig_bytes_total`, `resp_bytes_total`,
`orig_share`, or `connection_count`, those values describe only connection rows
where both byte counts were finite and non-negative. They are not a claim about
unmeasured rows for the same pair. The finding description states this once for
people; JSON carries the values in `evidence`, and CSV renders them in `signals`.

## The csv worklist

A remediation checklist, not a lossless export; `json` is the lossless one. One row
per finding, and a fixed ten-column header in this order:

`severity` · `detector` · `finding` · `next_steps` · `description` · `signals` ·
`data_window_start` · `data_window_end` · `status` · `notes`

`status` and `notes` are seeded empty for you to fill. csv is never capped and never
varies with `-v`/`-vv`. Its timestamps are ISO-8601 carrying the display timezone's
offset.

Control characters other than newline (the C0 range, DEL, and C1) are removed from
every cell before it is written. An embedded newline is deliberately kept, so a
multi-line `next_steps` cell stays intact as a quoted field. A cell whose remaining
first character is `=`, `+`, `-`, or `@` is then prefixed with a single quote so a
spreadsheet does not execute it.

## Config

The file is `~/.sigwood/config.toml` (or `/etc/sigwood/config.toml`, or whatever
`--config=` names). These paths stay recognized. New keys may be added; the ones
listed here do not disappear.

- **`[sigwood]`:** `root`, `detect`, `zeek_dir`, `syslog_dir`, `syslog_source`,
  `pihole_dir`, `cloudtrail_dir`, `home_net`, `export_dir`, `report_dir`,
  `output_format`, `warn_above`, `default_window`, `quiet`, `use_utc`,
  `max_findings_per_detector`
- **`[detectors.<name>]`** for each of the nine detectors. The documented tuning keys
  stay recognized; their default values may change. Seven of the nine expose keys;
  `auth` and `dnsblock` expose none, and a section for either is read and ignored.
  - `aws`: `min_events`, `min_scorable_principals`, `burst_gap_seconds`,
    `burst_window_edge_margin_seconds`, `burst_min_firsts`, `burst_high_error_rate`,
    `burst_high_service_count`, `composite_medium_threshold`,
    `composite_low_threshold`. Two of these are accepted for compatibility but no
    longer change behavior: `burst_high_service_count` and
    `burst_window_edge_margin_seconds` (service spread never escalates a burst's
    severity; the error-rate gate is the one escalation).
  - `beacon`: `min_connections`, `threshold`
  - `dns`: `min_cluster_size`, `min_samples`, `threshold`, `thresh_high_entropy`,
    `scan_dense_clusters`, `scan_min_high_entropy_fraction`,
    `scan_min_cluster_members`, `scan_min_regdomain_share`,
    `scan_max_members_per_cluster`, `promote_below_gate`, `promote_min_subdomains`,
    `promote_min_nxdomain_fraction`, and the nested
    **`[detectors.dns.pihole]`** (`min_cluster_size`, `min_samples`)
  - `auth`: no public tuning keys
  - `dnsblock`: no public tuning keys
  - `exfil`: `min_outbound_bytes`, `min_orig_share`
  - `ssl`: `min_connections`
  - `scan`: `window_secs`, `horizontal_threshold`, `vertical_threshold`,
    `block_host_threshold`, `block_port_threshold`, `block_state_min`,
    `slow_min_ports`, `slow_min_buckets`, `slow_state_min`
  - `syslog`: `rarity_pct`, `max_count`, `depth`, `sim_thresh`,
    `parametrize_numeric`, `line_trim_limit`, `burst_gap_seconds`, `burst_min_size`,
    `family_min_size`, `reboot_cluster_seconds`, `recognize_transactions`,
    `privileged_programs`
- **`[allowlist]`:** `enabled`, `allowlist_dir`, `domain_patterns`,
  `connection_rules`
- **`[allowlist.lists]`:** a boolean per shipped list. The documented names
  `common`, `devices`, `homelab` stay recognized; new lists may be added.
- **`[[allowlist.entry]]`:** `match`, `comment`, `detectors` stay recognized, and so
  do the two behaviour-bearing `match` kinds and the keys each one reads:
  - `match = "ip_pair"` reads `src`, `dst`, and optionally `dst_port`
  - `match = "dst_port"` reads `value`

  Any *other* key in a stanza is carried as open metadata and is not promised.
- **`[graph]`:** `target_bins`, `top_hosts`, `top_services`, `domain_level`
- **`[export.splunk]`:** `host`, `port`, `username`, `password`, `verify_tls`,
  `export_dir`
- **`[export.cloudtrail]`:** `path`, `egress_warn_gb`, `export_dir`
- **`[export.splunk.query.<name>]`:** the query *name* is yours and is not a
  contract; its leaves are: `spl`, `output_basename`, `export_dir`. (CloudTrail has
  no query table; it synthesises a single implicit query.)

An unknown top-level section is reported on stderr and ignored; the run continues on
defaults.

## Exit codes

- **0:** the run completed. Includes a run that found nothing, and a run where you
  declined the large-dataset confirmation (declining is a choice, not a failure).
- **1:** a failure: bad configuration, an unreadable source, or a detector that
  crashed. A report may still have been written; the code is what tells you the
  night was not clean.
- **130:** interrupted (Ctrl-C).
- **141:** a downstream reader closed the pipe, as in `sigwood hunt | head`.

If you schedule sigwood, branch on the exit code, not on whether output appeared.

## When a finding happened

Every finding carries the run's data window. Most also carry their own event time,
but the key name depends on the finding type, so a timeline script needs to know
which to read:

| Finding type | Key | Notes |
|---|---|---|
| beacon | `first_seen` | also `last_seen`, `span_seconds`, `cycles` |
| dns groups and singletons | `first_seen` | also `last_seen`, `span_seconds` |
| exfil | `first_seen` | also `last_seen`, `span_seconds` |
| ssl | `first_seen` | also `last_seen`, `span_seconds` |
| syslog families, bursts, single rare lines, transactions | `first_seen` | |
| syslog reboots | `reboot_ts` | the reboot instant (a different meaning, kept deliberately) |
| aws bursts | `start_time` | ISO-8601 with offset |
| scan | `window_start` | UTC, but written **without** a timezone offset |
| aws ranked summary | *(none)* | a summary of a whole scan, with no single entity |
| dns scan summary | *(none)* | same |

The two summary findings carry no event time by design: they describe a scan rather
than an entity, so there is nothing to timestamp.

## What is not stable

Deliberately outside the contract, and expected to move:

- which findings a given log produces; thresholds move when measurement says so
- severity calibration and scoring internals
- evidence keys this page does not name
- the wording of any human-facing message, including `notes` and `next_steps`
- the layout of `text`, `html`, and `pdf`
- the internals of the `graph` artifact

A tool that promised its findings would never change would be promising to stop
learning.
