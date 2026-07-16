# Contributing to sigwood

sigwood is a small, single-maintainer tool for hunting through your own logs. If
you've been running it and want to fix something, teach it a log format it doesn't
handle yet, or send along a pile of logs it should read better, this is the lay of
the land.

One very useful thing you can send even if you don't do Python is data.
The detectors are built against real logs, and a scrubbed sample of a format or
layout sigwood gets wrong (or doesn't support) does more for the next version
than almost any patch. You don't need to touch the code to help that way;
there's a section on it below.

The rest of this is a tour of how the pieces fit together, so if you do want to
change something, you know where it goes.

## The shape of the thing

There's one mental model, and most of the design falls out of it:

```
discover & parse  →  allowlist (suppress)  →  detect  →  render
```

Those stages don't reach across into each other. The **loader** finds files,
decompresses them, and normalizes every source to a canonical DataFrame. The
**allowlist** suppresses known-good traffic *before* analysis. **Detectors** are
pure analysis - they never open a file, read config, or suppress anything. **Output
handlers** only render. The **CLI** is the one place an error becomes an actionable
message, and the one place the process exits.

That separation is why a detector is a plain function you can call from a notebook,
why a new log format doesn't touch detector code, and why the tool stays honest
about what it is. Keep a change on the right side of those lines and most of the
review takes care of itself. The column contract between parsers and detectors is in
[docs/SCHEMA.md](docs/SCHEMA.md); the detectors and the reasoning behind their
methods are in [docs/FAQ.md](docs/FAQ.md).

The easiest change to take in is a fix that makes an existing thing more correct or
more honest - a detector that over-reports, a card that claims more than the data
supports, a discovery glob that misses a real-world layout. Pair it with a synthetic
regression test that pins the bug and there's very little left to discuss.

## Adding a detector

A detector is a module you drop into `sigwood/detectors/`. There's no registry
to edit and nothing to import anywhere - the framework scans the package at
startup and picks up any module that declares `DETECTOR_NAME` and `STATUS =
"available"`. Set `STATUS = "planned"` and it stays invisible until you're
ready; flip it the moment `run()` returns real findings. Some planned detectors
ship in this state.

The contract is a handful of module constants and one function:

```python
DETECTOR_NAME = "yours"
STATUS        = "available"
REQUIRED_LOGS = [{"source": "zeek_dir", "pattern": "conn*.log*"}]
OPTIONAL_LOGS: list[dict] = []
DEFAULT_CONFIG = {"threshold": 0.5, "min_connections": 20}

def run(context: DetectorContext) -> list[Finding]:
    ...
```

`source` is one of the four config dir keys (`zeek_dir`, `syslog_dir`, `pihole_dir`,
`cloudtrail_dir`); `pattern` is the glob the loader hands you files for. If a
required pattern turns up nothing, the detector is skipped with a note - never a
crash. `DEFAULT_CONFIG` is the *only* place your defaults live: the runner overlays
the user's `[detectors.yours]` config section on top and hands you the merged dict as
`context.config`. Don't restate defaults in `common/config.py` - `DEFAULT_CONFIG` is the single
source of truth, and a drift tripwire pins the shipped example config against it.

`run()` receives a `DetectorContext` - the loaded, already-filtered frames (keyed by
the glob **pattern** you declared, so you fetch with `context.logs.get("conn*.log*")`,
not the source key), your config section, the data window, and the operator's
`home_net`. It returns a list of `Finding`. Put the entity in the `title` and nothing
else - counts, columns, and classification go in the open `evidence` dict, and the
text handler assembles and aligns the display line. `description` and `next_steps`
are for the `-v` reader; leaving them empty is fine.

Two things a detector must *not* do, both straight from the separation above: it
never imports from `outputs/`, and it never opens a file, reads config off disk,
calls the allowlist to drop rows, or calls `sys.exit()`. The allowlist has already
run before you get the frame - suppression inside a detector is a bug. Raise an
ordinary exception if you need to; the runner catches it and the CLI owns the exit
code. The payoff for staying pure is that `run()` is callable straight from a
notebook with a hand-built context, which is how you'll want to develop it.

If your detector uses a real, named technique, say so with an optional
`DETECTOR_METHOD = MethodTag("FFT", named=True)`. Named published algorithms get the
parens and a glow on the run banner; honest house methods get
`MethodTag("heuristics", named=False)` and plain brackets. A heuristic labeled as a
heuristic is worth more than one dressed up as an algorithm. No constant at all just
prints the bare name.

The two-source detectors (`dns`, `syslog`) are the pattern for one question over two
feeds: leave `REQUIRED_LOGS` empty, list both sources in `OPTIONAL_LOGS`, set
`REQUIRES_ONE_OF_OPTIONAL = True`, and read both pattern keys inside `run()`,
concatenating whatever's non-empty. The detector stays source-blind - it reads only
the canonical columns both feeds share.

Tests go in `tests/test_<name>_detector.py`, built by hand: assemble a
`DetectorContext` around a synthetic frame and call `run()`. `tests/test_scan_detector.py`
is a good one to read for the fixture style.

> This is the map, not the full territory. For now the six existing detectors are the
> best guide - pick one and read it end to end.

## The notebooks

The detectors grew out of the notebooks in `notebooks/`. It's the exploration that
produced them - the FFT beacon scorer, the DNS clustering, drain3 syslog templating,
the CloudTrail dig - kept in the repo as runnable scripts and Jupyter notebooks. Some
run straight from the command line (`conn_fft.py` is the beacon prototype end to end);
`cloudflaws.ipynb` runs on the public flaws.cloud dataset, so you can pull it up and
run it yourself.

They aren't polished, and that's the point. They're the actual working-out, left in
because the method matters as much as the result - if you want to know why a detector
scores the way it does, the notebook that grew it is the most honest answer.

A notebook is also a good way to contribute. Prototyping a method against real logs -
showing where it fires and where it doesn't - is worth something on its own, well
before there's a detector wrapped around it, and it's the most natural place for a new
idea to start. If you've worked something out, a notebook in `notebooks/` is a real
contribution; polish not required.

## Adding a log format (big-tent ingestion)

sigwood reads a lot of on-disk variety - NDJSON and TSV, flat and date-partitioned
directories, rotation, `.gz`/`.bz2`/`.xz` - and the loader absorbs all of it so
detectors never have to. Teaching it a new *format within a family it already reads*
touches the loader, not the detectors.

The loader is one uniform pipeline (`run_load`) fed by a per-family strategy object
in a registry (`_SOURCE_LOADERS`, in `sigwood/common/loader/pipeline.py`). There's
no `can_parse()` sniffing, no base class, no `if source == …` chain. A strategy
declares only what actually varies for its family - how it discovers files, whether
it streams row-dicts or returns a whole frame, its timestamp policy, how it windows -
and inherits progress bars, coverage tracking, corruption handling, and accounting by
construction. So a new format is usually two things:

- a parser in `sigwood/parsers/` that turns the wire format into canonical columns,
  and
- for a new Zeek log type, an entry in `_NORMALIZER_MAP` plus a prefix in `_log_type`
  so the loader runs your normalizer.

That's it - the detector is unchanged; it declares the new pattern against the
*existing* source. (`_NORMALIZER_MAP` is Zeek's column-rename step specifically; a
non-Zeek family does its normalizing inside its own `_SOURCE_LOADERS` strategy, not
there.) A new syslog dialect is lighter still: flat syslog is content-sniffed, so a
dialect the RFC 3164 recognizer already accepts needs no wiring at all.

A genuinely **new source family** - a log origin that isn't Zeek, syslog, Pi-hole, or
CloudTrail - is a bigger piece of work. It threads through config, CLI routing, the
loader registry, the detector, and optionally a digest card and a sniff recognizer,
with a few drift tripwires keeping those in agreement. It's very doable, but it's
cross-cutting enough that it's worth opening an issue to talk through the shape before
building the whole thing.

## Send logs

One useful thing you can contribute is data, and you don't need to write any
code to do it. The detectors are built against real logs, so a well-sanitized corpus
- or even a clear description of a layout sigwood is getting wrong - moves things
further than you'd expect.

**CloudTrail from a real, busy AWS shop** is the one that would help most. The `aws`
detector learns per-principal behavior, and the variety in a live, multi-account,
many-role environment is exactly what's hard to synthesize. If you're sitting on that
kind of history and willing to scrub and share it, it's the kind of data the detector
can't get any other way.

Sanitize first, of course - strip or redact IPs, hostnames, account IDs, ARNs,
anything identifying - and keep the *shape* intact (timestamps, event names,
structure). If you're not sure how much to scrub, open an issue and we'll work
out a safe form together. If the data is sensitive enough that a public channel
is the wrong place, the contact in [SECURITY.md](SECURITY.md) works
for this too.

## A few things that hold throughout

- **No real network data. Anywhere.** Code, comments, configs, tests, fixtures,
  docstrings. Use [RFC 5737](https://datatracker.ietf.org/doc/html/rfc5737)
  documentation space (`192.0.2.x`, `198.51.100.x`, `203.0.113.x`) and obvious
  placeholders for everything else - account IDs, ARNs, hostnames, domains. Don't
  echo anything you saw in a real log while working here. This one is absolute.
- **Keep a change on its own side of the line.** Detection policy doesn't belong in a
  parser; rendering doesn't belong in a detector; suppression lives only in the
  allowlist. When you feel the urge to reach across, that's usually the design telling
  you where the change actually goes.
- **Honesty over cleverness.** A finding should be able to explain why it scored. A
  digest states facts, not verdicts. When the data can't support an answer, degrade
  visibly - no timeline you can't trust, no confident-but-wrong card.
- **Tests, synthetic and green.** New logic ships with tests built from RFC 5737
  fixtures; a new detector's tests call `assert_report_voice(findings)`, which pins
  the shape of your finding prose. Run the whole suite from the repo root and keep
  `main` runnable.
- **User-facing strings follow the house voice.** Errors carry the `sigwood:`
  prefix only at the CLI boundary; status and progress lines carry no prefix;
  finding titles are entities, not sentences. A voice tripwire test locks a lot
  of this so you don't have to memorize.
- **Fail with an actionable message.** `KeyError: 'id.orig_h'` is not something a user
  should ever see; `conn.log fields not found - is this a Zeek conn.log?` is.

## The mechanics

```bash
git clone https://github.com/helixmap/sigwood
cd sigwood
python3 -m venv .venv && source .venv/bin/activate
pip install -e '.[dev]'      # runtime extras + pytest
python -m pytest             # from the repo root
```

To exercise the archive boundary as well as the editable checkout, install the
packaging tools and run the same distribution check as CI:

```bash
python -m pip install build twine
python -m build
python -m twine check dist/*
python tools/validate_distribution.py dist
```

This catches missing package data, accidental test-suite leakage, malformed
metadata, and wheel/sdist version drift before a release checkout is involved.

`[dev]` deliberately leaves out `[pdf]` - WeasyPrint needs native libraries pip can't
install, so grab `.[dev,pdf]` plus your platform's Pango/HarfBuzz/fontconfig only if
you're working on PDF output. Requires Python 3.11+.

Fork, branch, keep the change small and self-contained, and open a PR against `main`.
For anything cross-cutting - a new source family, a schema change, a new dependency -
open an issue first so we can talk through the shape before you build. Security issues
go through [SECURITY.md](SECURITY.md), never a public issue.

sigwood is [MIT-licensed](LICENSE); contributions come in under the same license.

---

Thanks for reading this far. Questions, half-formed ideas, constructive
criticism, and bug reports are all welcome - open an issue and we'll take it
from there.
