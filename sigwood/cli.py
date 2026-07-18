"""CLI dispatcher - argument parsing, subcommand routing, and first-run experience.

Entry point: sigwood.cli:main (registered in pyproject.toml).

Dispatch table:
  sigwood hunt [options] [PATH ...]  run the default hunt
  sigwood PATH ...                   shorthand - point it at one or more log files
  sigwood beacon|dns|syslog|...      run a single detector
  sigwood digest [PATH ...]          orient-before-the-hunt card (sniff-driven)
  sigwood graph [PATH ...]           replay-oriented conn/DNS/Pi-hole graph artifact
  sigwood export                     pull logs from external systems
  sigwood init                       first-run setup wizard

Parsing is a small declarative spec (``_FLAG_LIST`` + ``_VERBS``) plus a
per-token loop (``_parse_args``). The spec governs allowed-flag membership,
validation, and generated per-command help. ``blob_path`` is NOT a flag -
it is an INTERNAL routing key synthesized post-sniff and MUST NOT enter
the spec.
"""

from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from sigwood import __version__
from sigwood.common import config as cfg
from sigwood.common.display import (
    compact_home,
    plural,
    set_display_utc,
    to_display_timezone,
)
from sigwood.common.errors import (
    DigestEmpty,
    ExportAborted,
    GraphEmpty,
    GraphSourceUnreadable,
    UsageError,
)
from sigwood.common.output import get_handler
from sigwood.common.paths import be_like_water, effective_root, resolve_path, unique_path
from sigwood.common.sanitize import strip_control
from sigwood.common.syslog_mode import (
    SyslogMode,
    SyslogModeError,
    parse_syslog_mode,
)


# ── flag/verb spec ────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class FlagSpec:
    """One advertised CLI flag.

    ``key`` is the underscore canonical key used by ``parsed[...]``, config,
    and runner kwargs - never the hyphenated display spelling.
    """
    key: str
    long: str
    short: str | None
    takes_value: bool
    metavar: str
    help: str


# Ordered list - also the display order for generated per-command help.
_FLAG_LIST: tuple[FlagSpec, ...] = (
    FlagSpec("help",             "--help",             "h",  False, "",
             "show this help and exit"),
    FlagSpec("version",          "--version",          "V",  False, "",
             "show version and exit"),
    FlagSpec("verbose",          "--verbose",          "v",  False, "",
             "verbose output (extended evidence and next-steps; -vv for full raw debug detail)"),
    FlagSpec("yes",              "--yes",              "y",  False, "",
             "assume yes to advisory prompts (large-dataset, egress)"),
    FlagSpec("all",              "--all",              "a",  False, "",
             "load all available data; overrides default window"),
    FlagSpec("quiet",            "--quiet",            "q",  False, "",
             "suppress progress and status output"),
    FlagSpec("out",              "--out",              "o",  True,  "PATH",
             "single per-run output target (file or dir; trailing / = dir)"),
    FlagSpec("config",           "--config",           "c",  True,  "FILE",
             "path to a config file (overrides search-path lookup)"),
    FlagSpec("since",            "--since",            "s",  True,  "DURATION|DATE",
             "window start (7d, 24h, or ISO date)"),
    FlagSpec("detect",           "--detect",           "d",  True,  "LIST",
             "detector selection (default, all, comma list, or 'all,!x,!y')"),
    FlagSpec("dry_run",          "--dry-run",          None, False, "",
             "show the plan without running detectors / writing output"),
    FlagSpec("no_allowlist",     "--no-allowlist",     None, False, "",
             "disable all allowlist suppression for this run"),
    FlagSpec("format",           "--format",           "f",  True,  "FORMAT",
             "output format (text, json, csv, html, pdf)"),
    FlagSpec("until",            "--until",            None, True,  "DATE",
             "window end (ISO date)"),
    FlagSpec("days",             "--days",             None, True,  "N-M",
             "days-ago range (e.g. 1-7); order-insensitive"),
    FlagSpec("hours",            "--hours",            None, True,  "N-M",
             "hours-ago range (e.g. 0-2); order-insensitive"),
    FlagSpec("utc",              "--utc",              None, False, "",
             "display times in UTC; naive --since/--until and --days read as UTC"),
    FlagSpec("zeek_dir",         "--zeek-dir",         None, True,  "PATH",
             "Zeek log directory (overrides config)"),
    FlagSpec("pihole_dir",       "--pihole-dir",       None, True,  "PATH",
             "Pi-hole / dnsmasq log directory (overrides config)"),
    FlagSpec("syslog_dir",       "--syslog-dir",       None, True,  "PATH",
             "file-backed syslog path; selects files for this run"),
    FlagSpec("syslog_source",    "--syslog-source",    None, True,  "MODE",
             "system-log input: auto, journal, files, or off"),
    FlagSpec("cloudtrail_dir",   "--cloudtrail-dir",   None, True,  "PATH",
             "CloudTrail JSON directory (overrides config)"),
)

_FLAGS_BY_KEY: dict[str, FlagSpec] = {f.key: f for f in _FLAG_LIST}
_FLAGS_BY_LONG: dict[str, FlagSpec] = {f.long: f for f in _FLAG_LIST}
_FLAGS_BY_SHORT: dict[str, FlagSpec] = {f.short: f for f in _FLAG_LIST if f.short}


@dataclass(frozen=True)
class VerbSpec:
    """One verb in the dispatcher.

    ``name == "hunt"`` is the default no-verb hunt route (the implicit path/flag
    route reuses it). ``allowed`` is the set
    of canonical flag keys (not long spellings) - short flags are aliases for
    their canonical key, so a short flag is allowed iff its canonical key is
    in ``allowed``.
    """
    name: str
    summary: str
    positional_shape: str
    allowed: frozenset[str]


_ANALYZE_ALLOWED: frozenset[str] = frozenset({
    "help", "verbose", "yes", "all", "quiet", "out", "config", "since", "detect",
    "dry_run", "no_allowlist", "format", "until", "days", "hours", "utc",
    "zeek_dir", "pihole_dir", "syslog_dir", "syslog_source", "cloudtrail_dir",
})
_SINGLE_DET_ALLOWED: frozenset[str] = _ANALYZE_ALLOWED - {
    "detect", "syslog_source",
}
_SYSLOG_ALLOWED: frozenset[str] = _SINGLE_DET_ALLOWED | {"syslog_source"}
_DIGEST_ALLOWED: frozenset[str] = frozenset({
    "help", "verbose", "yes", "all", "quiet", "out", "config", "since",
    "dry_run", "format", "until", "days", "hours", "utc", "zeek_dir",
})
_GRAPH_ALLOWED: frozenset[str] = frozenset({
    "help", "yes", "all", "quiet", "out", "config", "since", "dry_run",
    "until", "days", "hours", "utc", "zeek_dir", "pihole_dir",
})
_EXPORT_ALLOWED: frozenset[str] = frozenset({
    "help", "verbose", "yes", "out", "config", "since", "until", "days", "hours",
    "utc",
})
_INIT_ALLOWED: frozenset[str] = frozenset({"help"})
_ALLOWLIST_ALLOWED: frozenset[str] = frozenset({"help", "config"})


_VERBS: dict[str, VerbSpec] = {
    "hunt":     VerbSpec("hunt",     "run the default hunt",
                         "[PATH ...]", _ANALYZE_ALLOWED),
    "beacon":   VerbSpec("beacon",   "beacon detection (conn.log)",
                         "[PATH]", _SINGLE_DET_ALLOWED),
    "dns":      VerbSpec("dns",      "DNS clustering (Zeek or Pi-hole)",
                         "[PATH]", _SINGLE_DET_ALLOWED),
    "syslog":   VerbSpec("syslog",   "syslog anomaly detection",
                         "[PATH]", _SYSLOG_ALLOWED),
    "scan":     VerbSpec("scan",     "port scan detection (conn.log)",
                         "[PATH]", _SINGLE_DET_ALLOWED),
    "duration": VerbSpec("duration", "long connection detection (conn.log)",
                         "[PATH]", _SINGLE_DET_ALLOWED),
    "aws":      VerbSpec("aws",      "CloudTrail behavioral surfacing (per-principal)",
                         "[PATH]", _SINGLE_DET_ALLOWED),
    "digest":   VerbSpec("digest",   "orient-before-the-hunt card (schema sniffed)",
                         "[PATH ...]", _DIGEST_ALLOWED),
    "graph":    VerbSpec("graph",    "replay-oriented conn/DNS/Pi-hole HTML graph artifact",
                         "[PATH ...]", _GRAPH_ALLOWED),
    "export":   VerbSpec("export",   "pull logs from external systems to local files",
                         "[BACKEND] [QUERY ...]", _EXPORT_ALLOWED),
    "init":     VerbSpec("init",     "first-run setup wizard",
                         "", _INIT_ALLOWED),
    "allowlist": VerbSpec("allowlist", "inspect & manage suppression lists",
                         "[show|enable|disable|copy] [NAME]", _ALLOWLIST_ALLOWED),
}


_SINGLE_DETECTOR_COMMANDS: frozenset[str] = frozenset({
    "beacon", "dns", "syslog", "scan", "duration", "aws",
})

# User-initiated stop (Ctrl-C during compute). Named so the future error-voice
# pass can find the message and exit code together. 130 is the Unix 128 + SIGINT
# convention. Ctrl-C AT THE CONFIRM PROMPTS (runner.py) is a separate path that
# routes through ExportAborted → exit 0; this is the mid-run sibling.
_STOPPED_MESSAGE = "Stopped."
_SIGINT_EXIT_CODE = 130
_SIGPIPE_EXIT_CODE = 141


def main(argv: list[str] | None = None) -> None:
    """Parse arguments and dispatch to the appropriate subcommand or runner."""
    try:
        rc = _main(argv) or 0
    except KeyboardInterrupt:
        # Most terminals echo Ctrl-C as "^C" with no trailing newline before
        # Python sees the signal. Without a leading blank line on TTY stderr,
        # our message lands as "^CStopped." on one row. Non-TTY stderr stays
        # byte-exact at "Stopped.\n" so log capture / scripts are unaffected.
        if sys.stderr.isatty():
            print(file=sys.stderr)
        print(_STOPPED_MESSAGE, file=sys.stderr)
        sys.exit(_SIGINT_EXIT_CODE)
    except EOFError:
        # Closed stdin at a prompt is not a signal - a separate arm from
        # KeyboardInterrupt (130 is 128+SIGINT; no signal occurred here).
        # Backstop for any prompt without a local EOF guard: never a raw
        # traceback at the boundary.
        print("sigwood: unexpected end of input", file=sys.stderr)
        sys.exit(1)
    except ExportAborted as exc:
        print(strip_control(exc))
        sys.exit(0)
    except cfg.ConfigError as exc:
        print(f"sigwood: {strip_control(exc)}", file=sys.stderr)
        sys.exit(1)
    except UsageError as exc:
        # Argument / flag / form errors - the ONE place the usage pointer is
        # appended. UsageError subclasses ValueError, so this arm must precede
        # the plain-ValueError arm below.
        print(f"sigwood: {strip_control(exc)}", file=sys.stderr)
        print("run 'sigwood --help' for usage", file=sys.stderr)
        sys.exit(1)
    except ValueError as exc:
        print(f"sigwood: {strip_control(exc)}", file=sys.stderr)
        sys.exit(1)
    except BrokenPipeError:
        # A downstream reader (`sigwood ... | head`) closed the pipe. Redirect
        # any remaining stdout to devnull so the interpreter's shutdown flush
        # cannot raise a second BrokenPipeError (a traceback + exit 120), then
        # exit quietly - a closed pipe is not an error worth narrating.
        try:
            devnull = os.open(os.devnull, os.O_WRONLY)
            os.dup2(devnull, sys.stdout.fileno())
        except OSError:
            pass
        sys.exit(_SIGPIPE_EXIT_CODE)
    except OSError as exc:
        print(f"sigwood: {strip_control(exc)}", file=sys.stderr)
        sys.exit(1)
    if rc:
        sys.exit(rc)


def _main(argv: list[str] | None = None) -> int:
    """Internal CLI dispatcher. Exceptions are formatted by main().

    Returns an int exit code. Hunt returns runner-owned status; digest keeps
    its three-way fan-out policy. Every other branch returns 0.
    """
    args = argv if argv is not None else sys.argv[1:]

    if not args or args == ["--help"] or args == ["-h"]:
        _print_global_usage()
        return 0

    if args[0] in ("--version", "-V"):
        print(f"sigwood {__version__}")
        return 0

    cand = args[0]

    require_target = False
    leading_flag = False
    if cand in _SINGLE_DETECTOR_COMMANDS:
        verb = cand
        rest = args[1:]
    elif cand == "hunt":
        verb = "hunt"               # explicit verb - never requires a target
        rest = args[1:]
    elif cand in ("digest", "graph", "init", "export", "allowlist"):
        verb = cand
        rest = args[1:]
    elif cand.startswith("-") or _looks_like_path(cand):
        verb = "hunt"               # implicit (a leading path or flag) - intent must be a path
        rest = args
        require_target = True
        # A leading FLAG (not a leading path) is the one entry where a later
        # verb-named token signals flags-before-verb confusion - see
        # _leading_flag_verb_hint.
        leading_flag = cand.startswith("-")
    else:
        print(f"sigwood: unknown command '{strip_control(cand)}'", file=sys.stderr)
        print("run 'sigwood --help' for usage", file=sys.stderr)
        sys.exit(1)

    # Side-effect-light help short-circuit - STANDALONE --help / -h ONLY.
    # `--help=anything` and `-h=anything` are NOT help; they fall through to
    # the strict parser and produce "takes no value". This fires BEFORE
    # config load, output resolution, sniff dispatch, or wizard entry.
    if any(tok == "--help" or tok == "-h" for tok in rest):
        print(_render_verb_help(verb), end="")
        return 0

    if verb in _SINGLE_DETECTOR_COMMANDS:
        return _run_single_detector(verb, rest) or 0
    elif verb == "digest":
        return _run_digest(rest) or 0
    elif verb == "graph":
        return _run_graph(rest) or 0
    elif verb == "init":
        _run_init(rest)
    elif verb == "export":
        _run_export(rest)
    elif verb == "allowlist":
        _run_allowlist(rest)
    elif verb == "hunt":
        return _run_hunt(
            rest, require_target=require_target, leading_flag=leading_flag,
        ) or 0
    return 0


def _looks_like_path(s: str) -> bool:
    """Return True if the string looks like a filesystem path rather than a subcommand.

    Verbs are matched first in ``_main`` so verb names always win; this only
    decides whether a non-verb token routes to the analyze path or fails as
    an unknown command. The ``os.path.exists`` clause catches bare filenames
    in CWD (``sigwood conn.log``) that the prefix tests would miss; the
    extension clause catches a MISTYPED one (``sigwood nope.log``) so it
    reports ``<path>: not found`` rather than ``unknown command`` - a verb never
    carries a file extension.
    """
    if s.startswith("/") or s.startswith("~") or s.startswith("."):
        return True
    if "/" in s:
        return True
    if os.path.splitext(s)[1]:  # a filename-shaped token (nope.log, dump.json)
        return True
    try:
        if os.path.exists(s):
            return True
    except (OSError, ValueError):
        pass
    return False


# ── usage / help generation ───────────────────────────────────────────────────


def _global_usage_text(no_config: bool = False) -> str:
    """Compose the bare-sigwood / --help screen from the spec.

    When ``no_config`` is set, a one-line "run init" hint is inserted directly
    after the banner (above Usage) - the bare-invocation first-run nudge.
    """
    lines = [
        "sigwood - network threat hunting for self-hosters",
        "",
    ]
    if no_config:
        lines += [
            "No config found. Run 'sigwood init' to create one, or point sigwood at a log file.",
            "",
        ]
    lines += [
        "Usage:",
        "  sigwood hunt [options] [PATH ...]   run the default hunt",
        "  sigwood PATH ...                    shorthand - point it at one or more log files",
        "",
        "  sigwood beacon [options] PATH    beacon detection (conn.log)",
        "  sigwood dns [options] PATH       DNS clustering (Zeek or Pi-hole)",
        "  sigwood syslog [options] PATH    syslog anomaly detection",
        "  sigwood scan [options] PATH      port scan detection (conn.log)",
        "  sigwood duration [options] PATH  long connection detection (conn.log)",
        "  sigwood aws [options] PATH       CloudTrail behavioral surfacing (per-principal)",
        "",
        "  sigwood digest [options] PATH    orient-before-the-hunt card; schema is",
        "                                   inferred from the file (conn, dns, syslog,",
        "                                   cloudtrail, or blob for unrecognized text)",
        "  sigwood graph [options] [PATH ...] replay-oriented conn/DNS/Pi-hole HTML artifact",
        "",
        "  sigwood export                   pull logs from external systems",
        "  sigwood init                     first-run setup wizard",
        "  sigwood allowlist                inspect & manage suppression lists",
        "",
        "Common options (short forms shown for the frequently-typed flags):",
        "  --help, -h         --version, -V      --verbose, -v      --yes, -y",
        "  --all, -a          --quiet, -q        --out, -o=PATH     --config, -c=FILE",
        "  --since, -s=…      --detect, -d=LIST",
        "",
        "Less common: --dry-run --format, -f=FORMAT --until=DATE",
        "             --days=N-M --hours=N-M --utc",
        "             --zeek-dir=PATH --syslog-dir=PATH --pihole-dir=PATH --cloudtrail-dir=PATH",
        "",
        "Run 'sigwood <command> --help' for command-specific options.",
        "",
    ]
    return "\n".join(lines)


def _print_global_usage() -> None:
    """Print the first-run usage message; a no-config hint follows the banner."""
    print(_global_usage_text(no_config=cfg._find_config_file() is None), end="")


# Compatibility alias - internal helper kept under its historical name for
# tests/observers that import it directly.
_print_usage = _print_global_usage


def _render_verb_help(verb: str) -> str:
    """Render per-command help from the spec - drives `<verb> --help` / `-h`."""
    vs = _VERBS[verb]
    cmd = "sigwood" + (f" {verb}" if verb else "")
    shape = f" {vs.positional_shape}" if vs.positional_shape else ""
    lines = [f"Usage: {cmd} [options]{shape}".rstrip(), "", vs.summary, "", "Options:"]
    # Preserve display order from _FLAG_LIST so output is stable.
    for spec in _FLAG_LIST:
        if spec.key not in vs.allowed:
            continue
        if spec.short:
            head = f"  {spec.long}, -{spec.short}"
        else:
            head = f"  {spec.long}"
        if spec.takes_value:
            head += f"={spec.metavar}"
        lines.append(f"{head:<32} {spec.help}".rstrip())
    return "\n".join(lines) + "\n"


# ── parser ────────────────────────────────────────────────────────────────────


def _parse_args(args: list[str], verb: str) -> dict[str, Any]:
    """Parse CLI tokens for ``verb`` into a kwargs dict.

    Validation order is BINDING: identity → verb-membership → value-shape. A
    globally-known but verb-disallowed flag yields the wrong-verb error
    regardless of value shape (``digest -d`` and ``digest --detect`` both
    report "not valid for digest", NOT "needs a value").

    Duplicate flags are last-wins (preserving the original dict-overwrite
    behavior). Single-valued - never promoted to a list.

    Positionals: ``parsed["path"]`` = first; ``parsed["paths"]`` = full list.
    """
    if verb not in _VERBS:
        raise ValueError(f"unknown verb {verb!r}")
    allowed = _VERBS[verb].allowed
    verb_label = verb if verb else "analyze"

    def _wrong_verb_long(spec: FlagSpec) -> str:
        alias = f" (-{spec.short})" if spec.short else ""
        return f"{spec.long}{alias} is not valid for {verb_label}"

    def _wrong_verb_short(spec: FlagSpec) -> str:
        # Short was typed; lead with the short, alias is the long.
        return f"-{spec.short} ({spec.long}) is not valid for {verb_label}"

    def _needs_value(spec: FlagSpec) -> str:
        alias = f" (-{spec.short})" if spec.short else ""
        short_hint = f"-{spec.short}=… or " if spec.short else ""
        return f"{spec.long}{alias} needs a value: {short_hint}{spec.long}=…"

    def _no_value(spec: FlagSpec) -> str:
        alias = f" (-{spec.short})" if spec.short else ""
        return f"{spec.long}{alias} takes no value"

    result: dict[str, Any] = {}
    positionals: list[str] = []

    for arg in args:
        # `-vv` is a SINGLE explicitly-registered literal token - the one-off
        # spelling for verbose-level 2. Recognized BEFORE the normal short-flag
        # branch so the bundling-refusal lattice ("can't be combined") never
        # catches it. Anything longer (-vvv, -vy) falls through to the bundling
        # path and gets the existing pass-separately message. Wrong-verb parity:
        # `sigwood init -vv` raises the same wrong-verb error as
        # `sigwood init -v`, never "unknown flag" / "needs a value".
        if arg == "-vv":
            v_spec = _FLAGS_BY_SHORT.get("v")
            if v_spec is None or v_spec.key not in allowed:
                raise UsageError(_wrong_verb_short(v_spec))
            result["verbose_level"] = 2
            continue
        if arg.startswith("--"):
            body, eq, val = arg[2:].partition("=")
            long_form = f"--{body}"
            spec = _FLAGS_BY_LONG.get(long_form)
            if spec is None:
                raise UsageError(f"unknown flag --{body}")
            if spec.key not in allowed:
                raise UsageError(_wrong_verb_long(spec))
            if eq:
                if not spec.takes_value:
                    raise UsageError(_no_value(spec))
                result[spec.key] = val
            else:
                if spec.takes_value:
                    raise UsageError(_needs_value(spec))
                result[spec.key] = True
        elif arg.startswith("-") and arg != "-":
            stripped = arg[1:]
            body, eq, val = stripped.partition("=")
            if len(body) == 1:
                short = body
                spec = _FLAGS_BY_SHORT.get(short)
                if spec is None:
                    raise UsageError(f"unknown flag -{short}")
                if spec.key not in allowed:
                    raise UsageError(_wrong_verb_short(spec))
                if eq:
                    if not spec.takes_value:
                        raise UsageError(_no_value(spec))
                    result[spec.key] = val
                else:
                    if spec.takes_value:
                        raise UsageError(_needs_value(spec))
                    result[spec.key] = True
            elif len(body) > 1:
                # Bundling attempt - deliberately declined. Surface kindly when
                # every char is a known short; otherwise plain unknown-flag.
                if all(ch in _FLAGS_BY_SHORT for ch in body):
                    separated = " ".join(f"-{ch}" for ch in body)
                    raise UsageError(
                        f"short flags can't be combined (-{body}); "
                        f"pass separately: {separated}"
                    )
                raise UsageError(f"unknown flag -{body}")
            else:
                raise UsageError(f"unknown flag {arg}")
        else:
            positionals.append(arg)

    if positionals:
        result["path"] = positionals[0]
        result["paths"] = positionals

    return result


# ── shared resolution helpers ─────────────────────────────────────────────────


def _assert_all_vs_timeframe(parsed: dict[str, Any]) -> None:
    """``--all`` is mutually exclusive with explicit timeframe flags."""
    if parsed.get("all") and any(k in parsed for k in ("since", "until", "days", "hours")):
        raise UsageError(
            "--all cannot be combined with --since, --until, --days, or --hours"
        )


def _resolve_output_target(
    parsed: dict[str, Any], config: dict[str, Any],
) -> tuple[Path | None, Path | None]:
    """Resolve the ``--out`` / ``[sigwood].report_dir`` ladder.

    Returns ``(output_file, output_dir)`` - exactly one of which is non-None
    when a target is set; both ``None`` means stdout.
    """
    cfg_sigwood = config.get("sigwood", {})
    root = effective_root(config)
    cli_out = parsed.get("out") if "out" in parsed else None
    if cli_out:
        if cli_out == "-":
            # Unix stdout idiom - force stdout, bypassing report_dir.
            return None, None
        target = resolve_path(cli_out, "")
    else:
        target = resolve_path(cfg_sigwood.get("report_dir"), root)

    if target is None:
        return None, None
    resolved = be_like_water(target)
    if resolved.is_file:
        return resolved.path, None
    return None, resolved.path


# Digest filename sanitization: strip a trailing compression ext, take the part
# before the first dot, keep only [A-Za-z0-9_-]. conn.log → conn,
# pihole.log.3.gz → pihole, messages → messages.
_COMPRESSION_EXTS = (".gz", ".bz2", ".xz")


def _digest_token(first_positional: str | Path) -> str | None:
    """Auto-name token from the FIRST digest positional's basename, sanitized.
    Empty result → None (token omitted)."""
    name = Path(first_positional).name
    for ext in _COMPRESSION_EXTS:
        if name.endswith(ext):
            name = name[: -len(ext)]
            break
    name = re.sub(r"[^A-Za-z0-9_-]", "", name.split(".", 1)[0])
    return name or None


def _digest_basename(token: str | None) -> str:
    """Auto-named digest basename ``sigwood-digest_<token>_<YYYYMMDD>.txt``.

    The date renders in the display timezone - the same zone the digest's own
    timestamps use. ``_run_digest`` sets the display switch before any output
    naming, so the date is correct under ``--utc`` / ``use_utc``.
    """
    date = to_display_timezone(datetime.now(timezone.utc)).strftime("%Y%m%d")
    stem = f"sigwood-digest_{token}_{date}" if token else f"sigwood-digest_{date}"
    return f"{stem}.txt"


def _resolve_digest_output_target(
    parsed: dict[str, Any],
) -> tuple[Path | None, Path | None]:
    """Digest's ``--out``-only output resolver. NEVER reads config / report_dir.

    Returns ``(output_file, output_dir)`` where ``output_dir`` is ALWAYS None: a
    DIRECTORY verdict is COMPOSED into an exact ``sigwood-digest`` file here, so digest
    never hands an ``output_dir`` downstream (``_report_filename`` is never reached
    for digest). ``-o=-`` / no
    ``--out`` → ``(None, None)`` (stdout). An explicit FILE verdict → ``(file,
    None)`` EXACT. Bare digest and fan-out both receive an exact file ONLY when
    ``--out`` was explicit."""
    cli_out = parsed.get("out") if "out" in parsed else None
    if not cli_out or cli_out == "-":
        return None, None
    resolved = be_like_water(resolve_path(cli_out, ""))
    if resolved.is_file:
        return resolved.path, None
    paths = parsed.get("paths") or []
    token = _digest_token(paths[0]) if paths else None
    return unique_path(resolved.path, _digest_basename(token)), None


def _graph_basename(kind: str) -> str:
    """Return a display-timezone dated auto-name for one graph artifact."""
    date = to_display_timezone(datetime.now(timezone.utc)).strftime("%Y%m%d")
    return f"sigwood-graph_{kind}_{date}.html"


def _resolve_graph_output_target(
    parsed: dict[str, Any], config: dict[str, Any], kind: str,
) -> Path | None:
    """Resolve graph's ``--out > report_dir > CWD`` artifact ladder.

    Graph intentionally differs from digest: it participates in the configured
    ``report_dir`` policy, then falls back to an auto-named artifact in CWD.
    An explicit file verdict remains exact; a directory verdict receives a
    collision-free kind/date name. ``--out=-`` is the sole stdout sentinel.
    """
    cfg_sigwood = config.get("sigwood", {})
    cli_out = parsed.get("out") if "out" in parsed else None
    if cli_out:
        if cli_out == "-":
            return None
        target = resolve_path(cli_out, "")
    else:
        target = resolve_path(cfg_sigwood.get("report_dir"), effective_root(config))
        if target is None:
            target = "."

    resolved = be_like_water(target)
    if resolved.is_file:
        return resolved.path
    return unique_path(resolved.path, _graph_basename(kind))


def _resolve_timeframe(
    parsed: dict[str, Any],
    now: datetime | None = None,
    *,
    use_utc: bool = False,
) -> tuple[datetime | None, datetime | None]:
    """Convert --since/--until/--days/--hours into a (since, until) datetime pair.

    Wall-clock math (the --days midnight/end-of-day snapping and naive absolute
    dates) happens in the DISPLAY timezone - local, or UTC when ``use_utc`` is
    set. ``now`` is normalized into that timezone first, so the result is
    independent of the representation the caller passed. Relative forms (7d,
    24h, --hours) are pure deltas off the current instant. RETURN CONTRACT:
    every non-None value is an aware UTC datetime - the knob affects the math,
    never the returned representation.
    """
    if now is None:
        now = datetime.now(timezone.utc)
    now = now.astimezone(timezone.utc) if use_utc else now.astimezone()
    since: datetime | None = None
    until: datetime | None = None

    if "days" in parsed:
        a, b = _parse_range(str(parsed["days"]), "--days")
        since = (now - timedelta(days=b)).replace(hour=0, minute=0, second=0, microsecond=0)
        until = (now - timedelta(days=a)).replace(hour=23, minute=59, second=59, microsecond=0)
        return since.astimezone(timezone.utc), until.astimezone(timezone.utc)

    if "hours" in parsed:
        a, b = _parse_range(str(parsed["hours"]), "--hours")
        since = now - timedelta(hours=b)
        until = now - timedelta(hours=a)
        return since.astimezone(timezone.utc), until.astimezone(timezone.utc)

    if "since" in parsed:
        s = str(parsed["since"])
        if s.endswith("d"):
            since = now - timedelta(days=_parse_positive_int(s[:-1], "--since"))
        elif s.endswith("h"):
            since = now - timedelta(hours=_parse_positive_int(s[:-1], "--since"))
        else:
            since = _parse_iso_date(s, "--since", use_utc=use_utc)

    if "until" in parsed:
        until = _parse_iso_date(str(parsed["until"]), "--until", use_utc=use_utc)

    return (
        since.astimezone(timezone.utc) if since is not None else None,
        until.astimezone(timezone.utc) if until is not None else None,
    )


def _parse_range(value: str, flag: str) -> tuple[int, int]:
    """Parse N-M range arguments for --days and --hours."""
    parts = value.split("-")
    if len(parts) != 2:
        raise UsageError(f"{flag} expects a range like 3-5")
    try:
        start, end = sorted(int(part) for part in parts)
    except ValueError as exc:
        raise UsageError(f"{flag} expects numeric values like 3-5") from exc
    return start, end


def _parse_positive_int(value: str, flag: str) -> int:
    """Parse a positive integer embedded in a duration flag."""
    try:
        parsed = int(value)
    except ValueError as exc:
        raise UsageError(f"{flag} expects a duration like 7d or 24h") from exc
    if parsed < 0:
        raise UsageError(f"{flag} duration must be positive")
    return parsed


def _parse_iso_date(value: str, flag: str, *, use_utc: bool = False) -> datetime:
    """Parse an ISO date/time for CLI timeframe flags.

    An explicit offset in the value is honored; a naive value is interpreted
    in the display timezone (local, or UTC under --utc / use_utc). Returns an
    aware UTC datetime.
    """
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise UsageError(f"{flag} expects a date like 2026-05-01") from exc
    if parsed.tzinfo is not None:
        return parsed.astimezone(timezone.utc)
    if use_utc:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


# ── runner-kwargs builders ────────────────────────────────────────────────────


def _resolve_verbose_level(parsed: dict[str, Any]) -> int:
    """Collapse the parser's two-key verbose state into a single 0/1/2 dial.

    ``-vv`` is registered as the literal token ``verbose_level=2`` (see
    ``_parse_args``); ``-v`` / ``--verbose`` set ``verbose=True``. Their
    last-wins resolution lands here:
        none → 0; -v → 1; -vv → 2; combined → 2.
    Only the text handler distinguishes all three levels; every other
    consumer collapses to ``>= 1`` (export internals, csv/html description
    gate, digest summariser-failure breadcrumb).
    """
    if parsed.get("verbose_level") == 2:
        return 2
    return 1 if parsed.get("verbose") else 0


_ANALYZE_SOURCE_KEYS: tuple[str, ...] = (
    "zeek_dir", "syslog_dir", "pihole_dir", "cloudtrail_dir",
)


def _merge_family_value(
    bucket: list[str], flag_value: str | None,
) -> str | list[str] | None:
    """Combine a positional-derived bucket with the explicit ``--<family>-dir``
    flag value, returning the runner-kwarg shape for that family.

    MERGE rule: positionals routed to the family + the flag value BOTH
    contribute, both load. Order is positionals first, flag appended;
    dedup is the loader's job (via ``.resolve()``).

    Wire-shape compression for the runner kwarg:

    - empty + no flag → ``None`` (no override; config fallback within scope)
    - exactly one truthy value → scalar (string) - keeps programmatic
      scalar-caller shape byte-identical with the prior single-Path contract
    - 2+ values → ``list[str]`` - the multi-input shape

    All three shapes flow through ``runner.run`` → ``resolve_sources`` →
    ``_normalize_overrides``, which collapses to the same downstream
    ``list[Path]`` regardless. Raw strings only - the CLI does NOT
    ``Path(...)`` or ``resolve_path`` source values; ``_resolve_one`` is
    the SOLE string→Path site.
    """
    merged: list[str] = [b for b in bucket if b]
    if flag_value:
        merged.append(flag_value)
    if not merged:
        return None
    if len(merged) == 1:
        return merged[0]
    return merged


def _build_positional_buckets(
    paths: list[str], *, detector_module: Any | None,
) -> dict[str, list[str]]:
    """Sniff-classify each positional into its source-family bucket.

    Returns ``{family_key: [positional, …]}`` for the families touched.
    ``detector_module=None`` triggers the router's content-sniff mode
    (detect=all / unknown selector). Empty input → empty dict.

    A DIRECTORY positional whose bounded sample holds more than one log family
    is routed to the winning family only - the losing families' files are not
    loaded as their own kind, so that outcome is disclosed on stderr per
    directory (a status line, not an error; the run proceeds).
    """
    from sigwood.common.sources import route_positional_source

    buckets: dict[str, list[str]] = {}
    mixed_votes: dict[str, dict[str, int]] = {}
    for p in paths:
        routed = route_positional_source(
            p, detector_module=detector_module, _vote_sink=mixed_votes,
        )
        buckets.setdefault(routed, []).append(p)
        if p_tally := mixed_votes.pop(str(Path(p).expanduser()), None):
            tally = ", ".join(f"{origin} {n}" for origin, n in p_tally.items())
            family = routed.removesuffix("_dir")
            print(
                f"{strip_control(str(p))}: mixed log types sampled ({tally}) - "
                f"hunting it as {family}; pass the other files directly to "
                f"include them",
                file=sys.stderr,
            )
    return buckets


def _cli_syslog_mode(parsed: dict[str, Any]) -> SyslogMode | None:
    """Validate the optional system-log enum at the CLI usage boundary."""
    if "syslog_source" not in parsed:
        return None
    try:
        return parse_syslog_mode(parsed["syslog_source"])
    except SyslogModeError as exc:
        raise UsageError(str(exc)) from exc


def _runner_kwargs(
    parsed: dict[str, Any],
    config: dict[str, Any],
    detect: str | None = None,
    scope: frozenset[str] | None = None,
    source_buckets: dict[str, list[str]] | None = None,
    detector_selection: Any | None = None,
) -> dict[str, Any]:
    """Build the kwargs dict for runner.run() from parsed CLI args and loaded config.

    Source-dir overrides flow through as raw parsed strings, per-family lists,
    or ``None``. The CLI does NOT call ``resolve_path`` or ``Path(...)`` for
    source dirs - ``sigwood.common.sources._resolve_one`` is the SOLE site
    where a source-dir string becomes a resolved ``Path``. The runner threads
    the raw values into ``resolve_sources``, which normalizes scalar/list/None
    uniformly.

    ``source_buckets`` carries the per-positional sniff classification
    (``{family_key: [positional_path, …]}``). For each family the bucket is
    MERGED with the explicit ``--<family>-dir`` flag (positionals first, flag
    appended): a same-family flag + positional BOTH load - the flag adds to
    the positional rather than replacing it.

    ``scope`` is the SOLE scoping signal: ``None`` = unconstrained,
    ``frozenset(touched_families)`` = scope the run so sibling source-dirs
    stay unloaded. The caller computes ``scope`` from the bucket keys; a
    positional ALWAYS scopes. An explicit override outside ``scope`` still
    applies - the operator widening the run deliberately.
    """
    _assert_all_vs_timeframe(parsed)

    cfg_sigwood = config.get("sigwood", {})
    # CLI --utc wins; else [sigwood].use_utc (default false). Resolved ONCE
    # per verb path; timeframe parsing takes the explicit bool, never the
    # display switch. run() sets the switch at entry - the first display-policy
    # consumer on this path (dry-run banner, report auto-naming) is runner-side.
    use_utc = bool(parsed.get("utc")) or bool(cfg_sigwood.get("use_utc", False))
    since, until = _resolve_timeframe(parsed, use_utc=use_utc)

    buckets = source_buckets or {}
    family_values: dict[str, str | list[str] | None] = {
        key: _merge_family_value(buckets.get(key, []), parsed.get(key))
        for key in _ANALYZE_SOURCE_KEYS
    }
    mode = _cli_syslog_mode(parsed)
    if (
        mode in (SyslogMode.JOURNAL, SyslogMode.OFF)
        and family_values["syslog_dir"]
    ):
        raise UsageError(
            f"--syslog-source={mode.value} cannot be combined with a syslog "
            "PATH or --syslog-dir"
        )

    output_file, output_dir = _resolve_output_target(parsed, config)

    output_format = parsed.get("format", cfg_sigwood.get("output_format", "text"))
    # pdf fail-fast, BEFORE runner.run → before any log is read. Ordering matters:
    # refuse a no-target pdf to a TERMINAL first (binary safety), so a missing
    # WeasyPrint/Pango stack never masks the terminal-safety error (or -o=-+tty).
    # THEN preflight the stack for the targets that WILL render pdf (file / dir /
    # pipe, incl. config-derived output_format="pdf"). Base preflight() is a no-op.
    # SKIP entirely on --dry-run: run() short-circuits before building any handler
    # and renders NO pdf, so `-f pdf --dry-run` must print the plan, not error.
    if not parsed.get("dry_run"):
        if (
            output_format == "pdf"
            and output_file is None
            and output_dir is None
            and sys.stdout.isatty()
        ):
            from sigwood.outputs.pdf import PDF_TTY_ERROR
            raise ValueError(PDF_TTY_ERROR)
        get_handler(output_format).preflight()

    kwargs = dict(
        config=config,
        detect=detect or parsed.get("detect"),
        # Source-dir overrides: raw strings / lists / None - resolver owns Path conversion.
        zeek_dir=family_values["zeek_dir"],
        syslog_dir=family_values["syslog_dir"],
        pihole_dir=family_values["pihole_dir"],
        cloudtrail_dir=family_values["cloudtrail_dir"],
        scope=scope,
        since=since,
        until=until,
        output_format=output_format,
        output_dir=output_dir,
        output_file=output_file,
        verbose_level=_resolve_verbose_level(parsed),
        dry_run=bool(parsed.get("dry_run", False)),
        no_allowlist=bool(parsed.get("no_allowlist", False)),
        load_all=bool(parsed.get("all", False)),
        skip_confirm=bool(parsed.get("yes", False)),
        # CLI -q wins; else [sigwood].quiet (default false). No un-quiet flag.
        quiet=bool(parsed.get("quiet")) or bool(cfg_sigwood.get("quiet", False)),
        use_utc=use_utc,
    )
    if "syslog_source" in parsed:
        kwargs["syslog_source"] = parsed["syslog_source"]
    if detector_selection is not None:
        kwargs["_detector_selection"] = detector_selection
    return kwargs


# ── verb runners ──────────────────────────────────────────────────────────────


def _named_detector_module(detect: Any) -> Any:
    """Return the imported detector module for an exactly-one-detector selector.

    Returns ``None`` for selection keywords, comma lists, exclusion syntax,
    missing selectors, and unimportable names. Imports ONLY the explicitly named
    module via ``importlib`` - never iterates ``detectors/``. Used by the
    two analyze entry points to feed ``route_positional_source`` with the
    detector's REQUIRED_LOGS / OPTIONAL_LOGS metadata.
    """
    if not isinstance(detect, str):
        return None
    name = detect.strip()
    if not name or name.lower() in {"all", "default"} or "," in name or "!" in name:
        return None
    try:
        import importlib
        return importlib.import_module(f"sigwood.detectors.{name}")
    except ImportError:
        return None


def _require_positionals_exist(paths: list[str]) -> None:
    """Fail fast on an explicit positional PATH that does not exist.

    Plain ValueError (NOT UsageError): the boundary renders
    ``sigwood: <path>: not found`` with NO --help pointer - it is an
    operational error, not an argument error. Mirrors the digest fan-out's
    existence check; a path may be a file OR a directory (``.exists()`` covers
    both). ``~`` is expanded at the CLI seam (CLI provenance), as digest does.
    Without this, a nonexistent positional silently defaults to ``zeek_dir`` in
    sniff-routing and the operator sees the misleading source-discovery cascade.
    """
    for raw in paths:
        p = Path(os.path.expanduser(raw))
        if not p.exists():
            raise ValueError(f"{p}: not found")


def _leading_flag_verb_hint(paths: list[str], args: list[str]) -> None:
    """Raise UsageError when a leading-flag implicit hunt's FIRST missing
    positional exactly names a command (``sigwood --config=x hunt``).

    Flags-before-verb confusion: the leading flag routes to the implicit hunt
    and the verb token parses as a positional log path, so the plain not-found
    would misdirect. The suggestion is the operator's own tokens reordered -
    ``sigwood <verb> <remaining args in original order>``. Existence is
    tested exactly as ``_require_positionals_exist`` tests it (expanduser +
    ``Path.exists``), so a REAL file named like a command never triggers the
    hint; a missing non-verb token returns so the plain not-found owner raises
    on the same token it does today. ``_require_positionals_exist`` stays the
    sole plain not-found owner - this helper only preempts the one verb-named
    case.
    """
    for raw in paths:
        if Path(os.path.expanduser(raw)).exists():
            continue
        if raw in _VERBS:
            rest = list(args)
            rest.remove(raw)
            suggestion = " ".join(["sigwood", raw, *rest])
            raise UsageError(
                f"'{raw}' is a command - flags go after the verb: {suggestion}"
            )
        return


def _load_config(parsed: dict[str, Any]) -> dict[str, Any]:
    """Load config for a verb and disclose any top-level section nothing reads.

    An unrecognized section is not an error - the run proceeds on defaults - but it
    is never silent: a stale or mistyped name would otherwise void every setting
    under it with no diagnostic. Section names come from the user's file and a TOML
    quoted key can carry terminal control bytes, so they are stripped at this emit
    seam. Not quiet-gated: a warning is not progress narration.
    """
    config = cfg.load(parsed.get("config"))
    unknown = cfg.unknown_sections(config)
    if unknown:
        names = ", ".join(f"[{strip_control(name)}]" for name in unknown)
        noun = plural(len(unknown), "section")
        print(f"config: ignoring unknown {noun} {names}", file=sys.stderr)
    return config


def _run_hunt(args: list[str], *, require_target: bool = False,
              leading_flag: bool = False) -> int:
    """Parse args and invoke the runner for the default hunt.

    ``require_target`` rides only the IMPLICIT routes (a leading path or flag):
    a clean parse that carries no positional then fails as a no-intent
    ``UsageError`` - a lone flag is set dressing, never sufficient intent. The
    explicit ``hunt`` verb passes ``require_target=False`` and runs against the
    config nest even with no PATH. The guard sits immediately after the parse,
    BEFORE output-format validation / config load / path existence / sniffing,
    so ``sigwood --format=bogus`` reports "nothing to hunt", not "unknown
    output format" (intent failure dominates). Parser errors still win - they
    raise inside ``_parse_args`` above.

    ``leading_flag`` rides only the leading-FLAG implicit entry and arms the
    flags-before-verb hint (``_leading_flag_verb_hint``); the explicit ``hunt``
    verb and leading-PATH entries keep the default False.

    Each positional in ``parsed["paths"]`` is sniff-classified into its source
    family bucket via ``route_positional_source`` (detector_module=None for
    detect=all / unknown selector → content-sniff → ``{origin}_dir``,
    defaulting to ``zeek_dir`` on directory / unrecognized / OSError). The
    per-family bucket then MERGES with any explicit ``--<family>-dir`` flag
    inside ``_runner_kwargs``. ``scope = frozenset(touched_families)`` keeps
    sibling source-dirs suppressed.
    """
    import sigwood.runner as runner

    parsed = _parse_args(args, "hunt")
    syslog_mode = _cli_syslog_mode(parsed)

    if (
        require_target
        and not parsed.get("paths")
        and "syslog_source" not in parsed
    ):
        raise UsageError("nothing to hunt - run 'sigwood hunt' or pass a log file")

    if "format" in parsed:
        get_handler(parsed["format"])

    config = _load_config(parsed)

    selection = None
    if syslog_mode is not None:
        selection_spec = (
            parsed["detect"]
            if "detect" in parsed
            else config.get("sigwood", {}).get(
                "detect", cfg.DEFAULT_DETECT_SPEC
            )
        )
        selection = runner.select_detectors(
            selection_spec
        )
        if syslog_mode is not SyslogMode.OFF and "syslog" not in selection.selected:
            raise UsageError(
                f"--syslog-source={syslog_mode.value} requires the syslog detector "
                "in the final selection"
            )

    paths = parsed.get("paths") or []
    if leading_flag:
        _leading_flag_verb_hint(paths, args)
    _require_positionals_exist(paths)
    if paths:
        mod = _named_detector_module(parsed.get("detect"))
        buckets = _build_positional_buckets(paths, detector_module=mod)
        scope: frozenset[str] | None = frozenset(buckets) if buckets else None
    else:
        buckets = {}
        scope = None

    return runner.run(**_runner_kwargs(
        parsed, config, scope=scope, source_buckets=buckets,
        detector_selection=selection,
    ))


def _run_single_detector(detector: str, args: list[str]) -> int:
    """Parse args and invoke runner constrained to a single detector.

    Each positional in ``parsed["paths"]`` is sniff-classified into its source
    family bucket using the named detector module's REQUIRED_LOGS /
    OPTIONAL_LOGS metadata (via ``route_positional_source(detector_module=mod)``).
    The per-family bucket then MERGES with any explicit ``--<family>-dir`` flag
    inside ``_runner_kwargs``. ``scope = frozenset(touched_families)`` keeps
    sibling source-dirs suppressed.
    """
    import sigwood.runner as runner

    parsed = _parse_args(args, detector)
    syslog_mode = _cli_syslog_mode(parsed)

    if "format" in parsed:
        get_handler(parsed["format"])

    config = _load_config(parsed)

    selection = (
        runner.select_detectors(detector)
        if syslog_mode is not None
        else None
    )

    paths = parsed.get("paths") or []
    _require_positionals_exist(paths)
    if paths:
        mod = _named_detector_module(detector)
        buckets = _build_positional_buckets(paths, detector_module=mod)
        scope: frozenset[str] | None = frozenset(buckets) if buckets else None
    else:
        buckets = {}
        scope = None

    return runner.run(**_runner_kwargs(
        parsed, config, detect=detector, scope=scope, source_buckets=buckets,
        detector_selection=selection,
    ))


_SOURCE_DIR_KEYS = (
    "zeek_dir", "pihole_dir", "syslog_dir", "cloudtrail_dir", "blob_path",
)


def _route_sniffed_path(
    parsed: dict[str, Any],
    path: Path,
    result: Any,
) -> tuple[dict[str, Any], str]:
    """Build a per-path parsed-dict variant routing a sniffed PATH into the
    right source-dir kwarg. Clears prior-iteration source-dir keys so a stale
    value never leaks between paths in a fan-out loop."""
    parsed_for_path = {
        k: v for k, v in parsed.items() if k not in _SOURCE_DIR_KEYS
    }
    schema = result.schema
    path_str = str(path)
    if schema == "conn":
        parsed_for_path["zeek_dir"] = path_str
    elif schema == "dns":
        if result.origin == "pihole":
            parsed_for_path["pihole_dir"] = path_str
        else:
            parsed_for_path["zeek_dir"] = path_str
    elif schema == "syslog":
        # syslog is fidelity-aware: Zeek syslog.log → zeek_dir; flat
        # rsyslog → syslog_dir. Mirrors the dns origin-split above.
        if result.origin == "zeek":
            parsed_for_path["zeek_dir"] = path_str
        else:
            parsed_for_path["syslog_dir"] = path_str
    elif schema == "cloudtrail":
        parsed_for_path["cloudtrail_dir"] = path_str
    else:  # schema == "blob"
        # blob_path is INTERNAL - synthesized post-sniff. It is NOT a flag
        # and must NEVER appear in _FLAGS / _VERBS / help.
        parsed_for_path["blob_path"] = path_str
    return parsed_for_path, schema


def _run_graph(args: list[str]) -> int:
    """Sniff/fan out graphable inputs and write one artifact per kind bucket.

    Graph's CLI owns the public surface that is intentionally absent from the
    runner: positional sniffing, same-kind fan-out, report target selection,
    dry-run, and the final exit ledger across independently attempted buckets.
    Graph accepts conn, Zeek DNS, and Pi-hole inputs; other structured logs are
    not silently routed to digest or an unrelated graph.
    """
    import sigwood.runner as runner
    from sigwood.common.sources import probe_graph_inputs
    from sigwood.graph._core import validate_config

    parsed = _parse_args(args, "graph")
    _assert_all_vs_timeframe(parsed)

    paths = parsed.get("paths") or []
    if paths:
        for source_key in ("zeek_dir", "pihole_dir"):
            if source_key in parsed:
                raise UsageError(
                    f"--{source_key.replace('_', '-')} is not valid alongside "
                    "a positional PATH (positionals self-route via sniff)"
                )

    config = _load_config(parsed)
    cfg.validate_table_sections(config, ("sigwood", "graph"))
    # Validate once at the CLI seam even for --dry-run. run_graph repeats this
    # at its public/programmatic boundary rather than trusting this caller.
    validate_config(config.get("graph", {}))
    use_utc = bool(parsed.get("utc")) or bool(
        config.get("sigwood", {}).get("use_utc", False)
    )
    set_display_utc(use_utc)
    quiet = bool(parsed.get("quiet")) or bool(
        config.get("sigwood", {}).get("quiet", False)
    )
    since, until = _resolve_timeframe(parsed, use_utc=use_utc)

    raw_inputs: list[str] | None
    source_overrides = {
        source_key: str(parsed[source_key])
        for source_key in ("zeek_dir", "pihole_dir")
        if parsed.get(source_key)
    }
    if paths:
        raw_inputs = paths
    else:
        raw_inputs = None

    probe = probe_graph_inputs(
        config,
        raw_inputs,
        source_overrides=source_overrides or None,
    )
    buckets = probe.buckets
    input_errors = input_permissions = 0
    for issue in probe.issues:
        line = f"{strip_control(issue.path)}: {strip_control(issue.message)}"
        if issue.permission:
            print(f"sigwood: {line}", file=sys.stderr)
            input_permissions += 1
        elif issue.message.startswith("can't graph"):
            print(line, file=sys.stderr)
            input_errors += 1
        else:
            print(f"sigwood: {line}", file=sys.stderr)
            input_errors += 1
    if not buckets:
        print("sigwood: nothing to graph", file=sys.stderr)
        return 1

    targets = {
        kind: _resolve_graph_output_target(parsed, config, kind)
        for kind in buckets
    }
    if len(buckets) > 1:
        paths_or_stdout = list(targets.values())
        if any(target is None for target in paths_or_stdout):
            raise UsageError(
                "graph produced multiple kinds - stdout accepts one artifact; "
                "choose a directory target"
            )
        if len({str(target) for target in paths_or_stdout}) != len(paths_or_stdout):
            raise UsageError(
                "graph produced multiple kinds - choose a directory target "
                "instead of one exact output file"
            )

    if not quiet:
        for path, kinds in probe.multi_kinds.items():
            names = ", ".join(kinds)
            print(
                f"{strip_control(path)}: graphing discovered kinds separately ({names})",
                file=sys.stderr,
            )
        for path, tally in probe.mixed_votes.items():
            sampled = ", ".join(
                f"{origin} {count}" for origin, count in tally.items()
            )
            graph_kinds = ", ".join(
                kind for kind, inputs in buckets.items()
                if any(str(source) == path for source in inputs)
            )
            print(
                f"{strip_control(path)}: mixed log types sampled ({sampled}) - "
                f"graphing {graph_kinds}; non-graphable files skipped; try "
                "'sigwood digest PATH'",
                file=sys.stderr,
            )

    if parsed.get("dry_run"):
        print("sigwood  ·  graph  ·  dry run")
        for kind, inputs in buckets.items():
            source = ", ".join(strip_control(str(path)) for path in inputs)
            target = targets[kind]
            destination = "stdout" if target is None else str(compact_home(target))
            print(f"  {kind}: {source} -> {strip_control(destination)}")
        return 1 if input_permissions else 0

    rendered = clean_empty = 0
    ordinary_errors = input_errors
    permission_errors = input_permissions
    for kind, inputs in buckets.items():
        target = targets[kind]
        # A bucket produced from bare configuration must remain a config
        # fallback at the runner boundary.  Passing its resolved file here
        # would falsely turn it into a sniff-approved positional input and
        # bypass the loader's filename discovery gate.
        runner_inputs = inputs if raw_inputs is not None or source_overrides else None
        try:
            written = runner.run_graph(
                config,
                kind=kind,
                inputs=runner_inputs,
                since=since,
                until=until,
                output_file=target,
                stream=sys.stdout if target is None else None,
                load_all=bool(parsed.get("all", False)),
                skip_confirm=bool(parsed.get("yes", False)),
                quiet=quiet,
                use_utc=use_utc,
            )
        except GraphSourceUnreadable as exc:
            print(f"sigwood: {strip_control(exc)}", file=sys.stderr)
            permission_errors += 1
            continue
        except GraphEmpty as exc:
            print(f"sigwood: {strip_control(exc)} - skipping", file=sys.stderr)
            clean_empty += 1
            continue
        except (ValueError, OSError, OverflowError) as exc:
            print(f"sigwood: {kind}: {strip_control(exc)}", file=sys.stderr)
            ordinary_errors += 1
            continue

        rendered += 1
        if written is not None and not quiet:
            print(
                f"wrote graph to {strip_control(compact_home(written))}",
                file=sys.stderr,
            )

    # Permission denial is the lone failure that outranks a sibling artifact.
    # Ordinary malformed-source failures remain per-bucket and an artifact from
    # another bucket is an honest successful graph result. All clean-empty
    # recognized buckets are a no-op success; every other no-artifact case is
    # an actionable failure.
    if permission_errors:
        return 1
    if rendered:
        return 0
    if clean_empty and not ordinary_errors:
        return 0
    print("sigwood: nothing to graph", file=sys.stderr)
    return 1


def _run_digest(args: list[str]) -> int:
    """Parse args and dispatch to runner.run_digest, supporting N positionals."""
    import sigwood.runner as runner
    from sigwood.common.loader import (
        _permission_denied_message,
        sniff_format_detailed,
    )

    parsed = _parse_args(args, "digest")

    # Output validation: registry-first (uniform error voice), then digest's
    # text-only rail. The spec ALLOWS --format for digest but digest renders
    # text cards only.
    out_fmt = parsed.get("format", "text")
    get_handler(out_fmt)
    if out_fmt != "text":
        raise UsageError(
            f"digest currently supports only --format=text (got {out_fmt!r})"
        )

    # Positional + source-dir combination guard. The spec allows --zeek-dir
    # for BARE digest (no positional, single conn card from a configured
    # source dir). With a positional present, the positional self-routes via
    # sniff and source-dir flags would be silently overridden - reject the
    # combination up-front so the operator sees the conflict.
    if parsed.get("paths"):
        for flag in ("zeek_dir", "pihole_dir", "syslog_dir", "cloudtrail_dir"):
            if flag in parsed:
                raise UsageError(
                    f"--{flag.replace('_', '-')} is not valid alongside "
                    "a positional PATH (positionals self-route via sniff)"
                )

    config = _load_config(parsed)

    # CLI --utc wins; else [sigwood].use_utc. Resolved ONCE for this verb
    # path and threaded as an explicit bool. The display switch is set HERE -
    # digest names its output file CLI-side (_resolve_digest_output_target →
    # _digest_basename, on both the bare-config and fan-out routes below), so
    # a switch set only at run_digest entry would stamp the wrong date.
    use_utc = bool(parsed.get("utc")) or bool(
        config.get("sigwood", {}).get("use_utc", False)
    )
    set_display_utc(use_utc)

    # -q dial for the runner-owned narration below (CLI wins; else config).
    quiet = bool(parsed.get("quiet")) or bool(
        config.get("sigwood", {}).get("quiet", False)
    )

    paths_raw = parsed.get("paths") or []

    if not paths_raw:
        # No positional: config-driven path. Bare digest, single conn card.
        # Output target is resolved by _digest_runner_kwargs via the out-only
        # resolver (never report_dir); a DIR verdict is already composed into an
        # exact output_file there.
        kwargs = _digest_runner_kwargs(parsed, config, schema="conn", use_utc=use_utc)
        try:
            runner.run_digest(**kwargs)
        except DigestEmpty as exc:
            # Recognized-but-empty (e.g. header-only conn.log in the
            # configured directory). The file was understood - narrate
            # without a card and exit 0.
            print(
                f"sigwood: {strip_control(exc.basename)}: recognized as {exc.schema}, "
                "no parseable records - skipping",
                file=sys.stderr,
            )
            return 0
        # Report the written file ONLY after a clean run_digest return - DigestEmpty
        # raises before the file opens, so no false claim. stdout / -o=- runs
        # (output_file None) and --dry-run report nothing.
        out_file = kwargs.get("output_file")
        if out_file is not None and not parsed.get("dry_run") and not quiet:
            print(f"wrote digest to {strip_control(compact_home(out_file))}", file=sys.stderr)
        return 0

    # Fan-out path. Resolve the shared output target ONCE - never per path.
    is_dry_run = bool(parsed.get("dry_run", False))
    get_stream, close_stream, dest_path = _build_digest_fanout_stream(
        parsed, dry_run=is_dry_run,
    )

    is_multirun = len(paths_raw) > 1

    rendered = empty = recognized_empty = errored = permission_errored = 0
    try:
        for raw in paths_raw:
            path = Path(os.path.expanduser(raw))
            if not path.exists():
                print(f"sigwood: {strip_control(path)}: not found", file=sys.stderr)
                errored += 1
                continue
            if path.is_dir():
                # Multi-path fan-out: skip a directory positional with a
                # status note (a shell glob catching subdirectories is
                # routine - not an error, but never a silent omission).
                # The lone-positional case keeps the v1 contract - whole-
                # directory positionals are rejected with an actionable
                # stderr message and exit 1.
                if len(paths_raw) == 1:
                    print(
                        f"sigwood: {strip_control(path)}: is a directory - digest takes a file",
                        file=sys.stderr,
                    )
                    errored += 1
                else:
                    print(
                        f"skipping directory {strip_control(path)} - digest reads files",
                        file=sys.stderr,
                    )
                continue
            try:
                result = sniff_format_detailed(path)
                if result.state == "empty":
                    print(f"{strip_control(path.name)} is empty - nothing to do")
                    empty += 1
                    continue
                parsed_for_path, schema = _route_sniffed_path(
                    parsed, path, result,
                )
                kwargs = _digest_runner_kwargs(
                    parsed_for_path, config, schema=schema,
                    resolve_output=False, use_utc=use_utc,
                )
                if schema != "blob":
                    kwargs["fallback_blob_path"] = path
                runner.run_digest(
                    **kwargs,
                    stream=get_stream(),
                    leading_separator=(rendered > 0),
                    show_progress=not is_multirun,
                )
            except DigestEmpty as exc:
                print(
                    f"sigwood: {strip_control(exc.basename)}: recognized as {exc.schema}, "
                    "no parseable records - skipping",
                    file=sys.stderr,
                )
                recognized_empty += 1
                continue
            except PermissionError:
                print(
                    f"sigwood: {strip_control(_permission_denied_message(path))}",
                    file=sys.stderr,
                )
                permission_errored += 1
                errored += 1
                continue
            except (ValueError, OSError) as exc:
                print(f"sigwood: {strip_control(path.name)}: {strip_control(exc)}", file=sys.stderr)
                errored += 1
                continue
            rendered += 1
    finally:
        close_stream()

    # Report the written file ONLY after a card rendered AND the stream closed
    # cleanly. dest_path is None for stdout / dry-run; -q suppresses the line.
    if rendered > 0 and dest_path is not None and not quiet:
        print(f"wrote digest to {strip_control(compact_home(dest_path))}", file=sys.stderr)

    if permission_errored > 0:
        return 1
    if rendered > 0:
        return 0
    if errored == 0:
        return 0
    return 1


def _build_digest_fanout_stream(
    parsed: dict[str, Any],
    dry_run: bool = False,
) -> tuple[Any, Any, Path | None]:
    """Resolve the shared digest --out target into a lazy (get, close, dest) triple.

    Digest is fully OFF report_dir / ``_resolve_output_target`` - output is
    resolved by ``_resolve_digest_output_target`` (parsed-only). A DIRECTORY
    verdict was already composed into an exact file there, so this opens exactly
    that file or stays on stdout.

    Returns:
      get_stream() - sys.stdout for stdout runs; for a file target, opens on
        first call and returns the same handle on subsequent calls.
      close_stream() - closes the file only if get_stream() was ever called.
      dest - the file Path written, or None for stdout / dry-run (the CLI reports
        it after the stream closes cleanly).

    --dry-run skips output resolution entirely.
    """
    if dry_run:
        return (lambda: sys.stdout, lambda: None, None)

    output_file, _ = _resolve_digest_output_target(parsed)
    if output_file is None:
        return (lambda: sys.stdout, lambda: None, None)

    dest = output_file
    state: dict[str, Any] = {"fh": None}

    def _get_stream() -> Any:
        if state["fh"] is None:
            dest.parent.mkdir(parents=True, exist_ok=True)
            state["fh"] = dest.open("w", encoding="utf-8", newline="")
        return state["fh"]

    def _close_stream() -> None:
        fh = state["fh"]
        if fh is not None:
            fh.close()

    return (_get_stream, _close_stream, dest)


def _digest_runner_kwargs(
    parsed: dict[str, Any],
    config: dict[str, Any],
    schema: str = "conn",
    resolve_output: bool = True,
    use_utc: bool = False,
) -> dict[str, Any]:
    """Build the kwargs dict for runner.run_digest from parsed CLI args + config.

    ``use_utc`` arrives RESOLVED from ``_run_digest`` (which also set the
    display switch CLI-side, before output naming) - it is not re-resolved
    here; timeframe parsing takes the explicit bool.

    Source-dir overrides (``zeek_dir`` / ``pihole_dir`` / ``syslog_dir`` /
    ``cloudtrail_dir``) flow through as RAW strings (or ``None``). The CLI
    does NOT resolve or path-wrap them - ``sigwood.common.sources.resolve_digest_source``
    in ``run_digest`` owns the per-schema candidate ladder, wrong-key + XOR +
    not-configured errors, and the SOLE string→Path conversion site
    (``_resolve_one``). Window + output target stay here.

    ``blob_path`` is an INTERNAL routing key (NOT a flag) synthesized by
    ``_route_sniffed_path``; it stays a ``Path`` and is consumed by
    ``run_digest``'s blob branch BEFORE source resolution.

    ``resolve_output=False`` is the fan-out seam: the CLI's `_run_digest`
    has already resolved the shared `--out` target into a single TextIO
    stream that is passed alongside, so per-path kwargs MUST NOT re-resolve.
    """
    _assert_all_vs_timeframe(parsed)

    since, until = _resolve_timeframe(parsed, use_utc=use_utc)

    output_file: Path | None = None
    output_dir: Path | None = None
    if resolve_output:
        # Digest is OFF report_dir - its own --out-only resolver, never config.
        # A DIR verdict is composed into an exact output_file there (output_dir
        # is always None for digest), so _report_filename is never reached.
        output_file, output_dir = _resolve_digest_output_target(parsed)

    cli_blob = parsed.get("blob_path")

    return dict(
        config=config,
        # Source-dir overrides: raw strings (or None) - resolver owns Path conversion.
        zeek_dir=parsed.get("zeek_dir"),
        pihole_dir=parsed.get("pihole_dir"),
        syslog_dir=parsed.get("syslog_dir"),
        cloudtrail_dir=parsed.get("cloudtrail_dir"),
        # blob_path is internal routing - expanduser only (no SIGWOOD_ROOT, no
        # be_like_water). The blob branch in run_digest consumes it BEFORE
        # source resolution, so it never reaches resolve_digest_source.
        blob_path=Path(os.path.expanduser(cli_blob)) if cli_blob else None,
        since=since,
        until=until,
        output_format=parsed.get("format", "text"),
        output_dir=output_dir,
        output_file=output_file,
        verbose_level=_resolve_verbose_level(parsed),
        dry_run=bool(parsed.get("dry_run", False)),
        load_all=bool(parsed.get("all", False)),
        skip_confirm=bool(parsed.get("yes", False)),
        # CLI -q wins; else [sigwood].quiet (default false). run_digest combines
        # effective show_progress = show_progress and not quiet at the loader calls.
        quiet=bool(parsed.get("quiet"))
        or bool(config.get("sigwood", {}).get("quiet", False)),
        use_utc=use_utc,
        schema=schema,
    )


def _run_init(args: list[str]) -> None:
    """Validate init args via the spec, then delegate to the wizard.

    init's allowed set is help-only. Standalone ``--help`` / ``-h`` is
    short-circuited in ``_main`` BEFORE this function is invoked, so anything
    that reaches here MUST be an empty list - any unexpected token raises
    via the strict parser (unknown flag or wrong-verb).
    """
    _parse_args(args, "init")
    from sigwood.cli_init import run_init
    run_init()


def _run_allowlist(args: list[str]) -> None:
    """Inspect & manage suppression lists. Delegates to cli_allowlist; this layer
    only validates flags via the spec and threads the raw ``--config`` value."""
    from sigwood import cli_allowlist

    parsed = _parse_args(args, "allowlist")
    positionals: list[str] = parsed.get("paths") or []
    cli_allowlist.run_allowlist(positionals, config_path=parsed.get("config"))


def _run_export(args: list[str]) -> None:
    """Pull logs from an external system (Splunk, CloudTrail) to local files."""
    from sigwood.exporters import run_export

    parsed = _parse_args(args, "export")

    # Config loads BEFORE the timeframe: the use_utc knob must exist before a
    # naive --since/--until date is interpreted.
    config = _load_config(parsed)

    # CLI --utc wins; else [sigwood].use_utc. Resolved ONCE for this verb
    # path; run_export sets the display switch at entry (its window narration
    # is the first display-policy consumer, and it is run_export-side).
    use_utc = bool(parsed.get("utc")) or bool(
        config.get("sigwood", {}).get("use_utc", False)
    )

    # Timeframe: pass None when no flags given - exporter applies its own default
    since, until = _resolve_timeframe(parsed, use_utc=use_utc)

    positionals: list[str] = parsed.get("paths") or []

    # Disambiguate: first positional is a backend name if it matches a known backend
    _KNOWN_EXPORT_BACKENDS = {"splunk", "cloudtrail"}
    if positionals and positionals[0] in _KNOWN_EXPORT_BACKENDS:
        backend: str | None = positionals[0]
        query_names = positionals[1:]
    else:
        backend = None
        query_names = positionals

    # Pass the raw CLI string (preserving any trailing slash) - be_like_water
    # decides file vs directory inside the export pipeline.
    out_str = parsed.get("out") if "out" in parsed else None

    # Export collapses to a single bool: -vv on export == -v (no level-2
    # surface). The export pipeline keeps its bool internally; the CLI
    # collapses at the seam.
    run_export(
        config=config,
        backend=backend,
        query_names=query_names,
        since=since,
        until=until,
        out=out_str,
        verbose=(_resolve_verbose_level(parsed) >= 1),
        skip_confirm=bool(parsed.get("yes", False)),
        use_utc=use_utc,
    )
