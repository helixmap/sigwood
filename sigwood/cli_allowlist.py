"""The ``allowlist`` verb - inspect & manage suppression lists.

A NORMAL CLI helper (unlike the stdlib-restricted ``cli_init``): it MAY import
``common/allowlist``, ``common/config``, ``common/paths``, ``common/display``.

BOUNDARY RAIL - ``common/allowlist.py`` owns registry/resolver/matcher/count and
NOTHING ELSE. All rendering, the ``[allowlist.lists]`` config write, and the
``copy`` file write live HERE. We do NOT reach into ``cli_init``'s
``[sigwood]``-scoped private upsert - the wizard's writer is the wizard's; this
module carries its own focused ``[allowlist.lists]`` upsert.

Voice: the readout / show / confirmations are ADVISORY - no
``sigwood:`` prefix, lowercase-led, terse, ``plural()`` for counts. Operational
errors (unknown name, no config, dest exists) raise a plain ``ValueError`` so the
CLI boundary prints ``sigwood: <msg>`` with NO usage hint; a bad subcommand /
flag raises ``UsageError`` (which DOES get the usage hint).
"""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from sigwood.common import allowlist as al
from sigwood.common import config as cfg
from sigwood.common.display import compact_home, plural
from sigwood.common.errors import UsageError
from sigwood.common.paths import (
    private_mkdir,
    private_write_bytes,
    private_write_text,
)
from sigwood.common.sanitize import strip_control

_VALID_SUBCOMMANDS = ("show", "enable", "disable", "copy")


# ── entry point ───────────────────────────────────────────────────────────────


def run_allowlist(positionals: list[str], *, config_path: str | None = None) -> None:
    """Dispatch an ``allowlist`` invocation. No positionals → the readout."""
    if not positionals:
        _readout(config_path)
        return

    sub, rest = positionals[0], positionals[1:]
    if sub == "show":
        _show(rest, config_path)
    elif sub in ("enable", "disable"):
        _toggle(sub, rest, config_path)
    elif sub == "copy":
        _copy(rest, config_path)
    else:
        raise UsageError(
            f"unknown allowlist subcommand {sub!r}: "
            f"expected {', '.join(_VALID_SUBCOMMANDS)}"
        )


# ── readout (bare `sigwood allowlist`) ────────────────────────────────────────


def _readout(config_path: str | None) -> None:
    config = cfg.load(config_path)
    plan = al.resolve_allowlist_plan(config)

    summaries = {spec.name: spec.summary for spec in al._SHIPPED_LISTS}
    shipped = [rl for rl in plan.lists if rl.origin == "shipped"]
    dropins = [rl for rl in plan.lists if rl.origin == "dropin"]
    config_lists = [rl for rl in plan.lists if rl.origin == "config-path"]

    lines: list[str] = ["sigwood  ·  allowlist", ""]
    lines.append(f"suppression: {'on' if plan.master_enabled else 'off'}")

    if shipped:
        lines.append("")
        lines.append("shipped lists")
        name_w = max(len(rl.name) for rl in shipped)
        count_w = max(len(f"{rl.pattern_count:,}") for rl in shipped)
        for rl in shipped:
            state = "on " if rl.enabled else "off"
            count = f"{rl.pattern_count:,}".rjust(count_w)
            unit = _unit(rl.kind, rl.pattern_count)
            summary = summaries.get(rl.name, "")
            lines.append(
                f"  {rl.name.ljust(name_w)}  {state}  {count} {unit} · {summary}"
            )

    # Drop-ins live UNDER allowlist.d - label by filename, headered by the dir.
    if dropins:
        dir_label = strip_control(
            compact_home(al.resolve_allowlist_dir(config) or "allowlist.d/")
        )
        lines.append("")
        lines.append(f"your lists  ({dir_label})")
        # rl.name is a drop-in FILENAME reaching this terminal sink - neutralize
        # control bytes BEFORE the width calc: a control byte is zero-width on the
        # terminal but one char to len(), so a width from raw values misaligns rows.
        san_names = [strip_control(rl.name) for rl in dropins]
        name_w = max(len(s) for s in san_names)
        count_w = max(len(f"{rl.pattern_count:,}") for rl in dropins)
        nudges: list[str] = []
        for rl, sname in zip(dropins, san_names):
            count = f"{rl.pattern_count:,}".rjust(count_w)
            unit = _unit(rl.kind, rl.pattern_count)
            lines.append(f"  {sname.ljust(name_w)}  {count} {unit}")
            nudge = _dropin_nudge(rl.path.name)
            if nudge:
                nudges.append(f"    → {nudge}")
        lines.extend(nudges)

    # Files in allowlist.d that do NOT load under the dot rule but look like a list
    # (dotted / wrong suffix) - an advisory rename nudge, never an error. Readout-only
    # (plan.ignored), produced in the resolver's single pass; a trailing ~ or a
    # non-prefixed name stays silent. Placed after the loaded lists, before config.
    if plan.ignored:
        lines.append("")
        for ig in plan.ignored:
            # ig.name / ig.suggested derive from an on-disk allowlist.d FILENAME that
            # reaches this terminal sink - neutralize control bytes (the output
            # control-byte hygiene rail; strip is a no-op on a well-formed name).
            lines.append(
                f"{strip_control(ig.name)}: not loaded - drop-ins carry no "
                f"extension; rename to {strip_control(ig.suggested)}"
            )

    # Config-path lists live OUTSIDE allowlist.d (the domain_patterns /
    # connection_rules escape hatch) - label by their COMPACTED RESOLVED PATH so
    # the operator goes to the right file, not a phantom allowlist.d entry.
    if config_lists:
        lines.append("")
        lines.append("config lists")
        # Resolved config-path strings reach this sink - sanitize BEFORE the width
        # calc (same zero-width-control-byte reason as the drop-in names above).
        san_paths = [strip_control(compact_home(rl.path)) for rl in config_lists]
        path_w = max(len(s) for s in san_paths)
        count_w = max(len(f"{rl.pattern_count:,}") for rl in config_lists)
        for rl, spath in zip(config_lists, san_paths):
            count = f"{rl.pattern_count:,}".rjust(count_w)
            unit = _unit(rl.kind, rl.pattern_count)
            lines.append(f"  {spath.ljust(path_w)}  {count} {unit}")

    n = len(plan.entries)
    lines.append("")
    lines.append(f"classification: {n} {plural(n, 'stanza entry', 'stanza entries')}")

    print("\n".join(lines))


def _unit(kind: str, count: int) -> str:
    """Display unit for a list's loadable count."""
    if kind == "domain":
        return plural(count, "domain")
    return plural(count, "rule")


def _dropin_nudge(filename: str) -> str | None:
    """Nudge a drop-in that shadows (additively) a shipped list, or a
    ``domains_universal`` drop-in."""
    by_filename = {spec.filename: spec.name for spec in al._SHIPPED_LISTS}
    if filename in by_filename:
        return f"additive now; disable {by_filename[filename]} to replace"
    if filename == "domains_universal":
        return "additive now; the shipped list is 'common' - disable common to replace"
    return None


# ── show <name> ───────────────────────────────────────────────────────────────


def _show(rest: list[str], config_path: str | None) -> None:
    if not rest:
        raise UsageError("allowlist show needs a list name")
    name = rest[0]
    config = cfg.load(config_path)
    plan = al.resolve_allowlist_plan(config)

    rl = _resolve_named_list(plan, name)
    if rl is None:
        raise ValueError(
            f"no allowlist named {name!r} - "
            f"shipped: {', '.join(spec.name for spec in al._SHIPPED_LISTS)}"
        )

    if rl.kind == "domain":
        out = al.load_pattern_file(rl.path)
    else:
        out = [_format_numeric_rule(r) for r in al.load_numeric_rule_file(rl.path)]
    # `out` is FILE CONTENT (each pattern line) rendered straight to stdout -
    # neutralize control bytes per line; a no-op on the pure-ASCII shipped lists.
    print("\n".join(strip_control(line) for line in out))


def _resolve_named_list(plan: al.AllowlistPlan, name: str) -> al.ResolvedList | None:
    """Resolve ``name`` to a list in the plan: registry name, then drop-in by
    filename or stem. Works regardless of enabled state."""
    for rl in plan.lists:
        if rl.name == name or rl.path.name == name or rl.path.stem == name:
            return rl
    return None


def _format_numeric_rule(rule: al.NumericRule) -> str:
    """Reconstruct a flat numeric-rule line from a parsed NumericRule (show only)."""
    parts: list[str] = []
    if rule.ip1:
        parts.append(rule.ip1)
    if rule.ip2:
        parts.append(rule.ip2)
    if rule.port is not None or rule.proto is not None:
        port = str(rule.port) if rule.port is not None else "*"
        token = f":{port}"
        if rule.proto is not None:
            token += f"/{rule.proto}"
        parts.append(token)
    return " ".join(parts)


# ── enable | disable <name> ───────────────────────────────────────────────────


def _toggle(sub: str, rest: list[str], config_path: str | None) -> None:
    if not rest:
        raise UsageError(f"allowlist {sub} needs a list name")
    name = rest[0]
    valid = {spec.name for spec in al._SHIPPED_LISTS}
    if name not in valid:
        raise ValueError(
            f"{name!r} is not a shipped list - valid: {', '.join(sorted(valid))}"
        )

    target = _active_config_path(config_path)
    if target is None:
        raise ValueError("no config found - run sigwood init")

    try:
        raw = target.read_bytes()
    except OSError as exc:
        raise ValueError(f"cannot read {target}: {exc}") from exc

    enable = sub == "enable"
    new_text = _upsert_lists_key(raw.decode("utf-8"), name, enable)

    bak = target.with_suffix(target.suffix + ".bak")
    try:
        private_write_bytes(bak, raw)
        private_write_bytes(target, new_text.encode("utf-8"))
    except OSError as exc:
        raise ValueError(f"cannot write {target}: {exc}") from exc

    print(f"{'enabled' if enable else 'disabled'} {name}")


def _active_config_path(config_path: str | None) -> Path | None:
    """The config file to mutate: ``--config`` if given, else the first existing
    file in the search path. None when nothing exists."""
    if config_path:
        return Path(config_path).expanduser()
    for candidate in cfg.SEARCH_PATHS:
        if candidate.is_file():
            return candidate
    return None


_LISTS_HEADER_RE = re.compile(r"^\[allowlist\.lists\][^\n]*\n", re.MULTILINE)
_NEXT_TABLE_RE = re.compile(r"^\[", re.MULTILINE)


def _upsert_lists_key(text: str, name: str, value: bool) -> str:
    """Section-bound upsert of ``<name> = true|false`` inside the
    ``[allowlist.lists]`` table - creating the table at EOF if absent. Only the
    ``[allowlist.lists]`` span is touched; a token elsewhere is never rewritten."""
    literal = "true" if value else "false"
    new_line = f"{name} = {literal}"

    header = _LISTS_HEADER_RE.search(text)
    if header is None:
        sep = "" if text.endswith("\n") or text == "" else "\n"
        return f"{text}{sep}\n[allowlist.lists]\n{new_line}\n"

    body_start = header.end()
    nxt = _NEXT_TABLE_RE.search(text, body_start)
    body_end = nxt.start() if nxt else len(text)
    body = text[body_start:body_end]

    key_re = re.compile(rf"^[ \t]*{re.escape(name)}\s*=.*$", re.MULTILINE)
    km = key_re.search(body)
    if km is not None:
        new_body = body[:km.start()] + new_line + body[km.end():]
    else:
        new_body = new_line + "\n" + body
    return text[:body_start] + new_body + text[body_end:]


# ── copy <name> [as <newname>] ────────────────────────────────────────────────


def _copy(rest: list[str], config_path: str | None) -> None:
    if not rest:
        raise UsageError("allowlist copy needs a list name")
    name = rest[0]
    newname: str | None = None
    if len(rest) >= 2:
        if rest[1] == "as" and len(rest) >= 3:
            newname = rest[2]
        else:
            raise UsageError("allowlist copy: expected `copy <name> [as <newname>]`")

    # A new name is a bare token - never a path. Reject separators / `.` / `..`
    # rather than letting them build a confusing dest (`as a/b` → ENOENT on the
    # absent `domains_a/` parent; `as ../x` only fails to escape incidentally).
    if newname is not None and (
        newname in ("", ".", "..") or "/" in newname or "\\" in newname
    ):
        raise UsageError(
            f"invalid copy name {newname!r}: a list name cannot contain a path separator"
        )

    spec = next((s for s in al._SHIPPED_LISTS if s.name == name), None)
    if spec is None:
        raise ValueError(
            f"{name!r} is not a shipped list - valid: "
            f"{', '.join(s.name for s in al._SHIPPED_LISTS)}"
        )

    # Destination dir through the SHARED allowlist-dir owner - identical semantics
    # to the resolver, so copy never seeds a file the loader won't read. cfg.load()
    # supplies the default root + allowlist_dir even with NO config file (copy needs
    # none), preserving SIGWOOD_ROOT and an explicit root="". An explicit
    # allowlist_dir="" resolves to None (drop-ins disabled) - error, don't write a
    # file into a directory the resolver ignores.
    config = cfg.load(config_path)
    dest_dir = al.resolve_allowlist_dir(config)
    if dest_dir is None:
        raise ValueError(
            "allowlist_dir is empty - set [allowlist].allowlist_dir to a directory "
            "before copying, or drop-ins will not load"
        )
    prefix = "domains_" if spec.kind == "domain" else "connections_"
    dest_name = f"{prefix}{newname}" if newname else f"{prefix}{name}_local"
    # Reject unless the composed name classifies AS THE SAME KIND as the shipped list
    # copied - kind-EQUALITY, not "recognized". `_classify_dropin(dest) is not None`
    # is too weak: `copy common as my.toml` composes `domains_my.toml`, which clause 3
    # classifies "stanza" - copy would then write flat domain text into a file the
    # resolver hands to tomllib.load. The invariant is "copy writes a flat list whose
    # discovered kind matches the shipped list copied." Path-separator rejects already
    # fired above (directory escape is a separate concern).
    if al._classify_dropin(dest_name) != spec.kind:
        raise UsageError(
            f"invalid copy name {newname!r}: a list name cannot contain a path "
            "separator or a dot, or end in '~'"
        )
    dest = dest_dir / dest_name

    if dest.exists():
        raise ValueError(f"{compact_home(dest)} already exists")

    shipped_text = al._shipped_path(spec).read_text(encoding="utf-8")
    today = datetime.now().astimezone().date().isoformat()
    header = (
        f"# forked from sigwood shipped '{name}' on {today}\n"
        "# this is your copy - shipped updates will not reach it; it loads additively\n"
        f"# to replace the shipped list entirely: sigwood allowlist disable {name}\n\n"
    )
    try:
        private_mkdir(dest_dir)
        private_write_text(dest, header + shipped_text, encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"cannot write {compact_home(dest)}: {exc}") from exc

    print(f"copied {name} → {strip_control(compact_home(dest))}")
    print(f"to replace the shipped list, run: sigwood allowlist disable {name}")
