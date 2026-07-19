"""Drift tripwire - keep ``config_example.toml`` honest to runtime defaults.

Two assertions, structurally independent:

(a) ACTIVE-KEY agreement. Every UNCOMMENTED key under [sigwood], [allowlist],
    and [export.*] in the shipped example MUST equal the corresponding
    _DEFAULTS value. One-way: _DEFAULTS may carry extra keys the example
    doesn't show (e.g. splunk username/password).

(b) ENGINE-ROOM honesty. The commented [detectors.*] block at the end of the
    example IS user-facing documentation of detector defaults. Every shown
    `# key = value` line MUST match the corresponding DEFAULT_CONFIG entry.
    The shown set MAY be a SUBSET (deliberately omitted internals) - but it
    must NEVER show an absent key or a wrong value (the bug that shipped
    `duration.min_duration_seconds = 300` in the prior shape).
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest

from sigwood.common import allowlist as al
from sigwood.common import config as cfg
from sigwood.detectors import aws, beacon, dns, duration, scan, syslog


pytestmark = pytest.mark.real_defaults


EXAMPLE_PATH = Path("sigwood/data/config_example.toml")
ENGINE_ROOM_BANNER = "# Detector tuning - the engine room."


# ── (a) ACTIVE-KEY agreement ──────────────────────────────────────────────────


def _active_part(text: str) -> str:
    """Slice everything BEFORE the engine-room banner - the active config body."""
    idx = text.find(ENGINE_ROOM_BANNER)
    assert idx >= 0, "engine-room banner missing - has the example been retitled?"
    return text[:idx]


def test_example_active_keys_match_defaults() -> None:
    text = EXAMPLE_PATH.read_text(encoding="utf-8")
    parsed = tomllib.loads(_active_part(text))

    # Walk every uncommented key in the active body and assert it matches
    # _DEFAULTS at the same path. Skip top-level sections not in _DEFAULTS.
    for section, content in parsed.items():
        assert section in cfg._DEFAULTS, (
            f"example carries unknown top-level section [{section}] - defaults: "
            f"{sorted(cfg._DEFAULTS)}"
        )
        _assert_subset(content, cfg._DEFAULTS[section], section)


def _assert_subset(shown: dict, defaults: dict, path: str) -> None:
    """Every key in `shown` must match `defaults[key]` at the same path."""
    for key, val in shown.items():
        assert key in defaults, f"[{path}].{key} is not in _DEFAULTS - drift"
        if isinstance(val, dict):
            assert isinstance(defaults[key], dict), (
                f"[{path}].{key}: example shows a table but _DEFAULTS has scalar"
            )
            _assert_subset(val, defaults[key], f"{path}.{key}")
        else:
            assert val == defaults[key], (
                f"[{path}].{key}: example={val!r} vs _DEFAULTS={defaults[key]!r}"
            )


def _commented_splunk_block(text: str) -> str:
    lines = text.splitlines()
    start = next(
        (i for i, line in enumerate(lines) if line.strip() == "# [export.splunk]"),
        None,
    )
    assert start is not None, "example dropped the commented [export.splunk] block"
    block = [lines[start]]
    for line in lines[start + 1:]:
        if line.strip().startswith("#"):
            block.append(line)
        else:
            break
    return "\n".join(block)


def test_commented_splunk_verify_tls_matches_default() -> None:
    text = EXAMPLE_PATH.read_text(encoding="utf-8")
    match = re.search(
        r"(?m)^# verify_tls = (?P<value>true|false)$",
        _commented_splunk_block(text),
    )
    assert match is not None, "commented [export.splunk] block must show verify_tls"
    shown = tomllib.loads(f"verify_tls = {match.group('value')}")["verify_tls"]
    assert shown is cfg._DEFAULTS["export"]["splunk"]["verify_tls"]


# ── (c) [allowlist.lists] engine-room block matches the shipped registry ──────


def _allowlist_lists_block(text: str) -> str:
    """Slice the commented ``# [allowlist.lists]`` block (header + contiguous
    comment lines) from the active body."""
    lines = text.splitlines()
    start = next(
        (i for i, l in enumerate(lines) if l.strip() == "# [allowlist.lists]"),
        None,
    )
    assert start is not None, "example dropped the commented [allowlist.lists] block"
    block = [lines[start]]
    for l in lines[start + 1:]:
        if l.strip().startswith("#"):
            block.append(l)
        else:
            break
    return "\n".join(block)


def test_example_allowlist_lists_block_matches_registry() -> None:
    text = EXAMPLE_PATH.read_text(encoding="utf-8")
    # The HEADER stays commented - an active empty lists={} table would trip
    # arm (a) (absence ⇒ registry defaults, the literal contract).
    assert "\n# [allowlist.lists]" in text
    assert "\n[allowlist.lists]" not in text

    parsed = tomllib.loads(_uncomment_engine_room(_allowlist_lists_block(text)))
    shown = parsed["allowlist"]["lists"]
    registry = {spec.name: spec.default_on for spec in al._SHIPPED_LISTS}
    assert shown == registry, (
        f"example [allowlist.lists]={shown!r} vs registry default_on={registry!r}"
    )


# ── (b) ENGINE-ROOM honesty ───────────────────────────────────────────────────


_DETECTOR_DEFAULTS = {
    "beacon": beacon.DEFAULT_CONFIG,
    "scan": scan.DEFAULT_CONFIG,
    "duration": duration.DEFAULT_CONFIG,
    "dns": dns.DEFAULT_CONFIG,
    "syslog": syslog.DEFAULT_CONFIG,
    "aws": aws.DEFAULT_CONFIG,
}


def _engine_room_part(text: str) -> str:
    idx = text.find(ENGINE_ROOM_BANNER)
    assert idx >= 0
    return text[idx:]


def _uncomment_engine_room(block: str) -> str:
    """Strip leading "# " from lines that look like config (table headers,
    `key = value`); leave true comments and blank lines as comments.
    A "config" line is either a TOML table header or a key=value form."""
    out_lines: list[str] = []
    in_multiline_array = False
    for raw in block.splitlines():
        stripped = raw.lstrip()
        if not stripped.startswith("#"):
            out_lines.append(raw)
            continue
        body = stripped[1:].lstrip()      # text after "# "
        if in_multiline_array:
            # Array members and their inner grouping comments are valid TOML but
            # do not look like key=value lines. Keep them until the closing bracket.
            out_lines.append(body)
            if "]" in body:
                in_multiline_array = False
            continue
        # Inline trailing `# comment` after the value: keep the body, drop
        # everything from the first un-quoted '#' onward.
        if body.startswith("[") or _looks_like_kv(body):
            config_line = _strip_inline_trailing_comment(body)
            out_lines.append(config_line)
            if _looks_like_kv(body) and "[" in config_line and "]" not in config_line:
                in_multiline_array = True
        # else: a true narrative comment - drop it entirely (tomllib would
        # see it as a normal `#`-prefixed comment after un-commenting once,
        # but uncommenting body that doesn't look like config would inject
        # narrative into the TOML namespace).
    return "\n".join(out_lines)


_KV_RE = re.compile(r'^\s*[A-Za-z_][A-Za-z0-9_]*\s*=\s*')


def _looks_like_kv(body: str) -> bool:
    return bool(_KV_RE.match(body))


def _strip_inline_trailing_comment(body: str) -> str:
    """Strip a trailing `# narrative` from a KV line (no quoted strings with #
    in them in the engine-room block, so this is safe)."""
    if "[" in body and "]" in body and "=" not in body:
        return body            # table header
    if "#" in body:
        return body.split("#", 1)[0].rstrip()
    return body


def test_engine_room_keys_match_detector_defaults() -> None:
    text = EXAMPLE_PATH.read_text(encoding="utf-8")
    er = _engine_room_part(text)
    parsed = tomllib.loads(_uncomment_engine_room(er))

    detectors = parsed.get("detectors", {})
    assert detectors, "engine room shows no [detectors.*] blocks - has the example been gutted?"

    for name, shown_cfg in detectors.items():
        assert name in _DETECTOR_DEFAULTS, (
            f"engine room shows [detectors.{name}] but no DEFAULT_CONFIG known"
        )
        _assert_engine_subset(shown_cfg, _DETECTOR_DEFAULTS[name], f"detectors.{name}")


def _assert_engine_subset(shown: dict, defaults: dict, path: str) -> None:
    for key, val in shown.items():
        if isinstance(val, dict):
            assert key in defaults and isinstance(defaults[key], dict), (
                f"[{path}].{key}: engine room shows a nested table but "
                f"DEFAULT_CONFIG has no matching dict"
            )
            _assert_engine_subset(val, defaults[key], f"{path}.{key}")
        else:
            assert key in defaults, (
                f"[{path}].{key}: engine room shows a key absent from "
                f"DEFAULT_CONFIG (phantom key - exactly the {path} bug class)"
            )
            assert val == defaults[key], (
                f"[{path}].{key}: example={val!r} vs DEFAULT_CONFIG={defaults[key]!r}"
            )
