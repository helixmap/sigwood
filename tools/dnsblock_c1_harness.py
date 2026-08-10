#!/usr/bin/env python3
"""Internal pre-public product-path harness for planned dnsblock units."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import resource
import re
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager, redirect_stdout
from datetime import datetime, timezone
from pathlib import Path

from sigwood import runner
from sigwood.common.paths import private_mkdir, private_write_text
from sigwood.detectors import dnsblock


_FOLD_RSS_GREEN = 1536 * 1024 * 1024
_MIXED_INCREMENT_GREEN = 512 * 1024 * 1024
_WALL_GREEN_SECONDS = 15 * 60
_WATCHDOG_RSS = 8 * 1024 * 1024 * 1024
_WATCHDOG_SECONDS = 30 * 60


_NOTE_PATTERNS = tuple(
    re.compile(pattern)
    for pattern in (
        r"period coverage is not verifiable from these logs; period counts use data-bearing periods, and burst and recurring activity were not evaluated",
        r"dnsblock: [0-9]+ candidate (?:pair|pairs) withheld — not enough prior history in the loaded window",
        r"dnsblock: arrival analysis needs at least [0-9]+ prior periods; the loaded window has [0-9]+",
        r"dnsblock: first-activity analysis needs [0-9]+ eligible periods; the window has [0-9]+",
        r"dnsblock: burst analysis needs [0-9]+ eligible periods; the window has [0-9]+",
        r"dnsblock: recurring analysis needs every report period strongly covered; [0-9]+ of [0-9]+ were not",
        r"dnsblock: [0-9]+ synchronized first (?:appearance|appearances) withheld \([0-9]+ addresses reached the same family in one period\)",
        r"dnsblock: the allowlist removed [0-9]+ block-outcome (?:row|rows) from the report interval and [0-9]+ from context",
        r"dnsblock: no Pi-hole query rows in the window",
        r"dnsblock: no blocked-name outcomes logged in the window",
        r"dnsblock: all block-outcome rows were removed by the allowlist",
        r"dnsblock: blocked-name activity found, but nothing met the reporting thresholds",
    )
)


def _instant(text: str) -> datetime:
    normalized = text[:-1] + "+00:00" if text.endswith("Z") else text
    value = datetime.fromisoformat(normalized)
    if value.tzinfo is None or value.utcoffset() is None:
        raise argparse.ArgumentTypeError("timestamp must include a UTC offset")
    return value.astimezone(timezone.utc)


def _atomic_json(path: Path, payload: dict) -> None:
    private_mkdir(path.parent)
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    try:
        private_write_text(
            temporary,
            json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
        )
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while block := handle.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def _validate_summary_notes(payload: dict) -> None:
    """Reject any artifact note outside dnsblock's identity-free frozen grammar."""
    notes = payload.get("summary_notes")
    if not isinstance(notes, list):
        raise ValueError("dnsblock artifact summary_notes must be a list")
    cap_lines = {
        f"dnsblock: analysis stopped — {axis} exceeded its bound ({limit}); no findings emitted this run"
        for _token, axis, limit in runner._DNSBLOCK_CAP_NOTES
    }
    for line in notes:
        if not isinstance(line, str) or "\n" in line:
            raise ValueError("dnsblock artifact contains an unsafe summary note")
        if line in cap_lines:
            continue
        if not any(pattern.fullmatch(line) for pattern in _NOTE_PATTERNS):
            raise ValueError("dnsblock artifact contains a non-template summary note")


@contextmanager
def _selected_source(source: Path, manifest: Path | None):
    if manifest is None:
        yield source, None
        return
    members: list[tuple[str, int, str]] = []
    for line in manifest.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        fields = line.split("\t")
        if len(fields) != 3:
            raise ValueError("corpus manifest row must have path, bytes, and sha256")
        name, size_text, digest = fields
        if Path(name).name != name or len(digest) != 64:
            raise ValueError("corpus manifest contains an unsafe member")
        members.append((name, int(size_text), digest))
    with tempfile.TemporaryDirectory(prefix="dnsblock-u2b-") as temporary:
        staged = Path(temporary)
        for name, expected_size, expected_digest in members:
            path = source / name
            if path.stat().st_size != expected_size or _sha256(path) != expected_digest:
                raise ValueError("corpus member does not match the frozen manifest")
            (staged / name).symlink_to(path)
        yield staged, {
            "manifest_sha256": _sha256(manifest),
            "member_count": len(members),
            "member_bytes": sum(size for _name, size, _digest in members),
        }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pihole-dir", type=Path, required=True)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--since", type=_instant)
    parser.add_argument("--until", type=_instant)
    parser.add_argument("--all", action="store_true", dest="load_all")
    parser.add_argument("--window", default="7d")
    parser.add_argument("--output-format", default="text")
    parser.add_argument("--no-allowlist", action="store_true")
    parser.add_argument("--mixed-baseline-rss", type=int)
    args = parser.parse_args(argv)
    if args.load_all and (args.since is not None or args.until is not None):
        parser.error("--all cannot be combined with --since/--until")
    source = args.pihole_dir.expanduser().resolve()
    artifact = args.artifact.expanduser().resolve()
    if not source.exists():
        parser.error("--pihole-dir does not exist")
    if artifact.exists() and artifact.is_dir():
        parser.error("--artifact must be a file path")

    manifest = args.manifest.expanduser().resolve() if args.manifest else None
    if manifest is not None and (not source.is_dir() or not manifest.is_file()):
        parser.error("--manifest requires a source directory and readable manifest")

    selection = runner.DetectorSelection(
        {"dnsblock": dnsblock},
        ["dnsblock"],
        {},
        vocab={"dnsblock": {}},
    )
    effective_config = {
        "sigwood": {
            "root": "",
            "warn_above": 0,
            "default_window": args.window,
        }
    }
    with tempfile.TemporaryDirectory(prefix="dnsblock-u4-evidence-") as evidence_dir:
        evidence_path = Path(evidence_dir) / "aggregate.json"
        with _selected_source(source, manifest) as (selected_source, corpus_facts):
            started = time.monotonic()
            # The harness proves the real Reporter path but never persists or echoes
            # estate identities.  The runner writes a private provisional aggregate;
            # only grammar-validated notes may reach the requested final artifact.
            with open(os.devnull, "w", encoding="utf-8") as report_sink, redirect_stdout(
                report_sink
            ):
                rc = runner.run(
                    config=effective_config,
                    detect="dnsblock",
                    pihole_dir=selected_source,
                    since=args.since,
                    until=args.until,
                    output_format=args.output_format,
                    no_allowlist=args.no_allowlist,
                    load_all=args.load_all,
                    skip_confirm=True,
                    scope=frozenset({"pihole_dir"}),
                    quiet=True,
                    use_utc=True,
                    _detector_selection=selection,
                    _dnsblock_preflight_path=evidence_path,
                    invocation="dnsblock-c1-harness",
                )
        payload = json.loads(evidence_path.read_text(encoding="utf-8"))
        _validate_summary_notes(payload)
    elapsed = time.monotonic() - started
    peak_rss = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    if sys.platform != "darwin":
        peak_rss *= 1024
    if args.mixed_baseline_rss is None:
        rss_green = peak_rss <= _FOLD_RSS_GREEN
        rss_bar = {"kind": "fold_absolute", "limit_bytes": _FOLD_RSS_GREEN}
    else:
        rss_green = peak_rss <= args.mixed_baseline_rss + _MIXED_INCREMENT_GREEN
        rss_bar = {
            "kind": "mixed_incremental",
            "baseline_bytes": args.mixed_baseline_rss,
            "increment_limit_bytes": _MIXED_INCREMENT_GREEN,
        }
    lane = payload["preflight"]["coverage_lane"]
    payload["harness"] = {
        "runner_exit_code": rc,
        "elapsed_seconds": elapsed,
        "peak_process_rss_bytes": peak_rss,
        "rss_green": rss_green,
        "rss_bar": rss_bar,
        "wall_green": elapsed <= _WALL_GREEN_SECONDS,
        "wall_limit_seconds": _WALL_GREEN_SECONDS,
        "watchdog_rss_bytes": _WATCHDOG_RSS,
        "watchdog_seconds": _WATCHDOG_SECONDS,
        "source_head": subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=Path(__file__).resolve().parents[1],
            text=True,
            capture_output=True,
            check=True,
        ).stdout.strip(),
        "config_sha256": hashlib.sha256(
            json.dumps(effective_config, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
        "corpus": corpus_facts,
        "strong_corpus_recommendation": (
            "retain_manifest_backed_captures"
            if lane == "strong"
            else "reexport_retained_upstream_data_with_manifests_or_keep_strong_channels_dormant"
        ),
    }
    _atomic_json(artifact, payload)
    if rc != 0:
        return rc
    if payload["preflight"]["state"] != "READY":
        return 3
    if not rss_green or elapsed > _WALL_GREEN_SECONDS:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
