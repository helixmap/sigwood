from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_harness_uses_real_runner_and_writes_aggregate_preflight(tmp_path):
    log = tmp_path / "pihole.log"
    log.write_text(
        "Jan 20 00:00:00 resolver.example.test dnsmasq[1]: "
        "query[A] x.example from 192.0.2.7\n"
        "Jan 20 00:00:01 resolver.example.test dnsmasq[1]: "
        "gravity blocked x.example is 0.0.0.0\n",
        encoding="utf-8",
    )
    artifact = tmp_path / "aggregate.json"
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "tools" / "dnsblock_c1_harness.py"),
            "--pihole-dir",
            str(log),
            "--artifact",
            str(artifact),
            "--since",
            "2026-01-19T00:00:00Z",
            "--until",
            "2026-01-21T00:00:00Z",
            "--no-allowlist",
            "--output-format",
            "json",
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == ""
    payload = json.loads(artifact.read_text(encoding="utf-8"))
    assert payload["detector"] == "dnsblock"
    assert payload["status"] == "planned"
    assert payload["preflight"]["state"] == "READY"
    assert len(payload["preflight"]["grids"]) == 12
    assert payload["channels"]["burst"] == {
        "cause": "weak_coverage",
        "eligible_periods": 1,
        "periods_required": 3,
        "status": "ABSTAINED",
    }
    assert payload["channels"]["recurring"]["status"] == "ABSTAINED"
    assert payload["burst_grids"] == []
    assert payload["summary_notes"][0] == (
        "period coverage is not verifiable from these logs; period counts use "
        "data-bearing periods, and burst and recurring activity were not evaluated"
    )
    assert {label for label, _seconds in payload["preflight"]["pass_wall_seconds"]} == {
        "anchor_block",
        "population",
    }
    assert payload["harness"]["rss_bar"]["limit_bytes"] == 1536 * 1024 * 1024
    assert payload["harness"]["wall_limit_seconds"] == 15 * 60
    digest = payload["harness"]["semantic_digest"]
    assert digest["schema"] == "sigwood.dnsblock.semantic-digest"
    assert digest["version"] == 1
    assert digest["format"] == "json"
    assert len(digest["sha256"]) == 64
    assert digest["finding_count"] == 0
    second_artifact = tmp_path / "aggregate-second.json"
    second_command = [
        sys.executable,
        str(ROOT / "tools" / "dnsblock_c1_harness.py"),
        "--pihole-dir",
        str(log),
        "--artifact",
        str(second_artifact),
        "--since",
        "2026-01-19T00:00:00Z",
        "--until",
        "2026-01-21T00:00:00Z",
        "--no-allowlist",
        "--output-format",
        "json",
    ]
    second = subprocess.run(
        second_command,
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert second.returncode == 0, second.stderr
    second_payload = json.loads(second_artifact.read_text(encoding="utf-8"))
    assert second_payload["harness"]["semantic_digest"]["sha256"] == digest["sha256"]
    serialized = artifact.read_text(encoding="utf-8")
    assert "192.0.2.7" not in serialized
    assert "x.example" not in serialized
