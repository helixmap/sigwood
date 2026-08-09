"""U2a exporter provenance, loader binding, and runner lane contracts."""

from __future__ import annotations

import json
import stat
import subprocess
import sys
from dataclasses import fields
from datetime import datetime, timezone
from pathlib import Path

import pytest

from sigwood import exporters, runner
from sigwood.common.finding import DetectorContext
from sigwood.common.loader import (
    AvailabilityReason,
    AvailabilityState,
    CoverageDecisionReason,
    CoverageLane,
    ExportAvailability,
    PROVENANCE_LOCK_NAME,
    PROVENANCE_MANIFEST_NAME,
    PROVENANCE_SCHEMA_VERSION,
    PROVENANCE_STAGE_PREFIX,
    ProvenanceEntry,
    ProvenanceManifest,
    ProvenanceManifestError,
    _syslog_files,
    canonical_manifest_bytes,
    discover_cloudtrail_files,
    discover_files,
    discover_zeek_files,
    hash_file,
    load_required_logs,
    parse_manifest_bytes,
    read_manifest,
    validate_selected_files,
)
from sigwood.common.paths import private_write_bytes


UTC = timezone.utc
START = datetime(2026, 8, 1, tzinfo=UTC)
END = datetime(2026, 8, 2, tzinfo=UTC)
PIHOLE_ROW = (
    "Aug  1 00:00:01 resolver.example.test dnsmasq[123]: "
    "query[A] example.test from 192.0.2.10"
)


def _entry(path: Path, **overrides: object) -> ProvenanceEntry:
    values: dict[str, object] = {
        "schema_version": PROVENANCE_SCHEMA_VERSION,
        "content_sha256": hash_file(path),
        "size_bytes": path.stat().st_size,
        "requested_start_utc": START,
        "requested_end_utc": END,
        "request_zone": "Etc/UTC",
        "tzdata_version": None,
        "exporter": "sigwood",
        "backend": "splunk",
        "completion": "success",
    }
    values.update(overrides)
    return ProvenanceEntry(**values)  # type: ignore[arg-type]


def _write_manifest(parent: Path, entries: dict[str, ProvenanceEntry], generation: int = 1) -> Path:
    path = parent / PROVENANCE_MANIFEST_NAME
    private_write_bytes(
        path,
        canonical_manifest_bytes(
            ProvenanceManifest(
                PROVENANCE_SCHEMA_VERSION,
                generation,
                datetime(2026, 8, 9, tzinfo=UTC),
                entries,
            )
        ),
    )
    return path


def _export_config() -> dict[str, object]:
    return {
        "export": {
            "splunk": {
                "host": "192.0.2.20",
                "port": 8089,
                "query": {
                    "dns": {
                        "spl": "search index=dns",
                        "output_basename": "pihole",
                    }
                },
            }
        }
    }


def _run_real_writer(monkeypatch: pytest.MonkeyPatch, parent: Path) -> Path:
    from sigwood.exporters import splunk

    monkeypatch.setattr(
        splunk,
        "fetch",
        lambda *_args, **_kwargs: (
            [{"_time": "2026-08-01T00:00:01Z", "_raw": PIHOLE_ROW}],
            {"units": 1, "unit_label": "chunks"},
        ),
    )
    exporters.run_export(
        _export_config(),
        "splunk",
        ["dns"],
        START,
        END,
        f"{parent}/",
        False,
        use_utc=True,
    )
    return parent / "pihole_20260801_1d.log"


def test_request_zone_identity_utc_and_resolvable_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert exporters._request_zone_identity(True) == "Etc/UTC"
    monkeypatch.setenv("TZ", "America/Chicago")
    assert exporters._request_zone_identity(False) == "America/Chicago"


@pytest.mark.parametrize("tz_value", ["Not/AZone", "/usr/share/zoneinfo/America/Chicago"])
def test_request_zone_identity_rejects_unresolvable_or_absolute_candidates(
    monkeypatch: pytest.MonkeyPatch,
    tz_value: str,
) -> None:
    class MissingLocaltime:
        def resolve(self, *, strict: bool):
            assert strict is True
            raise OSError("localtime identity unavailable")

    monkeypatch.setenv("TZ", tz_value)
    monkeypatch.setattr(exporters, "Path", lambda _value: MissingLocaltime())
    assert exporters._request_zone_identity(False) is None


def test_tzdata_version_uses_package_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(exporters.importlib.metadata, "version", lambda _name: "2026.2")
    assert exporters._tzdata_version() == "2026.2"


def test_tzdata_version_returns_none_when_no_identity_is_readable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class MissingVersionFile:
        def open(self, *_args, **_kwargs):
            raise FileNotFoundError("zoneinfo version unavailable")

    def missing_package(_name: str) -> str:
        raise exporters.importlib.metadata.PackageNotFoundError

    monkeypatch.setattr(exporters.importlib.metadata, "version", missing_package)
    monkeypatch.setattr(exporters, "Path", lambda _value: MissingVersionFile())
    assert exporters._tzdata_version() is None


def test_real_writer_commits_private_data_and_manifest(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    data = _run_real_writer(monkeypatch, tmp_path)
    manifest_path = tmp_path / PROVENANCE_MANIFEST_NAME
    manifest = read_manifest(manifest_path)
    entry = manifest.entries[data.name]

    assert manifest.generation == 1
    assert entry.requested_start_utc == START
    assert entry.requested_end_utc == END
    assert entry.request_zone == "Etc/UTC"
    assert entry.backend == "splunk"
    assert entry.completion == "success"
    assert entry.size_bytes == data.stat().st_size
    assert entry.content_sha256 == hash_file(data)
    assert stat.S_IMODE(data.stat().st_mode) == 0o600
    assert stat.S_IMODE(manifest_path.stat().st_mode) == 0o600
    assert stat.S_IMODE((tmp_path / PROVENANCE_LOCK_NAME).stat().st_mode) == 0o600
    assert str(data) in capsys.readouterr().out
    assert not list(tmp_path.glob(f"{PROVENANCE_STAGE_PREFIX}*"))


def test_same_basename_reexport_replaces_binding_and_advances_generation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    data = _run_real_writer(monkeypatch, tmp_path)
    first = read_manifest(tmp_path / PROVENANCE_MANIFEST_NAME)
    data.write_text("stale\n", encoding="utf-8")
    _run_real_writer(monkeypatch, tmp_path)
    second = read_manifest(tmp_path / PROVENANCE_MANIFEST_NAME)

    assert first.generation == 1
    assert second.generation == 2
    assert second.entries[data.name].content_sha256 == hash_file(data)
    assert data.read_text(encoding="utf-8").strip() == PIHOLE_ROW


def test_subprocess_writers_serialize_without_losing_entries(tmp_path: Path) -> None:
    seed = tmp_path / "seed.log"
    seed.write_bytes(b"seed\n")
    manifest_path = _write_manifest(tmp_path, {seed.name: _entry(seed)})
    seed_wire = json.loads(manifest_path.read_text(encoding="utf-8"))["entries"][seed.name]
    gate = tmp_path / "go"
    helper = Path(__file__).with_name("provenance_writer_helper.py")
    commands = [
        [sys.executable, str(helper), str(tmp_path), "alpha.log", "alpha\n", str(gate)],
        [sys.executable, str(helper), str(tmp_path), "beta.log", "beta\n", str(gate)],
    ]
    processes = [
        subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for command in commands
    ]
    gate.write_text("go\n", encoding="utf-8")
    failures: list[str] = []
    for process in processes:
        stdout, stderr = process.communicate(timeout=20)
        if process.returncode:
            failures.append(f"rc={process.returncode} stdout={stdout!r} stderr={stderr!r}")
    assert not failures, failures

    manifest = read_manifest(manifest_path)
    wire = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest.generation == 3
    assert set(manifest.entries) == {"seed.log", "alpha.log", "beta.log"}
    assert wire["entries"][seed.name] == seed_wire


def test_manifest_last_failure_cannot_create_a_trusted_receipt(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    real_replace = exporters.os.replace

    def fail_manifest(source: Path, destination: Path) -> None:
        if Path(destination).name == PROVENANCE_MANIFEST_NAME:
            raise OSError("injected manifest replace failure")
        real_replace(source, destination)

    monkeypatch.setattr(exporters.os, "replace", fail_manifest)
    with pytest.raises(OSError, match="injected manifest"):
        _run_real_writer(monkeypatch, tmp_path)

    data = tmp_path / "pihole_20260801_1d.log"
    assert data.is_file()
    fact = validate_selected_files([data])[0]
    assert fact.state is AvailabilityState.UNKNOWN
    assert fact.reason is AvailabilityReason.MANIFEST_MISSING


def test_malformed_existing_manifest_refuses_without_final_mutation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    private_write_bytes(tmp_path / PROVENANCE_MANIFEST_NAME, b"{}\n")
    with pytest.raises(ValueError, match="existing provenance manifest is malformed"):
        _run_real_writer(monkeypatch, tmp_path)
    assert not (tmp_path / "pihole_20260801_1d.log").exists()
    assert (tmp_path / PROVENANCE_MANIFEST_NAME).read_bytes() == b"{}\n"


def test_symlink_lock_refuses_without_final_mutation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    target = tmp_path / "lock-target"
    target.write_text("do not touch\n", encoding="utf-8")
    (tmp_path / PROVENANCE_LOCK_NAME).symlink_to(target)
    with pytest.raises(ValueError, match="symbolic link"):
        _run_real_writer(monkeypatch, tmp_path)
    assert target.read_text(encoding="utf-8") == "do not touch\n"
    assert not (tmp_path / "pihole_20260801_1d.log").exists()


@pytest.mark.parametrize("failure", ["duplicate", "bytes"])
def test_backend_write_metadata_fails_before_final_mutation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    failure: str,
) -> None:
    from sigwood.exporters import splunk

    monkeypatch.setattr(
        splunk,
        "fetch",
        lambda *_args, **_kwargs: ([], {"units": 1, "unit_label": "chunks"}),
    )

    def invalid_write(_rows: object, outpath: Path, _verbose: bool):
        private_write_bytes(outpath, b"x")
        if failure == "duplicate":
            return 1, {"bytes": 2, "paths": [outpath, outpath]}
        return 1, {"bytes": 2, "paths": [outpath]}

    monkeypatch.setattr(splunk, "write", invalid_write)
    message = "escaping or duplicate" if failure == "duplicate" else "inconsistent"
    with pytest.raises(ValueError, match=message):
        exporters.run_export(
            _export_config(), "splunk", ["dns"], START, END,
            f"{tmp_path}/", False, use_utc=True,
        )
    assert not (tmp_path / "pihole_20260801_1d.log").exists()
    assert not (tmp_path / PROVENANCE_MANIFEST_NAME).exists()


@pytest.mark.parametrize(
    "leaf",
    [PROVENANCE_MANIFEST_NAME, PROVENANCE_LOCK_NAME, f"{PROVENANCE_STAGE_PREFIX}owned"],
)
def test_export_refuses_reserved_output_before_fetch(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    leaf: str,
) -> None:
    from sigwood.exporters import splunk

    monkeypatch.setattr(
        splunk,
        "fetch",
        lambda *_args, **_kwargs: pytest.fail("reserved output reached fetch"),
    )
    with pytest.raises(ValueError, match="reserved for sigwood export provenance"):
        exporters.run_export(
            _export_config(), "splunk", ["dns"], START, END,
            str(tmp_path / leaf), False, use_utc=True,
        )


def test_strict_manifest_round_trip_and_duplicate_rejection(tmp_path: Path) -> None:
    data = tmp_path / "pihole.log"
    data.write_bytes(b"row\n")
    encoded = canonical_manifest_bytes(
        ProvenanceManifest(
            1,
            1,
            datetime(2026, 8, 9, tzinfo=UTC),
            {data.name: _entry(data)},
        )
    )
    assert canonical_manifest_bytes(parse_manifest_bytes(encoded)) == encoded

    duplicate_top = encoded.decode().replace(
        '"generation":1,', '"generation":1,"generation":2,', 1,
    ).encode()
    with pytest.raises(ProvenanceManifestError, match="malformed"):
        parse_manifest_bytes(duplicate_top)

    duplicate_entry = encoded.decode().replace(
        f'"{data.name}":', f'"{data.name}":{{}},"{data.name}":', 1,
    ).encode()
    with pytest.raises(ProvenanceManifestError, match="malformed"):
        parse_manifest_bytes(duplicate_entry)


def test_manifest_caps_reject_before_partial_facts(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import sigwood.common.loader.provenance as provenance

    data = tmp_path / "pihole.log"
    data.write_bytes(b"row\n")
    base = json.loads(
        canonical_manifest_bytes(
            ProvenanceManifest(1, 1, datetime(2026, 8, 9, tzinfo=UTC), {data.name: _entry(data)})
        )
    )
    entry = base["entries"][data.name]
    base["entries"] = {"a.log": entry, "b.log": entry}
    monkeypatch.setattr(provenance, "MAX_AVAILABILITY_SPANS", 2)
    assert len(parse_manifest_bytes(json.dumps(base).encode()).entries) == 2
    base["entries"]["c.log"] = entry
    with pytest.raises(ProvenanceManifestError, match="entry limit"):
        parse_manifest_bytes(json.dumps(base).encode())

    monkeypatch.setattr(provenance, "MAX_PROVENANCE_BYTES", 5)
    with pytest.raises(ProvenanceManifestError, match="byte limit"):
        parse_manifest_bytes(b"123456")


def test_selected_population_cap_downgrades_without_partial_trust(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import sigwood.common.loader.provenance as provenance

    paths = [tmp_path / f"{name}.log" for name in ("a", "b", "c")]
    for path in paths:
        path.write_bytes(path.name.encode())
    _write_manifest(tmp_path, {path.name: _entry(path) for path in paths})
    monkeypatch.setattr(provenance, "MAX_AVAILABILITY_SPANS", 2)
    facts = validate_selected_files(paths)
    assert all(fact.state is AvailabilityState.UNKNOWN for fact in facts)
    assert {fact.reason for fact in facts} == {AvailabilityReason.RESOURCE_LIMIT}


@pytest.mark.parametrize(
    "bad_name",
    ["../pihole.log", "a/b.log", ".sigwood-export-provenance.json", "safe\u202eevil.log"],
)
def test_manifest_rejects_unsafe_or_reserved_entry_names(
    tmp_path: Path,
    bad_name: str,
) -> None:
    data = tmp_path / "pihole.log"
    data.write_bytes(b"row\n")
    good = json.loads(
        canonical_manifest_bytes(
            ProvenanceManifest(1, 1, datetime(2026, 8, 9, tzinfo=UTC), {data.name: _entry(data)})
        )
    )
    good["entries"] = {bad_name: good["entries"][data.name]}
    with pytest.raises(ProvenanceManifestError, match="basename"):
        parse_manifest_bytes(json.dumps(good).encode())


def test_validation_downgrades_missing_mismatch_incomplete_and_symlink(
    tmp_path: Path,
) -> None:
    data = tmp_path / "pihole.log"
    data.write_bytes(b"row\n")
    assert validate_selected_files([data])[0].reason is AvailabilityReason.MANIFEST_MISSING

    _write_manifest(tmp_path, {data.name: _entry(data, completion="partial")})
    assert validate_selected_files([data])[0].reason is AvailabilityReason.INCOMPLETE

    _write_manifest(tmp_path, {data.name: _entry(data)})
    data.write_bytes(b"changed\n")
    assert validate_selected_files([data])[0].reason is AvailabilityReason.BINDING_MISMATCH

    target = tmp_path / "target.log"
    target.write_bytes(b"row\n")
    link = tmp_path / "link.log"
    link.symlink_to(target)
    _write_manifest(tmp_path, {link.name: _entry(target)})
    fact = validate_selected_files([link])[0]
    assert fact.state is AvailabilityState.UNKNOWN
    assert fact.reason is AvailabilityReason.BINDING_MISMATCH


def test_manifest_symlink_downgrades_selected_objects(tmp_path: Path) -> None:
    source = tmp_path / "source"
    selected = tmp_path / "selected"
    source.mkdir()
    selected.mkdir()
    data = selected / "pihole.log"
    data.write_bytes(b"row\n")
    real_manifest = _write_manifest(source, {data.name: _entry(data)})
    (selected / PROVENANCE_MANIFEST_NAME).symlink_to(real_manifest)
    fact = validate_selected_files([data])[0]
    assert fact.state is AvailabilityState.UNKNOWN
    assert fact.reason is AvailabilityReason.MANIFEST_MALFORMED


def test_explicit_manifest_is_actionably_rejected_before_flat_routing(tmp_path: Path) -> None:
    manifest = tmp_path / PROVENANCE_MANIFEST_NAME
    manifest.write_text("{}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="reserved sigwood provenance artifact"):
        load_required_logs(
            {"pihole*.log*": "pihole_dir"},
            {"pihole_dir": [manifest]},
        )


def test_reserved_namespace_stays_out_of_real_discovery_routes(tmp_path: Path) -> None:
    (tmp_path / PROVENANCE_MANIFEST_NAME).write_text("{}\n", encoding="utf-8")
    (tmp_path / PROVENANCE_LOCK_NAME).write_text("", encoding="utf-8")
    stage = tmp_path / f"{PROVENANCE_STAGE_PREFIX}abandoned"
    stage.mkdir()
    (stage / "dns.json").write_text('{"eventVersion":"1.0"}\n', encoding="utf-8")
    ordinary = tmp_path / "pihole.log"
    ordinary.write_text(PIHOLE_ROW + "\n", encoding="utf-8")

    for paths in (
        discover_files(tmp_path, "*.log*"),
        discover_zeek_files(tmp_path, "*.log*"),
        _syslog_files(tmp_path, "*.log*"),
        discover_cloudtrail_files(tmp_path),
    ):
        assert all(PROVENANCE_STAGE_PREFIX not in str(path) for path in paths)
        assert all(path.name not in {PROVENANCE_MANIFEST_NAME, PROVENANCE_LOCK_NAME} for path in paths)


def test_real_export_load_and_runner_lane_then_mutation_downgrade(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    data = _run_real_writer(monkeypatch, tmp_path)
    needed = {"pihole*.log*": "pihole_dir"}
    sources = {"pihole_dir": [tmp_path]}
    loaded = load_required_logs(needed, sources, START, END)
    facts = loaded.availability["pihole*.log*"]
    decision = runner._select_coverage_lane(facts, (START, END))
    assert facts[0].state is AvailabilityState.TRUSTED
    assert decision.lane is CoverageLane.STRONG
    assert decision.reason is CoverageDecisionReason.COMPLETE

    data.write_bytes(data.read_bytes() + (PIHOLE_ROW + "\n").encode())
    changed = load_required_logs(needed, sources, START, END)
    changed_decision = runner._select_coverage_lane(
        changed.availability["pihole*.log*"], (START, END),
    )
    assert changed_decision.lane is CoverageLane.WEAK
    assert changed_decision.reason is CoverageDecisionReason.OBJECT_UNKNOWN


def test_runner_merges_overlaps_and_keeps_unbounded_conservative(tmp_path: Path) -> None:
    facts = [
        ExportAvailability(
            tmp_path / "a.log", AvailabilityState.TRUSTED, AvailabilityReason.TRUSTED,
            (START, datetime(2026, 8, 1, 16, tzinfo=UTC)),
        ),
        ExportAvailability(
            tmp_path / "b.log", AvailabilityState.TRUSTED, AvailabilityReason.TRUSTED,
            (datetime(2026, 8, 1, 12, tzinfo=UTC), END),
        ),
    ]
    complete = runner._select_coverage_lane(facts, (START, END))
    assert complete.lane is CoverageLane.STRONG
    assert complete.trusted_intervals == ((START, END),)

    unbounded = runner._select_coverage_lane(facts, None)
    assert unbounded.lane is CoverageLane.WEAK
    assert unbounded.reason is CoverageDecisionReason.INTERVAL_UNBOUNDED
    assert "coverage" not in {field.name for field in fields(DetectorContext)}
