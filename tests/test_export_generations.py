"""A repeated logical export retires only its superseded generation."""

from __future__ import annotations

import json
import os
import fcntl
from datetime import datetime, timezone
from pathlib import Path

import pytest

from sigwood import exporters
from sigwood.exporters import cloudtrail, splunk
from sigwood.common.loader import (
    AvailabilityState, PROVENANCE_MANIFEST_NAME, ProvenanceEntry,
    ProvenanceManifest, canonical_manifest_bytes, discover_cloudtrail_files,
    hash_file, read_manifest, validate_selected_files,
)
from sigwood.common.paths import private_write_bytes


START = datetime(2026, 8, 1, tzinfo=timezone.utc)
END = datetime(2026, 8, 2, tzinfo=timezone.utc)
LOGICAL = "cloudtrail_20260801_1d.json.log"


def _run(monkeypatch: pytest.MonkeyPatch, parent: Path, count: int, *, split: bool = True) -> None:
    events = [{"eventTime": "2026-08-01T00:00:01Z", "sourceIPAddress": "192.0.2.10",
               "eventID": f"event-{n}"} for n in range(count)]
    monkeypatch.setattr(cloudtrail, "fetch", lambda *a, **kw: (
        events, {"units": 1, "unit_label": "objects"},
    ))
    monkeypatch.setattr(cloudtrail, "_PART_SPLIT_BYTES", 1 if split else 1_000_000)
    exporters.run_export(
        {"export": {"cloudtrail": {"path": "s3://events.example.test/"}}},
        "cloudtrail", [], START, END, str(parent) + "/", False, use_utc=True,
    )


def _parts(count: int) -> set[str]:
    return {cloudtrail._split_name(Path(LOGICAL), n).name for n in range(1, count + 1)}


def _seed(parent: Path, names: list[str]) -> dict[str, ProvenanceEntry]:
    manifest = read_manifest(parent / PROVENANCE_MANIFEST_NAME)
    entries = dict(manifest.entries)
    for name in names:
        path = parent / name
        private_write_bytes(path, b"retained\n")
        entries[name] = ProvenanceEntry(
            1, hash_file(path), path.stat().st_size, START, END,
            "Etc/UTC", None, "sigwood", "cloudtrail", "success",
        )
    private_write_bytes(parent / PROVENANCE_MANIFEST_NAME, canonical_manifest_bytes(
        ProvenanceManifest(1, manifest.generation, END, entries),
    ))
    return entries


def _set_entries(parent: Path, entries: dict[str, ProvenanceEntry]) -> None:
    manifest = read_manifest(parent / PROVENANCE_MANIFEST_NAME)
    private_write_bytes(parent / PROVENANCE_MANIFEST_NAME, canonical_manifest_bytes(
        ProvenanceManifest(1, manifest.generation, END, entries),
    ))


@pytest.mark.parametrize("before,after,expected", [
    ((3, True), (2, True), _parts(2)),
    ((3, True), (1, False), {LOGICAL}),
    ((1, False), (2, True), _parts(2)),
])
def test_reexport_selects_only_the_current_generation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
    capsys: pytest.CaptureFixture[str], before: tuple[int, bool],
    after: tuple[int, bool], expected: set[str],
) -> None:
    _run(monkeypatch, tmp_path, before[0], split=before[1])
    old = set(read_manifest(tmp_path / PROVENANCE_MANIFEST_NAME).entries)
    capsys.readouterr()
    _run(monkeypatch, tmp_path, after[0], split=after[1])
    output = capsys.readouterr().out
    manifest = read_manifest(tmp_path / PROVENANCE_MANIFEST_NAME)
    selected = discover_cloudtrail_files(tmp_path)
    disk = {p.name for p in tmp_path.iterdir() if not p.name.startswith(".sigwood")}
    print(json.dumps({"disk": sorted(disk), "manifest": sorted(manifest.entries),
                      "discovery": sorted(p.name for p in selected),
                      "trust": [f.state.value for f in validate_selected_files(selected)]}))
    assert disk == expected
    assert set(manifest.entries) == expected
    assert {p.name for p in selected} == expected
    assert all(f.state is AvailabilityState.TRUSTED for f in validate_selected_files(selected))
    removed = len(old - expected)
    noun = "file" if removed == 1 else "files"
    assert f"note: removed {removed} {noun} left by an earlier export of this window\n" in output


@pytest.mark.parametrize("logical", [LOGICAL, "events", "events.audit.json.log", ".events"])
def test_output_family_matches_the_writer_and_only_canonical_parts(logical: str) -> None:
    member = exporters.output_family_member
    assert member(logical, logical, parts=False)
    for n in range(1, 121):
        name = cloudtrail._split_name(Path(logical), n).name
        assert member(name, logical, parts=True)
        assert not member(name, logical, parts=False)
    for digits in ["00", "001", "0100", "5", "", "01x", "01\n", "０１", "٠١"]:
        canonical = cloudtrail._split_name(Path(logical), 1).name
        suffixes = "".join(Path(logical).suffixes)
        stem = logical[:-len(suffixes)] if suffixes else logical
        name = stem + "_part" + digits + suffixes
        assert not member(name, logical, parts=True), (canonical, name)
    for name in [".sigwood-export-provenance.json", ".sigwood-export-provenance.lock",
                 ".sigwood-export-stage-test", "cloudtrail_20260801_1d_extra.json.log",
                 "cloudtrail_20260801_7d.json.log"]:
        assert not member(name, logical, parts=True)
    assert cloudtrail.OUTPUT_PARTS is True
    assert not getattr(splunk, "OUTPUT_PARTS", False)


def test_cleanup_preserves_other_families_and_near_miss_bindings(monkeypatch, tmp_path) -> None:
    _run(monkeypatch, tmp_path, 3)
    names = ["cloudtrail_20260802_1d_part01.json.log", "cloudtrail_20260801_1d_extra.json.log",
             "cloudtrail_20260801_1d_part00.json.log", "cloudtrail_20260801_1d_part001.json.log",
             "cloudtrail_20260801_1d_part0100.json.log", "cloudtrail_20260801_1d_part5.json.log",
             "cloudtrail_20260801_1d_part.json.log", "cloudtrail_20260801_1d_part01x.json.log",
             "cloudtrail_20260801_1d_part０１.json.log", "cloudtrail_20260801_1d_part٠١.json.log",
             "syslog_20260801_1d.log"]
    entries = _seed(tmp_path, names)
    control_name = "cloudtrail_20260801_1d_part01\n.json.log"
    private_write_bytes(tmp_path / control_name, b"unrecorded\n")
    _run(monkeypatch, tmp_path, 2)
    after = read_manifest(tmp_path / PROVENANCE_MANIFEST_NAME)
    for name in names:
        assert (tmp_path / name).read_bytes() == b"retained\n"
        assert after.entries[name] == entries[name]
    assert (tmp_path / control_name).read_bytes() == b"unrecorded\n"


def test_splunk_reexport_preserves_a_part_looking_sibling(monkeypatch, tmp_path, capsys) -> None:
    _run(monkeypatch, tmp_path, 1, split=False)
    entries = _seed(tmp_path, ["foo_part01.log"])
    monkeypatch.setattr(splunk, "fetch", lambda *a, **kw: (
        [{"_time": "2026-08-01T00:00:01Z", "_raw": "synthetic"}],
        {"units": 1, "unit_label": "chunks"},
    ))
    config = {"export": {"splunk": {"host": "192.0.2.20", "query": {"default": {"spl": "x"}}}}}
    for _ in range(2):
        capsys.readouterr()
        exporters.run_export(config, "splunk", [], START, END, str(tmp_path / "foo.log"), False)
        assert "note: removed" not in capsys.readouterr().out
        assert (tmp_path / "foo_part01.log").read_bytes() == b"retained\n"
        assert read_manifest(tmp_path / PROVENANCE_MANIFEST_NAME).entries["foo_part01.log"] == entries["foo_part01.log"]


@pytest.mark.parametrize("kind", ["unrecorded-link", "directory", "dangling"])
def test_retirement_distinguishes_disk_types_from_manifest_entries(
    monkeypatch, tmp_path, capsys, kind,
) -> None:
    _run(monkeypatch, tmp_path, 3)
    stale = tmp_path / cloudtrail._split_name(Path(LOGICAL), 3).name
    stale.unlink()
    target = tmp_path / "link-target.txt"
    if kind == "unrecorded-link":
        target.write_bytes(b"untouched\n")
        stale.symlink_to(target)
        entries = dict(read_manifest(tmp_path / PROVENANCE_MANIFEST_NAME).entries)
        del entries[stale.name]
        _set_entries(tmp_path, entries)
    elif kind == "directory":
        stale.mkdir()
    capsys.readouterr()
    _run(monkeypatch, tmp_path, 2)
    output = capsys.readouterr().out
    assert stale.name not in read_manifest(tmp_path / PROVENANCE_MANIFEST_NAME).entries
    if kind == "unrecorded-link":
        assert not stale.is_symlink() and target.read_bytes() == b"untouched\n"
        assert "note: removed 1 file left" in output
    else:
        assert stale.is_dir() if kind == "directory" else not stale.exists()
        assert "note: removed" not in output


@pytest.mark.parametrize("change", ["disappear", "directory", "denied"])
def test_retirement_rechecks_type_and_only_tolerates_disappearance(
    monkeypatch, tmp_path, capsys, change,
) -> None:
    _run(monkeypatch, tmp_path, 3)
    stale = tmp_path / cloudtrail._split_name(Path(LOGICAL), 3).name
    real_lstat = Path.lstat
    changed = False

    def replace_before_check(path, *args, **kwargs):
        nonlocal changed
        if path == stale and not changed:
            changed = True
            if change == "denied":
                raise PermissionError("injected retirement denial")
            stale.unlink()
            if change == "directory":
                stale.mkdir()
        return real_lstat(path, *args, **kwargs)

    capsys.readouterr()
    with monkeypatch.context() as patch:
        patch.setattr(Path, "lstat", replace_before_check)
        if change == "denied":
            with pytest.raises(PermissionError, match="injected retirement"):
                _run(patch, tmp_path, 2)
        else:
            _run(patch, tmp_path, 2)
    assert "note: removed" not in capsys.readouterr().out
    if change == "directory":
        assert stale.is_dir()
    elif change == "denied":
        assert stale.exists()


@pytest.mark.parametrize("window", ["before-retirement", "before-manifest"])
def test_interrupted_generation_is_repaired_by_the_next_commit(monkeypatch, tmp_path, window) -> None:
    _run(monkeypatch, tmp_path, 3)
    stale = tmp_path / cloudtrail._split_name(Path(LOGICAL), 3).name
    real_unlink, real_replace = os.unlink, os.replace

    def interrupt_unlink(path, *args, **kwargs):
        if path == stale:
            raise OSError("injected before retirement")
        return real_unlink(path, *args, **kwargs)

    def interrupt_manifest(source, destination):
        if Path(destination).name == PROVENANCE_MANIFEST_NAME:
            raise OSError("injected before manifest")
        return real_replace(source, destination)

    with monkeypatch.context() as patch:
        if window == "before-retirement":
            patch.setattr(exporters.os, "unlink", interrupt_unlink)
        else:
            patch.setattr(exporters.os, "replace", interrupt_manifest)
        with pytest.raises(OSError, match="injected before"):
            _run(patch, tmp_path, 2)
    manifest = read_manifest(tmp_path / PROVENANCE_MANIFEST_NAME)
    assert stale.name in manifest.entries
    selected = discover_cloudtrail_files(tmp_path)
    if window == "before-retirement":
        assert stale in selected
        assert validate_selected_files([stale])[0].state is AvailabilityState.TRUSTED
    else:
        assert stale not in selected
        assert len(validate_selected_files(selected)) == 2
    _run(monkeypatch, tmp_path, 2)
    assert not stale.exists()
    assert set(read_manifest(tmp_path / PROVENANCE_MANIFEST_NAME).entries) == _parts(2)


def test_lock_covers_retirement_and_both_directory_syncs(monkeypatch, tmp_path) -> None:
    _run(monkeypatch, tmp_path, 3)
    events = []
    held = False
    real_flock, real_replace = fcntl.flock, os.replace
    real_unlink, real_sync = os.unlink, exporters._fsync_directory

    def flock(fd, operation):
        nonlocal held
        result = real_flock(fd, operation)
        held = operation == fcntl.LOCK_EX
        return result

    def replace(source, destination):
        assert held
        events.append("manifest" if Path(destination).name == PROVENANCE_MANIFEST_NAME else "data")
        return real_replace(source, destination)

    def unlink(path, *args, **kwargs):
        if path == tmp_path / cloudtrail._split_name(Path(LOGICAL), 3).name:
            assert held
            events.append("unlink")
        return real_unlink(path, *args, **kwargs)

    def sync(path):
        assert held
        events.append("sync")
        return real_sync(path)

    monkeypatch.setattr(exporters.fcntl, "flock", flock)
    monkeypatch.setattr(exporters.os, "replace", replace)
    monkeypatch.setattr(exporters.os, "unlink", unlink)
    monkeypatch.setattr(exporters, "_fsync_directory", sync)
    _run(monkeypatch, tmp_path, 2)
    assert events == ["data", "data", "unlink", "sync", "manifest", "sync"]
    assert not held


@pytest.mark.parametrize("failure", ["gone", "denied"])
def test_unlink_only_tolerates_a_missing_leaf(monkeypatch, tmp_path, capsys, failure) -> None:
    _run(monkeypatch, tmp_path, 3)
    stale = tmp_path / cloudtrail._split_name(Path(LOGICAL), 3).name
    real_unlink = os.unlink

    def unlink(path, *args, **kwargs):
        if path == stale:
            if failure == "denied":
                raise PermissionError("injected unlink denial")
            real_unlink(path)
            raise FileNotFoundError("injected concurrent disappearance")
        return real_unlink(path, *args, **kwargs)

    capsys.readouterr()
    with monkeypatch.context() as patch:
        patch.setattr(exporters.os, "unlink", unlink)
        if failure == "denied":
            with pytest.raises(PermissionError, match="injected unlink"):
                _run(patch, tmp_path, 2)
        else:
            _run(patch, tmp_path, 2)
            assert stale.name not in read_manifest(tmp_path / PROVENANCE_MANIFEST_NAME).entries
    assert "note: removed" not in capsys.readouterr().out


@pytest.mark.parametrize("overrides", [
    {"logical_name": "../other.json.log"}, {"logical_name": "unsafe\n.json.log"},
    {"logical_name": ".sigwood-export-provenance.json"},
    {"logical_name": "other.json.log"}, {"parts": "yes"},
])
def test_invalid_family_arguments_refuse_before_final_mutation(monkeypatch, tmp_path, overrides) -> None:
    _run(monkeypatch, tmp_path, 3)
    before = {p.name: p.read_bytes() for p in tmp_path.iterdir() if p.is_file()}
    commit = exporters._commit_export_provenance

    def invalid(staged, **kwargs):
        kwargs.update(overrides)
        return commit(staged, **kwargs)

    monkeypatch.setattr(exporters, "_commit_export_provenance", invalid)
    with pytest.raises(ValueError):
        _run(monkeypatch, tmp_path, 2)
    assert {p.name: p.read_bytes() for p in tmp_path.iterdir() if p.is_file()} == before
