"""U2 archive planner and observation model controls."""

from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

from sigwood.era.eligibility import SourcePartition, eligible_display_day, eligible_iso_weeks
from sigwood.era.observation import (
    Availability,
    CaptureLossInterval,
    Completeness,
    FamilyDayObservation,
    ParseUsability,
    summarize_capture_loss,
)
from sigwood.era.planner import ArchivePlanner, InventoryState, canonical_date_group
import sigwood.era.planner as planner_mod

UTC = timezone.utc


def _source_dir(root: Path, name: str, *, files: tuple[str, ...] = ()) -> Path:
    directory = root / name
    directory.mkdir()
    for file_name in files:
        (directory / file_name).write_bytes(b"fixture")
    return directory


def test_tsvpre_collapses_to_one_canonical_day_and_uses_stat_bytes(tmp_path: Path) -> None:
    primary = _source_dir(tmp_path, "2026-04-12", files=("conn.1.log.gz",))
    renamed = _source_dir(tmp_path, "2026-04-12-TSVPRE", files=("dns.1.log.gz",))
    plan = ArchivePlanner(tmp_path, baseline_dates={date(2026, 4, 12)}).plan()

    assert [group.canonical_date for group in plan.groups] == [date(2026, 4, 12)]
    assert plan.groups[0].directories == (primary, renamed)
    assert plan.groups[0].tsvpre_collapsed is True
    assert plan.work_estimate.compressed_bytes == 14
    assert plan.reconciliation.collapsed_tsvpre_dates == (date(2026, 4, 12),)
    assert plan.reconciliation.missing_dates == ()


def test_only_exact_tsvpre_is_a_date_alias(tmp_path: Path) -> None:
    _source_dir(tmp_path, "2026-04-12-OTHER")
    assert canonical_date_group(tmp_path / "2026-04-12-OTHER") is None
    assert canonical_date_group(tmp_path / "2026-04-12-TSVPRE") == (date(2026, 4, 12), True)
    assert ArchivePlanner(tmp_path).plan().groups == ()


def test_empty_family_and_post_baseline_drift_remain_visible(tmp_path: Path) -> None:
    _source_dir(tmp_path, "2026-04-12-TSVPRE", files=("conn.1.log.gz",))
    _source_dir(tmp_path, "2026-04-13", files=("conn.1.log.gz",))
    plan = ArchivePlanner(tmp_path, baseline_dates={date(2026, 4, 12)}).plan()

    assert plan.reconciliation.baseline_source_directory_absent == (date(2026, 4, 12),)
    assert plan.reconciliation.post_baseline_dates == (date(2026, 4, 13),)
    apr12 = dict(plan.inventory)[date(2026, 4, 12)]
    assert next(item for item in apr12 if item.family == "dns").state is InventoryState.EMPTY


def test_denied_directory_is_a_typed_inventory_fact(tmp_path: Path, monkeypatch) -> None:
    _source_dir(tmp_path, "2026-04-12")

    def denied(*args, _directory_skips, **kwargs):
        _directory_skips["denied"] = object()
        return []

    monkeypatch.setattr(planner_mod, "discover_for_source_key", denied)
    families = dict(ArchivePlanner(tmp_path).plan().inventory)[date(2026, 4, 12)]
    assert all(family.state is InventoryState.DENIED for family in families)


def test_capture_loss_absence_is_unknown_and_peers_never_cross_sum() -> None:
    observation = FamilyDayObservation(
        availability=Availability.PRESENT,
        parse_usability=ParseUsability.USABLE,
        completeness=Completeness.UNKNOWN,
        committed_usable_rows=4,
    )
    assert observation.completeness is Completeness.UNKNOWN
    start = datetime(2026, 6, 1, tzinfo=UTC)
    summaries = summarize_capture_loss(
        (
            CaptureLossInterval("peer-a", start, start + timedelta(hours=1), 1, 9),
            CaptureLossInterval("peer-b", start, start + timedelta(hours=1), 9, 1),
        )
    )
    assert [(summary.peer, summary.weighted_loss_percent) for summary in summaries] == [
        ("peer-a", 10.0),
        ("peer-b", 90.0),
    ]


def test_non_utc_day_requires_every_overlapping_partition() -> None:
    zone = ZoneInfo("America/Chicago")
    day = date(2026, 6, 2)
    start = datetime(2026, 6, 2, tzinfo=UTC)
    partitions = (
        SourcePartition(start - timedelta(days=1), start, True, True),
        SourcePartition(start, start + timedelta(days=1), True, False),
        SourcePartition(start + timedelta(days=1), start + timedelta(days=2), True, True),
    )
    result = eligible_display_day(
        day,
        zone=zone,
        partitions=partitions,
        committed_usable_timestamps=(datetime(2026, 6, 2, 12, tzinfo=UTC),),
    )
    assert result.partition_count == 2
    assert result.eligible is False
    assert result.failed_partitions == (partitions[1],)


def test_source_partitions_reject_non_utc_boundaries() -> None:
    zone = ZoneInfo("America/Chicago")
    start = datetime(2026, 6, 1, tzinfo=zone)
    try:
        SourcePartition(start, start + timedelta(days=1), True, True)
    except ValueError as exc:
        assert "UTC" in str(exc)
    else:
        raise AssertionError("non-UTC source partition was accepted")


def test_both_dst_boundaries_use_instant_projection() -> None:
    zone = ZoneInfo("America/Chicago")
    for day in (date(2026, 3, 8), date(2026, 11, 1)):
        local_start = datetime.combine(day, datetime.min.time(), tzinfo=zone)
        local_end = local_start + timedelta(days=1)
        utc_start = local_start.astimezone(UTC).replace(hour=0, minute=0, second=0, microsecond=0)
        partitions = (
            SourcePartition(utc_start, utc_start + timedelta(days=1), True, True),
            SourcePartition(utc_start + timedelta(days=1), utc_start + timedelta(days=2), True, False),
        )
        result = eligible_display_day(
            day,
            zone=zone,
            partitions=partitions,
            committed_usable_timestamps=(local_start + timedelta(hours=2),),
        )
        assert local_end > local_start
        assert result.eligible is False


def test_iso_week_requires_seven_days_and_six_eligible() -> None:
    first = date(2026, 6, 1)
    days = [
        eligible_display_day(
            first + timedelta(days=index),
            zone=ZoneInfo("UTC"),
            partitions=(
                SourcePartition(
                    datetime(2026, 6, 1 + index, tzinfo=UTC),
                    datetime(2026, 6, 2 + index, tzinfo=UTC),
                    True,
                    index != 0,
                ),
            ),
            committed_usable_timestamps=(datetime(2026, 6, 1 + index, 12, tzinfo=UTC),),
        )
        for index in range(7)
    ]
    assert eligible_iso_weeks(days) == ((2026, 23),)
