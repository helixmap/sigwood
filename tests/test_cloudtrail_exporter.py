"""Tests for the CloudTrail S3 exporter framework.

No live S3 connection - boto3 is mocked via a hand-rolled FakeS3Client.
All bucket names and account IDs are obviously fake.

botocore-dependent tests (those constructing real ClientError / credential /
MissingDependency classes) live in tests/test_cloudtrail_exporter_botocore.py
behind an importorskip. This file is intentionally AWS-lib-free so it runs on a
base checkout: the ``_boto3_stand_in`` autouse fixture supplies a fake ``boto3``
module when the real one is absent, so the FakeS3Client patches land regardless.
"""

from __future__ import annotations

import io
import json
import sys
import types
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from sigwood.common import display as display_mod
from sigwood.common.display import (
    _CURSOR_HIDE,
    _CURSOR_SHOW,
    hidden_cursor,
)
from sigwood.common.errors import ExportAborted
from sigwood.exporters import _resolve_output_path
from sigwood.exporters import cloudtrail as ct

from tests._cloudtrail_fakes import FakeS3Client, _gz_envelope


@pytest.fixture(autouse=True)
def _boto3_stand_in(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep these FakeS3Client tests genuinely AWS-lib-free (their whole point).

    The tests patch ``ct.boto3.client`` to hand back a FakeS3Client; on a base
    checkout boto3 is not installed, so ``ct.boto3`` is ``None`` and that patch
    would raise ``AttributeError``. Stand in an empty module object carrying a
    ``client`` attribute so the per-test patch lands; a no-op when boto3 is present.
    """
    if ct.boto3 is None:
        monkeypatch.setattr(ct, "boto3", types.SimpleNamespace(client=None))


# ── module-level contract ─────────────────────────────────────────────────────


def test_is_configured() -> None:
    assert ct.is_configured({"path": "s3://example-trail-bucket/AWSLogs/"})
    assert not ct.is_configured({})
    assert not ct.is_configured({"path": ""})
    assert not ct.is_configured({"path": "   "})


def test_summary_descriptor() -> None:
    assert ct.summary_descriptor({"path": "s3://example-trail-bucket/AWSLogs/"}) == \
        "s3://example-trail-bucket/AWSLogs/"
    assert ct.summary_descriptor({}) == ""


def test_implicit_default_query_and_extension() -> None:
    # Filename fix depends on the basename being explicit - assert it directly.
    assert ct.implicit_default_query() == {"output_basename": "cloudtrail"}
    assert ct.OUTPUT_EXTENSION == ".json.log"


def test_filename_json_log(tmp_path: Path) -> None:
    # _resolve_output_path with extension=".json.log" produces cloudtrail_..._Nd.json.log
    query_cfg = {"output_basename": "cloudtrail"}
    since = datetime(2026, 6, 1, 0, 0, 0)
    until = datetime(2026, 6, 8, 0, 0, 0)
    result = _resolve_output_path(
        query_cfg, str(tmp_path), since, until, "default",
        extension=".json.log",
        backend_config={}, sigwood_config={},
    )
    assert result.name == "cloudtrail_20260601_7d.json.log"


# ── _parse_s3_path ────────────────────────────────────────────────────────────


def test_parse_s3_path_with_prefix() -> None:
    bucket, prefix = ct._parse_s3_path("s3://example-trail-bucket/AWSLogs/")
    assert bucket == "example-trail-bucket"
    assert prefix == "AWSLogs/"


def test_parse_s3_path_root_only() -> None:
    bucket, prefix = ct._parse_s3_path("s3://example-trail-bucket")
    assert bucket == "example-trail-bucket"
    assert prefix == ""


def test_parse_s3_path_appends_trailing_slash() -> None:
    _, prefix = ct._parse_s3_path("s3://example-trail-bucket/AWSLogs")
    assert prefix == "AWSLogs/"


def test_parse_s3_path_bad_scheme() -> None:
    with pytest.raises(ValueError, match="must start with s3://"):
        ct._parse_s3_path("https://example-trail-bucket/")


# ── _enumerate_days (day-range overlap) ───────────────────────────────────────


def test_day_range_excludes_midnight_upper_bound() -> None:
    # [2026-06-01 00:00 UTC, 2026-06-02 00:00 UTC) - only June 1 overlaps.
    # Use tz-aware UTC datetimes so the assertion is stable across test
    # runners regardless of local timezone (S3 partitions are UTC-keyed).
    since = datetime(2026, 6, 1, 0, 0, 0, tzinfo=timezone.utc)
    until = datetime(2026, 6, 2, 0, 0, 0, tzinfo=timezone.utc)
    days = ct._enumerate_days(since, until)
    assert days == [(2026, 6, 1)]


def test_day_range_includes_second_day_when_window_spills_in() -> None:
    # One second past midnight pulls in the next day
    since = datetime(2026, 6, 1, 0, 0, 0, tzinfo=timezone.utc)
    until = datetime(2026, 6, 2, 0, 0, 1, tzinfo=timezone.utc)
    days = ct._enumerate_days(since, until)
    assert days == [(2026, 6, 1), (2026, 6, 2)]


def test_day_range_local_window_includes_utc_spillover_day() -> None:
    """A local non-UTC window must enumerate S3 days in UTC.

    2026-06-01 00:00 -0500 → 2026-06-02 00:00 -0500 is 2026-06-01 05:00 UTC →
    2026-06-02 05:00 UTC, which spans two UTC date partitions. A UTC-blind
    enumeration would return only [(2026, 6, 1)] - events under 2026/06/02/
    would be missed.
    """
    tz_minus5 = timezone(timedelta(hours=-5))
    since = datetime(2026, 6, 1, 0, 0, 0, tzinfo=tz_minus5)
    until = datetime(2026, 6, 2, 0, 0, 0, tzinfo=tz_minus5)
    assert ct._enumerate_days(since, until) == [(2026, 6, 1), (2026, 6, 2)]


def test_day_range_empty_for_zero_or_inverted_window() -> None:
    same = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
    assert ct._enumerate_days(same, same) == []
    assert ct._enumerate_days(same, same.replace(hour=11)) == []


# ── _has_cloudtrail_segment ───────────────────────────────────────────────────


def test_cloudtrail_segment_detection() -> None:
    assert ct._has_cloudtrail_segment("AWSLogs/000000000000/CloudTrail/us-east-1/")
    assert ct._has_cloudtrail_segment("CloudTrail/us-east-1/")
    assert not ct._has_cloudtrail_segment("AWSLogs/000000000000/elasticloadbalancing/us-east-1/")
    # Digest is a different segment, not a match
    assert not ct._has_cloudtrail_segment("AWSLogs/000000000000/CloudTrail-Digest/us-east-1/")


# ── _split_name ───────────────────────────────────────────────────────────────


def test_split_name_inserts_part_before_double_suffix() -> None:
    base = Path("/tmp/cloudtrail_20260601_7d.json.log")
    result = ct._split_name(base, 1)
    assert result.name == "cloudtrail_20260601_7d_part01.json.log"
    result = ct._split_name(base, 12)
    assert result.name == "cloudtrail_20260601_7d_part12.json.log"


# ── prefix construction / year-invariant walk ────────────────────────────────


def _build_classic_bucket() -> FakeS3Client:
    """s3://example-trail-bucket/AWSLogs/000000000000/CloudTrail/us-east-1/2026/06/01/..."""
    c = FakeS3Client()
    base = "AWSLogs/000000000000/CloudTrail/us-east-1/2026/06/01/"
    events = [{"eventTime": "2026-06-01T12:00:00Z", "eventName": "RunInstances"}]
    c.add_object(base + "obj1.json.gz", _gz_envelope(events))
    return c


def test_prefix_construction_classic(monkeypatch) -> None:
    client = _build_classic_bucket()
    monkeypatch.setattr(ct.boto3, "client", lambda _svc: client)

    cfg = {"path": "s3://example-trail-bucket/AWSLogs/", "egress_warn_gb": 100}
    since = datetime(2026, 6, 1, 0, 0, 0, tzinfo=timezone.utc)
    until = datetime(2026, 6, 2, 0, 0, 0, tzinfo=timezone.utc)
    events, meta = ct.fetch({}, cfg, since, until, verbose=False)

    assert meta == {"units": 1, "unit_label": "objects"}
    assert len(events) == 1
    assert events[0]["eventName"] == "RunInstances"


def test_prefix_construction_org_layout(monkeypatch) -> None:
    """Org-trail inserts an o-xxxx segment before the account id - walk still finds years."""
    client = FakeS3Client()
    base = "AWSLogs/o-aaaa1111/000000000000/CloudTrail/us-east-1/2026/06/01/"
    events = [{"eventTime": "2026-06-01T01:23:45Z", "eventName": "AssumeRole"}]
    client.add_object(base + "obj1.json.gz", _gz_envelope(events))
    monkeypatch.setattr(ct.boto3, "client", lambda _svc: client)

    cfg = {"path": "s3://example-trail-bucket/AWSLogs/", "egress_warn_gb": 100}
    since = datetime(2026, 6, 1, 0, 0, 0, tzinfo=timezone.utc)
    until = datetime(2026, 6, 2, 0, 0, 0, tzinfo=timezone.utc)
    events, meta = ct.fetch({}, cfg, since, until, verbose=False)
    assert meta["units"] == 1
    assert events[0]["eventName"] == "AssumeRole"


def test_cloudtrail_digest_branch_skipped(monkeypatch) -> None:
    """A sibling CloudTrail-Digest tree must not be descended."""
    client = _build_classic_bucket()
    # Add a Digest sibling with its own year tree and objects
    digest_base = "AWSLogs/000000000000/CloudTrail-Digest/us-east-1/2026/06/01/"
    client.add_object(digest_base + "manifest.json.gz", _gz_envelope([
        {"eventTime": "2026-06-01T12:00:00Z", "eventName": "DIGEST_MARKER"},
    ]))
    monkeypatch.setattr(ct.boto3, "client", lambda _svc: client)

    cfg = {"path": "s3://example-trail-bucket/AWSLogs/", "egress_warn_gb": 100}
    since = datetime(2026, 6, 1, 0, 0, 0, tzinfo=timezone.utc)
    until = datetime(2026, 6, 2, 0, 0, 0, tzinfo=timezone.utc)
    events, meta = ct.fetch({}, cfg, since, until, verbose=False)
    # Only the event from the CloudTrail event tree, never the digest marker
    assert meta["units"] == 1
    assert all(e["eventName"] != "DIGEST_MARKER" for e in events)


def test_non_cloudtrail_year_tree_rejected(monkeypatch) -> None:
    """An ELB tree that shares the YYYY/MM/DD layout must not be picked up."""
    client = FakeS3Client()
    base = "AWSLogs/000000000000/elasticloadbalancing/us-east-1/2026/06/01/"
    client.add_object(base + "obj1.json.gz", _gz_envelope([
        {"eventTime": "2026-06-01T12:00:00Z", "eventName": "ELB_EVENT"},
    ]))
    monkeypatch.setattr(ct.boto3, "client", lambda _svc: client)

    cfg = {"path": "s3://example-trail-bucket/AWSLogs/", "egress_warn_gb": 100}
    since = datetime(2026, 6, 1, 0, 0, 0, tzinfo=timezone.utc)
    until = datetime(2026, 6, 2, 0, 0, 0, tzinfo=timezone.utc)
    with pytest.raises(ValueError, match="no CloudTrail objects found"):
        ct.fetch({}, cfg, since, until, verbose=False)


def test_is_cloudtrail_ancestor_segment() -> None:
    """The ancestor-segment heuristic accepts only structural parents of CloudTrail/."""
    # Accepted: things that can sit above CloudTrail/ in standard AWS layouts.
    assert ct._is_cloudtrail_ancestor_segment("AWSLogs/")
    assert ct._is_cloudtrail_ancestor_segment("CloudTrail/")
    assert ct._is_cloudtrail_ancestor_segment("000000000000/")    # 12-digit account
    assert ct._is_cloudtrail_ancestor_segment("12345/")           # lenient on digit count
    assert ct._is_cloudtrail_ancestor_segment("o-aaaa1111/")      # AWS organization id
    # Rejected: sibling AWS service trees, anything else.
    assert not ct._is_cloudtrail_ancestor_segment("elasticloadbalancing/")
    assert not ct._is_cloudtrail_ancestor_segment("RDS/")
    assert not ct._is_cloudtrail_ancestor_segment("vpc-flow-logs/")
    # Digest is also independently blocked by the explicit digest check, but the
    # heuristic must reject it too.
    assert not ct._is_cloudtrail_ancestor_segment("CloudTrail-Digest/")


def test_walk_does_not_descend_non_cloudtrail_service_branches(monkeypatch) -> None:
    """The walker must NOT list inside elasticloadbalancing/ etc.

    Two trees live under the same account: a real CloudTrail tree (events) and
    a sibling ELB tree. The walker must descend only into CloudTrail/. We
    assert no recorded list call's Prefix contains 'elasticloadbalancing/'.
    """
    client = FakeS3Client()
    ct_base = "AWSLogs/000000000000/CloudTrail/us-east-1/2026/06/01/"
    elb_base = "AWSLogs/000000000000/elasticloadbalancing/us-east-1/2026/06/01/"
    client.add_object(ct_base + "obj1.json.gz", _gz_envelope([
        {"eventTime": "2026-06-01T01:00:00Z", "eventName": "Good"},
    ]))
    client.add_object(elb_base + "elb.log", b"some content")
    monkeypatch.setattr(ct.boto3, "client", lambda _svc: client)

    cfg = {"path": "s3://example-trail-bucket/AWSLogs/", "egress_warn_gb": 100}
    since = datetime(2026, 6, 1, 0, 0, 0, tzinfo=timezone.utc)
    until = datetime(2026, 6, 2, 0, 0, 0, tzinfo=timezone.utc)
    events, meta = ct.fetch({}, cfg, since, until, verbose=False)

    assert meta["units"] == 1
    assert events[0]["eventName"] == "Good"
    # The recorder must not show ANY list call into the ELB branch.
    for listed in client.list_prefix_log:
        assert "elasticloadbalancing" not in listed, (
            f"walker listed inside non-CloudTrail branch: {listed!r}"
        )


def test_fetch_includes_utc_spillover_day_under_local_window(monkeypatch) -> None:
    """End-to-end: a local UTC-5 window must fetch events from the next UTC day.

    Window 2026-06-01 00:00 -0500 → 2026-06-02 00:00 -0500 covers UTC
    05:00..05:00 of the next UTC day, so an event at 2026-06-02T03:00:00Z
    sits under the 2026/06/02/ partition AND inside the precise window.
    A single-partition _enumerate_days would list only 2026/06/01/, so this
    event would be silently dropped.
    """
    client = FakeS3Client()
    d1 = "AWSLogs/000000000000/CloudTrail/us-east-1/2026/06/01/"
    d2 = "AWSLogs/000000000000/CloudTrail/us-east-1/2026/06/02/"
    client.add_object(d1 + "a.json.gz", _gz_envelope([
        {"eventTime": "2026-06-01T12:00:00Z", "eventName": "InDay1"},
    ]))
    client.add_object(d2 + "b.json.gz", _gz_envelope([
        {"eventTime": "2026-06-02T03:00:00Z", "eventName": "InUtcSpillover"},
        {"eventTime": "2026-06-02T10:00:00Z", "eventName": "PastWindow"},
    ]))
    monkeypatch.setattr(ct.boto3, "client", lambda _svc: client)

    tz_minus5 = timezone(timedelta(hours=-5))
    cfg = {"path": "s3://example-trail-bucket/AWSLogs/", "egress_warn_gb": 100}
    since = datetime(2026, 6, 1, 0, 0, 0, tzinfo=tz_minus5)
    until = datetime(2026, 6, 2, 0, 0, 0, tzinfo=tz_minus5)
    events, meta = ct.fetch({}, cfg, since, until, verbose=False)

    names = [e["eventName"] for e in events]
    # Both day partitions are listed.
    assert meta["units"] == 2
    # Spillover event is present; past-window event is trimmed.
    assert "InDay1" in names
    assert "InUtcSpillover" in names
    assert "PastWindow" not in names


def test_empty_result_raises(monkeypatch) -> None:
    client = FakeS3Client()  # totally empty bucket
    monkeypatch.setattr(ct.boto3, "client", lambda _svc: client)
    cfg = {"path": "s3://example-trail-bucket/AWSLogs/", "egress_warn_gb": 100}
    since = datetime(2026, 6, 1, tzinfo=timezone.utc)
    until = datetime(2026, 6, 2, tzinfo=timezone.utc)
    with pytest.raises(ValueError, match="no CloudTrail objects found"):
        ct.fetch({}, cfg, since, until, verbose=False)


# ── bad-object handling ──────────────────────────────────────────────────────


def test_bad_object_skipped_with_warning(monkeypatch, capsys) -> None:
    client = FakeS3Client()
    base = "AWSLogs/000000000000/CloudTrail/us-east-1/2026/06/01/"
    good = [{"eventTime": "2026-06-01T12:00:00Z", "eventName": "Good"}]
    client.add_object(base + "good.json.gz", _gz_envelope(good))
    client.add_object(base + "corrupt.json.gz", b"this is not gzip")
    monkeypatch.setattr(ct.boto3, "client", lambda _svc: client)

    cfg = {"path": "s3://example-trail-bucket/AWSLogs/", "egress_warn_gb": 100}
    since = datetime(2026, 6, 1, tzinfo=timezone.utc)
    until = datetime(2026, 6, 2, tzinfo=timezone.utc)
    events, meta = ct.fetch({}, cfg, since, until, verbose=False)

    assert meta["units"] == 2  # both objects counted
    assert len(events) == 1    # only the good one parsed
    assert events[0]["eventName"] == "Good"
    err = capsys.readouterr().err
    assert "skipped unreadable object:" in err
    assert "corrupt.json.gz" in err


# ── egress guard ─────────────────────────────────────────────────────────────


def _bucket_with_large_object(monkeypatch, body_size: int) -> FakeS3Client:
    """Build a bucket whose single object reports `body_size` bytes."""
    client = FakeS3Client()
    base = "AWSLogs/000000000000/CloudTrail/us-east-1/2026/06/01/"
    events = [{"eventTime": "2026-06-01T01:00:00Z", "eventName": "x"}]
    body = _gz_envelope(events)
    # Report a fake huge size via Size, but the body itself is tiny so the parse works.
    client.add_object(base + "obj1.json.gz", body, size=body_size)
    monkeypatch.setattr(ct.boto3, "client", lambda _svc: client)
    return client


def test_egress_guard_fires_and_user_declines(monkeypatch) -> None:
    _bucket_with_large_object(monkeypatch, body_size=10 * 10**9)  # 10 GB
    monkeypatch.setattr("builtins.input", lambda *_: "n")
    cfg = {"path": "s3://example-trail-bucket/AWSLogs/", "egress_warn_gb": 5.0}
    since = datetime(2026, 6, 1, tzinfo=timezone.utc)
    until = datetime(2026, 6, 2, tzinfo=timezone.utc)
    with pytest.raises(ExportAborted, match="aborted by user"):
        ct.fetch({}, cfg, since, until, verbose=False)


def test_egress_guard_user_accepts(monkeypatch) -> None:
    _bucket_with_large_object(monkeypatch, body_size=10 * 10**9)
    monkeypatch.setattr("builtins.input", lambda *_: "y")
    cfg = {"path": "s3://example-trail-bucket/AWSLogs/", "egress_warn_gb": 5.0}
    since = datetime(2026, 6, 1, tzinfo=timezone.utc)
    until = datetime(2026, 6, 2, tzinfo=timezone.utc)
    events, meta = ct.fetch({}, cfg, since, until, verbose=False)
    assert meta["units"] == 1
    assert len(events) == 1


def test_egress_prompt_temporarily_shows_then_rehides_cursor(monkeypatch) -> None:
    class _CursorTTY(io.StringIO):
        def isatty(self) -> bool:
            return True

    fake = _CursorTTY()
    observed_at_input: list[str] = []
    observed_after_input: list[str] = []
    _bucket_with_large_object(monkeypatch, body_size=10 * 10**9)
    monkeypatch.delenv("TERM", raising=False)
    monkeypatch.setattr(sys, "stderr", fake)
    monkeypatch.setattr(display_mod, "_NARRATION_ENABLED", True)

    def _accept(*_args: object, **_kwargs: object) -> str:
        observed_at_input.append(fake.getvalue())
        assert fake.getvalue().endswith(_CURSOR_SHOW)
        return "y"

    def _checking_tqdm(items, **_kwargs):
        observed_after_input.append(fake.getvalue())
        assert fake.getvalue().rfind(_CURSOR_HIDE) > fake.getvalue().rfind(
            _CURSOR_SHOW
        )
        return items

    monkeypatch.setattr("builtins.input", _accept)
    monkeypatch.setattr(ct, "tqdm", _checking_tqdm)
    cfg = {"path": "s3://example-trail-bucket/AWSLogs/", "egress_warn_gb": 5.0}
    since = datetime(2026, 6, 1, tzinfo=timezone.utc)
    until = datetime(2026, 6, 2, tzinfo=timezone.utc)

    with hidden_cursor(fake):
        events, _meta = ct.fetch({}, cfg, since, until, verbose=False)

    assert len(events) == 1
    assert observed_at_input and observed_after_input
    assert fake.getvalue().count(_CURSOR_HIDE) == 2
    assert fake.getvalue().count(_CURSOR_SHOW) == 2
    assert fake.getvalue().endswith(_CURSOR_SHOW)


def test_egress_guard_bypassed_by_skip_confirm(monkeypatch) -> None:
    _bucket_with_large_object(monkeypatch, body_size=10 * 10**9)
    # Recorder: input must NOT be called when skip_confirm is True.
    called: list[bool] = []

    def _recording_input(*_args, **_kw):
        called.append(True)
        return "n"

    monkeypatch.setattr("builtins.input", _recording_input)

    cfg = {"path": "s3://example-trail-bucket/AWSLogs/", "egress_warn_gb": 5.0}
    since = datetime(2026, 6, 1, tzinfo=timezone.utc)
    until = datetime(2026, 6, 2, tzinfo=timezone.utc)
    events, meta = ct.fetch({}, cfg, since, until, verbose=False, skip_confirm=True)
    assert called == []
    assert meta["units"] == 1
    assert len(events) == 1


def test_egress_guard_below_threshold_does_not_prompt(monkeypatch) -> None:
    _bucket_with_large_object(monkeypatch, body_size=1000)  # well under 5 GB

    def _no_input(*_a, **_kw):
        raise AssertionError("egress prompt must not fire below threshold")

    monkeypatch.setattr("builtins.input", _no_input)
    cfg = {"path": "s3://example-trail-bucket/AWSLogs/", "egress_warn_gb": 5.0}
    since = datetime(2026, 6, 1, tzinfo=timezone.utc)
    until = datetime(2026, 6, 2, tzinfo=timezone.utc)
    events, _meta = ct.fetch({}, cfg, since, until, verbose=False)
    assert len(events) == 1


# ── eventTime sort + window trim ─────────────────────────────────────────────


def test_event_time_sort_and_trim(monkeypatch) -> None:
    """Events arrive out-of-order across days; result is sorted & trimmed."""
    client = FakeS3Client()
    # Two objects, one for each day in the window. Events are not monotonic.
    d1 = "AWSLogs/000000000000/CloudTrail/us-east-1/2026/06/01/"
    d2 = "AWSLogs/000000000000/CloudTrail/us-east-1/2026/06/02/"
    client.add_object(d1 + "a.json.gz", _gz_envelope([
        {"eventTime": "2026-06-01T18:00:00Z", "eventName": "E_LATE"},
        {"eventTime": "2026-06-01T08:00:00Z", "eventName": "E_EARLY"},
        {"eventTime": "2026-05-31T23:00:00Z", "eventName": "E_BEFORE_WINDOW"},
    ]))
    client.add_object(d2 + "b.json.gz", _gz_envelope([
        # Past the precise upper bound - must be trimmed
        {"eventTime": "2026-06-02T05:00:00Z", "eventName": "E_AFTER_WINDOW"},
        # Inside the window (with seconds-spillover upper bound)
        {"eventTime": "2026-06-02T00:00:00Z", "eventName": "E_BOUNDARY"},
    ]))
    monkeypatch.setattr(ct.boto3, "client", lambda _svc: client)

    cfg = {"path": "s3://example-trail-bucket/AWSLogs/", "egress_warn_gb": 100}
    since = datetime(2026, 6, 1, 0, 0, 0, tzinfo=timezone.utc)
    # Pick an upper bound that includes E_BOUNDARY but not E_AFTER_WINDOW
    until = datetime(2026, 6, 2, 1, 0, 0, tzinfo=timezone.utc)
    events, _ = ct.fetch({}, cfg, since, until, verbose=False)

    names = [e["eventName"] for e in events]
    # E_BEFORE_WINDOW and E_AFTER_WINDOW must be filtered
    assert "E_BEFORE_WINDOW" not in names
    assert "E_AFTER_WINDOW" not in names
    # Remaining events are sorted ascending by eventTime
    assert names == ["E_EARLY", "E_LATE", "E_BOUNDARY"]


# ── write(): 2 GB split with _partNN-only-on-split ────────────────────────────


def test_write_no_split(tmp_path: Path) -> None:
    events = [{"eventTime": "2026-06-01T01:00:00Z", "eventName": "x"}]
    outpath = tmp_path / "cloudtrail_20260601_1d.json.log"
    n, _ = ct.write(events, outpath, verbose=False)
    assert n == 1
    assert outpath.exists()
    # No sibling _part* files
    assert sorted(p.name for p in tmp_path.iterdir()) == ["cloudtrail_20260601_1d.json.log"]


def test_write_splits_into_part_files(tmp_path: Path, monkeypatch) -> None:
    # Tiny split threshold forces splits without writing 2 GB.
    monkeypatch.setattr(ct, "_PART_SPLIT_BYTES", 200)
    # Each line is ~60-80 bytes; 10 events produces multiple parts.
    events = [
        {"eventTime": f"2026-06-01T01:00:{i:02d}Z", "eventName": "x", "i": i}
        for i in range(10)
    ]
    outpath = tmp_path / "cloudtrail_20260601_1d.json.log"
    n, _ = ct.write(events, outpath, verbose=False)

    assert n == 10
    # Bare file must NOT exist - first split renames it to _part01
    assert not outpath.exists()
    parts = sorted(tmp_path.glob("cloudtrail_20260601_1d_part*.json.log"))
    assert len(parts) >= 2  # at least one split occurred
    # Line counts sum to total, no line is split mid-row
    total_lines = 0
    for p in parts:
        text = p.read_text(encoding="utf-8")
        lines = text.splitlines()
        for line in lines:
            json.loads(line)   # each line must be a complete JSON object
        total_lines += len(lines)
    assert total_lines == 10


def test_write_split_threshold_just_below_does_not_split(tmp_path: Path, monkeypatch) -> None:
    # Pick a threshold larger than the entire payload.
    monkeypatch.setattr(ct, "_PART_SPLIT_BYTES", 10_000)
    events = [
        {"eventTime": f"2026-06-01T01:00:{i:02d}Z", "eventName": "x", "i": i}
        for i in range(3)
    ]
    outpath = tmp_path / "cloudtrail_20260601_1d.json.log"
    ct.write(events, outpath, verbose=False)
    assert outpath.exists()
    assert sorted(p.name for p in tmp_path.iterdir()) == ["cloudtrail_20260601_1d.json.log"]


# ── CLI clean-abort path ──────────────────────────────────────────────────────


def test_cli_export_aborted_exits_cleanly(monkeypatch, capsys) -> None:
    """ExportAborted from run_export becomes exit-0 in cli.main()."""
    from sigwood import cli
    from sigwood.common import config as cfg_mod

    # Avoid loading a real config from the user's filesystem.
    def _fake_load(_path=None):
        return {"export": {"splunk": {"host": "192.0.2.20", "port": 8089,
                                      "query": {"default": {"spl": "x"}}}}}

    monkeypatch.setattr(cfg_mod, "load", _fake_load)

    def _fake_run_export(*_args, **_kwargs):
        raise ExportAborted("sigwood export: aborted by user")

    # _run_export() rebinds via `from sigwood.exporters import run_export`, so
    # patching the symbol on the exporters package is what it picks up.
    monkeypatch.setattr("sigwood.exporters.run_export", _fake_run_export)

    with pytest.raises(SystemExit) as exc_info:
        cli.main(["export", "splunk"])

    assert exc_info.value.code == 0
    captured = capsys.readouterr()   # drain once
    assert "aborted by user" in captured.out
    assert "sigwood:" not in captured.err            # not the ValueError prefix
    assert "Run 'sigwood --help'" not in captured.err  # no usage nudge


# ── liveness narration (gate: stderr seals, prompt never spanned) ────────────


from tests.test_display import _FakeStream  # noqa: E402  reuse non-tty mock


def test_listing_seals_on_populated_path(monkeypatch) -> None:
    """Populated listing seals 'listed <N> objects (<GB> GB)' to stderr."""
    client = FakeS3Client()
    base = "AWSLogs/000000000000/CloudTrail/us-east-1/2026/06/01/"
    client.add_object(base + "a.json.gz", _gz_envelope([
        {"eventTime": "2026-06-01T12:00:00Z", "eventName": "x"},
    ]))
    monkeypatch.setattr(ct.boto3, "client", lambda _svc: client)

    fake = _FakeStream(tty=False)
    monkeypatch.setattr(sys, "stderr", fake)

    cfg = {"path": "s3://example-trail-bucket/AWSLogs/", "egress_warn_gb": 100}
    since = datetime(2026, 6, 1, tzinfo=timezone.utc)
    until = datetime(2026, 6, 2, tzinfo=timezone.utc)
    ct.fetch({}, cfg, since, until, verbose=False)

    assert "listed 1 objects (" in fake.output
    assert " GB)" in fake.output


def test_listing_seals_on_zero_objects_path(monkeypatch) -> None:
    """Zero-objects path seals 'listed 0 objects (0.0 GB)' BEFORE raising."""
    client = FakeS3Client()  # empty
    monkeypatch.setattr(ct.boto3, "client", lambda _svc: client)

    fake = _FakeStream(tty=False)
    monkeypatch.setattr(sys, "stderr", fake)

    cfg = {"path": "s3://example-trail-bucket/AWSLogs/", "egress_warn_gb": 100}
    since = datetime(2026, 6, 1, tzinfo=timezone.utc)
    until = datetime(2026, 6, 2, tzinfo=timezone.utc)
    with pytest.raises(ValueError, match="no CloudTrail objects found"):
        ct.fetch({}, cfg, since, until, verbose=False)

    # The seal MUST land even though the ValueError fires immediately after.
    assert "listed 0 objects (0.0 GB)" in fake.output


def test_listing_seal_lands_before_input_prompt(monkeypatch) -> None:
    """No liveness block may span input(); listing seal must commit first.

    We monkeypatch builtins.input to inspect the fake stderr at call time -
    if the listing seal is already in the buffer when input() is invoked, no
    spinner is spanning the prompt. Decline the prompt to take the abort path
    cleanly.
    """
    _bucket_with_large_object(monkeypatch, body_size=10 * 10**9)  # 10 GB

    fake = _FakeStream(tty=False)
    monkeypatch.setattr(sys, "stderr", fake)

    def _inspecting_input(*_args, **_kw):
        # At the moment input() fires, the listing seal must already exist.
        assert "listed 1 objects (" in fake.output, (
            "listing liveness was still active when input() fired - "
            "a spinner block is spanning the egress prompt"
        )
        return "n"   # decline → ExportAborted via the existing abort path

    monkeypatch.setattr("builtins.input", _inspecting_input)

    cfg = {"path": "s3://example-trail-bucket/AWSLogs/", "egress_warn_gb": 5.0}
    since = datetime(2026, 6, 1, tzinfo=timezone.utc)
    until = datetime(2026, 6, 2, tzinfo=timezone.utc)
    with pytest.raises(ExportAborted, match="aborted by user"):
        ct.fetch({}, cfg, since, until, verbose=False)


def test_sort_and_trim_seals_record(monkeypatch) -> None:
    """Sort+trim block seals 'sorted and trimmed to <N> events in window'."""
    client = FakeS3Client()
    base = "AWSLogs/000000000000/CloudTrail/us-east-1/2026/06/01/"
    client.add_object(base + "a.json.gz", _gz_envelope([
        {"eventTime": "2026-06-01T08:00:00Z", "eventName": "InWindow1"},
        {"eventTime": "2026-06-01T18:00:00Z", "eventName": "InWindow2"},
        {"eventTime": "2026-05-31T20:00:00Z", "eventName": "BeforeWindow"},
    ]))
    monkeypatch.setattr(ct.boto3, "client", lambda _svc: client)

    fake = _FakeStream(tty=False)
    monkeypatch.setattr(sys, "stderr", fake)

    cfg = {"path": "s3://example-trail-bucket/AWSLogs/", "egress_warn_gb": 100}
    since = datetime(2026, 6, 1, tzinfo=timezone.utc)
    until = datetime(2026, 6, 2, tzinfo=timezone.utc)
    ct.fetch({}, cfg, since, until, verbose=False)

    assert "sorted and trimmed to 2 events in window" in fake.output
