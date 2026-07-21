"""CloudTrail S3 exporter - pulls gzipped JSON event objects from S3 to local NDJSON.

Invoked via: sigwood export cloudtrail

CloudTrail writes objects under a rigid layout:
    <prefix>/AWSLogs/<account-id>/CloudTrail/<region>/YYYY/MM/DD/<file>.json.gz
each containing {"Records": [ ...events... ]}. A sibling CloudTrail-Digest/ prefix
holds integrity manifests (not events) and is skipped.

AWS authentication is outside this tool: the user authenticates their shell
(aws login / SSO / env vars / instance role) before running sigwood, and boto3
resolves the ambient credential chain. We never read, store, or prompt for
AWS credentials.

Date-root discovery keys off the 4-digit-year prefix invariant, NOT a fixed
segment count - resilient to org-id segments and to the user pointing at any
level at or above the region.

The pull is two-phase: list-only (free) to estimate object bytes and prompt
above ``egress_warn_gb`` if needed, then download/parse on confirmation. The
prompt is suppressed when ``skip_confirm=True``.
"""

from __future__ import annotations

import contextlib
import gzip
import io
import json
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from tqdm import tqdm

try:
    import boto3
    import botocore.exceptions as botocore_exc
except ImportError:
    boto3 = None  # type: ignore[assignment]
    botocore_exc = None  # type: ignore[assignment]

from sigwood.common.display import fmt_window, liveness, plural
from sigwood.common.errors import ExportAborted
from sigwood.common.paths import private_mkdir, private_open
from sigwood.common.sanitize import strip_control


_YEAR_RE = re.compile(r"^\d{4}/$")
_ACCOUNT_ID_RE = re.compile(r"^\d+/$")
_ORG_ID_RE = re.compile(r"^o-[a-z0-9]+/$")
_DIGEST_SEGMENT = "CloudTrail-Digest/"
_EVENT_SEGMENT = "CloudTrail/"
_KNOWN_ANCESTOR_SEGMENTS = frozenset({"AWSLogs/", _EVENT_SEGMENT})
_AUTH_ERROR_CODES = {
    "AccessDenied",
    "ExpiredToken",
    "InvalidToken",
    "InvalidAccessKeyId",
    "SignatureDoesNotMatch",
    "RequestExpired",
}

# Size threshold for splitting NDJSON output into _partNN files.
# Exposed at module scope so tests can monkeypatch a tiny value.
_PART_SPLIT_BYTES = 2_000_000_000  # 2 GB

OUTPUT_EXTENSION = ".json.log"


def is_configured(backend_cfg: dict[str, Any]) -> bool:
    """True when [export.cloudtrail].path is set - analogue of Splunk's host check."""
    return bool(backend_cfg.get("path", "").strip())


def summary_descriptor(backend_cfg: dict[str, Any]) -> str:
    """Identifier shown in the final summary's `Backend :` line, e.g. s3://bucket/AWSLogs/."""
    return backend_cfg.get("path", "")


def implicit_default_query() -> dict[str, Any]:
    """CloudTrail has no per-query SPL - synthetic default supplies the basename.

    Returning {} would cause _resolve_output_path to fall back to the query name
    ("default"), producing files like default_20260601_7d.json.log. We want
    cloudtrail_20260601_7d.json.log, so the synthetic query carries an explicit
    output_basename.
    """
    return {"output_basename": "cloudtrail"}


def _auth_error_message() -> str:
    return (
        "AWS credentials not found or expired - authenticate your shell "
        "(e.g. your aws login) and try again"
    )


@contextlib.contextmanager
def _translate_boto_errors():
    """Translate botocore exceptions into actionable ValueErrors uniformly.

    Centralizes the mapping table so every boto call site uses the same
    translation. The well-known cases (missing/partial credentials, the
    missing botocore[crt] dep, auth-code ClientErrors) get tailored messages
    naming the exact remedy; the long tail (endpoint resolution, profile
    config errors, non-auth ClientErrors, etc.) is swept up as
    "AWS error during CloudTrail export: <detail>" so a raw botocore
    traceback never reaches the user.

    Order matters - more specific BotoCoreError subclasses must be caught
    before the BotoCoreError sweep. ClientError is a separate hierarchy
    (not a subclass of BotoCoreError) and is handled in its own branch.

    Does NOT catch bare Exception - genuinely non-botocore errors
    (programmer bugs, OS issues, etc.) must still surface unmasked.
    """
    try:
        yield
    except (botocore_exc.NoCredentialsError,
            botocore_exc.PartialCredentialsError) as exc:
        raise ValueError(_auth_error_message()) from exc
    except botocore_exc.MissingDependencyException as exc:
        raise ValueError(
            "AWS credential provider needs an extra dependency - run: "
            "pip install 'botocore[crt]' (your AWS profile likely uses "
            f"SSO/login-based credentials). botocore detail: {exc}"
        ) from exc
    except botocore_exc.ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code in _AUTH_ERROR_CODES:
            raise ValueError(_auth_error_message()) from exc
        raise ValueError(f"AWS error during CloudTrail export: {exc}") from exc
    except botocore_exc.BotoCoreError as exc:
        raise ValueError(f"AWS error during CloudTrail export: {exc}") from exc


def _parse_s3_path(s3_path: str) -> tuple[str, str]:
    """Split s3://bucket/key/prefix/ into (bucket, prefix). Prefix ends with /."""
    if not s3_path.startswith("s3://"):
        raise ValueError(
            f"CloudTrail path must start with s3:// - got: {s3_path}"
        )
    rest = s3_path[5:]
    if "/" in rest:
        bucket, prefix = rest.split("/", 1)
    else:
        bucket, prefix = rest, ""
    if not bucket:
        raise ValueError(f"CloudTrail path is missing a bucket name: {s3_path}")
    if prefix and not prefix.endswith("/"):
        prefix += "/"
    return bucket, prefix


def _has_cloudtrail_segment(prefix: str) -> bool:
    """True iff ``prefix`` contains 'CloudTrail/' as a whole path segment.

    Padded with a leading '/' so a prefix starting at the literal characters
    'CloudTrail/' still matches. Does NOT match 'CloudTrail-Digest/' (different
    segment) or any other compound name.
    """
    return f"/{prefix}".find(f"/{_EVENT_SEGMENT}") != -1


def _is_cloudtrail_ancestor_segment(segment: str) -> bool:
    """True iff ``segment`` (trailing-slash form) could plausibly be a structural
    parent of CloudTrail/ in standard AWS layouts.

    The walker only descends through these patterns when not already inside a
    CloudTrail/ subtree. Co-located non-CloudTrail service segments
    (elasticloadbalancing, RDS, vpc-flow-logs, etc.) are rejected here, so the
    walk never lists inside them - saving S3 calls and preventing an
    AccessDenied in an unrelated branch from aborting an otherwise-readable
    CloudTrail pull.

    Users with non-standard prefix layouts can point [export.cloudtrail].path deeper
    (at or below CloudTrail/) to bypass - past CloudTrail/, the walker
    descends every child.
    """
    if segment in _KNOWN_ANCESTOR_SEGMENTS:
        return True
    if _ACCOUNT_ID_RE.match(segment):
        return True
    if _ORG_ID_RE.match(segment):
        return True
    return False


def _list_common_prefixes(client, bucket: str, prefix: str) -> list[str]:
    """Return immediate child common-prefixes under ``prefix`` (one level deep)."""
    with _translate_boto_errors():
        paginator = client.get_paginator("list_objects_v2")
        common: list[str] = []
        for page in paginator.paginate(Bucket=bucket, Prefix=prefix, Delimiter="/"):
            for cp in page.get("CommonPrefixes", []) or []:
                common.append(cp["Prefix"])
        return common


def _find_date_roots(client, bucket: str, base_prefix: str) -> list[str]:
    """Walk down from base_prefix until children look like YYYY/ segments.

    A prefix is accepted as a date root only if its full path contains the
    'CloudTrail/' event segment - this prevents accidental discovery of
    sibling AWS service trees that share the YYYY/MM/DD layout.

    CloudTrail-Digest/ branches are skipped during the walk.
    """
    accepted: list[str] = []
    queue: list[str] = [base_prefix]
    visited: set[str] = set()

    while queue:
        current = queue.pop(0)
        if current in visited:
            continue
        visited.add(current)

        children = _list_common_prefixes(client, bucket, current)
        inside_cloudtrail = _has_cloudtrail_segment(current)

        # If immediate children look like 4-digit years, this is a date root
        # candidate. Accept only when the path includes /CloudTrail/.
        year_children = [
            c for c in children if _YEAR_RE.match(c[len(current):])
        ]
        if year_children:
            if inside_cloudtrail:
                accepted.append(current)
            # Either way, do not descend further past a year level.
            continue

        # Outside CloudTrail/: only descend known structural ancestors. Inside
        # CloudTrail/: descend freely (regions, years, etc.).
        for child in children:
            tail = child[len(current):]
            if tail == _DIGEST_SEGMENT:
                continue
            if not inside_cloudtrail and not _is_cloudtrail_ancestor_segment(tail):
                # Sibling AWS-service tree (ELB/RDS/etc.) - skip.
                continue
            queue.append(child)

    return accepted


def _list_objects_for_day(client, bucket: str, day_prefix: str) -> list[dict[str, Any]]:
    """List .json.gz objects directly under ``day_prefix`` (recursive within the day)."""
    with _translate_boto_errors():
        paginator = client.get_paginator("list_objects_v2")
        out: list[dict[str, Any]] = []
        for page in paginator.paginate(Bucket=bucket, Prefix=day_prefix):
            for obj in page.get("Contents", []) or []:
                if obj["Key"].endswith(".json.gz"):
                    out.append(obj)
        return out


def _enumerate_days(since: datetime, until: datetime) -> list[tuple[int, int, int]]:
    """Whole days (UTC-keyed, matching CloudTrail's S3 partitions) that overlap
    [since, until). Exclusive upper bound.

    CloudTrail writes day prefixes in UTC, so the window must be normalized to
    UTC before extracting date parts. A local UTC-5 window 2026-06-01 00:00 →
    2026-06-02 00:00 is 2026-06-01 05:00 UTC → 2026-06-02 05:00 UTC and must
    list BOTH 2026/06/01/ and 2026/06/02/. The downstream per-event trim still
    enforces the precise [since, until) window.

    Returns list of (year, month, day) tuples in UTC, ascending. For
    until <= since, returns [].
    """
    if until <= since:
        return []
    since_utc = _to_utc(since)
    until_utc = _to_utc(until)
    start_day = since_utc.date()
    last_day = (until_utc - timedelta(microseconds=1)).date()
    days: list[tuple[int, int, int]] = []
    day = start_day
    while day <= last_day:
        days.append((day.year, day.month, day.day))
        day += timedelta(days=1)
    return days


def _parse_event_time(s: str) -> datetime | None:
    """Best-effort parse of CloudTrail eventTime. Returns None on failure."""
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def _to_utc(dt: datetime) -> datetime:
    """Treat naive datetimes as local and convert to UTC for comparison."""
    if dt.tzinfo is None:
        return dt.astimezone(timezone.utc)
    return dt.astimezone(timezone.utc)


def _split_name(base: Path, part_num: int) -> Path:
    """Insert _part{NN} before all of base's suffixes.

    cloudtrail_20260601_7d.json.log + 1 -> cloudtrail_20260601_7d_part01.json.log
    """
    name = base.name
    suffixes = "".join(base.suffixes)
    if suffixes:
        stem_full = name[: -len(suffixes)]
    else:
        stem_full = name
    return base.with_name(f"{stem_full}_part{part_num:02d}{suffixes}")


def fetch(
    query_config: dict[str, Any],
    cloudtrail_config: dict[str, Any],
    since: datetime,
    until: datetime,
    verbose: bool,
    *,
    skip_confirm: bool = False,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Pull CloudTrail events from S3 for the given window.

    Args:
        query_config: Unused (CloudTrail has no per-query SPL).
        cloudtrail_config: [export.cloudtrail] section (path, egress_warn_gb).
        since: Start of window (inclusive).
        until: End of window (exclusive).
        verbose: If True, print discovery details.
        skip_confirm: Bypass the egress-cost prompt.

    Returns:
        (events, fetch_meta) where fetch_meta = {"units": N, "unit_label": "objects"}.

    Raises:
        ValueError: bad path, no objects, AWS credential/access errors, missing boto3.
        ExportAborted: operator declined the egress-cost prompt.
    """
    if boto3 is None:
        raise ValueError("boto3 not installed - run: pip install 'sigwood[cloudtrail]'")

    path = cloudtrail_config.get("path", "").strip()
    if not path:
        raise ValueError(
            "[export.cloudtrail].path is empty - set it to an s3:// URL (see config_example.toml)"
        )
    bucket, base_prefix = _parse_s3_path(path)
    egress_warn_gb = float(cloudtrail_config.get("egress_warn_gb", 5.0))

    with _translate_boto_errors():
        client = boto3.client("s3")

    # Phase 1: list-only. Boundary covers _find_date_roots (the slow S3
    # prefix/delimiter walk) + _enumerate_days + the per-day list loop, so the
    # spinner starts the moment discovery begins. On failure inside discovery
    # the block exits by exception, no seal is written, and the error
    # propagates - display.liveness clears the spinner cleanly.
    objects: list[tuple[str, dict[str, Any]]] = []  # (bucket, obj_dict)
    with liveness("listing CloudTrail objects") as ln:
        date_roots = _find_date_roots(client, bucket, base_prefix)
        if verbose:
            print(
                f"cloudtrail: discovered {len(date_roots)} "
                f"{plural(len(date_roots), 'date root')}",
                flush=True,
            )
        days = _enumerate_days(since, until)
        for root in date_roots:
            for (y, m, d) in days:
                day_prefix = f"{root}{y:04d}/{m:02d}/{d:02d}/"
                for obj in _list_objects_for_day(client, bucket, day_prefix):
                    objects.append((bucket, obj))
        total_bytes = sum(int(o["Size"]) for _, o in objects)
        ln.seal(f"listed {len(objects)} objects ({total_bytes / 1e9:.1f} GB)")

    if not objects:
        raise ValueError(
            f"no CloudTrail objects found under {path} for {fmt_window((since, until))} - "
            f"check the S3 path and date range"
        )

    # Egress guard
    if total_bytes > egress_warn_gb * 1e9 and not skip_confirm:
        prompt = (
            f"this pull will transfer ~{total_bytes / 1e9:.1f} GB from S3, "
            f"which may incur AWS egress charges. Continue? [y/N] "
        )
        try:
            answer = input(prompt).strip().lower()
        except EOFError:
            answer = ""
        if answer not in {"y", "yes"}:
            raise ExportAborted("aborted by user")

    # Phase 2: fetch + parse, skip corrupt, propagate auth.
    # leave=False so the live fetch bar clears to the result line (the export
    # narration owns the permanent record now). Countable phases stay on tqdm.
    events: list[dict[str, Any]] = []
    for bkt, obj in tqdm(
        objects,
        desc="fetching",
        unit="obj",
        leave=False,
        bar_format="{desc}: {n_fmt} objects [{elapsed}]",
    ):
        key = obj["Key"]
        with _translate_boto_errors():
            body = client.get_object(Bucket=bkt, Key=key)["Body"].read()
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(body)) as gz:
                envelope = json.load(gz)
            events.extend(envelope.get("Records", []) or [])
        except (gzip.BadGzipFile, json.JSONDecodeError, OSError, UnicodeDecodeError) as exc:
            print(f"skipped unreadable object: {strip_control(key)} ({strip_control(exc)})", file=sys.stderr)
            continue

    # Sort + trim - one logical "order and window" operation. delay=0.25 so
    # trivially small exports do not flicker (the detector loop uses 0.0; we
    # diverge here because typical export-dev-loop datasets are small).
    with liveness("ordering and windowing events", delay=0.25) as ln:
        # Sort by eventTime ascending; events without a parseable eventTime sort first.
        events.sort(key=lambda e: _parse_event_time(e.get("eventTime", "")) or datetime.min.replace(tzinfo=timezone.utc))

        # Trim to precise [since, until) window
        since_utc = _to_utc(since)
        until_utc = _to_utc(until)
        trimmed: list[dict[str, Any]] = []
        for e in events:
            et = _parse_event_time(e.get("eventTime", ""))
            if et is None:
                continue   # drop events with no parseable timestamp
            if since_utc <= et < until_utc:
                trimmed.append(e)
        ln.seal(f"sorted and trimmed to {len(trimmed)} events in window")

    return trimmed, {"units": len(objects), "unit_label": "objects"}


def write(
    events: list[dict[str, Any]], outpath: Path, verbose: bool,
) -> tuple[int, dict[str, Any]]:
    """Write events as NDJSON, splitting at ~2 GB into _partNN files when needed.

    Naming: ``outpath`` is used as-is for the first (and only) file when output
    fits under the size limit. On first overflow the existing file is closed and
    renamed to its _part01 form, then writing continues into _part02, etc.

    Returns:
        ``(line_count, write_meta)`` where ``write_meta`` carries
        ``{"bytes": int, "paths": list[Path]}``. ``paths`` lists every part
        actually produced - single-element when no split occurred,
        ``[_part01, _part02, …]`` after the first overflow. The caller uses
        ``len(paths) > 1`` to detect a split and reports ``+K more`` where
        ``K = len(paths) - 1``.
    """
    private_mkdir(outpath.parent)

    current_path = outpath
    current_handle = private_open(current_path, encoding="utf-8")
    current_bytes = 0
    part_num = 0   # 0 means "no split yet"; first split renames current to _part01.
    total_lines = 0
    total_bytes = 0
    paths: list[Path] = [current_path]

    try:
        for ev in events:
            line = json.dumps(ev, default=str) + "\n"
            line_bytes = len(line.encode("utf-8"))

            if current_bytes > 0 and current_bytes + line_bytes > _PART_SPLIT_BYTES:
                current_handle.close()
                if part_num == 0:
                    # First split: rename the bare-named file to _part01 and
                    # update the paths list in place (the bare path was added
                    # at open time; the rename is the same physical file).
                    renamed = _split_name(outpath, 1)
                    current_path.rename(renamed)
                    paths[0] = renamed
                    part_num = 1
                next_part = part_num + 1
                current_path = _split_name(outpath, next_part)
                current_handle = private_open(current_path, encoding="utf-8")
                paths.append(current_path)
                current_bytes = 0
                part_num = next_part

            current_handle.write(line)
            current_bytes += line_bytes
            total_bytes += line_bytes
            total_lines += 1
    finally:
        current_handle.close()

    return total_lines, {"bytes": total_bytes, "paths": paths}
