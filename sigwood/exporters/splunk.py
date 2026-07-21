"""Splunk log exporter - pulls search results from Splunk REST API to local files.

Invoked via: sigwood export  (or: sigwood export splunk)
Connects to the Splunk management port (default 8089), runs hourly-chunked oneshot
queries, and writes results as flat syslog text to the configured output file.

Credentials (in priority order):
  SIGWOOD_SPLUNK_USER, SIGWOOD_SPLUNK_PASS  environment variables
  username, password in [export.splunk] config section

Splunk developer/free licenses enforce a hard per-query result cap at the binary
level that limits.conf cannot override. Hourly chunking keeps each query well
under this ceiling. For a 7-day pull this is 168 queries.
"""

from __future__ import annotations

import os
import re
import ssl
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from tqdm import tqdm

from sigwood.common.paths import private_mkdir, private_open

try:
    import splunklib.client as splunk_client
    import splunklib.results as splunk_results
except ImportError:
    splunk_client = None  # type: ignore[assignment]
    splunk_results = None  # type: ignore[assignment]

# RFC 3164 PRI field: <N> or <NN> or <NNN> at start of line
PRI_RE = re.compile(r"^<\d+>")


def is_configured(backend_cfg: dict[str, Any]) -> bool:
    """True when [export.splunk] has a non-empty host - preserves prior auto-detect behavior."""
    return bool(backend_cfg.get("host", "").strip())


def summary_descriptor(backend_cfg: dict[str, Any]) -> str:
    """Identifier shown in the final export summary's `Backend :` line."""
    host = backend_cfg.get("host", "")
    port = backend_cfg.get("port", "")
    return f"{host}:{port}"


def _verify_tls(config: dict[str, Any]) -> bool:
    """Return the strict Splunk TLS verification setting."""
    if "verify_tls" not in config:
        return True
    value = config["verify_tls"]
    if isinstance(value, bool):
        return value
    raise ValueError("[export.splunk].verify_tls must be true or false")


def _get_credentials(config: dict[str, Any]) -> tuple[str, str]:
    """Return (username, password) from env vars or config.

    Environment variables take priority over config-file values.
    """
    user = os.environ.get("SIGWOOD_SPLUNK_USER", "").strip() or config.get("username", "").strip()
    passwd = os.environ.get("SIGWOOD_SPLUNK_PASS", "").strip() or config.get("password", "").strip()
    if not user or not passwd:
        raise ValueError(
            "Splunk credentials not found - set SIGWOOD_SPLUNK_USER and "
            "SIGWOOD_SPLUNK_PASS, or add username/password to [export.splunk] in config"
        )
    return user, passwd


def _is_cert_verification_failure(exc: BaseException) -> bool:
    """True when the exception chain carries a TLS certificate-verification failure.

    splunklib surfaces ``ssl.SSLCertVerificationError`` raw from ``connect``, but a
    wrapper could re-raise it - walk ``__cause__``/``__context__`` so the failure is
    recognized wherever it sits in the chain.
    """
    seen: set[int] = set()
    e: BaseException | None = exc
    while e is not None and id(e) not in seen:
        seen.add(id(e))
        if isinstance(e, ssl.SSLCertVerificationError):
            return True
        e = e.__cause__ or e.__context__
    return False


def _sdk_error_message(exc: Exception, host: str, port: int) -> str:
    """Return an actionable user-facing message for Splunk SDK failures."""
    if _is_cert_verification_failure(exc):
        return (
            f"TLS certificate verification failed for Splunk at {host}:{port} - the "
            "server presented a certificate no local trust store accepts (Splunk's "
            "default self-signed certificate is the common case). For a self-signed "
            "certificate on a trusted network, set verify_tls = false under "
            "[export.splunk]."
        )
    exc_name = exc.__class__.__name__
    if exc_name == "AuthenticationError":
        return (
            "Splunk login failed - check [export.splunk].username/password in config "
            "and SIGWOOD_SPLUNK_USER/SIGWOOD_SPLUNK_PASS environment overrides"
        )
    return (
        f"could not connect to Splunk management API at {host}:{port} - "
        f"check [export.splunk].host, [export.splunk].port, network reachability, and credentials"
    )


def _build_hour_windows(
    since: datetime,
    until: datetime,
) -> list[tuple[datetime, datetime]]:
    """Return one-hour (start, end) pairs spanning since..until.

    Both since and until are floored to their hour boundary so every emitted
    chunk is exactly one hour - no partial-hour chunks, mirroring the migration.

    Args:
        since: Start of the window (timezone-aware or naive).
        until: End of the window (timezone-aware or naive).

    Returns:
        List of (chunk_start, chunk_end) in the timezone of the passed-in
        datetimes, oldest first.
    """
    # Use datetimes as-is - honor the tzinfo already embedded in them.
    # Calling .astimezone() with no argument would re-express in the process
    # timezone (UTC on a server), shifting hour boundaries away from the user's
    # calendar day. replace() below preserves tzinfo unchanged.
    local_since = since
    local_until = until

    # Floor both endpoints to their hour boundary
    window_start = local_since.replace(minute=0, second=0, microsecond=0)
    window_end   = local_until.replace(minute=0, second=0, microsecond=0)

    total_hours = int((window_end - window_start).total_seconds() // 3600)
    return [
        (window_start + timedelta(hours=i), window_start + timedelta(hours=i + 1))
        for i in range(max(total_hours, 0))
    ]


def fetch(
    query_config: dict[str, Any],
    splunk_config: dict[str, Any],
    since: datetime,
    until: datetime,
    verbose: bool,
    *,
    skip_confirm: bool = False,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Connect to Splunk and pull all rows in hourly chunks.

    Args:
        query_config: Single query stanza from config (must have "spl" key).
        splunk_config: [export.splunk] section of config (host, port, credentials).
        since: Start of window.
        until: End of window.
        verbose: Threaded from the orchestrator. The narration grammar keeps
            export stdout terse and level-invariant - Splunk's fetch currently
            ignores this flag (no per-chunk chatter at level 1).
        skip_confirm: Part of the uniform backend contract - Splunk has no
            cost-prompt and ignores this. Accepted so the orchestrator can
            invoke every backend with the same signature.

    Returns:
        A tuple ``(rows, fetch_meta)``:
          - ``rows``: result rows as a flat list of dicts with at minimum _time and _raw.
          - ``fetch_meta``: ``{"units": <hour-window count>, "unit_label": "chunks"}``
            - used by the orchestrator to render the run-summary span string.
    """
    if splunk_client is None:
        raise ValueError("splunk-sdk not installed - run: pip install 'sigwood[splunk]'")

    user, passwd = _get_credentials(splunk_config)
    host = splunk_config.get("host", "")
    port = int(splunk_config.get("port", 8089))
    verify_tls = _verify_tls(splunk_config)
    spl = query_config.get("spl", "")

    try:
        service = splunk_client.connect(
            host=host,
            port=port,
            username=user,
            password=passwd,
            verify=verify_tls,
        )
    except Exception as exc:
        raise ValueError(_sdk_error_message(exc, host, port)) from exc

    windows = _build_hour_windows(since, until)
    all_rows: list[dict[str, Any]] = []

    for chunk_start, chunk_end in tqdm(
        windows,
        desc="fetching",
        unit="hr",
        leave=False,
        bar_format="{desc}: {n_fmt} hours [{elapsed}]",
    ):
        earliest = str(int(chunk_start.timestamp()))
        latest   = str(int(chunk_end.timestamp()))
        try:
            job = service.jobs.oneshot(
                spl,
                count=0,
                output_mode="json",
                earliest_time=earliest,
                latest_time=latest,
            )
        except Exception as exc:
            raise ValueError(_sdk_error_message(exc, host, port)) from exc
        chunk = [r for r in splunk_results.JSONResultsReader(job) if isinstance(r, dict)]
        all_rows.extend(chunk)

    return all_rows, {"units": len(windows), "unit_label": "chunks"}


def write(
    rows: list[dict[str, Any]],
    outpath: Path,
    verbose: bool,
) -> tuple[int, dict[str, Any]]:
    """Write syslog rows to a flat text file, one line per event.

    Sorts by _time ascending, strips RFC 3164 PRI prefixes, writes non-empty lines.

    Args:
        rows: Result rows from fetch(), each with _time and _raw fields.
        outpath: Destination file path.
        verbose: Reserved for future use.

    Returns:
        ``(line_count, write_meta)`` where ``write_meta`` carries
        ``{"bytes": int, "paths": list[Path]}``. Splunk writes a single file -
        ``paths`` is a one-element list.
    """
    rows_sorted = sorted(rows, key=lambda r: r.get("_time", ""))
    count = 0
    byte_total = 0
    try:
        private_mkdir(outpath.parent)
        with private_open(outpath, encoding="utf-8") as fh:
            for row in rows_sorted:
                raw = PRI_RE.sub("", row.get("_raw", "").strip())
                if raw:
                    line = raw + "\n"
                    fh.write(line)
                    byte_total += len(line.encode("utf-8"))
                    count += 1
    except OSError as exc:
        raise ValueError(f"could not write export file {outpath}: {exc}") from exc
    return count, {"bytes": byte_total, "paths": [outpath]}
