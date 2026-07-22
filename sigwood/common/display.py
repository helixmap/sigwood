"""Shared display constants and helpers for human-facing terminal output.

The ``liveness`` context manager is the shared primitive for TTY
progress narration. It draws an indeterminate spinner on stderr for opaque
blocking phases when stderr is a tty, and seals a permanent one-line record
on the way out (visible on tty AND non-tty - only the live animation is
tty-gated). Countable phases stay on ``tqdm``; ``liveness`` is for the cases
where there is no natural tick.
"""

from __future__ import annotations

import os
import sys
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Iterable, Iterator

if TYPE_CHECKING:
    from sigwood.common.finding import SuppressionSummary

from tqdm import tqdm

TEXT_RULE_WIDTH = 80
TEXT_RULE = "─" * TEXT_RULE_WIDTH
TEXT_RULE_DOUBLE = "═" * TEXT_RULE_WIDTH

# Spinner frames cycle in this exact order. Only the horizontal frame upgrades
# to the box-drawing bar (─) on capable terminals - the full box set (│ ╱ ╲)
# left rendering artifacts on some terminals, so | / \ stay ASCII. Weak/minimal
# terminals fall back to a plain ASCII hyphen.
_SPINNER_FRAMES = ("|", "/", "─", "\\")
_ASCII_SPINNER_FRAMES = ("|", "/", "-", "\\")
# Per-frame interval. 120ms sits in the middle of the 100-150ms band that
# reads as "alive" without thrashing the terminal.
_SPINNER_INTERVAL_S = 0.12


# ── Method-chrome color seam (text handler only) ────────────────────────────
#
# Minimal: a single SGR constant for the method-glow paint, a TTY/NO_COLOR
# gate, and one paint() helper. Not a general terminal-capability layer; the
# only consumer is the text handler's Detectors: line. Rebound for retuning
# the glow in a single place.
_METHOD_SGR = "\x1b[96;1m"  # bright-cyan + bold
_RESET = "\x1b[0m"


def _stream_isatty(stream: Any) -> bool:
    """Raw TTY probe. No color-policy coupling.

    Shared by ``_color_enabled``, ``_LivenessHandle``, and ``progress``. Color
    layers ``NO_COLOR``/``TERM=dumb`` on top; liveness and progress gate on
    TTY only - a color preference is not a progress preference.
    """
    isatty = getattr(stream, "isatty", lambda: False)
    try:
        return bool(isatty())
    except Exception:
        return False


def _stream_can_encode(stream: Any, text: str) -> bool:
    """True when ``stream`` advertises an encoding that can write ``text``."""
    encoding = getattr(stream, "encoding", None)
    if not encoding:
        return False
    try:
        text.encode(encoding)
    except (LookupError, TypeError, UnicodeEncodeError):
        return False
    return True


def _spinner_frames_for(stream: Any) -> tuple[str, ...]:
    """Return liveness spinner frames suited to this terminal stream."""
    if os.environ.get("TERM") == "dumb":
        return _ASCII_SPINNER_FRAMES
    if not _stream_can_encode(stream, "".join(_SPINNER_FRAMES)):
        return _ASCII_SPINNER_FRAMES
    return _SPINNER_FRAMES


# ── Detector-owned narration gate (the -q seam the runner can't thread) ─────
#
# Loader bars and liveness spinners take an explicit ``show_progress`` /
# ``enabled`` flag the runner sets to ``not quiet``. DETECTOR-owned progress
# (the syslog drain3 miner bar) can't take that flag without the detector
# reading a quiet field - which would cross the detectors-are-render-blind rail.
# So the runner sets ONE process-global gate here (``set_narration_enabled``),
# and the detector routes its bar through ``narration_active`` instead of asking
# its context. The detector stays result-set-invariant and never learns about
# quiet - the same shape as color's environment gate (``_color_enabled`` reads
# ambient state; the text handler is never handed a "color" field). Default True
# keeps standalone/notebook callers narrating (still TTY-gated below).
_NARRATION_ENABLED = True

# Terminal cursor control is a third policy category beside color and progress:
# it follows narration + terminal capability, but deliberately ignores NO_COLOR.
# State is process-global because the cursor itself is terminal-global. The outer
# engaged scope owns the stream; nested scopes and prompt suspensions only adjust
# depth, so they cannot double-hide or prematurely restore it.
_CURSOR_HIDE = "\x1b[?25l"
_CURSOR_SHOW = "\x1b[?25h"
_CURSOR_DEPTH = 0
_CURSOR_SUSPEND_DEPTH = 0
_CURSOR_STREAM: Any | None = None
_CURSOR_LOCK = threading.RLock()


def set_narration_enabled(enabled: bool) -> None:
    """Set the process-global gate for DETECTOR-owned stderr narration.

    The runner calls this once per run with ``not quiet``. It governs only the
    detector-owned progress bars that can't be handed a per-run flag (the syslog
    drain3 miner); runner-owned narration keeps its explicit ``show_progress`` /
    ``enabled`` arguments.
    """
    global _NARRATION_ENABLED
    _NARRATION_ENABLED = enabled


def narration_active(stream: Any = None) -> bool:
    """True iff detector-owned narration should render: the runner's global gate
    AND the stream is a real TTY (``stream`` defaults to stderr, the narration
    stream). A piped/redirected run is silent without any quiet flag, matching
    the loader bars' TTY gate."""
    if stream is None:
        stream = sys.stderr
    return _NARRATION_ENABLED and _stream_isatty(stream)


def _cursor_write(stream: Any, control: str) -> None:
    """Write and immediately flush one tool-authored cursor-control value."""
    stream.write(control)
    stream.flush()


@contextmanager
def hidden_cursor(stream: Any = None) -> Iterator[None]:
    """Hide the stderr cursor for one narration lifecycle.

    The outer eligible scope emits DECTCEM hide/show. Nested scopes share that
    lifecycle without duplicate bytes. Non-TTY, dumb-terminal, and narration-
    disabled contexts are exact no-ops.
    """
    global _CURSOR_DEPTH, _CURSOR_STREAM
    if stream is None:
        stream = sys.stderr

    engaged = False
    with _CURSOR_LOCK:
        eligible = (
            _NARRATION_ENABLED
            and _stream_isatty(stream)
            and os.environ.get("TERM") != "dumb"
        )
        if eligible:
            if _CURSOR_DEPTH == 0:
                _CURSOR_STREAM = stream
                _cursor_write(stream, _CURSOR_HIDE)
            _CURSOR_DEPTH += 1
            engaged = True

    try:
        yield
    finally:
        if engaged:
            with _CURSOR_LOCK:
                _CURSOR_DEPTH -= 1
                if _CURSOR_DEPTH == 0:
                    active_stream = _CURSOR_STREAM
                    try:
                        if _CURSOR_SUSPEND_DEPTH == 0 and active_stream is not None:
                            _cursor_write(active_stream, _CURSOR_SHOW)
                    finally:
                        _CURSOR_STREAM = None


@contextmanager
def cursor_visible() -> Iterator[None]:
    """Temporarily show the cursor inside an engaged hidden narration scope."""
    global _CURSOR_SUSPEND_DEPTH
    engaged = False
    with _CURSOR_LOCK:
        if _CURSOR_DEPTH > 0 and _CURSOR_STREAM is not None:
            if _CURSOR_SUSPEND_DEPTH == 0:
                _cursor_write(_CURSOR_STREAM, _CURSOR_SHOW)
            _CURSOR_SUSPEND_DEPTH += 1
            engaged = True

    try:
        yield
    finally:
        if engaged:
            with _CURSOR_LOCK:
                _CURSOR_SUSPEND_DEPTH -= 1
                if (
                    _CURSOR_SUSPEND_DEPTH == 0
                    and _CURSOR_DEPTH > 0
                    and _CURSOR_STREAM is not None
                ):
                    _cursor_write(_CURSOR_STREAM, _CURSOR_HIDE)


def _color_enabled(stream: Any) -> bool:
    """True when the stream is a real TTY and color is not opted out.

    Honors the NO_COLOR ambient convention and the TERM=dumb signal.
    File streams (--out / report_dir) and pipes are not TTYs and therefore
    plain - automatic, no extra wiring at call sites.
    """
    if not _stream_isatty(stream):
        return False
    if os.environ.get("NO_COLOR") is not None:
        return False
    if os.environ.get("TERM") == "dumb":
        return False
    return True


def paint(text: str, *, stream: Any) -> str:
    """Wrap ``text`` in the method SGR when ``stream`` admits color.

    No-op on non-TTYs, on NO_COLOR-set environments, and on TERM=dumb. The
    single SGR constant ``_METHOD_SGR`` is the one place to retune the glow.
    """
    return f"{_METHOD_SGR}{text}{_RESET}" if _color_enabled(stream) else text


def phase_separator(stream: Any = None) -> None:
    """Terminate a transient stderr phase so a following report on the OTHER
    stream is cleanly separated.

    Cross-stream phase separation is owned by the stderr (transient) side: the
    stdout report must NOT emit a blank line whose sole purpose is to separate
    it from preceding stderr narration, because tqdm leaves timing-dependent
    cursor state on stderr and stdout spacing must never depend on it. The
    runner calls this at the load→report boundary, before the banner.

    tty-gated (``_stream_isatty``) - a NO-OP on a non-tty so piped/redirected
    output stays byte-clean. Writes a single newline and flushes.
    """
    if stream is None:
        stream = sys.stderr
    if not _stream_isatty(stream):
        return
    stream.write("\n")
    stream.flush()


def human_bytes(n: float) -> str:
    """Human-readable -h-style byte size.

    Consumers: the digest/blob renderers in text.py and the exporter
    narration. Digest ``conn.py`` keeps its deliberate local helper - do
    not repoint that one.
    """
    if n < 1024:
        return f"{int(n)} B"
    if n < 1024 ** 2:
        return f"{n / 1024:.1f} KB"
    if n < 1024 ** 3:
        return f"{n / (1024 ** 2):.1f} MB"
    if n < 1024 ** 4:
        return f"{n / (1024 ** 3):.1f} GB"
    return f"{n / (1024 ** 4):.1f} TB"


def compact_home(path: "str | Path") -> str:
    """Return ``path`` as a string with the user's home prefix replaced by ``~``.

    Pure display helper for exporter narration and similar surfaces. Operates
    on the STRING form so a trailing slash is preserved (callers shouldn't
    have to special-case that). Returns ``path`` unchanged when it doesn't
    fall under ``$HOME`` or when ``HOME`` is unset.
    """
    text = str(path)
    home = os.path.expanduser("~")
    if not home or home == "~":
        return text
    if text == home:
        return "~"
    prefix = home if home.endswith(os.sep) else home + os.sep
    if text.startswith(prefix):
        return "~" + os.sep + text[len(prefix):]
    return text


# ── Timestamp / window rendering (one renderer) ─────────────────────────────
#
# Every HUMAN-facing window or timestamp (text findings, digest cards, banners,
# stderr diagnostics, export narration) renders through these. The lossless
# machine format (json) keeps ISO-8601 UTC and does NOT route through here; the
# csv worklist DOES use the conversion (ISO-with-offset, no label) via the public
# `to_display_timezone`. The timezone decision is one module switch -
# ``_DISPLAY_UTC``, set per run from ``[sigwood].use_utc`` / ``--utc`` - read
# by exactly one conversion function (``to_display_timezone``) and one label
# helper (``_tz_label``); no caller ever writes the label string itself.
_DISPLAY_UTC = False


def set_display_utc(enabled: bool) -> None:
    """Set the process-global display timezone: UTC when enabled, else local.

    The CLI seam and ``run``/``run_digest``/``run_export`` entries call this
    with the resolved ``use_utc`` value. It governs only render-time display
    (conversion + label) - internal time stays true-UTC epoch, and timeframe
    INPUT interpretation takes the resolved bool explicitly, never this switch.
    Default False keeps standalone/notebook callers on local display.
    """
    global _DISPLAY_UTC
    _DISPLAY_UTC = enabled


def _tz_label() -> str:
    """The label rendered after human timestamps: ``UTC`` under the display
    switch, else ``local``. Read only by the shared human time formatters."""
    return "UTC" if _DISPLAY_UTC else "local"


def to_display_timezone(dt: datetime) -> datetime:
    """Render-time tz normalization (the single conversion point). Naive input
    is treated as UTC, then converted to the display timezone - machine-local,
    or UTC under the display switch. Returns an AWARE datetime - no label.

    The single home of tz policy: ``_DISPLAY_UTC`` flips this body (and
    ``_tz_label``) and every human surface plus the csv worklist follows. The
    human formatters add the label; csv calls ``.isoformat()`` on the result
    (an aware datetime carries the offset).
    """
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc) if _DISPLAY_UTC else dt.astimezone()


def fmt_timestamp(dt: datetime) -> str:
    """One labeled human timestamp: ``2026-06-18 00:00 local``.

    For the open-ended (one-sided) window callers - the present bound renders
    through here while the absent bound is composed caller-side as prose
    (``beginning of data`` / ``end of data``). The label comes from
    ``_tz_label``; callers never write it.
    """
    return f"{to_display_timezone(dt):%Y-%m-%d %H:%M} {_tz_label()}"


_SYSLOG_MONTHS = (
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
)


def fmt_syslog_timestamp(dt: datetime) -> str:
    """One syslog wall-clock stamp.

    Local examples are ``Jul 12 21:57:33`` and ``Jul  1 03:12:47``;
    UTC appends its label, as in ``Jul 12 21:57:33 UTC``.
    """
    rendered = to_display_timezone(dt)
    stamp = (
        f"{_SYSLOG_MONTHS[rendered.month - 1]} {rendered.day:2d} "
        f"{rendered.hour:02d}:{rendered.minute:02d}:{rendered.second:02d}"
    )
    # Branch on the shared label's returned value; timezone state has no reader here.
    label = _tz_label()
    return stamp if label == "local" else f"{stamp} {label}"


def fmt_window(window: "tuple[datetime, datetime]") -> str:
    """One human window: ``2026-06-18 00:00 → 2026-06-19 00:00 local``.

    Single-spaced arrow; the tz label appears once at the end. EDGE CONTRACT:
    both bounds are REAL datetimes - ``fmt_window`` is never handed ``None``.
    Open-ended windows compose from ``fmt_timestamp`` + prose instead.
    """
    lo, hi = window
    return (
        f"{to_display_timezone(lo):%Y-%m-%d %H:%M} → "
        f"{to_display_timezone(hi):%Y-%m-%d %H:%M} {_tz_label()}"
    )


def fmt_compact_span(td: timedelta) -> str:
    """Compact span for a duration - ``"20m"`` / ``"18h"`` / ``"7d"`` / ``"1.5d"``.

    The shared renderer for the window-suffix (digest card / finding tail / banner
    data-found), the data-found underfill parenthetical, and the beacon span-adequacy
    note. ``< 1h`` → integer minutes (``"20m"``); ``< 24h`` → integer hours
    (``"18h"``); ``>= 24h`` → days, integer when whole else one decimal (``"2d"``,
    ``"1.5d"``). Rounding never crosses a unit surprisingly: minutes that round up to
    a full hour print ``"1h"`` and hours that round up to a full day print ``"1d"``,
    never ``"60m"`` / ``"24h"``.
    """
    minutes = td.total_seconds() / 60
    if minutes < 60:
        rounded_m = int(round(minutes))
        if rounded_m < 60:
            return f"{rounded_m}m"
        # rounded up to a full hour - promote the unit rather than print "60m"
        return "1h"
    hours = td.total_seconds() / 3600
    if hours < 24:
        rounded = int(round(hours))
        if rounded < 24:
            return f"{rounded}h"
        # rounded up to a full day - promote the unit rather than print "24h"
        return "1d"
    days = td.total_seconds() / 86400
    if abs(days - round(days)) < 1e-9:
        return f"{int(round(days))}d"
    return f"{days:.1f}d"


def default_window_advisory(spec: str) -> str:
    """The default-window disclosure line, shared by analyze and digest.

    One sentence: the unqualified run truncated to the last ``spec`` of
    available data, plus how to widen. Two consumers route through here so
    they cannot drift - the analyze pre-load stderr advisory (``run``) and
    the digest card's identity-block note (``run_digest``).
    """
    return (f"default window: last {spec} of available data - "
            "use --all for the full archive, or --since/--days to widen")


def plural(n: int, singular: str, plural: str | None = None) -> str:
    """Return the correctly-pluralized NOUN ONLY (no count).

    ``plural(1, "principal")`` → ``"principal"``;
    ``plural(3, "principal")`` → ``"principals"``;
    ``plural(2, "query", "queries")`` → ``"queries"``. The caller composes the
    count: ``f"{n} {plural(n, 'principal')}"``. Default plural appends ``"s"``.
    """
    if n == 1:
        return singular
    return plural if plural is not None else singular + "s"


def _suppression_pct(count: int, total: int) -> str | None:
    """Row-based suppression percentage with two honesty guards.

    ``None`` when ``total <= 0`` (omit the parenthetical - structurally
    shouldn't happen). count>0 but rounds to 0 → ``"<1%"``; count<total but
    rounds to 100 → ``">99%"``. Bare fact, no verdict word.
    """
    if total <= 0:
        return None
    pct = round(100 * count / total)
    if count > 0 and pct == 0:
        return "<1%"
    if count < total and pct == 100:
        return ">99%"
    return f"{pct}%"


def _suppression_clause(count: int, total: int, noun: str) -> str:
    """One ``"{count:,} {plural} ({pct})"`` clause; drops ``(pct)`` when total==0."""
    base = f"{count:,} {plural(count, noun)}"
    pct = _suppression_pct(count, total)
    return f"{base} ({pct})" if pct is not None else base


def fmt_suppression(summary: "SuppressionSummary") -> str:
    """Render the run-summary allowlist-coverage value - three states, shared by
    the text banner and the HTML report header so they cannot drift. Connections
    lead; a single-kind run drops the other clause. Fact, not verdict.

      off:    not enabled
      no hits: enabled, nothing matched
      else:   "suppressed 1,284 connections (12%) and 312 domains (59%)"

    The percentage is row-based (numerator and denominator both count rows over
    the same eligible frames). Takes the SuppressionSummary so the denominators
    travel with the counts.
    """
    if not summary.enabled:
        return "off"
    if summary.connections == 0 and summary.domains == 0:
        return "no hits"
    clauses: list[str] = []
    if summary.connections:
        clauses.append(
            _suppression_clause(summary.connections, summary.connection_total, "connection")
        )
    if summary.domains:
        clauses.append(
            _suppression_clause(summary.domains, summary.domain_total, "domain")
        )
    return "suppressed " + " and ".join(clauses)


def progress(
    iterable: Iterable[Any],
    *,
    desc: str,
    show_progress: bool = True,
    unit: str = " lines",
    total: int | None = None,
    stream: Any = None,
) -> Iterator[Any]:
    """TTY-aware tqdm wrapper for loader read loops.

    Returns a counting GENERATOR on a TTY when ``show_progress`` is True;
    otherwise returns the bare iterable (``tqdm`` is NEVER constructed). Gate
    is raw isatty + the explicit ``show_progress`` flag; color policy
    (``NO_COLOR``/``TERM=dumb``) is NOT consulted - a color preference is not
    a progress preference.

    The TTY branch constructs the tqdm WITHOUT an iterable and drives it via
    ``bar.update(1)`` from a generator. This is what makes the count survive
    PARSER RE-ITERATION: parsers that sniff-then-resume (Zeek
    ``itertools.chain(prefix, line_iter)``; CloudTrail's second loop) call
    ``iter()`` on the returned object a second time - for a generator,
    ``iter(gen) is gen``, so the same generator (and its counter) continues,
    whereas a bare tqdm's own ``__iter__`` would be orphaned (the
    ``loaded X: 0.00 lines`` bug).

    The pinned ``bar_format`` reproduces the long-standing NDJSON loader bar
    byte-for-byte when ``unit=" lines"``; ``unit`` is parameterized so future
    non-line-oriented callers can be honest about what they count.
    """
    if stream is None:
        stream = sys.stderr
    if not show_progress or not _stream_isatty(stream):
        return iter(iterable)
    bar = tqdm(
        desc=desc,
        unit=unit,
        unit_scale=True,
        leave=True,
        mininterval=0.5,
        total=total,
        file=stream,
        bar_format=f"{{desc}}: {{n_fmt}}{unit} [{{elapsed}}]",
    )

    def _counting() -> Iterator[Any]:
        try:
            for item in iterable:
                bar.update(1)
                yield item
        finally:
            bar.close()

    return _counting()


class _LivenessHandle:
    """Handle returned from a ``liveness`` context manager.

    Owns the spinner thread, the captured stderr stream, and the bookkeeping
    needed to keep ``seal()`` and ``__exit__`` honest about whether the
    spinner actually drew anything.
    """

    def __init__(self, label: str, delay: float) -> None:
        self._label = label
        self._delay = delay
        # Capture the stream at construction so a single
        # monkeypatch.setattr(sys, "stderr", fake) before __enter__ is
        # observed for the whole lifecycle, and so a later redirect of
        # sys.stderr does not steal our writes.
        self._stream = sys.stderr
        self._isatty = _stream_isatty(self._stream)
        self._frames = _spinner_frames_for(self._stream)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        # _drew flips True inside the spinner thread immediately before its
        # first frame write. seal() / __exit__ only emit a clearing sequence
        # when _drew is True - a phase that seals before the spinner ever
        # drew prints exactly the sealed line, no \r flicker.
        self._drew = False
        self._sealed = False
        # Guard concurrent writes between the spinner thread and seal/exit.
        self._lock = threading.Lock()

    # ── lifecycle ───────────────────────────────────────────────────────────

    def _start(self) -> None:
        if not self._isatty:
            return
        self._thread = threading.Thread(target=self._spin, daemon=True)
        self._thread.start()

    def _spin(self) -> None:
        # Wait out the initial delay. If sealed during the delay, leave
        # without ever writing - this is the seal-before-delay invariant.
        if self._stop.wait(self._delay):
            return
        i = 0
        frames = self._frames
        while not self._stop.is_set():
            with self._lock:
                if self._stop.is_set():
                    return
                # Flip _drew before the first write so the buffer state
                # and the flag agree from the same critical section.
                self._drew = True
                try:
                    self._stream.write(f"\r{frames[i % len(frames)]} {self._label}")
                    self._stream.flush()
                except Exception:
                    return
            i += 1
            if self._stop.wait(_SPINNER_INTERVAL_S):
                return

    def _clear_line(self) -> None:
        # Pad-erase wide enough to cover one frame char + space + label, plus
        # a small cushion for terminals whose glyph metrics are imperfect.
        width = 6 + len(self._label)
        try:
            self._stream.write("\r" + (" " * width) + "\r")
            self._stream.flush()
        except Exception:
            pass

    def seal(self, text: str) -> None:
        """Commit a permanent one-line record and stop the spinner.

        Idempotent - a second seal is a no-op. On a tty, clears the spinner
        line first (only if the spinner actually drew); otherwise writes the
        record straight to the stream. The sealed record is the only stderr
        artifact that promises "this phase finished cleanly."
        """
        with self._lock:
            if self._sealed:
                return
            self._sealed = True
            self._stop.set()
        if self._thread is not None:
            self._thread.join()
        with self._lock:
            if self._isatty and self._drew:
                self._clear_line()
            try:
                self._stream.write(f"{text}\n")
                self._stream.flush()
            except Exception:
                pass

    def _teardown(self, had_exception: bool) -> None:
        """Single teardown path called from __exit__.

        Stops the spinner thread, then clears the partial spinner line if
        the spinner drew anything. Never writes a sealed record - that is
        seal()'s job, and a body that did not call seal() (whether by
        exception or by choice) leaves no record.
        """
        with self._lock:
            already_sealed = self._sealed
            self._stop.set()
        if self._thread is not None:
            self._thread.join()
        if already_sealed:
            # seal() already cleared and wrote; nothing more to do.
            return
        with self._lock:
            if self._isatty and self._drew:
                self._clear_line()
        # had_exception is informational - same teardown either way once
        # we know seal() did not fire. A partial spinner gets cleared; no
        # record is written. The exception (if any) propagates from
        # __exit__'s caller.


class _NoOpLivenessHandle:
    """A silent stand-in for ``_LivenessHandle`` under ``liveness(enabled=False)``.

    Exposes only the public surface the call sites use - ``seal(text)`` - as a
    no-op. No spinner thread is ever started and nothing is written to stderr
    (no frames, no clear sequence, no sealed record). This is the ``-q`` path:
    the runner-owned liveness narration goes fully dark.
    """

    def seal(self, text: str) -> None:
        """No-op - quiet runs commit no liveness record."""


@contextmanager
def liveness(
    label: str, delay: float = 0.0, *, enabled: bool = True
) -> Iterator[_LivenessHandle | _NoOpLivenessHandle]:
    """Indeterminate-spinner liveness for an opaque blocking phase.

    Usage::

        with liveness("running beacon") as ln:
            findings = run_beacon(ctx)
            ln.seal(f"beacon: {len(findings)} findings")

    On a tty, draws a single-line spinner ``"<frame> <label>"`` on stderr
    after ``delay`` seconds (so fast phases never flicker). On non-tty,
    draws nothing. ``ln.seal(text)`` commits a permanent record line.

    If the body raises (including KeyboardInterrupt - Ctrl-C during the
    phase), the spinner line is cleared, no sealed record is written, and
    the exception propagates. This is what lets the runner's top-level
    Ctrl-C handler print "Stopped." without a false-success seal landing
    just before it.

    ``enabled=False`` (the ``-q`` path) yields a no-op handle that starts no
    thread and emits nothing - not even a teardown/clear sequence.
    """
    if not enabled:
        yield _NoOpLivenessHandle()
        return
    handle = _LivenessHandle(label, delay)
    handle._start()
    try:
        yield handle
    except BaseException:
        handle._teardown(had_exception=True)
        raise
    else:
        handle._teardown(had_exception=False)
