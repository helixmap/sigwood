"""Tests for the liveness primitive in sigwood.common.display."""

from __future__ import annotations

import sys
import threading
import time
from datetime import datetime, timedelta, timezone

import pytest

from sigwood.common import display as display_mod
from sigwood.common.display import (
    _ASCII_SPINNER_FRAMES,
    _CURSOR_HIDE,
    _CURSOR_SHOW,
    _SPINNER_FRAMES,
    _color_enabled,
    _spinner_frames_for,
    _stream_isatty,
    cursor_visible,
    default_window_advisory,
    fmt_data_found,
    fmt_generated,
    hidden_cursor,
    liveness,
    narration_active,
    phase_separator,
    progress,
    set_narration_enabled,
    version_string,
)


def test_default_window_advisory_exact_string() -> None:
    """The shared default-window advisory - one sentence, em-dash, the exact
    bytes both the analyze pre-load advisory and the digest card note emit."""
    assert default_window_advisory("1d") == (
        "default window: last 1d of available data - "
        "use --all for the full archive, or --since/--days to widen"
    )
    # spec is interpolated, not hardcoded
    assert "last 7d of available data" in default_window_advisory("7d")


@pytest.mark.parametrize(
    ("data_span", "requested_span", "suffix"),
    [
        (timedelta(hours=18), timedelta(days=1), "(18h data span in 1d window)"),
        (timedelta(hours=23), timedelta(days=1), "(23h data span in 1d window)"),
        (timedelta(hours=23, minutes=30), timedelta(days=1), "(1d)"),
        (timedelta(days=3), timedelta(days=1), "(3d)"),
        (timedelta(hours=6), None, "(6h)"),
        (timedelta(0), None, "(0m)"),
    ],
)
def test_fmt_data_found_suffix_arms(
    data_span: timedelta,
    requested_span: timedelta | None,
    suffix: str,
) -> None:
    start = datetime(2026, 6, 1, tzinfo=timezone.utc)

    assert fmt_data_found(
        (start, start + data_span),
        requested_span,
    ).endswith(suffix)


def test_fmt_generated_arms() -> None:
    assert fmt_generated(None) == version_string()
    assert fmt_generated(
        datetime(2026, 7, 23, 9, 14, tzinfo=timezone.utc)
    ) == (
        f"2026-07-23 09:14 local  ·  {version_string()}"
    )


class _FakeStream:
    """Minimal stderr stand-in for liveness tests.

    Exposes ``isatty()``, ``write()``, ``flush()`` and an ``output``
    property that joins the captured chunks. Writes are guarded by a lock
    so the spinner thread and the test body do not tear a string.
    """

    def __init__(self, tty: bool, encoding: str | None = "utf-8") -> None:
        self._tty = tty
        self.encoding = encoding
        self._chunks: list[str] = []
        self._lock = threading.Lock()

    def isatty(self) -> bool:
        return self._tty

    def write(self, s: str) -> int:
        with self._lock:
            self._chunks.append(s)
        return len(s)

    def flush(self) -> None:  # pragma: no cover - no-op
        return None

    @property
    def output(self) -> str:
        with self._lock:
            return "".join(self._chunks)


@pytest.fixture()
def _restore_cursor_state():
    """Keep the process-global cursor manager hermetic across unit tests."""
    saved = (
        display_mod._NARRATION_ENABLED,
        display_mod._CURSOR_DEPTH,
        display_mod._CURSOR_SUSPEND_DEPTH,
        display_mod._CURSOR_STREAM,
    )
    display_mod._CURSOR_DEPTH = 0
    display_mod._CURSOR_SUSPEND_DEPTH = 0
    display_mod._CURSOR_STREAM = None
    try:
        yield
    finally:
        (
            display_mod._NARRATION_ENABLED,
            display_mod._CURSOR_DEPTH,
            display_mod._CURSOR_SUSPEND_DEPTH,
            display_mod._CURSOR_STREAM,
        ) = saved


def test_hidden_cursor_dectcem_pair_is_byte_exact(
    monkeypatch, _restore_cursor_state,
) -> None:
    fake = _FakeStream(tty=True)
    monkeypatch.delenv("TERM", raising=False)
    set_narration_enabled(True)

    with hidden_cursor(fake):
        pass

    assert fake.output == _CURSOR_HIDE + _CURSOR_SHOW


def test_hidden_cursor_nesting_and_visible_suspension_are_reentrant(
    monkeypatch, _restore_cursor_state,
) -> None:
    fake = _FakeStream(tty=True)
    observed: list[str] = []
    monkeypatch.delenv("TERM", raising=False)
    set_narration_enabled(True)

    with hidden_cursor(fake):
        with hidden_cursor(fake):
            pass
        with cursor_visible():
            observed.append(fake.output)
            with cursor_visible():
                with hidden_cursor(fake):
                    observed.append(fake.output)

    assert observed == [
        _CURSOR_HIDE + _CURSOR_SHOW,
        _CURSOR_HIDE + _CURSOR_SHOW,
    ]
    assert fake.output == (
        _CURSOR_HIDE + _CURSOR_SHOW + _CURSOR_HIDE + _CURSOR_SHOW
    )


def test_hidden_cursor_restores_after_exception(
    monkeypatch, _restore_cursor_state,
) -> None:
    fake = _FakeStream(tty=True)
    monkeypatch.delenv("TERM", raising=False)
    set_narration_enabled(True)

    with pytest.raises(RuntimeError, match="boom"):
        with hidden_cursor(fake):
            raise RuntimeError("boom")

    assert fake.output == _CURSOR_HIDE + _CURSOR_SHOW


@pytest.mark.parametrize(
    ("tty", "term", "enabled"),
    [
        (False, "xterm-256color", True),
        (True, "dumb", True),
        (True, "xterm-256color", False),
    ],
)
def test_hidden_cursor_gate_matrix_writes_nothing(
    monkeypatch, _restore_cursor_state, tty: bool, term: str, enabled: bool,
) -> None:
    fake = _FakeStream(tty=tty)
    monkeypatch.setenv("TERM", term)
    set_narration_enabled(enabled)

    with hidden_cursor(fake):
        pass

    assert fake.output == ""


def test_hidden_cursor_default_captured_stderr_writes_nothing(
    monkeypatch, capsys, _restore_cursor_state,
) -> None:
    monkeypatch.delenv("TERM", raising=False)
    set_narration_enabled(True)

    with hidden_cursor():
        pass

    assert capsys.readouterr().err == ""


def test_hidden_cursor_ignores_no_color(
    monkeypatch, _restore_cursor_state,
) -> None:
    fake = _FakeStream(tty=True)
    monkeypatch.setenv("TERM", "xterm-256color")
    monkeypatch.setenv("NO_COLOR", "1")
    set_narration_enabled(True)

    with hidden_cursor(fake):
        pass

    assert fake.output == _CURSOR_HIDE + _CURSOR_SHOW


def test_hidden_cursor_leaves_piped_stderr_byte_clean(
    monkeypatch, _restore_cursor_state,
) -> None:
    pipe = _FakeStream(tty=False)
    pipe.write("existing diagnostic\n")
    monkeypatch.delenv("TERM", raising=False)
    set_narration_enabled(True)

    with hidden_cursor(pipe):
        pass

    assert pipe.output == "existing diagnostic\n"


def _has_any_frame(text: str) -> bool:
    return any(f in text for f in _SPINNER_FRAMES + _ASCII_SPINNER_FRAMES)


def _poll_until_drew(stream: _FakeStream, budget_s: float = 0.5) -> bool:
    """Poll the fake's buffer until a \\r appears, signalling _drew flipped."""
    deadline = time.monotonic() + budget_s
    while time.monotonic() < deadline:
        if "\r" in stream.output:
            return True
        time.sleep(0.005)
    return False


# ── Test 1 ──────────────────────────────────────────────────────────────────


def test_non_tty_silent_enter_seal_writes_record_only(monkeypatch):
    fake = _FakeStream(tty=False)
    monkeypatch.setattr(sys, "stderr", fake)
    with liveness("running thing") as ln:
        ln.seal("done")
    assert fake.output == "done\n"


# ── Test 2 ──────────────────────────────────────────────────────────────────


def test_non_tty_exception_writes_nothing(monkeypatch):
    fake = _FakeStream(tty=False)
    monkeypatch.setattr(sys, "stderr", fake)
    with pytest.raises(RuntimeError):
        with liveness("running thing"):
            raise RuntimeError("boom")
    assert fake.output == ""


# ── Test 3 - the byte-exact one ─────────────────────────────────────────────


def test_seal_before_delay_is_byte_exact(monkeypatch):
    fake = _FakeStream(tty=True)
    monkeypatch.setattr(sys, "stderr", fake)
    # delay=10s means the spinner thread is parked in stop_event.wait(10);
    # immediate seal sets the event before any frame can draw.
    with liveness("running thing", delay=10.0) as ln:
        ln.seal("done")
    # Exact buffer: only the record line. No \r, no spaces, no frame chars.
    assert fake.output == "done\n"


# ── Test 4 ──────────────────────────────────────────────────────────────────


def test_exception_after_drew_clears_no_record(monkeypatch):
    fake = _FakeStream(tty=True)
    monkeypatch.setattr(sys, "stderr", fake)
    with pytest.raises(RuntimeError):
        with liveness("running thing", delay=0.0):
            assert _poll_until_drew(fake), (
                "spinner thread did not draw within budget - _drew=True "
                "branch not exercised"
            )
            raise RuntimeError("boom")
    # Spinner drew, so _drew was True, so teardown emitted a clearing \r.
    assert "\r" in fake.output
    # And nothing claiming success was written.
    assert "done" not in fake.output
    # __exit__ never writes a newline-terminated record on its own -
    # only the spinner's own \r-redrawn line should be in the buffer.
    assert "\n" not in fake.output


# ── Test 5 ──────────────────────────────────────────────────────────────────


def test_keyboard_interrupt_propagates(monkeypatch):
    fake = _FakeStream(tty=True)
    monkeypatch.setattr(sys, "stderr", fake)
    with pytest.raises(KeyboardInterrupt):
        with liveness("running thing", delay=0.0):
            # No need to wait for a frame here - the contract is that
            # KeyboardInterrupt (a BaseException, not an Exception) is
            # not swallowed by the context manager.
            raise KeyboardInterrupt
    # No false seal.
    assert "done" not in fake.output


# ── Test 6 ──────────────────────────────────────────────────────────────────


def test_seal_is_idempotent(monkeypatch):
    fake = _FakeStream(tty=False)
    monkeypatch.setattr(sys, "stderr", fake)
    with liveness("running thing") as ln:
        ln.seal("done")
        ln.seal("done")
    assert fake.output == "done\n"


# ── Bonus: a spinner that actually drew, then sealed, clears once ──────────


def test_seal_after_drew_clears_then_writes_record(monkeypatch):
    fake = _FakeStream(tty=True)
    monkeypatch.setattr(sys, "stderr", fake)
    with liveness("running thing", delay=0.0) as ln:
        assert _poll_until_drew(fake), (
            "spinner thread did not draw within budget"
        )
        ln.seal("done")
    out = fake.output
    # Spinner drew at least one frame char.
    assert _has_any_frame(out)
    # Sealed record is present and is the LAST thing in the buffer.
    assert out.endswith("done\n")
    # Exactly one record line.
    assert out.count("done\n") == 1


def test_liveness_falls_back_to_ascii_spinner_on_non_unicode_stream(
    monkeypatch,
):
    fake = _FakeStream(tty=True, encoding="ascii")
    monkeypatch.delenv("TERM", raising=False)
    monkeypatch.setattr(sys, "stderr", fake)
    with liveness("running thing", delay=0.0) as ln:
        assert _poll_until_drew(fake), (
            "spinner thread did not draw within budget"
        )
        ln.seal("done")
    assert any(f in fake.output for f in _ASCII_SPINNER_FRAMES)
    # The | / \ frames are shared with the box-drawing set, so they appear in
    # ASCII fallback too - only the box-exclusive glyph (the ─ horizontal bar)
    # proves which set rendered. In fallback it must never reach the stream.
    box_only = set(_SPINNER_FRAMES) - set(_ASCII_SPINNER_FRAMES)
    assert not any(f in fake.output for f in box_only)


def test_spinner_frames_prefers_box_drawing_when_stream_can_encode(
    monkeypatch,
):
    monkeypatch.delenv("TERM", raising=False)
    assert _spinner_frames_for(
        _FakeStream(tty=True, encoding="utf-8")
    ) == _SPINNER_FRAMES


def test_spinner_frames_falls_back_on_dumb_terminal(monkeypatch):
    monkeypatch.setenv("TERM", "dumb")
    assert _spinner_frames_for(
        _FakeStream(tty=True, encoding="utf-8")
    ) == _ASCII_SPINNER_FRAMES


def test_spinner_frames_falls_back_when_stream_cannot_encode(monkeypatch):
    monkeypatch.delenv("TERM", raising=False)
    assert _spinner_frames_for(
        _FakeStream(tty=True, encoding="ascii")
    ) == _ASCII_SPINNER_FRAMES


# ── progress() helper ───────────────────────────────────────────────────────


class _TqdmSpy:
    """Spy that records construction kwargs and acts as the tqdm bar object.

    Patched in for `sigwood.common.display.tqdm` so progress() tests can
    assert that tqdm IS or IS NOT constructed, inspect the kwargs the helper
    passes when it is, and observe the counter (`progress()` now drives the bar
    via `update(1)` from its own generator - NO iterable is passed to tqdm).
    """

    def __init__(self) -> None:
        self.calls: list[dict] = []
        self.n = 0
        self.closed = False

    def __call__(self, iterable=None, **kwargs):
        self.calls.append(kwargs)
        return self

    def __iter__(self):
        # progress() must drive the bar via update(1) from its OWN generator and
        # never iterate the tqdm object directly. If a regression returns the bar
        # itself (the `loaded X: 0.00 lines` orphaned-counter bug), fail LOUDLY
        # here rather than with a confusing AttributeError downstream.
        raise AssertionError(
            "progress() iterated the tqdm bar directly - it must wrap it in its "
            "own counting generator (iter(gen) is gen) so the count survives "
            "parser re-iteration"
        )

    def update(self, k: int = 1) -> None:
        self.n += k

    def close(self) -> None:
        self.closed = True


def test_progress_disabled_returns_bare_iterable_no_tqdm(monkeypatch):
    spy = _TqdmSpy()
    monkeypatch.setattr(display_mod, "tqdm", spy)
    fake = _FakeStream(tty=True)
    items = [1, 2, 3]
    result = list(progress(items, desc="loaded x.log",
                           show_progress=False, stream=fake))
    assert result == [1, 2, 3]
    assert spy.calls == []  # tqdm NEVER constructed when disabled


def test_progress_non_tty_returns_bare_iterable_no_tqdm(monkeypatch):
    spy = _TqdmSpy()
    monkeypatch.setattr(display_mod, "tqdm", spy)
    fake = _FakeStream(tty=False)
    items = ["a", "b"]
    result = list(progress(items, desc="loaded x.log",
                           show_progress=True, stream=fake))
    assert result == ["a", "b"]
    assert spy.calls == []  # tqdm NEVER constructed off a TTY


def test_progress_tty_constructs_tqdm_with_pinned_format(monkeypatch):
    spy = _TqdmSpy()
    monkeypatch.setattr(display_mod, "tqdm", spy)
    fake = _FakeStream(tty=True)
    # The return is now a GENERATOR wrapping the tqdm; tqdm is constructed WITHOUT
    # an iterable and driven via update(1).
    out = list(progress(["a"], desc="loaded x.log",
                        show_progress=True, unit=" lines", stream=fake))
    assert out == ["a"]
    assert len(spy.calls) == 1
    kw = spy.calls[0]
    # Pinned bar_format reproduces the long-standing NDJSON bar byte-for-byte
    # when unit=" lines".
    assert kw["bar_format"] == "{desc}: {n_fmt} lines [{elapsed}]"
    assert kw["desc"] == "loaded x.log"
    assert kw["unit"] == " lines"
    assert kw["leave"] is True
    assert kw["unit_scale"] is True
    assert kw["mininterval"] == 0.5
    assert kw["file"] is fake
    # The generator drove the bar and closed it.
    assert spy.n == 1
    assert spy.closed is True


def test_progress_count_survives_two_phase_reiteration(monkeypatch):
    """Regression for `loaded X: 0.00 lines`: a parser that sniffs-then-resumes
    (Zeek `itertools.chain(prefix, line_iter)`) re-iterates the progress result.
    Because progress() returns a GENERATOR (iter(gen) is gen), the SAME counter
    continues - every item is counted exactly once. Exercises the REAL progress()
    (only `tqdm` is faked for inspection; progress itself is NOT replaced)."""
    import itertools

    spy = _TqdmSpy()
    monkeypatch.setattr(display_mod, "tqdm", spy)
    fake = _FakeStream(tty=True)
    items = list(range(10))

    it = progress(items, desc="loaded conn.log",
                  show_progress=True, unit=" lines", stream=fake)
    # Phase 1: sniff one item then break (mimics the NDJSON-vs-TSV sniff).
    prefix: list[int] = []
    for x in it:
        prefix.append(x)
        break
    # Phase 2: chain the prefix back and consume the rest from the SAME iterator.
    rest = list(itertools.chain(prefix, it))

    assert rest == items, "every item observed once, in order, across re-iteration"
    assert spy.n == 10, "counter is the TRUE total, not orphaned at the sniff break"
    assert spy.closed is True


def test_progress_unit_parameterization(monkeypatch):
    """Different units (e.g. " events") thread cleanly into bar_format."""
    spy = _TqdmSpy()
    monkeypatch.setattr(display_mod, "tqdm", spy)
    fake = _FakeStream(tty=True)
    list(progress(["a"], desc="loaded x", show_progress=True,
                  unit=" events", stream=fake))
    assert spy.calls[0]["bar_format"] == "{desc}: {n_fmt} events [{elapsed}]"


def test_progress_ignores_no_color(monkeypatch):
    """Color policy is NOT a progress policy - a color preference must not
    suppress the progress bar."""
    spy = _TqdmSpy()
    monkeypatch.setattr(display_mod, "tqdm", spy)
    monkeypatch.setenv("NO_COLOR", "1")
    fake = _FakeStream(tty=True)
    list(progress(["a"], desc="loaded x", show_progress=True, stream=fake))
    assert len(spy.calls) == 1


def test_progress_ignores_term_dumb(monkeypatch):
    """TERM=dumb is a color signal, not a progress signal."""
    spy = _TqdmSpy()
    monkeypatch.setattr(display_mod, "tqdm", spy)
    monkeypatch.setenv("TERM", "dumb")
    fake = _FakeStream(tty=True)
    list(progress(["a"], desc="loaded x", show_progress=True, stream=fake))
    assert len(spy.calls) == 1


def test_progress_defaults_to_sys_stderr(monkeypatch):
    """When stream= is not passed, the helper resolves it to sys.stderr."""
    spy = _TqdmSpy()
    monkeypatch.setattr(display_mod, "tqdm", spy)
    fake = _FakeStream(tty=True)
    monkeypatch.setattr(sys, "stderr", fake)
    list(progress(["a"], desc="loaded x", show_progress=True))
    assert len(spy.calls) == 1
    assert spy.calls[0]["file"] is fake


# ── _stream_isatty factoring regression ─────────────────────────────────────


def test_stream_isatty_handles_missing_attr():
    """An object without isatty() resolves to False (no crash)."""

    class _Bare:
        pass

    assert _stream_isatty(_Bare()) is False


def test_stream_isatty_handles_raising_isatty():
    """isatty() raising is treated as False (no propagation)."""

    class _Boom:
        def isatty(self):
            raise OSError("nope")

    assert _stream_isatty(_Boom()) is False


def test_stream_isatty_true_and_false():
    assert _stream_isatty(_FakeStream(tty=True)) is True
    assert _stream_isatty(_FakeStream(tty=False)) is False


# ── phase_separator ─────────────────────────────────────────────────────────


def test_phase_separator_tty_writes_newline_and_flushes():
    """A tty stream gets exactly one newline (the cross-stream phase break)."""
    flushed: list[bool] = []
    fake = _FakeStream(tty=True)
    fake.flush = lambda: flushed.append(True)  # type: ignore[method-assign]
    phase_separator(fake)
    assert fake.output == "\n"
    assert flushed == [True]


def test_phase_separator_non_tty_writes_nothing():
    """Non-tty (piped/redirected) → no write, byte-clean stdout/stderr."""
    fake = _FakeStream(tty=False)
    phase_separator(fake)
    assert fake.output == ""


def test_phase_separator_defaults_to_sys_stderr(monkeypatch):
    """Default stream is sys.stderr (gated by its own tty state)."""
    fake = _FakeStream(tty=True)
    monkeypatch.setattr(sys, "stderr", fake)
    phase_separator()
    assert fake.output == "\n"


def test_color_enabled_still_layers_no_color_and_term_dumb(monkeypatch):
    """Color policy keeps NO_COLOR / TERM=dumb ON TOP of the raw TTY probe."""
    fake_tty = _FakeStream(tty=True)
    fake_non_tty = _FakeStream(tty=False)

    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.delenv("TERM", raising=False)
    assert _color_enabled(fake_tty) is True
    assert _color_enabled(fake_non_tty) is False

    monkeypatch.setenv("NO_COLOR", "1")
    assert _color_enabled(fake_tty) is False

    monkeypatch.delenv("NO_COLOR")
    monkeypatch.setenv("TERM", "dumb")
    assert _color_enabled(fake_tty) is False


# ── fmt_window / fmt_timestamp / plural - voice-consistency pass ────────────────

import os  # noqa: E402
from datetime import datetime, timedelta, timezone  # noqa: E402

from sigwood.common.display import (  # noqa: E402
    fmt_syslog_timestamp,
    fmt_timestamp,
    fmt_window,
    plural,
    set_display_utc,
    to_display_timezone,
)


def _pin_tz(name: str):
    """Set TZ + tzset, returning a restore callable for the prior value."""
    prev = os.environ.get("TZ")
    os.environ["TZ"] = name
    time.tzset()

    def _restore() -> None:
        if prev is None:
            os.environ.pop("TZ", None)
        else:
            os.environ["TZ"] = prev
        time.tzset()

    return _restore


def test_plural_zero_one_many_and_explicit_override() -> None:
    assert plural(0, "principal") == "principals"
    assert plural(1, "principal") == "principal"
    assert plural(2, "principal") == "principals"
    assert plural(7, "day") == "days"
    # Explicit irregular plural is used for n != 1, singular for n == 1.
    assert plural(1, "query", "queries") == "query"
    assert plural(3, "query", "queries") == "queries"


def test_fmt_window_renders_local_label_single_arrow() -> None:
    """Deterministic under a pinned UTC zone: values match the UTC input,
    single-spaced arrow, one trailing ``local`` label."""
    restore = _pin_tz("UTC")
    try:
        w = (
            datetime(2026, 6, 18, 0, 0, tzinfo=timezone.utc),
            datetime(2026, 6, 19, 0, 0, tzinfo=timezone.utc),
        )
        assert fmt_window(w) == "2026-06-18 00:00 → 2026-06-19 00:00 local"
    finally:
        restore()


def test_fmt_timestamp_is_labeled_single_bound() -> None:
    restore = _pin_tz("UTC")
    try:
        assert fmt_timestamp(datetime(2026, 6, 18, 0, 0, tzinfo=timezone.utc)) == (
            "2026-06-18 00:00 local"
        )
    finally:
        restore()


def test_fmt_syslog_timestamp_local_and_utc_shapes(
    pin_tz, restore_display_utc,
) -> None:
    pin_tz("UTC")
    single = datetime(2026, 7, 1, 3, 12, 47, tzinfo=timezone.utc)
    double = datetime(2026, 7, 12, 21, 57, 33, tzinfo=timezone.utc)

    assert fmt_syslog_timestamp(single) == "Jul  1 03:12:47"
    assert fmt_syslog_timestamp(double) == "Jul 12 21:57:33"

    set_display_utc(True)
    assert fmt_syslog_timestamp(single) == "Jul  1 03:12:47 UTC"
    assert fmt_syslog_timestamp(double) == "Jul 12 21:57:33 UTC"


def test_fmt_window_converts_to_machine_local_zone() -> None:
    """The renderer is machine-LOCAL: a fixed UTC instant shifts under a
    non-UTC zone. Proves tz policy lives in one spot (the renderer), and the
    helper restores the prior TZ so suite ordering is unaffected."""
    restore = _pin_tz("America/New_York")  # UTC-4 on this date (EDT)
    try:
        w = (
            datetime(2026, 6, 18, 12, 0, tzinfo=timezone.utc),
            datetime(2026, 6, 18, 13, 0, tzinfo=timezone.utc),
        )
        # 12:00 UTC → 08:00 EDT; label is still "local".
        assert fmt_window(w) == "2026-06-18 08:00 → 2026-06-18 09:00 local"
    finally:
        restore()


def test_fmt_timestamp_treats_naive_input_as_utc() -> None:
    restore = _pin_tz("UTC")
    try:
        # A naive datetime is treated as UTC, then rendered local (== UTC here).
        assert fmt_timestamp(datetime(2026, 6, 18, 6, 30)) == "2026-06-18 06:30 local"
    finally:
        restore()


# ── Detector-owned narration gate (the -q seam for the syslog drain3 bar) ─────
@pytest.fixture()
def _restore_narration():
    """Save/restore the process-global narration flag so a test that flips it
    can't leak into the rest of the suite."""
    saved = display_mod._NARRATION_ENABLED
    try:
        yield
    finally:
        display_mod._NARRATION_ENABLED = saved


def test_narration_active_gates_on_global_and_tty(_restore_narration):
    """``narration_active`` is True iff the runner's global gate is on AND the
    stream is a TTY - both arms required, matching color's ambient gate."""
    tty = _FakeStream(tty=True)
    pipe = _FakeStream(tty=False)

    set_narration_enabled(True)
    assert narration_active(tty) is True       # enabled + tty → narrate
    assert narration_active(pipe) is False     # enabled + pipe → silent (TTY gate)

    set_narration_enabled(False)               # the -q path
    assert narration_active(tty) is False      # quiet wins even on a tty
    assert narration_active(pipe) is False


def test_narration_active_defaults_to_stderr(monkeypatch, _restore_narration):
    """A bare call gates on stderr (the narration stream)."""
    set_narration_enabled(True)
    monkeypatch.setattr(sys, "stderr", _FakeStream(tty=True))
    assert narration_active() is True
    monkeypatch.setattr(sys, "stderr", _FakeStream(tty=False))
    assert narration_active() is False


# ── Display timezone switch (the --utc / use_utc seam) ────────────────────────


def test_fmt_display_switch_flips_zone_and_label(pin_tz, restore_display_utc) -> None:
    """Switch off → wall-clock shifted by the pinned zone with label ``local``;
    switch on → UTC wall-clock with label ``UTC``. Expected values by manual
    offset arithmetic (Etc/GMT+6 is UTC-6 - POSIX sign inversion)."""
    pin_tz("Etc/GMT+6")
    w = (
        datetime(2026, 6, 18, 12, 0, tzinfo=timezone.utc),
        datetime(2026, 6, 18, 13, 0, tzinfo=timezone.utc),
    )
    assert fmt_window(w) == "2026-06-18 06:00 → 2026-06-18 07:00 local"
    assert fmt_timestamp(datetime(2026, 6, 18, 12, 0, tzinfo=timezone.utc)) == (
        "2026-06-18 06:00 local"
    )

    set_display_utc(True)
    assert fmt_window(w) == "2026-06-18 12:00 → 2026-06-18 13:00 UTC"
    assert fmt_timestamp(datetime(2026, 6, 18, 12, 0, tzinfo=timezone.utc)) == (
        "2026-06-18 12:00 UTC"
    )


def test_to_display_timezone_follows_switch(pin_tz, restore_display_utc) -> None:
    """The conversion returns a display-offset representation of the SAME
    instant: pinned-local offset when the switch is off, +00:00 when on."""
    pin_tz("Etc/GMT+6")
    dt = datetime(2026, 6, 18, 12, 0, tzinfo=timezone.utc)

    off = to_display_timezone(dt)
    assert off.utcoffset() == timedelta(hours=-6)
    assert off == dt

    set_display_utc(True)
    on = to_display_timezone(dt)
    assert on.utcoffset() == timedelta(0)
    assert on == dt


def test_naive_input_still_assumed_utc_under_switch(restore_display_utc) -> None:
    """The naive branch's assume-UTC contract is switch-independent: internal
    naive datetimes are UTC by contract, the switch only picks the OUTPUT zone."""
    set_display_utc(True)
    out = to_display_timezone(datetime(2026, 6, 18, 6, 30))
    assert out == datetime(2026, 6, 18, 6, 30, tzinfo=timezone.utc)
    assert out.utcoffset() == timedelta(0)
