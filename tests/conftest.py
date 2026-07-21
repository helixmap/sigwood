"""Test fixtures shared across the suite."""

from __future__ import annotations

import os
import time

import pytest


@pytest.fixture(autouse=True)
def _restore_process_umask():
    """Keep process-wide CLI umask changes isolated to one in-process test."""
    previous = os.umask(0)
    os.umask(previous)
    try:
        yield
    finally:
        os.umask(previous)


@pytest.fixture(autouse=True, scope="session")
def _pin_utc_timezone():
    """Pin the process timezone to UTC for the whole suite.

    The human window/timestamp renderers (``common/display.fmt_window`` /
    ``fmt_timestamp``) render in the machine-LOCAL zone. Pinning UTC makes
    local == UTC, so window strings are deterministic across developer/CI
    machine zones AND render the same numbers as the (UTC) input datetimes.
    Restores the prior ``TZ`` afterward so the pinning is not order-dependent.
    """
    prev = os.environ.get("TZ")
    os.environ["TZ"] = "UTC"
    time.tzset()
    try:
        yield
    finally:
        if prev is None:
            os.environ.pop("TZ", None)
        else:
            os.environ["TZ"] = prev
        time.tzset()


@pytest.fixture()
def pin_tz():
    """Per-test TZ pin - call ``pin_tz("Etc/GMT+6")`` inside the test body.

    Timezone-sensitive tests (host-local wall-clock parsing, local rendering)
    pin a FIXED-OFFSET zone through this one helper. Teardown restores the
    prior ``TZ`` and calls ``time.tzset()`` even when the test body fails, so
    the session-wide UTC pin stays order-safe.
    """
    prev = os.environ.get("TZ")

    def _pin(name: str) -> None:
        os.environ["TZ"] = name
        time.tzset()

    try:
        yield _pin
    finally:
        if prev is None:
            os.environ.pop("TZ", None)
        else:
            os.environ["TZ"] = prev
        time.tzset()


@pytest.fixture()
def restore_display_utc():
    """Save/restore the display-timezone process global around a test.

    EVERY test that flips the display switch - directly, via
    ``set_display_utc``, or by driving ``run``/``run_digest``/``run_export``/
    ``cli.main`` with ``--utc`` or ``use_utc=True`` - declares this fixture,
    so the process-global never leaks across tests regardless of where the
    flip happened. The restore runs even when the test body fails.
    """
    import sigwood.common.display as display_mod

    prev = display_mod._DISPLAY_UTC
    try:
        yield
    finally:
        display_mod._DISPLAY_UTC = prev


def pytest_configure(config: pytest.Config) -> None:
    """Register custom markers."""
    # Reserved for future opt-in/opt-out behaviour; the drift tripwire still
    # uses it as a self-documenting hint that the test depends on real shipped
    # _DEFAULTS. There is no autouse fixture to opt out of.
    config.addinivalue_line(
        "markers",
        "real_defaults: documents that the test depends on the actual shipped "
        "_DEFAULTS (no per-test mutation of config defaults applied)",
    )
