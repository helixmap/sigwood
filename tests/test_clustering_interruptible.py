"""Process-isolation harness for HDBSCAN.fit_predict - Ctrl-C honoured.

Covers sigwood.common.clustering.fit_predict_interruptible and its
helpers. Detector-logic tests live in tests/test_dns_detector.py and
are intentionally NOT extended here - they flip _CLUSTERING_ISOLATE_ENABLED
to False via an autouse fixture and exercise the in-process path.

Worker targets MUST be module-level so they pickle cleanly under spawn.
Nested functions, lambdas, and closures would not survive spawn re-import.
Tests rebind clustering._WORKER_TARGET to the helpers below before
invoking fit_predict_interruptible; the spawn child re-imports this
module (its qualified name is tests.test_clustering_interruptible) and
finds the target by name.

All test data is synthetic numpy - no real network data anywhere.
"""

from __future__ import annotations

import importlib
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import numpy as np
import pytest

from sigwood.common import clustering


# ── Module-level workers (picklable under spawn) ─────────────────────────────


def _blocking_worker(
    result_queue, X, min_cluster_size, min_samples, backend,
) -> None:
    """Test target: park forever until the parent kills us. Used to
    verify that a parent-side KeyboardInterrupt drives the
    terminate→kill→cleanup sequence and that the child does not leak."""
    while True:
        time.sleep(0.05)


def _erroring_worker(
    result_queue, X, min_cluster_size, min_samples, backend,
) -> None:
    """Test target: report an error tuple and exit. Verifies the parent
    surfaces worker errors as a normal ValueError, not a multiprocessing
    traceback."""
    result_queue.put(("error", "RuntimeError: induced failure"))


def _dying_worker(
    result_queue, X, min_cluster_size, min_samples, backend,
) -> None:
    """Test target: exit WITHOUT putting anything on the queue. Simulates
    segfault / OOM kill / unhandled signal in the real worker. The parent
    polling rail must raise RuntimeError, not hang forever."""
    sys.exit(7)


def _good_worker(
    result_queue, X, min_cluster_size, min_samples, backend,
) -> None:
    """Test target: return a fixed all-zeros label array."""
    result_queue.put(("ok", np.zeros(len(X), dtype=np.int64)))


# ── 0. Tiny-input preservation control ──────────────────────────────────────


def test_two_samples_preserve_active_backend_labels() -> None:
    """Two samples are a working backend input and must stay on the real path.

    This control is green before the degenerate-input guard lands. Comparing
    the shared helper to the active backend prevents a future guard from
    swallowing the smallest input the backend can compute.
    """
    X = np.zeros((2, 4), dtype=np.float64)
    expected = clustering.HDBSCAN(
        min_cluster_size=25, min_samples=5,
    ).fit_predict(X)

    actual = clustering.fit_predict_interruptible(
        X, min_cluster_size=25, min_samples=5,
    )

    assert np.array_equal(actual, expected)
    assert actual.dtype.kind == expected.dtype.kind


@pytest.mark.parametrize("config_path", ["zeek", "pihole"])
@pytest.mark.parametrize("sample_count", [0, 1])
def test_fewer_than_two_samples_return_noise_without_spawning(
    monkeypatch: pytest.MonkeyPatch,
    config_path: str,
    sample_count: int,
) -> None:
    """Both DNS config pairs share the parent-side all-noise fast path."""
    from sigwood.detectors.dns import DEFAULT_CONFIG

    config = (
        DEFAULT_CONFIG
        if config_path == "zeek"
        else DEFAULT_CONFIG["pihole"]
    )
    min_cluster_size = config["min_cluster_size"]
    min_samples = config["min_samples"]
    reference = clustering.HDBSCAN(
        min_cluster_size=min_cluster_size,
        min_samples=min_samples,
    ).fit_predict(np.zeros((2, 4), dtype=np.float64))

    def _spawn_is_a_failure(_method: str) -> None:
        pytest.fail("degenerate input reached multiprocessing.get_context")

    monkeypatch.setattr(
        clustering.multiprocessing, "get_context", _spawn_is_a_failure,
    )

    labels = clustering.fit_predict_interruptible(
        np.zeros((sample_count, 4), dtype=np.float64),
        min_cluster_size=min_cluster_size,
        min_samples=min_samples,
    )

    assert labels.shape == (sample_count,)
    assert np.all(labels == -1)
    assert labels.dtype.kind == reference.dtype.kind


# ── 1. Interruptibility - KeyboardInterrupt propagates, child terminated ────


def test_keyboard_interrupt_propagates_and_terminates_child(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A parent-side KeyboardInterrupt during the polling wait causes the
    helper to invoke the committed terminate→join→kill→cleanup→re-raise
    sequence. The KeyboardInterrupt must propagate to the caller; the
    child must be terminated (not zombied); and the helper's cleanup
    must complete without raising (a still-alive child would make
    Process.close() raise - that's the implicit proof the child died).

    Deterministic harness: patch _await_child_result to raise
    KeyboardInterrupt directly. The polling loop's queue.get is what
    would actually raise when the main thread sees SIGINT; raising
    explicitly avoids racing a real signal in the test process.
    """
    monkeypatch.setattr(
        clustering, "_WORKER_TARGET", _blocking_worker,
    )

    # Spy on Process.terminate so we capture state BEFORE the helper's
    # cleanup calls child.close() (which makes the handle unqueryable).
    snapshot: dict = {}
    real_terminate = type(
        clustering.multiprocessing.get_context("spawn").Process(
            target=_good_worker, args=(None, None, 0, 0, "x"),
        )
    ).terminate

    def _spy_terminate(self):
        snapshot["alive_before_terminate"] = self.is_alive()
        return real_terminate(self)

    monkeypatch.setattr(
        clustering.multiprocessing.context.SpawnProcess,
        "terminate", _spy_terminate,
    )

    def _intercepted_await(result_queue, child):
        # Hand the live child to the snapshot dict so a post-cleanup
        # query against its (now-closed) handle isn't required.
        snapshot["proc"] = child
        raise KeyboardInterrupt

    monkeypatch.setattr(
        clustering, "_await_child_result", _intercepted_await,
    )

    X = np.zeros((10, 2), dtype=np.float64)
    with pytest.raises(KeyboardInterrupt):
        clustering.fit_predict_interruptible(
            X, min_cluster_size=5, min_samples=2,
        )

    # The terminate spy fired - proves the helper went down the interrupt
    # cleanup path rather than the normal-return cleanup path. Child was
    # alive when terminate ran (i.e. it was a real running process the
    # interrupt-cleanup had to take down, not a no-op).
    assert snapshot.get("alive_before_terminate") is True
    # The helper completed cleanup without raising from child.close() -
    # which would have raised if the child were still alive at that
    # point. That's the implicit proof that terminate→join→(kill?) drove
    # the child to a terminated state.


# ── 2. No resource_tracker leak - subprocess harness ────────────────────────


@pytest.mark.skipif(
    sys.platform.startswith("win"),
    reason="multiprocessing.resource_tracker is a POSIX concern",
)
def test_no_resource_tracker_warning_on_interrupt(tmp_path: Path) -> None:
    """Regression guard: a SIGINT during a stock-hdbscan clustering run
    must terminate the child cleanly with NO resource_tracker 'leaked
    semaphore' message on subprocess stderr.

    pytest's warnings.catch_warnings does NOT reliably capture
    multiprocessing.resource_tracker output - that line is emitted on
    process-shutdown stderr from a sibling thread the pytest capture
    machinery has already torn down. A subprocess harness captures the
    real stderr, including post-shutdown chatter.

    Stock hdbscan is the target backend: it spawns the nested
    multiprocessing pool that leaks semaphores. fast_hdbscan uses numba
    threads, so the bug never manifests there. The harness explicitly
    rebinds clustering.HDBSCAN to stock's class - setting
    ACTIVE_BACKEND='hdbscan' alone would leave clustering.HDBSCAN
    pointing at fast_hdbscan.HDBSCAN (which won at module-load time) and
    _build_clusterer would pass core_dist_n_jobs=1 to the wrong class.
    """
    try:
        import hdbscan as _stock  # noqa: F401
    except ImportError:
        pytest.skip("stock hdbscan not importable")

    script = tmp_path / "harness.py"
    script.write_text(textwrap.dedent('''
        import os
        import signal
        import threading
        import time

        import numpy as np
        import hdbscan as _stock

        from sigwood.common import clustering

        # Both knobs are required - ACTIVE_BACKEND drives
        # _build_clusterer's kwarg branch; clustering.HDBSCAN drives
        # the class actually constructed. Setting one without the
        # other silently mis-targets the test.
        clustering.HDBSCAN = _stock.HDBSCAN
        clustering.ACTIVE_BACKEND = "hdbscan"

        # Reasonably sized synthetic feature matrix so clustering takes
        # long enough for the SIGINT thread below to land mid-compute.
        rng = np.random.default_rng(0)
        X = rng.normal(size=(2000, 4)).astype(np.float64)

        def _sigint_after():
            time.sleep(0.5)
            os.kill(os.getpid(), signal.SIGINT)

        threading.Thread(target=_sigint_after, daemon=True).start()
        try:
            clustering.fit_predict_interruptible(
                X, min_cluster_size=50, min_samples=5,
            )
        except KeyboardInterrupt:
            pass
    '''))

    result = subprocess.run(
        [sys.executable, str(script)],
        capture_output=True, text=True, timeout=60,
    )
    # Harness must complete cleanly - a crash for unrelated reasons
    # would leave the resource_tracker assertions trivially true and
    # silently false-pass the regression. The harness's own
    # except-KeyboardInterrupt arm swallows the interrupt, so a
    # clean exit code is the right expectation.
    assert result.returncode == 0, (
        f"harness crashed (rc={result.returncode}); "
        f"stderr={result.stderr!r}"
    )
    # The regression signals - none of these strings may appear in
    # post-interrupt stderr.
    assert "resource_tracker" not in result.stderr, result.stderr
    assert "leaked semaphore" not in result.stderr, result.stderr
    assert "leaked shared_memory" not in result.stderr, result.stderr


# ── 3. Equivalence - isolated vs in-process ─────────────────────────────────


def test_isolation_does_not_change_labels() -> None:
    """The isolated path and the in-process escape hatch must produce
    identical label arrays on the same input. Isolation is a control
    affordance, not a numerical change.

    Uses a synthetic feature matrix with a clear two-cluster structure
    + a handful of outliers, so HDBSCAN produces a deterministic
    non-trivial label vector both ways.
    """
    rng = np.random.default_rng(42)
    cluster_a = rng.normal(loc=0.0, scale=0.05, size=(60, 4))
    cluster_b = rng.normal(loc=2.0, scale=0.05, size=(60, 4))
    outliers = rng.uniform(low=-3.0, high=5.0, size=(8, 4))
    X = np.ascontiguousarray(
        np.vstack([cluster_a, cluster_b, outliers]).astype(np.float64),
    )

    # Run isolated first so any backend-conditional kwarg in the worker
    # is exercised - the in-process run is the calibration reference.
    labels_isolated = clustering.fit_predict_interruptible(
        X, min_cluster_size=10, min_samples=5,
    )

    # Force the in-process path for the second run.
    saved = clustering._CLUSTERING_ISOLATE_ENABLED
    clustering._CLUSTERING_ISOLATE_ENABLED = False
    try:
        labels_in_process = clustering.fit_predict_interruptible(
            X, min_cluster_size=10, min_samples=5,
        )
    finally:
        clustering._CLUSTERING_ISOLATE_ENABLED = saved

    assert np.array_equal(labels_isolated, labels_in_process), (
        f"isolated={labels_isolated.tolist()!r} "
        f"in_process={labels_in_process.tolist()!r}"
    )


# ── 4. Backend-conditional kwarg - _build_clusterer direct ──────────────────


def test_build_clusterer_stock_passes_core_dist_n_jobs_1(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Stock hdbscan branch: core_dist_n_jobs=1 must be in the kwargs so
    no nested multiprocessing pool spawns (the source of the leaked-
    semaphore warning). Tested by mocking clustering.HDBSCAN to a
    recording fake and calling _build_clusterer directly - no spawn,
    no escape-hatch path, just the construction surface."""
    recorded: dict = {}

    class _RecordingHDBSCAN:
        def __init__(self, **kwargs):
            recorded.update(kwargs)

    monkeypatch.setattr(clustering, "HDBSCAN", _RecordingHDBSCAN)

    clustering._build_clusterer(
        "hdbscan", min_cluster_size=100, min_samples=10,
    )

    assert recorded == {
        "min_cluster_size": 100,
        "min_samples": 10,
        "core_dist_n_jobs": 1,
    }


def test_build_clusterer_fast_omits_core_dist_n_jobs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """fast_hdbscan branch: core_dist_n_jobs is NOT in the kwargs (it
    isn't in fast_hdbscan's signature; passing it would TypeError).
    Numba threads on the fast backend don't use semaphores, so no
    resource-tracker concern exists there."""
    recorded: dict = {}

    class _RecordingHDBSCAN:
        def __init__(self, **kwargs):
            recorded.update(kwargs)

    monkeypatch.setattr(clustering, "HDBSCAN", _RecordingHDBSCAN)

    clustering._build_clusterer(
        "fast_hdbscan", min_cluster_size=2000, min_samples=100,
    )

    assert recorded == {"min_cluster_size": 2000, "min_samples": 100}
    assert "core_dist_n_jobs" not in recorded


# ── 5. Error propagation - worker raises → parent ValueError ────────────────


def test_worker_error_surfaces_as_value_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A worker that puts an ('error', ...) tuple must surface as a
    normal ValueError in the parent - the existing detector contract.
    No hang, no multiprocessing traceback bleeding through."""
    monkeypatch.setattr(
        clustering, "_WORKER_TARGET", _erroring_worker,
    )

    X = np.zeros((10, 2), dtype=np.float64)
    with pytest.raises(ValueError, match="induced failure"):
        clustering.fit_predict_interruptible(
            X, min_cluster_size=5, min_samples=2,
        )


# ── 6. Child dies without queueing - parent RuntimeError, no hang ───────────


def test_child_dying_without_result_raises_runtime_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If the worker exits without putting a result on the queue
    (segfault, OOM kill, unhandled signal), the polling rail's
    is_alive() check must raise RuntimeError mentioning the exit code.
    Indefinite queue.get() would have hung forever - this is the
    regression guard for the hang.

    Also asserts the universal cleanup path RAN on this abnormal-exit
    code path. The guarded failure mode: fit_predict_interruptible only
    caught KeyboardInterrupt, so RuntimeError from _await_child_result
    bypassed queue drain/close/join_thread AND child.close - the exact
    multiprocessing resource leak the helper was designed to handle.
    Spying on _drain_and_close_queue confirms the cleanup ran.
    """
    monkeypatch.setattr(
        clustering, "_WORKER_TARGET", _dying_worker,
    )

    cleanup_calls: list = []
    real_drain = clustering._drain_and_close_queue

    def _spy_drain(result_queue):
        cleanup_calls.append("drain")
        return real_drain(result_queue)

    monkeypatch.setattr(
        clustering, "_drain_and_close_queue", _spy_drain,
    )

    X = np.zeros((10, 2), dtype=np.float64)
    start = time.monotonic()
    with pytest.raises(RuntimeError, match=r"exitcode=7"):
        clustering.fit_predict_interruptible(
            X, min_cluster_size=5, min_samples=2,
        )
    elapsed = time.monotonic() - start
    # If this exceeds a few seconds, the polling rail regressed (the
    # helper waited on an indefinite queue.get instead of polling
    # is_alive). Generous bound - startup overhead varies.
    assert elapsed < 10.0, f"helper took {elapsed:.2f}s - polling rail regressed?"
    # Cleanup MUST have run on the abnormal-exit path. Without this,
    # RuntimeError flies past both cleanup branches and
    # resource_tracker leaks on exactly the path the helper exists
    # to handle.
    assert cleanup_calls == ["drain"], (
        f"cleanup did not run on dead-child path; called: {cleanup_calls!r}"
    )


# ── Module export sanity ────────────────────────────────────────────────────


def test_clustering_module_public_surface() -> None:
    """The new helper is exported alongside HDBSCAN and ACTIVE_BACKEND."""
    importlib.reload(clustering)
    assert set(clustering.__all__) == {
        "HDBSCAN", "ACTIVE_BACKEND", "fit_predict_interruptible",
    }
    assert callable(clustering.fit_predict_interruptible)
