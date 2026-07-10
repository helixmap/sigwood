"""HDBSCAN backend shim - prefer fast_hdbscan, fall back to stock hdbscan.

Both backends expose an identical ``HDBSCAN(min_cluster_size=, min_samples=)``
plus ``.fit_predict(X)`` API and produce equivalent findings; ``fast_hdbscan``
is a drop-in accelerator over stock ``hdbscan``.

This module resolves which implementation is in use exactly once at import
time and exposes that class at module level as ``HDBSCAN`` so callers can
``from sigwood.common.clustering import HDBSCAN`` and construct it
directly - no factory, no rename. ``ACTIVE_BACKEND`` records which one
resolved.

Resolution order: ``fast_hdbscan`` first (the accelerator selected on 64-bit
platforms and by the ``sigwood[fast]`` extra), then stock ``hdbscan``
(selected on 32-bit ARM and available through the ``sigwood[hdbscan]``
extra). If neither is importable we raise ``ImportError`` at import time
rather than letting the failure surface later at a construction site.

Process-isolated entry point
----------------------------

``fit_predict_interruptible`` is the new shared call site for DNS clustering
(both Zeek and Pi-hole paths). It runs ``HDBSCAN(...).fit_predict(X)`` in a
spawned child process so the parent main thread can honour Ctrl-C
regardless of the native call's GIL state. On ``KeyboardInterrupt`` the
child is terminated, the queue is drained and closed, and the exception
re-raises to the caller (the existing ``liveness()`` teardown + the
``cli.main()`` top-level handler print "Stopped." and exit 130).

For notebook / standalone callers (or any environment where ``spawn`` is
fragile - Jupyter is the canonical case), the module-level switch
``_CLUSTERING_ISOLATE_ENABLED`` may be flipped to ``False``; the helper
then runs in-process via ``_inline_fit_predict`` and preserves today's
``HDBSCAN(min_cluster_size=, min_samples=).fit_predict(X)`` call verbatim.
The CLI/runner path inherits the default ON.
"""

from __future__ import annotations

import multiprocessing
import queue as _queue
from typing import Any

import numpy as np

try:
    from fast_hdbscan import HDBSCAN
    ACTIVE_BACKEND = "fast_hdbscan"
except ImportError:
    try:
        from hdbscan import HDBSCAN
        ACTIVE_BACKEND = "hdbscan"
    except ImportError as e:
        raise ImportError(
            "No HDBSCAN backend available - neither 'fast_hdbscan' nor "
            "'hdbscan' was importable. sigwood installs one automatically "
            "(fast-hdbscan on 64-bit platforms, stock hdbscan on 32-bit ARM), so "
            "this usually means a broken install; reinstall sigwood, or "
            "force a backend with 'pip install sigwood[fast]' "
            "(fast-hdbscan) or 'pip install sigwood[hdbscan]' "
            "(stock hdbscan)."
        ) from e


# ── Process-isolation knobs ──────────────────────────────────────────────────

# Quarantine-style switch - mirrors digest/blob.py:_BLOB_DRAIN3_ENABLED.
# When False, fit_predict_interruptible runs in-process (today's behaviour
# exactly). The CLI/runner path inherits the default True; notebook /
# standalone callers can flip it for in-process determinism, or to keep
# multiprocessing out of a Jupyter kernel where spawn is fragile.
# DO NOT route this through DetectorContext - detector signatures stay
# clean; this is environment-shaped, not detector-shaped.
_CLUSTERING_ISOLATE_ENABLED: bool = True

# Queue polling interval - the main thread wakes this often to check the
# child's exit status. 100 ms is fast enough that Ctrl-C feels instant
# without spinning the CPU.
_POLL_INTERVAL_SEC: float = 0.1

# Bounded join window after SIGTERM before escalating to SIGKILL.
_TERMINATE_TIMEOUT_SEC: float = 1.0

# Brief join on the NORMAL-return path so a healthy child exit isn't
# converted into a SIGTERM for no reason. Not used on the interrupt path -
# the committed interrupt sequence is terminate → join → kill (no grace).
_GRACEFUL_JOIN_SEC: float = 0.2


def _build_clusterer(
    backend: str, *, min_cluster_size: int, min_samples: int,
) -> Any:
    """Construct an HDBSCAN clusterer with backend-conditional kwargs.

    Stock ``hdbscan`` gets ``core_dist_n_jobs=1`` so it spawns no nested
    multiprocessing pool - our one child is then the only extra process
    and SIGKILL is clean (no ``resource_tracker`` "leaked semaphore"
    warning on shutdown). ``fast_hdbscan`` has no ``core_dist_n_jobs``
    parameter (would TypeError); it uses numba threads anyway, so there
    are no semaphores to leak.

    Called by ``_cluster_worker`` in the SPAWNED CHILD only. The
    in-process escape-hatch path (``_inline_fit_predict``) does NOT
    call this helper - that path preserves today's
    ``HDBSCAN(min_cluster_size=, min_samples=)`` construction
    byte-for-byte to avoid drifting the detector's calibration surface.
    """
    if backend == "hdbscan":
        return HDBSCAN(
            min_cluster_size=min_cluster_size,
            min_samples=min_samples,
            core_dist_n_jobs=1,
        )
    return HDBSCAN(
        min_cluster_size=min_cluster_size,
        min_samples=min_samples,
    )


def _cluster_worker(
    result_queue: Any,
    X: "np.ndarray",
    min_cluster_size: int,
    min_samples: int,
    backend: str,
) -> None:
    """Module-level worker for spawn pickling.

    Picklable BECAUSE it is module-level - nested functions, lambdas, and
    closures would not survive ``spawn`` re-import. Constructs an HDBSCAN
    clusterer via ``_build_clusterer`` (which applies the
    backend-conditional ``core_dist_n_jobs=1`` for stock hdbscan), calls
    ``.fit_predict(X)``, and puts ``("ok", labels)`` or
    ``("error", "<ExcType>: <msg>")`` on the queue.

    Does NOT raise to the parent - all failures become serialised error
    tuples so the parent path is uniform and arbitrary exception objects
    never need to round-trip through pickle.

    ``backend`` is passed explicitly (not re-read from ``ACTIVE_BACKEND``
    in the child) so that test paths exercising backend-conditional
    behaviour can target a fixed string without monkeypatching across
    the spawn boundary.
    """
    try:
        clusterer = _build_clusterer(
            backend,
            min_cluster_size=min_cluster_size,
            min_samples=min_samples,
        )
        labels = clusterer.fit_predict(X)
        result_queue.put(("ok", labels))
    except Exception as exc:  # noqa: BLE001 - serialised, not raised
        result_queue.put(("error", f"{type(exc).__name__}: {exc}"))


# Indirection seam for tests: rebind this to one of the module-level test
# helpers in tests/test_clustering_interruptible.py to exercise specific
# child-process behaviours (block, raise, die without queueing) without
# closures crossing the spawn boundary.
_WORKER_TARGET = _cluster_worker


def _await_child_result(
    result_queue: Any, child: "multiprocessing.Process",
) -> tuple:
    """Poll the result queue + child liveness until one of them yields.

    Does NOT call an indefinite ``queue.get()`` - that would hang
    forever if the child segfaults / OOMs / exits without putting a
    result. Instead polls with ``queue.get(timeout=_POLL_INTERVAL_SEC)``
    and, between polls, checks ``child.is_alive()`` / ``child.exitcode``.

    On a dead child without a queued result, raises ``RuntimeError`` -
    a normal exception that the existing CLI ``ValueError``/``OSError``
    arms can surface. Never returns ``None``.

    ``KeyboardInterrupt`` propagates naturally: ``queue.get`` is a
    Python-level wait, so SIGINT delivered to the main thread is
    raised out of this function and the caller's interrupt branch
    handles cleanup.
    """
    while True:
        try:
            return result_queue.get(timeout=_POLL_INTERVAL_SEC)
        except _queue.Empty:
            pass
        if not child.is_alive():
            exitcode = child.exitcode
            raise RuntimeError(
                "DNS clustering worker died "
                f"(exitcode={exitcode}) without returning a result. "
                "The clustering library may have crashed; try the "
                "alternate backend (pip install 'sigwood[fast]' or "
                "pip install hdbscan)."
            )


def _drain_and_close_queue(result_queue: Any) -> None:
    """Drain pending items, then close and join the feeder thread.

    Called from BOTH the normal-return and interrupt cleanup paths,
    always AFTER the child is no longer alive. ``close()`` + ``join_thread()``
    together prevent the ``multiprocessing.resource_tracker`` "leaked
    semaphore" warning at process shutdown; ``close()`` alone is not
    enough (the feeder thread may still hold a reference). Draining
    pending items first stops ``close()`` from blocking the feeder on
    unsent data.
    """
    try:
        while True:
            result_queue.get_nowait()
    except _queue.Empty:
        pass
    result_queue.close()
    result_queue.join_thread()


def _inline_fit_predict(
    X: "np.ndarray", min_cluster_size: int, min_samples: int,
) -> "np.ndarray":
    """In-process escape hatch - preserves today's calibration surface
    exactly. NOT routed through ``_build_clusterer`` on purpose: the
    backend-conditional ``core_dist_n_jobs=1`` is a child-process
    resource-tracker concern, not a calibration choice we want to drift
    into notebook / standalone callers.
    """
    clusterer = HDBSCAN(
        min_cluster_size=min_cluster_size, min_samples=min_samples,
    )
    return clusterer.fit_predict(X)


def fit_predict_interruptible(
    X: "np.ndarray", *, min_cluster_size: int, min_samples: int,
) -> "np.ndarray":
    """HDBSCAN ``.fit_predict(X)`` with Ctrl-C honoured on a long compute.

    The single ``fit_predict`` entry point both DNS call sites use. Return
    contract is a label int array, shape ``(len(X),)``; the detector logic
    above/below is unchanged.

    When ``_CLUSTERING_ISOLATE_ENABLED`` is True (the CLI/runner default),
    runs the compute in a spawned child process so SIGINT delivered to
    the parent main thread is honoured regardless of the native call's
    GIL state. On ``KeyboardInterrupt`` the child is terminated and the
    exception re-raises to the caller (``liveness()`` teardown +
    ``cli.main()``'s top-level handler print "Stopped." and exit 130).

    When False (notebook / standalone escape hatch), runs in-process via
    ``_inline_fit_predict`` and preserves today's behaviour byte-for-byte.

    Raises:
        ValueError: when the child reports a clustering failure
            (degenerate input, etc.) - preserves the detector contract
            that a clustering failure surfaces as a normal exception.
        RuntimeError: when the child dies without putting a result
            (segfault, OOM kill, etc.) - never silently hangs.
        KeyboardInterrupt: re-raised after child termination so the
            existing ``liveness()`` + ``cli.main()`` machinery handles
            teardown.
    """
    if not _CLUSTERING_ISOLATE_ENABLED:
        return _inline_fit_predict(X, min_cluster_size, min_samples)

    ctx = multiprocessing.get_context("spawn")
    result_queue = ctx.Queue()
    child = ctx.Process(
        target=_WORKER_TARGET,
        args=(result_queue, X, min_cluster_size, min_samples, ACTIVE_BACKEND),
    )
    child.start()

    # Universal cleanup discipline. The try body runs the await + an
    # optional graceful join on the normal-return path; the finally
    # ALWAYS runs the committed terminate → kill → drain/close → close
    # sequence regardless of how the body exited. This covers four
    # cases with one structure:
    #
    #   - Normal return: await yields, graceful join runs in the body,
    #     finally's terminate/kill are no-ops (child already exited),
    #     queue is drained+closed, child handle closed.
    #   - KeyboardInterrupt: await raises, body skips straight to
    #     finally. Graceful join is NEVER reached on this path - the
    #     operator wants the helper out NOW - so the finally's
    #     terminate fires immediately. This matches the committed
    #     interrupt sequence (terminate → join → kill → cleanup →
    #     re-raise) exactly: the re-raise is the implicit post-finally
    #     propagation.
    #   - RuntimeError (dead child without result): await raises,
    #     finally runs. Child is already dead so terminate/kill are
    #     no-ops, but queue drain/close + child.close still run -
    #     preventing the resource_tracker leak on the exact abnormal-
    #     death path the helper exists to handle.
    #   - Any future non-KBI exception from the await path: same
    #     guarantee as the RuntimeError case. If the child happens to
    #     still be alive, the finally's terminate/kill takes it down
    #     before draining the queue (closing the queue with a live
    #     child would hang the feeder thread).
    try:
        result = _await_child_result(result_queue, child)
        # NORMAL-RETURN PATH continues here. Brief join so a healthy
        # exit isn't converted to SIGTERM by the finally below; if
        # the child stalls past the grace window, finally's
        # terminate/kill takes over.
        if child.is_alive():
            child.join(_GRACEFUL_JOIN_SEC)
    finally:
        if child.is_alive():
            child.terminate()
            child.join(_TERMINATE_TIMEOUT_SEC)
        if child.is_alive():
            child.kill()
            child.join()
        _drain_and_close_queue(result_queue)
        child.close()

    if result[0] == "ok":
        return result[1]
    raise ValueError(f"DNS clustering failed in worker: {result[1]}")


__all__ = [
    "HDBSCAN",
    "ACTIVE_BACKEND",
    "fit_predict_interruptible",
]
