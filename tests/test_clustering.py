"""Tests for the HDBSCAN backend shim - resolution and exposure only.

Contract under test (sigwood.common.clustering):

1. ``HDBSCAN`` is exposed as a class at module level, constructable with the
   standard ``min_cluster_size=`` and ``min_samples=`` kwargs and exposing
   ``fit_predict``.
2. ``ACTIVE_BACKEND`` is one of ``{"fast_hdbscan", "hdbscan"}`` and matches
   whichever backend is actually importable in the current environment, in
   the same priority order the shim itself uses.
3. When ``fast_hdbscan`` is force-blocked at import time, the shim falls
   back to stock ``hdbscan`` and reports ``ACTIVE_BACKEND == "hdbscan"``.
4. Cross-backend label parity on well-separated data (below): the two
   backends must produce the SAME cluster partition on unambiguous
   structure, or "drop-in accelerator" is an overclaim. Parity on
   ambiguous, borderline data is deliberately NOT asserted.
"""

from __future__ import annotations

import importlib
import sys

import pytest

from sigwood.common import clustering


def _expected_backend_in_env() -> str:
    """Resolve the expected backend in the same priority order as the shim.

    Mirrors the shim's logic exactly so the assertion fails clearly if the
    environment has no clustering backend installed.
    """
    try:
        import fast_hdbscan  # noqa: F401
        return "fast_hdbscan"
    except ImportError:
        try:
            import hdbscan  # noqa: F401
            return "hdbscan"
        except ImportError as e:
            pytest.fail(
                "Neither fast_hdbscan nor hdbscan is importable in the test "
                "environment. A clustering backend (fast_hdbscan on 64-bit "
                "platforms, stock hdbscan elsewhere or via the [hdbscan] extra) "
                "must be present for the shim to resolve. Original error: "
                f"{e!r}"
            )


def test_shim_exposes_constructable_hdbscan_class():
    cls = clustering.HDBSCAN
    assert isinstance(cls, type), "HDBSCAN must be exposed as a class, not a factory"
    instance = cls(min_cluster_size=5, min_samples=2)
    assert hasattr(instance, "fit_predict"), "HDBSCAN instance must expose fit_predict"


def test_active_backend_is_one_of_expected_strings():
    assert clustering.ACTIVE_BACKEND in {"fast_hdbscan", "hdbscan"}


def test_active_backend_matches_environment():
    assert clustering.ACTIVE_BACKEND == _expected_backend_in_env()


def test_import_error_names_arch_selected_backend_install(monkeypatch):
    monkeypatch.setitem(sys.modules, "fast_hdbscan", None)
    monkeypatch.setitem(sys.modules, "hdbscan", None)
    try:
        with pytest.raises(ImportError) as excinfo:
            importlib.reload(clustering)

        message = str(excinfo.value)
        assert "No HDBSCAN backend available" in message
        assert "neither 'fast_hdbscan' nor 'hdbscan'" in message
        assert "sigwood installs one automatically" in message
        assert "sigwood[fast]" in message
        assert "sigwood[hdbscan]" in message
        assert "base dependency" not in message
    finally:
        sys.modules.pop("fast_hdbscan", None)
        sys.modules.pop("hdbscan", None)
        importlib.reload(clustering)


def test_fallback_resolves_to_hdbscan_when_fast_hdbscan_blocked(monkeypatch):
    """Force-block fast_hdbscan and reload; the shim must fall through to hdbscan.

    Uses the standard ``sys.modules[name] = None`` sentinel pattern: when the
    import machinery sees None in ``sys.modules`` for a name, it raises
    ``ModuleNotFoundError`` rather than attempting to resolve the module.
    That gives us deterministic fallback coverage regardless of whether
    fast_hdbscan is actually installed on disk.
    """
    try:
        import hdbscan  # noqa: F401
    except ImportError:
        pytest.skip("stock hdbscan not importable")

    monkeypatch.setitem(sys.modules, "fast_hdbscan", None)
    try:
        importlib.reload(clustering)
        assert clustering.ACTIVE_BACKEND == "hdbscan"
        cls = clustering.HDBSCAN
        assert isinstance(cls, type)
        instance = cls(min_cluster_size=5, min_samples=2)
        assert hasattr(instance, "fit_predict")
    finally:
        sys.modules.pop("fast_hdbscan", None)
        importlib.reload(clustering)


_NUMBA_CACHE_ERROR = (
    "cannot cache function '_init_node': no locator available for file "
    "'/usr/local/lib/python3.12/site-packages/fast_hdbscan/numba_kdtree.py'"
)


def _install_failing_fast_hdbscan(monkeypatch, tmp_path, message: str) -> None:
    """Shadow fast_hdbscan with a package whose import raises RuntimeError.

    numba raises a plain RuntimeError while decorating a cache=True function
    when no directory is writable for its compile cache, which surfaces as a
    RuntimeError from ``import fast_hdbscan``. The real module is removed from
    sys.modules (monkeypatch restores it) so the shadow is what imports.
    """
    package = tmp_path / "fast_hdbscan"
    package.mkdir()
    (package / "__init__.py").write_text(
        f"raise RuntimeError({message!r})\n", encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    monkeypatch.delitem(sys.modules, "fast_hdbscan", raising=False)


def test_unusable_fast_backend_without_fallback_is_an_import_error(
    monkeypatch, tmp_path,
):
    """An unwritable numba cache must not escape as a RuntimeError.

    Detector discovery contains ImportError only, so a RuntimeError from the
    backend import used to crash every analyze command with a raw traceback.
    """
    _install_failing_fast_hdbscan(monkeypatch, tmp_path, _NUMBA_CACHE_ERROR)
    monkeypatch.setitem(sys.modules, "hdbscan", None)
    try:
        with pytest.raises(ImportError) as excinfo:
            importlib.reload(clustering)
        message = str(excinfo.value)
        assert message == (
            "fast_hdbscan failed to load: numba found no writable directory "
            "for its compile cache - set NUMBA_CACHE_DIR to a writable directory"
        )
        assert isinstance(excinfo.value.__cause__, RuntimeError)
    finally:
        monkeypatch.undo()
        importlib.reload(clustering)


def test_unusable_fast_backend_reports_an_unrecognized_runtime_error_verbatim(
    monkeypatch, tmp_path,
):
    """Only numba's cache failure earns the NUMBA_CACHE_DIR remedy."""
    _install_failing_fast_hdbscan(monkeypatch, tmp_path, "boom\nsecond line")
    monkeypatch.setitem(sys.modules, "hdbscan", None)
    try:
        with pytest.raises(ImportError) as excinfo:
            importlib.reload(clustering)
        assert str(excinfo.value) == "fast_hdbscan failed to load: boom"
    finally:
        monkeypatch.undo()
        importlib.reload(clustering)


def test_unusable_fast_backend_falls_back_to_stock_hdbscan(monkeypatch, tmp_path):
    try:
        import hdbscan  # noqa: F401
    except ImportError:
        pytest.skip("stock hdbscan not importable")
    _install_failing_fast_hdbscan(monkeypatch, tmp_path, _NUMBA_CACHE_ERROR)
    try:
        importlib.reload(clustering)
        assert clustering.ACTIVE_BACKEND == "hdbscan"
    finally:
        monkeypatch.undo()
        importlib.reload(clustering)


def test_unusable_fast_backend_skips_dns_and_leaves_other_detectors_running(
    monkeypatch, tmp_path,
):
    """Discovery records dns as an import failure; beacon stays available."""
    from sigwood import runner

    _install_failing_fast_hdbscan(monkeypatch, tmp_path, _NUMBA_CACHE_ERROR)
    monkeypatch.setitem(sys.modules, "hdbscan", None)
    monkeypatch.delitem(sys.modules, "sigwood.common.clustering")
    monkeypatch.delitem(sys.modules, "sigwood.detectors.dns", raising=False)
    try:
        failures: dict[str, str] = {}
        available = runner.discover_detectors(_failures=failures)
        assert "beacon" in available
        assert "dns" not in available
        assert failures["dns"].startswith(
            "fast_hdbscan failed to load: numba found no writable directory"
        )
    finally:
        monkeypatch.undo()
        importlib.reload(clustering)


def _partition(labels) -> tuple[frozenset, frozenset]:
    """Reduce a labeling to a label-permutation-invariant partition.

    Returns (set of clusters-as-member-index-sets, noise index set) so two
    labelings compare equal iff they group the same points together,
    regardless of which integer names each cluster.
    """
    from collections import defaultdict

    groups: dict[int, list[int]] = defaultdict(list)
    for i, label in enumerate(labels):
        groups[int(label)].append(i)
    clusters = frozenset(
        frozenset(members) for label, members in groups.items() if label != -1
    )
    noise = frozenset(groups.get(-1, []))
    return clusters, noise


def test_backends_agree_on_well_separated_data() -> None:
    """Both backends must find the SAME partition on unambiguous structure.

    Seeded, well-separated blobs plus far-flung noise: any HDBSCAN
    implementation worth calling a drop-in for another must recover exactly
    these clusters. Failure here means the backends materially diverge and
    the accelerator claim needs revisiting. Ambiguous, borderline data is
    deliberately out of scope - implementations may legitimately differ there.
    """
    fast = pytest.importorskip("fast_hdbscan")
    stock = pytest.importorskip("hdbscan")
    import numpy as np

    rng = np.random.default_rng(3759)
    blobs = [rng.normal(loc, 0.05, size=(100, 4)) for loc in (0.0, 5.0, 10.0)]
    noise = rng.uniform(20.0, 40.0, size=(7, 4))
    X = np.vstack(blobs + [noise])

    labels_fast = fast.HDBSCAN(min_cluster_size=25, min_samples=10).fit_predict(X)
    labels_stock = stock.HDBSCAN(min_cluster_size=25, min_samples=10).fit_predict(X)

    assert _partition(labels_fast) == _partition(labels_stock)
    clusters, noise_set = _partition(labels_fast)
    assert sorted(len(c) for c in clusters) == [100, 100, 100]
    assert len(noise_set) == 7
