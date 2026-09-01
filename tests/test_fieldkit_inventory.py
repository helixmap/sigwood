"""Keep the standalone Fieldkit's privacy vocabulary bound to live sigwood."""

from __future__ import annotations

import ast
import importlib.util
import sys
from pathlib import Path
from types import ModuleType

from sigwood import runner
from sigwood.runner import discover_detectors


ROOT = Path(__file__).resolve().parent.parent
FIELDKIT_PATH = ROOT / "tools" / "fieldkit.py"


def _load_script() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "fieldkit_inventory_test", FIELDKIT_PATH
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


fieldkit = _load_script()


def _live_contract() -> tuple[set[str], set[str], set[str]]:
    modules = discover_detectors()
    detectors = set(modules)
    patterns: set[str] = set()
    sources: set[str] = set()
    for module in modules.values():
        for spec in [*module.REQUIRED_LOGS, *module.OPTIONAL_LOGS]:
            source = spec["source"]
            pattern = spec["pattern"]
            patterns.add(pattern)
            sources.update(
                runner._derive_data_sources(
                    {pattern: source},
                    {pattern: 1},
                )
            )
    return detectors, patterns, sources


def test_literal_vocabulary_tables_match_live_detector_contract() -> None:
    detectors, patterns, sources = _live_contract()

    assert set(fieldkit.DETECTOR_TOKENS) == detectors
    assert set(fieldkit.RECORD_PATTERN_TOKENS) == patterns
    assert set(fieldkit.DATA_SOURCE_TOKENS) == sources
    assert set(fieldkit.NUMERIC_EVIDENCE) == detectors
    assert set(fieldkit.ENUM_EVIDENCE) == detectors

    assert all(
        isinstance(fieldkit.NUMERIC_EVIDENCE[name], frozenset)
        for name in detectors
    )
    assert all(isinstance(fieldkit.ENUM_EVIDENCE[name], dict) for name in detectors)
    assert fieldkit.NUMERIC_EVIDENCE["auth"] == frozenset()
    assert fieldkit.NUMERIC_EVIDENCE["dnsblock"] == frozenset()
    assert fieldkit.ENUM_EVIDENCE["beacon"] == {}
    assert fieldkit.ENUM_EVIDENCE["exfil"] == {}


def test_standalone_script_is_python39_syntax_and_has_no_product_or_network_imports() -> None:
    source = FIELDKIT_PATH.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(FIELDKIT_PATH), feature_version=(3, 9))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
    assert not {
        name for name in imported if name == "sigwood" or name.startswith("sigwood.")
    }
    assert not imported.intersection(
        {"http", "http.client", "requests", "socket", "urllib", "urllib.request"}
    )
