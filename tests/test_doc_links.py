"""Keep public documentation links honest without using the network."""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

from tools import validate_doc_links as doc_links


_ROOT = Path(__file__).resolve().parents[1]
_VALIDATOR = _ROOT / "tools" / "validate_doc_links.py"


def _doc_tree(root: Path, contents: dict[str, str] | None = None) -> Path:
    files = {path.as_posix(): "" for path in doc_links.DOC_FILES}
    files["docs/INDEX.md"] = "# Index\n"
    files.update(contents or {})
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def test_live_public_doc_corpus_has_no_findings() -> None:
    assert doc_links.validate_doc_links(_ROOT) == []


def test_live_cli_summary_discloses_unchecked_counts(capsys: pytest.CaptureFixture[str]) -> None:
    assert doc_links.main([str(_ROOT)]) == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    assert re.fullmatch(
        r"validated \d+ doc links across 9 files "
        r"\(\d+ external not checked, 0 pinned refs\)\n",
        captured.out,
    )


def test_relative_path_rule_can_fail_and_pass(tmp_path: Path) -> None:
    root = _doc_tree(tmp_path, {"CONTRIBUTING.md": "[guide](missing.md)\n"})
    findings = doc_links.validate_doc_links(root)
    assert [(item.target, item.rule) for item in findings] == [
        ("missing.md", doc_links.RULE_RELATIVE)
    ]

    (root / "missing.md").write_text("present\n", encoding="utf-8")
    assert doc_links.validate_doc_links(root) == []


def test_relative_fragment_rule_can_fail_and_pass(tmp_path: Path) -> None:
    root = _doc_tree(
        tmp_path,
        {
            "CONTRIBUTING.md": "[target](docs/TARGET.md#missing)\n",
            "docs/TARGET.md": "## Present heading\n",
        },
    )
    findings = doc_links.validate_doc_links(root)
    assert [(item.target, item.rule) for item in findings] == [
        ("docs/TARGET.md#missing", doc_links.RULE_RELATIVE)
    ]

    (root / "CONTRIBUTING.md").write_text(
        "[target](docs/TARGET.md#present-heading)\n", encoding="utf-8"
    )
    assert doc_links.validate_doc_links(root) == []


def test_same_file_anchor_rule_can_fail_and_pass(tmp_path: Path) -> None:
    root = _doc_tree(
        tmp_path,
        {"SECURITY.md": "## Available\n\n[jump](#missing)\n"},
    )
    findings = doc_links.validate_doc_links(root)
    assert [(item.target, item.rule) for item in findings] == [
        ("#missing", doc_links.RULE_ANCHOR)
    ]

    (root / "SECURITY.md").write_text(
        "## Available\n\n[jump](#available)\n", encoding="utf-8"
    )
    assert doc_links.validate_doc_links(root) == []


def test_main_repo_path_rule_can_fail_and_pass(tmp_path: Path) -> None:
    target = "https://github.com/helixmap/sigwood/blob/main/docs/asset.txt"
    root = _doc_tree(tmp_path, {"SECURITY.md": f"[asset]({target})\n"})
    findings = doc_links.validate_doc_links(root)
    assert [(item.target, item.rule) for item in findings] == [
        (target, doc_links.RULE_REPO_PATH)
    ]

    (root / "docs" / "asset.txt").write_text("present\n", encoding="utf-8")
    assert doc_links.validate_doc_links(root) == []


def test_repo_identity_rule_rejects_each_first_party_lookalike(tmp_path: Path) -> None:
    wrong_owner = "https://github.com/someone-else/sigwood/issues"
    wrong_repo = "https://github.com/helixmap/other/issues"
    canonical = "https://github.com/helixmap/sigwood/issues"
    third_party = "https://github.com/example-org/example-tool"
    root = _doc_tree(
        tmp_path,
        {
            "SECURITY.md": "\n".join(
                f"[link]({target})"
                for target in (wrong_owner, wrong_repo, canonical, third_party)
            )
        },
    )
    findings = doc_links.validate_doc_links(root)
    assert [(item.target, item.rule) for item in findings] == [
        (wrong_owner, doc_links.RULE_REPO_IDENTITY),
        (wrong_repo, doc_links.RULE_REPO_IDENTITY),
    ]


def test_readme_relative_path_rule_rejects_files_and_directories(tmp_path: Path) -> None:
    root = _doc_tree(
        tmp_path,
        {"README.md": "## Local\n\n[security](SECURITY.md) [docs](docs/)\n"},
    )
    findings = doc_links.validate_doc_links(root)
    assert [(item.target, item.rule) for item in findings] == [
        ("SECURITY.md", doc_links.RULE_README_RELATIVE),
        ("docs/", doc_links.RULE_README_RELATIVE),
    ]

    (root / "README.md").write_text(
        "## Local\n\n[jump](#local)\n", encoding="utf-8"
    )
    assert doc_links.validate_doc_links(root) == []


def test_markdown_image_and_nested_badge_targets_are_extracted(tmp_path: Path) -> None:
    missing_image = (
        "https://raw.githubusercontent.com/helixmap/sigwood/main/docs/missing.png"
    )
    root = _doc_tree(
        tmp_path,
        {
            "SECURITY.md": (
                "## License\n\n"
                "[![badge](https://badges.example/status.svg)](#missing)\n"
                f"![hero]({missing_image})\n"
            )
        },
    )
    findings = doc_links.validate_doc_links(root)
    assert {(item.target, item.rule) for item in findings} == {
        ("#missing", doc_links.RULE_ANCHOR),
        (missing_image, doc_links.RULE_REPO_PATH),
    }
    assert "https://badges.example/status.svg" in doc_links.external_doc_links(root)

    (root / "docs" / "missing.png").write_bytes(b"image")
    (root / "SECURITY.md").write_text(
        "## License\n\n"
        "[![badge](https://badges.example/status.svg)](#license)\n"
        f"![hero]({missing_image})\n",
        encoding="utf-8",
    )
    assert doc_links.validate_doc_links(root) == []


def test_html_anchor_and_image_targets_use_the_same_rules(tmp_path: Path) -> None:
    missing_image = (
        "https://raw.githubusercontent.com/helixmap/sigwood/main/docs/missing.png"
    )
    root = _doc_tree(
        tmp_path,
        {
            "docs/PAGE.md": (
                "## Present\n"
                '<a href="#missing">jump</a>\n'
                f'<!-- <img src="{missing_image}" alt="hero"> -->\n'
            )
        },
    )
    findings = doc_links.validate_doc_links(root)
    assert {(item.target, item.rule) for item in findings} == {
        ("#missing", doc_links.RULE_ANCHOR),
        (missing_image, doc_links.RULE_REPO_PATH),
    }

    (root / "docs" / "missing.png").write_bytes(b"image")
    (root / "docs" / "PAGE.md").write_text(
        "## Present\n"
        '<a href="#present">jump</a>\n'
        f'<!-- <img src="{missing_image}" alt="hero"> -->\n',
        encoding="utf-8",
    )
    assert doc_links.validate_doc_links(root) == []


def test_html_readme_relative_target_uses_package_index_rule(tmp_path: Path) -> None:
    root = _doc_tree(
        tmp_path,
        {"README.md": "<a href='SECURITY.md'>security</a>\n"},
    )
    findings = doc_links.validate_doc_links(root)
    assert [(item.target, item.rule) for item in findings] == [
        ("SECURITY.md", doc_links.RULE_README_RELATIVE)
    ]


def test_link_looking_text_inside_a_fence_is_validated(tmp_path: Path) -> None:
    root = _doc_tree(
        tmp_path,
        {"CONTRIBUTING.md": "```text\n[example](missing.md)\n```\n"},
    )
    findings = doc_links.validate_doc_links(root)
    assert [(item.target, item.rule) for item in findings] == [
        ("missing.md", doc_links.RULE_RELATIVE)
    ]

    (root / "missing.md").write_text("present\n", encoding="utf-8")
    assert doc_links.validate_doc_links(root) == []


def test_slug_algorithm_handles_inline_code_punctuation_and_duplicates(tmp_path: Path) -> None:
    root = _doc_tree(
        tmp_path,
        {
            "SECURITY.md": (
                "## A `Code` Heading!\n"
                "## Repeat\n"
                "## Repeat\n\n"
                "[code](#a-code-heading) [duplicate](#repeat-1)\n"
            )
        },
    )
    assert doc_links.validate_doc_links(root) == []

    with (root / "SECURITY.md").open("a", encoding="utf-8") as handle:
        handle.write("[missing duplicate](#repeat-2)\n")
    findings = doc_links.validate_doc_links(root)
    assert [(item.target, item.rule) for item in findings] == [
        ("#repeat-2", doc_links.RULE_ANCHOR)
    ]


def test_external_and_pinned_targets_are_disclosed_without_findings(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    external = "https://github.com/example-org/example-tool"
    pinned = "https://github.com/helixmap/sigwood/blob/v0.2.3/missing.md"
    root = _doc_tree(
        tmp_path,
        {"SECURITY.md": f"[external]({external}) [history]({pinned})\n"},
    )
    result = doc_links.scan_doc_links(root)
    assert result.findings == ()
    assert result.external_targets == (external,)
    assert result.pinned_targets == (pinned,)

    assert doc_links.main([str(root)]) == 0
    captured = capsys.readouterr()
    assert "1 external not checked, 1 pinned ref" in captured.out
    assert captured.err == ""


def test_relative_paths_cannot_escape_the_repository_root(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    _doc_tree(root, {"CONTRIBUTING.md": "[outside](../outside.md)\n"})
    (tmp_path / "outside.md").write_text("outside\n", encoding="utf-8")
    findings = doc_links.validate_doc_links(root)
    assert [(item.target, item.rule) for item in findings] == [
        ("../outside.md", doc_links.RULE_RELATIVE)
    ]


def test_cli_reports_every_finding_before_failing(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    root = _doc_tree(
        tmp_path,
        {"CONTRIBUTING.md": "[one](missing-one.md) [two](missing-two.md)\n"},
    )
    assert doc_links.main([str(root)]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    lines = captured.err.splitlines()
    assert len(lines) == 2
    assert "missing-one.md" in lines[0]
    assert "missing-two.md" in lines[1]
    assert all(doc_links.RULE_RELATIVE in line for line in lines)


def test_validator_import_surface_has_no_network_clients() -> None:
    tree = ast.parse(_VALIDATOR.read_text(encoding="utf-8"))
    imported_roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_roots.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported_roots.add(node.module.split(".", 1)[0])

    assert imported_roots.isdisjoint({"urllib", "http", "socket", "requests"})
