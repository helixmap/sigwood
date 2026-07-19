#!/usr/bin/env python3
"""Validate public documentation links against the current repository tree.

The validator is intentionally standard-library-only and performs no network I/O.
Commit-local paths and anchors are checked here; external liveness is handled by a
separate informational workflow.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Sequence


DOC_FILES = (
    PurePosixPath("README.md"),
    PurePosixPath("CONTRIBUTING.md"),
    PurePosixPath("SECURITY.md"),
    PurePosixPath("demo/README.md"),
)
DOCS_GLOB = "docs/*.md"

REPO_OWNER = "helixmap"
REPO_NAME = "sigwood"

RULE_RELATIVE = "relative-link"
RULE_ANCHOR = "same-file-anchor"
RULE_REPO_PATH = "repo-main-path"
RULE_REPO_IDENTITY = "repo-identity"
RULE_README_RELATIVE = "readme-relative-target"

_GITHUB_URL = re.compile(
    r"^https?://github\.com/(?P<owner>[^/?#]+)/(?P<repo>[^/?#]+)"
    r"(?P<rest>/[^?#]*)?(?:\?[^#]*)?(?:#.*)?$"
)
_RAW_GITHUB_URL = re.compile(
    r"^https?://raw\.githubusercontent\.com/(?P<owner>[^/?#]+)/"
    r"(?P<repo>[^/?#]+)(?P<rest>/[^?#]*)?(?:\?[^#]*)?(?:#.*)?$"
)
_EXTERNAL_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")
_HTML_TAG = re.compile(
    r"<\s*(?P<tag>a|img)\b"
    r"(?P<attrs>(?:[^>\"']|\"[^\"]*\"|'[^']*')*)>",
    re.IGNORECASE | re.DOTALL,
)
_ATX_HEADING = re.compile(r"^ {0,3}#{1,6}(?:[ \t]+|$)(?P<text>.*)$")


@dataclass(frozen=True)
class Finding:
    """One documentation target that violates a validation rule."""

    file: str
    target: str
    rule: str
    detail: str


@dataclass(frozen=True)
class ScanResult:
    """Structured result and disclosure counts for one documentation scan."""

    findings: tuple[Finding, ...]
    file_count: int
    link_count: int
    external_targets: tuple[str, ...]
    pinned_targets: tuple[str, ...]


@dataclass(frozen=True)
class _ExtractedTarget:
    position: int
    target: str


def _is_escaped(text: str, index: int) -> bool:
    backslashes = 0
    index -= 1
    while index >= 0 and text[index] == "\\":
        backslashes += 1
        index -= 1
    return backslashes % 2 == 1


def _closing_delimiter(text: str, start: int, opening: str, closing: str) -> int | None:
    depth = 0
    for index in range(start, len(text)):
        char = text[index]
        if _is_escaped(text, index):
            continue
        if char == opening:
            depth += 1
        elif char == closing:
            depth -= 1
            if depth == 0:
                return index
    return None


def _markdown_destination(value: str) -> str:
    value = value.strip()
    if not value:
        return ""
    if value.startswith("<"):
        closing = value.find(">", 1)
        return value[1:closing] if closing >= 0 else value

    depth = 0
    for index, char in enumerate(value):
        if _is_escaped(value, index):
            continue
        if char == "(":
            depth += 1
        elif char == ")" and depth:
            depth -= 1
        elif char.isspace() and depth == 0:
            return value[:index]
    return value


def _markdown_targets(text: str) -> list[_ExtractedTarget]:
    targets: list[_ExtractedTarget] = []
    for start, char in enumerate(text):
        if char != "[" or _is_escaped(text, start):
            continue
        label_end = _closing_delimiter(text, start, "[", "]")
        if label_end is None or label_end + 1 >= len(text) or text[label_end + 1] != "(":
            continue
        target_end = _closing_delimiter(text, label_end + 1, "(", ")")
        if target_end is None:
            continue
        raw = text[label_end + 2 : target_end]
        targets.append(_ExtractedTarget(start, _markdown_destination(raw)))
    return targets


def _quoted_attribute(attrs: str, name: str) -> tuple[int, str] | None:
    match = re.search(
        rf"(?:^|[ \t\r\n]){re.escape(name)}\s*=\s*"
        rf"(?P<quote>[\"'])(?P<value>.*?)(?P=quote)",
        attrs,
        re.IGNORECASE | re.DOTALL,
    )
    if match is None:
        return None
    return match.start("value"), match.group("value").strip()


def _html_targets(text: str) -> list[_ExtractedTarget]:
    targets: list[_ExtractedTarget] = []
    for match in _HTML_TAG.finditer(text):
        attribute = "href" if match.group("tag").lower() == "a" else "src"
        found = _quoted_attribute(match.group("attrs"), attribute)
        if found is not None:
            offset, target = found
            targets.append(_ExtractedTarget(match.start("attrs") + offset, target))
    return targets


def _extract_targets(text: str) -> list[str]:
    extracted = _markdown_targets(text) + _html_targets(text)
    return [item.target for item in sorted(extracted, key=lambda item: item.position)]


def _heading_slugs(text: str) -> set[str]:
    counts: dict[str, int] = {}
    slugs: set[str] = set()
    for line in text.splitlines():
        match = _ATX_HEADING.fullmatch(line)
        if match is None:
            continue
        heading = re.sub(r"[ \t]+#+[ \t]*$", "", match.group("text").strip())
        base = re.sub(r"[^\w -]", "", heading.replace("`", "").lower())
        base = base.replace(" ", "-")
        duplicate = counts.get(base, 0)
        slug = base if duplicate == 0 else f"{base}-{duplicate}"
        counts[base] = duplicate + 1
        slugs.add(slug)
    return slugs


def _document_paths(root: Path) -> tuple[Path, ...]:
    fixed = tuple(root / Path(path) for path in DOC_FILES)
    missing = [path.relative_to(root).as_posix() for path in fixed if not path.is_file()]
    if missing:
        raise ValueError(f"missing public documentation files: {', '.join(missing)}")

    docs_dir = root / "docs"
    if not docs_dir.is_dir():
        raise ValueError("missing public documentation directory: docs")
    docs = tuple(sorted(path for path in root.glob(DOCS_GLOB) if path.is_file()))
    if not docs:
        raise ValueError("no public Markdown files found under docs")
    return fixed + docs


def _inside_root(root: Path, candidate: Path) -> Path | None:
    resolved = candidate.resolve()
    return resolved if resolved.is_relative_to(root) else None


def _finding(source: Path, root: Path, target: str, rule: str, detail: str) -> Finding:
    return Finding(source.relative_to(root).as_posix(), target, rule, detail)


def _validate_repo_path(
    source: Path,
    root: Path,
    target: str,
    repo_path: str,
) -> list[Finding]:
    candidate = _inside_root(root, root / repo_path)
    if not repo_path or candidate is None or not candidate.exists():
        return [
            _finding(
                source,
                root,
                target,
                RULE_REPO_PATH,
                "main-branch path does not exist in this tree",
            )
        ]
    return []


def _inspect_repo_url(
    source: Path,
    root: Path,
    target: str,
) -> tuple[list[Finding], str | None]:
    github = _GITHUB_URL.fullmatch(target)
    raw = _RAW_GITHUB_URL.fullmatch(target)
    match = github or raw
    if match is None:
        return [], None

    owner = match.group("owner")
    repo = match.group("repo")
    looks_first_party = owner.lower() == REPO_OWNER or repo.lower() == REPO_NAME
    # GitHub resolves case-insensitively, but documentation requires the canonical
    # lowercase pair so casing drift is reported rather than normalized silently.
    if looks_first_party and (owner, repo) != (REPO_OWNER, REPO_NAME):
        return (
            [
                _finding(
                    source,
                    root,
                    target,
                    RULE_REPO_IDENTITY,
                    f"first-party-looking URL must use {REPO_OWNER}/{REPO_NAME}",
                )
            ],
            "handled",
        )
    if (owner, repo) != (REPO_OWNER, REPO_NAME):
        return [], "external"

    rest = (match.group("rest") or "").lstrip("/")
    if github is not None:
        if not rest.startswith("blob/"):
            return [], "external"
        parts = rest.split("/", 2)
        if len(parts) != 3 or not parts[2]:
            return _validate_repo_path(source, root, target, ""), "handled"
        ref, repo_path = parts[1], parts[2]
    else:
        parts = rest.split("/", 1)
        if len(parts) != 2 or not parts[1]:
            return _validate_repo_path(source, root, target, ""), "handled"
        ref, repo_path = parts

    if ref != "main":
        return [], "pinned"
    return _validate_repo_path(source, root, target, repo_path), "handled"


def _inspect_relative_target(
    source: Path,
    root: Path,
    target: str,
    heading_cache: dict[Path, set[str]],
) -> list[Finding]:
    path_and_query, separator, fragment = target.partition("#")
    path_text = path_and_query.partition("?")[0]
    findings: list[Finding] = []

    if not path_text and separator:
        if fragment not in heading_cache[source]:
            findings.append(
                _finding(
                    source,
                    root,
                    target,
                    RULE_ANCHOR,
                    "fragment does not match a heading in this file",
                )
            )
        return findings

    candidate = _inside_root(root, source.parent / path_text)
    if source == root / "README.md" and path_text:
        findings.append(
            _finding(
                source,
                root,
                target,
                RULE_README_RELATIVE,
                "README path targets must be absolute for the package index",
            )
        )

    if not path_text or candidate is None or not candidate.exists():
        findings.append(
            _finding(
                source,
                root,
                target,
                RULE_RELATIVE,
                "target path does not exist relative to this file",
            )
        )
        return findings

    if fragment and candidate.is_file() and candidate.suffix.lower() == ".md":
        slugs = heading_cache.get(candidate)
        if slugs is None:
            slugs = _heading_slugs(candidate.read_text(encoding="utf-8"))
            heading_cache[candidate] = slugs
        if fragment not in slugs:
            findings.append(
                _finding(
                    source,
                    root,
                    target,
                    RULE_RELATIVE,
                    "fragment does not match a heading in the target file",
                )
            )
    return findings


def scan_doc_links(root: Path = Path(".")) -> ScanResult:
    """Scan the public documentation tree and return findings plus disclosure data."""
    root = root.resolve()
    documents = _document_paths(root)
    texts = {path: path.read_text(encoding="utf-8") for path in documents}
    heading_cache = {path: _heading_slugs(text) for path, text in texts.items()}
    findings: list[Finding] = []
    external_targets: list[str] = []
    pinned_targets: list[str] = []
    link_count = 0

    for source, text in texts.items():
        for target in _extract_targets(text):
            link_count += 1
            repo_findings, classification = _inspect_repo_url(source, root, target)
            if classification is not None:
                findings.extend(repo_findings)
                if classification == "external":
                    external_targets.append(target)
                elif classification == "pinned":
                    pinned_targets.append(target)
                continue

            if _EXTERNAL_SCHEME.match(target):
                external_targets.append(target)
                continue
            findings.extend(
                _inspect_relative_target(source, root, target, heading_cache)
            )

    return ScanResult(
        findings=tuple(findings),
        file_count=len(documents),
        link_count=link_count,
        external_targets=tuple(external_targets),
        pinned_targets=tuple(pinned_targets),
    )


def validate_doc_links(root: Path = Path(".")) -> list[Finding]:
    """Return all public-document link findings for ``root`` without network access."""
    return list(scan_doc_links(root).findings)


def external_doc_links(root: Path = Path(".")) -> list[str]:
    """Return unique HTTP targets reserved for the informational liveness workflow."""
    result = scan_doc_links(root)
    return sorted(
        {
            target
            for target in result.external_targets
            if target.startswith(("http://", "https://"))
        }
    )


def _plural(count: int, singular: str) -> str:
    return singular if count == 1 else f"{singular}s"


def main(argv: Sequence[str] | None = None) -> int:
    """Run documentation validation and return a process exit code."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "root",
        nargs="?",
        type=Path,
        default=Path("."),
        help="repository root to validate (default: current directory)",
    )
    args = parser.parse_args(argv)

    try:
        result = scan_doc_links(args.root)
    except (OSError, ValueError) as exc:
        print(f"doc-link validation failed: {exc}", file=sys.stderr)
        return 1

    if result.findings:
        for finding in result.findings:
            print(
                f"{finding.file}: {finding.target!r}: {finding.rule}: {finding.detail}",
                file=sys.stderr,
            )
        return 1

    print(
        f"validated {result.link_count} doc {_plural(result.link_count, 'link')} "
        f"across {result.file_count} {_plural(result.file_count, 'file')} "
        f"({len(result.external_targets)} external not checked, "
        f"{len(result.pinned_targets)} pinned "
        f"{_plural(len(result.pinned_targets), 'ref')})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
