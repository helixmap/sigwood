"""Live detector inventory and its public count statements stay in lockstep."""

from __future__ import annotations

import re
from collections import Counter
from pathlib import Path

import pytest

from sigwood.runner import discover_detectors


_ROOT = Path(__file__).resolve().parents[1]
_PUBLIC_PAGES = (
    "README.md",
    "docs/FAQ.md",
    "docs/CONTRACT.md",
    "docs/ROADMAP.md",
    "docs/KNOWN-ISSUES.md",
)
_NUMBER_WORDS = {
    "one": 1,
    "two": 2,
    "three": 3,
    "four": 4,
    "five": 5,
    "six": 6,
    "seven": 7,
    "eight": 8,
    "nine": 9,
    "ten": 10,
    "eleven": 11,
    "twelve": 12,
}
_COUNT_RE = re.compile(
    r"\b(?P<count>\d+|" + "|".join(_NUMBER_WORDS) + r")\s+"
    r"(?:callable\s+)?detectors\b",
    re.IGNORECASE,
)
_EXPECTED_COUNT_SITES = Counter({
    "README.md": 1,
    "docs/FAQ.md": 1,
    "docs/CONTRACT.md": 2,
    "docs/ROADMAP.md": 1,
})


def _read(path: str) -> str:
    return (_ROOT / path).read_text(encoding="utf-8")


def _count_value(token: str) -> int:
    folded = token.casefold()
    return int(folded) if folded.isdigit() else _NUMBER_WORDS[folded]


def _assert_public_inventory(detector_names: set[str]) -> None:
    mentions: list[tuple[str, str, int]] = []
    for path in _PUBLIC_PAGES:
        for match in _COUNT_RE.finditer(_read(path)):
            mentions.append(
                (path, match.group(0).casefold(), _count_value(match.group("count")))
            )

    assert Counter(path for path, _phrase, _count in mentions) == _EXPECTED_COUNT_SITES
    assert {count for _path, _phrase, count in mentions} == {len(detector_names)}

    readme_section = _read("README.md").split("## What it hunts", 1)[1].split(
        "## ", 1
    )[0]
    readme_names = set(
        re.findall(r"^\| `([a-z][a-z0-9_]*)`", readme_section, re.MULTILINE)
    )
    assert readme_names == detector_names

    contract = _read("docs/CONTRACT.md")
    callable_sentence = contract.split(" callable detectors are ", 1)[1].split(";", 1)[0]
    assert set(re.findall(r"`([a-z][a-z0-9_]*)`", callable_sentence)) == detector_names

    shipped = _read("docs/ROADMAP.md").split("## Shipped", 1)[1].split(
        "## Coverage", 1
    )[0].split("\n- ", 1)[1].split("\n- ", 1)[0]
    assert {
        name for name in detector_names if re.search(rf"\b{re.escape(name)}\b", shipped)
    } == detector_names


def test_public_detector_inventory_matches_live_discovery() -> None:
    _assert_public_inventory(set(discover_detectors()))


def test_detector_inventory_tripwire_rejects_seeded_wrong_count() -> None:
    with pytest.raises(AssertionError):
        _assert_public_inventory({*discover_detectors(), "seeded_wrong_count"})
