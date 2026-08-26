"""Live detector inventory and its public count statements stay in lockstep."""

from __future__ import annotations

import re
from collections import Counter
from pathlib import Path

import pytest

from sigwood.runner import discover_detectors


_ROOT = Path(__file__).resolve().parents[1]
_PUBLIC_PAGES = (
    "CONTRIBUTING.md",
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
# The optional qualifier is deliberately ARBITRARY (`\S+`) and must NOT be narrowed to an
# enumeration of adjectives. A public page can state its count as "<N> existing detectors",
# "<N> shipped detectors" or "<N> **callable** detectors"; a named-word list matches only the
# forms someone already thought of, so a qualified count drifts silently - the exact silence
# this scan exists to prevent. Bounded at ONE token so a match cannot span a clause.
# The ARBITRARY grammar is the invariant, not the two seeded cases below: the parametrized
# regression pins one enumerated and one unenumerated qualifier, which fails a narrowing
# that drops either - but an allow-list naming BOTH would still pass it. The rule is the
# guard here; the examples only witness it.
_COUNT_RE = re.compile(
    r"\b(?P<count>\d+|" + "|".join(_NUMBER_WORDS) + r")\s+"
    r"(?:\S+\s+)?detectors\b",
    re.IGNORECASE,
)
_EXPECTED_COUNT_SITES = Counter({
    "README.md": 1,
    "docs/FAQ.md": 1,
    "docs/CONTRACT.md": 2,
    "docs/ROADMAP.md": 1,
})
_EVIDENCE_PAGE = "docs/EVIDENCE.md"
_EVIDENCE_ROW_RE = re.compile(
    r"^\| `(?P<name>[a-z][a-z0-9_]*)` \| "
    r"(?P<disposition>[^|]+?) \| (?P<body>.*) \|$",
    re.MULTILINE,
)
_EVIDENCE_DISPOSITIONS = {
    "published conclusion": frozenset({"auth", "beacon", "dns", "exfil", "syslog"}),
    "measured; conclusion not yet published": frozenset({"dnsblock", "ssl"}),
    "no calibration campaign found": frozenset({"aws", "scan"}),
}


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


def _evidence_rows(page: str) -> list[tuple[str, str, str]]:
    return [
        (
            match.group("name"),
            match.group("disposition").strip(),
            match.group("body"),
        )
        for match in _EVIDENCE_ROW_RE.finditer(page)
    ]


def _assert_evidence_inventory(
    detector_names: set[str], *, page: str | None = None
) -> None:
    page = _read(_EVIDENCE_PAGE) if page is None else page
    rows = _evidence_rows(page)
    row_names = [name for name, _disposition, _body in rows]

    assert len(row_names) == len(detector_names)
    assert Counter(row_names) == Counter(detector_names)

    by_disposition = {
        disposition: frozenset(
            name
            for name, row_disposition, _body in rows
            if row_disposition == disposition
        )
        for disposition in _EVIDENCE_DISPOSITIONS
    }
    assert by_disposition == _EVIDENCE_DISPOSITIONS
    assert {disposition for _name, disposition, _body in rows} == set(
        _EVIDENCE_DISPOSITIONS
    )

    published = _EVIDENCE_DISPOSITIONS["published conclusion"]
    for name, disposition, body in rows:
        if name in published:
            target = f"evidence/{name}.md"
            assert f"]({target})" in body
            assert (_ROOT / "docs" / target).is_file()
        else:
            assert disposition != "published conclusion"
            assert "](evidence/" not in body


def test_public_detector_inventory_matches_live_discovery() -> None:
    _assert_public_inventory(set(discover_detectors()))


def test_evidence_ledger_matches_live_detector_inventory() -> None:
    _assert_evidence_inventory(set(discover_detectors()))


def test_evidence_ledger_tripwire_rejects_seeded_extra_detector() -> None:
    with pytest.raises(AssertionError):
        _assert_evidence_inventory({*discover_detectors(), "seeded_extra"})


def test_evidence_ledger_tripwire_rejects_duplicate_row() -> None:
    page = _read(_EVIDENCE_PAGE)
    duplicate = next(
        line for line in page.splitlines() if line.startswith("| `auth` |")
    )
    with pytest.raises(AssertionError):
        _assert_evidence_inventory(set(discover_detectors()), page=f"{page}\n{duplicate}\n")


def test_detector_inventory_tripwire_rejects_seeded_wrong_count() -> None:
    with pytest.raises(AssertionError):
        _assert_public_inventory({*discover_detectors(), "seeded_wrong_count"})


@pytest.mark.parametrize(
    "drift",
    (
        "For now the six existing detectors are the best guide.",
        "The nine shipped detectors are covered.",
    ),
)
def test_detector_inventory_tripwire_rejects_qualified_count_in_contributing(
    monkeypatch: pytest.MonkeyPatch,
    drift: str,
) -> None:
    read = _read

    def read_with_drift(path: str) -> str:
        page = read(path)
        if path == "CONTRIBUTING.md":
            return page + f"\n{drift}\n"
        return page

    monkeypatch.setitem(globals(), "_read", read_with_drift)
    with pytest.raises(AssertionError):
        _assert_public_inventory(set(discover_detectors()))
