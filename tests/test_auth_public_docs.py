"""Public documentation must describe the shipped auth surface exactly."""

from __future__ import annotations

from pathlib import Path


_ROOT = Path(__file__).resolve().parents[1]


def _read(path: str) -> str:
    return (_ROOT / path).read_text(encoding="utf-8")


def test_readme_lists_eight_detectors_and_auth() -> None:
    readme = _read("README.md")
    assert "The nine detectors work and are covered by tests" in readme
    assert "| `auth`" in readme
    assert "auth uses authentication structure" in readme


def test_faq_moves_auth_out_of_the_planned_roster_and_explains_severity() -> None:
    faq = _read("docs/FAQ.md")
    assert "The nine detectors above work and are covered by tests" in faq
    state = faq[faq.index("### What state is sigwood in?"):]
    assert "`auth`" not in state.split("### How would I add", 1)[0]
    auth_answer = faq[faq.index("### What does the auth detector look for?"):]
    auth_answer = auth_answer.split("\n### ", 1)[0]
    for signal in (
        "concentrated failures",
        "source volume",
        "account volume",
        "multi-host failures",
        "failures followed by a success",
    ):
        assert signal in auth_answer
    assert "HIGH" in auth_answer
    assert "multi-host" in auth_answer and "success" in auth_answer


def test_schema_names_auth_as_a_shipped_consumer() -> None:
    schema = _read("docs/SCHEMA.md")
    assert "future auth" not in schema
    assert "auth` detector (planned" not in schema
    assert schema.count("`auth` detector") >= 2


def test_roadmap_no_longer_places_auth_in_the_future() -> None:
    roadmap = _read("docs/ROADMAP.md")
    shipped = roadmap.split("## MITRE ATT&CK coverage", 1)[0]
    assert "**Nine detectors**" in shipped
    assert "auth (five" in shipped
    assert "once `auth` lands" not in roadmap
    later = roadmap.split("## Later", 1)[1]
    assert "(`auth`)" not in later
    for tactic in ("Initial Access", "Privilege Escalation", "Credential Access", "Lateral Movement"):
        row = next(line for line in roadmap.splitlines() if line.startswith(f"| {tactic} |"))
        assert "`auth`" in row.split("|")[2]


def test_known_issues_carries_the_four_auth_residuals() -> None:
    issues = _read("docs/KNOWN-ISSUES.md").casefold()
    assert "auth" in issues
    assert "medium" in issues and "landing" in issues
    assert "window-relative" in issues and "first_seen" in issues
    assert "source address" in issues and "individually" in issues and "allowlist" in issues
    assert "synthetic" in issues and "high" in issues and "estate" in issues


def test_unreleased_changelog_records_auth_activation_without_claiming_a_regression() -> None:
    changelog = _read("CHANGELOG.md")
    unreleased = changelog.split("## [0.2.9]", 1)[0]
    flat = " ".join(unreleased.split())
    assert "**Authentication analysis" in unreleased
    assert "`sigwood auth`" in unreleased
    assert "five" in unreleased and "HIGH" in unreleased
    assert "pre-existing limitations" in flat
    assert "all six detectors" not in unreleased
