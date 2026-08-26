"""The known-issues opening keeps its honest gap-disclosure taxonomy."""

from pathlib import Path


_ROOT = Path(__file__).resolve().parents[1]


def test_known_issues_opening_does_not_restore_categorical_safety_claim() -> None:
    issues = (_ROOT / "docs/KNOWN-ISSUES.md").read_text(encoding="utf-8")
    opening = " ".join(issues.split("\n\n", 2)[1].split())

    assert "None of them lose" not in opening
    assert "Where sigwood can notice a gap at run time it says so in the run itself" in opening
    assert 'if an entry says "silently," it means it' in opening
