"""Public and binding documentation for the shipped dnsblock surface."""

from __future__ import annotations

from pathlib import Path

import pytest


_ROOT = Path(__file__).resolve().parents[1]


def _read(path: str) -> str:
    return (_ROOT / path).read_text(encoding="utf-8")


def test_public_pages_name_dnsblock_as_available_and_opt_in() -> None:
    readme = _read("README.md")
    assert "The nine detectors work and are covered by tests" in readme
    assert "| `dnsblock`" in readme
    assert "sigwood dnsblock /var/log/pihole" in readme
    assert "Neither joins the curated default hunt automatically" in readme
    assert "28-day file-selection aperture" in readme
    assert "four\ntimes the report span by duration" in readme

    faq = _read("docs/FAQ.md")
    section = faq.split("### What does the dnsblock detector look for?", 1)[1]
    assert "does not\nship a reputation feed" in section
    assert "first time in the available history" in section
    assert "query-burst" not in section  # voice uses ordinary "large burst"
    assert "select 21 additional days of rotated files" in faq
    assert "28-day selection aperture" in faq
    state = faq.split("### What state is sigwood in?", 1)[1]
    assert "A protocol\nclassifier remains a roadmap future" in state
    assert "promise of a future detector" in state
    assert "`dnsblock`" not in state.split("### How would I add", 1)[0]


def test_contract_roadmap_changelog_and_known_issue_agree() -> None:
    contract = _read("docs/CONTRACT.md")
    assert "Sixteen, all of which stay recognized:" in contract
    assert "The nine callable detectors are" in contract
    assert "`dnsblock` \u2014 no public tuning keys" in contract

    roadmap = _read("docs/ROADMAP.md")
    shipped = roadmap.split("## MITRE ATT&CK coverage", 1)[0]
    assert "**Nine detectors**" in shipped
    assert "dnsblock (first activity, bursts, and recurrence" in shipped
    assert "**Known-bad access patterns** - **dnsblock**" not in roadmap

    issues = _read("docs/KNOWN-ISSUES.md")
    assert "**`dnsblock` can report a persistently blocked name again" in issues
    assert "**An implicit `dnsblock` run can read more Pi-hole rotations" in issues

    unreleased = _read("CHANGELOG.md").split("## [0.3.0]", 1)[0]
    assert "**`dnsblock` is now available as an opt-in detector" in unreleased
    assert "curated default hunt remains unchanged" in unreleased


def test_binding_rails_have_no_activation_stubs_left() -> None:
    rails = Path("private") / "rails"
    if not (_ROOT / rails).is_dir():
        pytest.skip("binding rails not present - dev-box enforced, public CI skips")

    detectors = _read(str(rails / "detectors.md"))
    runner = _read(str(rails / "runner.md"))

    assert "| dnsblock   | pihole_dir                           | exists    |" in detectors
    assert "STATUS available \u2014 opt-in" in detectors
    assert "Public discovery includes dnsblock" in detectors
    assert "dnsblock detector (STATUS planned" not in detectors
    assert "planned `dnsblock` detector" not in detectors
    assert "publicly\navailable, opt-in dnsblock preparation" in runner
    assert "public discovery and\nthe CLI cannot run it" not in runner
