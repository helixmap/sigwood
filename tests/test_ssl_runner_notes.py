"""Runner-owned ssl disclosure notes.

The detector owns every measurement; this seam owns wording only, reduces the
detector's pair-keyed facts to counts, and never lets an identity reach a note.
Addresses are RFC 5737 documentation space.
"""

from __future__ import annotations

import pandas as pd

import sigwood.runner as runner
from sigwood.detectors import ssl as ssl_detector
from sigwood.runner import RunPlan

HOME_NET = ["192.0.2.0/24"]


def _plan(*, will_run=("ssl",), module=ssl_detector) -> RunPlan:
    return RunPlan(
        detectors={"ssl": module} if module is not None else {},
        selected=list(will_run),
        will_run=list(will_run),
        skipped={},
        needed_logs={"ssl*.log*": "zeek_dir"},
    )


def _row(**over):
    base = {
        "ts": 1785000000.0,
        "src": "192.0.2.10",
        "dst": "198.51.100.20",
        "port": 443,
        "version": "TLSv12",
        "cipher": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "curve": "secp256r1",
        "alpn": "h2",
        "sni": "service.example.com",
        "resumed": False,
        "established": True,
        "validation_status": "ok",
        "cert_fp": "aa11",
    }
    base.update(over)
    return base


def _logs(rows):
    return {"ssl*.log*": pd.DataFrame(rows)}


def _visibility(logs, *, plan=None) -> str | None:
    """Render the visibility line through the ASSEMBLED one-measurement path."""
    facts = runner._ssl_facts(plan or _plan(), logs, HOME_NET)
    return None if facts is None else runner._ssl_visibility_line(facts)


def _zero(logs, *, plan=None) -> str | None:
    """Render the zero-cause line through the assembled path."""
    facts = runner._ssl_facts(plan or _plan(), logs, HOME_NET)
    return None if facts is None else runner._ssl_zero_findings_line(facts)


# ── the visibility note ───────────────────────────────────────────────────────

def test_visibility_note_states_the_measured_share() -> None:
    logs = _logs([_row(), _row(cert_fp=None, version="TLSv13")])
    note = _visibility(logs)
    assert note is not None
    assert "1 of 2" in note
    assert "50" in note
    assert "validation leg covers only those" in note


def test_visibility_note_reconciles_with_the_finding_share() -> None:
    """The note's N/M and a pair's cert_visible_share must be the same
    measurement, or the report contradicts itself on one screen."""
    rows = [_row(sni=None), _row(sni=None, cert_fp=None)]
    note = _visibility(_logs(rows))
    from sigwood.common.finding import DetectorContext
    from datetime import datetime, timezone

    context = DetectorContext.unsuppressed(
        _logs(rows),
        data_window=(
            datetime(2026, 8, 1, tzinfo=timezone.utc),
            datetime(2026, 8, 8, tzinfo=timezone.utc),
        ),
        home_net=HOME_NET,
    )
    finding = ssl_detector.run(context)[0]
    assert "1 of 2" in note
    assert finding.evidence["cert_visible_share"] == 0.5


def test_visibility_note_uses_a_real_plural() -> None:
    note = _visibility(_logs([_row()]))
    assert "1 of 1 outbound session " in note or "1 of 1 outbound session" in note
    assert "session(s)" not in note


def test_visibility_note_is_silent_when_ssl_is_not_planned() -> None:
    assert _visibility(_logs([_row()]), plan=_plan(will_run=())) is None


def test_visibility_note_is_silent_without_a_module_or_helper() -> None:
    assert _visibility(_logs([_row()]), plan=_plan(module=None)) is None

    class Bare:
        pass

    assert _visibility(_logs([_row()]), plan=_plan(module=Bare())) is None


def test_visibility_note_is_silent_with_no_eligible_outbound_rows() -> None:
    logs = _logs([_row(dst="192.0.2.99")])
    assert _visibility(logs) is None


# ── the zero-findings note ────────────────────────────────────────────────────

def test_zero_note_names_absent_required_columns() -> None:
    frame = pd.DataFrame([_row()]).drop(columns=["dst"])
    note = _zero({"ssl*.log*": frame})
    assert note is not None
    assert "dst" in note


def test_zero_note_names_the_absent_outbound_population() -> None:
    note = _zero(_logs([_row(dst="192.0.2.99")]))
    assert note is not None
    assert "outbound" in note


def test_zero_note_distinguishes_a_non_routable_destination_population() -> None:
    note = _zero(_logs([_row(dst="239.0.0.1")]))
    assert note is not None
    assert "routable" in note


def test_zero_note_is_silent_when_rows_are_eligible() -> None:
    assert _zero(_logs([_row()])) is None


# ── identity ──────────────────────────────────────────────────────────────────

def test_no_note_carries_an_address_or_a_server_name() -> None:
    rows = [
        _row(sni=None),
        _row(dst="203.0.113.7", sni="secret.example.com"),
        _row(dst="239.0.0.1"),
    ]
    logs = _logs(rows)
    joined = " ".join(runner._ssl_eligibility_notes(_plan(), logs, HOME_NET))
    for identity in ("192.0.2.10", "198.51.100.20", "203.0.113.7",
                     "239.0.0.1", "secret.example.com", "aa11"):
        assert identity not in joined


def test_eligibility_is_measured_once_for_both_lines(monkeypatch) -> None:
    """One measurement feeds both renderers: a second call could report a
    different funnel and put two numbers about one run on one screen."""
    calls = {"n": 0}
    real = ssl_detector.eligibility

    def counting(df, home_net=None):
        calls["n"] += 1
        return real(df, home_net)

    monkeypatch.setattr(ssl_detector, "eligibility", counting)
    runner._ssl_eligibility_notes(_plan(), _logs([_row(), _row(cert_fp=None)]), HOME_NET)
    assert calls["n"] == 1


def test_the_two_destination_causes_are_mutually_exclusive() -> None:
    inside = _zero(_logs([_row(dst="192.0.2.99")]))
    non_routable = _zero(_logs([_row(dst="239.0.0.1")]))
    assert inside is not None and non_routable is not None
    assert inside != non_routable
    assert "inside home_net" in inside and "non-routable" not in inside
    assert "non-routable" in non_routable and "inside home_net" not in non_routable
