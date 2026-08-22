"""The ssl detector: outbound TLS-setup surfacing over Zeek ssl.log.

All addresses are RFC 5737 documentation space and all names are reserved.
"""

from __future__ import annotations

import re
import shlex
from datetime import datetime, timezone

import pandas as pd
import pytest

from sigwood.common.finding import DetectorContext, Severity
from sigwood.detectors import ssl as ssl_detector
from tests.test_voice_consistency import assert_report_voice

WINDOW = (
    datetime(2026, 8, 1, tzinfo=timezone.utc),
    datetime(2026, 8, 8, tzinfo=timezone.utc),
)


def _ctx(frame: pd.DataFrame, *, x509: pd.DataFrame | None = None, config=None):
    logs = {"ssl*.log*": frame}
    if x509 is not None:
        logs["x509*.log*"] = x509
    return DetectorContext.unsuppressed(
        logs, data_window=WINDOW, config=config or {},
        home_net=["192.0.2.0/24"],
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


def _frame(rows):
    return pd.DataFrame(rows)


# ── the two legs ──────────────────────────────────────────────────────────────

def test_sni_absent_leg_surfaces_a_low_finding() -> None:
    findings = ssl_detector.run(_ctx(_frame([_row(sni=None)])))
    assert len(findings) == 1
    assert findings[0].severity is Severity.LOW
    assert findings[0].evidence["severity_basis"] == ["sni_absent"]


def test_validation_leg_surfaces_a_low_finding() -> None:
    findings = ssl_detector.run(
        _ctx(_frame([_row(validation_status="self signed certificate")]))
    )
    assert len(findings) == 1
    assert findings[0].severity is Severity.LOW
    assert findings[0].evidence["severity_basis"] == ["validation"]


def test_both_legs_on_one_pair_earn_medium() -> None:
    findings = ssl_detector.run(_ctx(_frame([
        _row(sni=None),
        _row(validation_status="self signed certificate"),
    ])))
    assert len(findings) == 1
    assert findings[0].severity is Severity.MEDIUM
    assert findings[0].evidence["severity_basis"] == ["sni_absent", "validation"]


def test_a_clean_session_surfaces_nothing() -> None:
    assert ssl_detector.run(_ctx(_frame([_row()]))) == []


def test_high_is_unreachable_inside_the_detector() -> None:
    findings = ssl_detector.run(_ctx(_frame([
        _row(sni=None), _row(validation_status="certificate has expired"),
    ] * 40)))
    assert all(f.severity is not Severity.HIGH for f in findings)


# ── leg A strictness ──────────────────────────────────────────────────────────

@pytest.mark.parametrize("over", [
    {"sni": None, "established": False},
    {"sni": None, "resumed": True},
])
def test_sni_leg_requires_established_and_not_resumed(over) -> None:
    assert ssl_detector.run(_ctx(_frame([_row(**over)]))) == []


def test_sni_leg_uses_strict_booleans_not_truthiness() -> None:
    """A non-boolean truthy value is not an established handshake."""
    assert ssl_detector.run(_ctx(_frame([_row(sni=None, established=1)]))) == []


# ── leg B: the abstention matrix ──────────────────────────────────────────────

@pytest.mark.parametrize("status", [None, float("nan"), "", "   ", 17, True])
def test_validation_leg_abstains_on_an_unmeasured_status(status) -> None:
    """cert_fp present with no measured status must not claim a failed
    validation - pandas reads NaN != 'ok' as True, which would fabricate one."""
    findings = ssl_detector.run(_ctx(_frame([_row(validation_status=status)])))
    assert findings == []


def test_validation_leg_abstains_on_a_missing_status_column() -> None:
    frame = _frame([_row()]).drop(columns=["validation_status"])
    assert ssl_detector.run(_ctx(frame)) == []


def test_validation_leg_abstains_on_the_literal_ok() -> None:
    assert ssl_detector.run(_ctx(_frame([_row(validation_status="ok")]))) == []


def test_validation_leg_abstains_without_a_certificate() -> None:
    """TLS 1.3 rows carry no certificate: no cert_fp, no validation claim."""
    findings = ssl_detector.run(_ctx(_frame([
        _row(version="TLSv13", cert_fp=None, validation_status="self signed certificate"),
    ])))
    assert findings == []


def test_an_abstaining_row_still_counts_toward_certificate_visibility() -> None:
    findings = ssl_detector.run(_ctx(_frame([
        _row(sni=None, validation_status=None, cert_fp="aa11"),
    ])))
    assert findings[0].evidence["cert_visible_share"] == 1.0
    assert "validation_status" not in findings[0].evidence


# ── eligibility order ─────────────────────────────────────────────────────────

def test_an_unparseable_destination_is_never_read_as_external() -> None:
    """Parse precedes the direction gates: both destination predicates fail
    open, so a garbage value would compose into 'external'."""
    assert ssl_detector.run(_ctx(_frame([_row(sni=None, dst="not-an-address")]))) == []


def test_an_internal_destination_is_out_of_scope() -> None:
    assert ssl_detector.run(_ctx(_frame([_row(sni=None, dst="192.0.2.99")]))) == []


def test_a_non_routable_destination_is_out_of_scope() -> None:
    assert ssl_detector.run(_ctx(_frame([_row(sni=None, dst="239.0.0.1")]))) == []


def test_an_external_source_is_out_of_scope() -> None:
    assert ssl_detector.run(_ctx(_frame([_row(sni=None, src="203.0.113.5")]))) == []


def test_missing_required_columns_make_the_detector_abstain() -> None:
    frame = _frame([_row(sni=None)]).drop(columns=["dst"])
    assert ssl_detector.run(_ctx(frame)) == []
    assert ssl_detector.eligibility(frame, home_net=["192.0.2.0/24"])["missing_columns"] == ("dst",)


def test_an_empty_frame_makes_no_column_claim() -> None:
    facts = ssl_detector.eligibility(pd.DataFrame(), home_net=["192.0.2.0/24"])
    assert facts["missing_columns"] == ()
    assert facts["rows_total"] == 0


# ── deterministic evidence ────────────────────────────────────────────────────

def test_representative_status_is_the_mode_with_a_lexical_tie_break() -> None:
    findings = ssl_detector.run(_ctx(_frame([
        _row(validation_status="self signed certificate"),
        _row(validation_status="certificate has expired"),
    ])))
    ev = findings[0].evidence
    assert ev["validation_status"] == "certificate has expired"
    assert ev["validation_mix"] == {
        "certificate has expired": 1, "self signed certificate": 1,
    }


def test_evidence_is_independent_of_input_order() -> None:
    rows = [
        _row(validation_status="self signed certificate"),
        _row(validation_status="certificate has expired"),
        _row(sni=None),
    ]
    first = ssl_detector.run(_ctx(_frame(rows)))[0].evidence
    second = ssl_detector.run(_ctx(_frame(list(reversed(rows)))))[0].evidence
    assert first == second


def test_tuple_share_is_window_relative() -> None:
    """The denominator is every loaded row in the window, not the pair's."""
    rows = [_row(sni=None)] + [_row(src="192.0.2.11") for _ in range(3)]
    findings = ssl_detector.run(_ctx(_frame(rows)))
    assert findings[0].evidence["tuple_share"] == pytest.approx(1.0)
    mixed = [_row(sni=None)] + [_row(src="192.0.2.11", cipher="OTHER") for _ in range(3)]
    findings = ssl_detector.run(_ctx(_frame(mixed)))
    assert findings[0].evidence["tuple_share"] == pytest.approx(0.25)


def test_certificate_visible_share_is_pair_local() -> None:
    findings = ssl_detector.run(_ctx(_frame([
        _row(sni=None, cert_fp="aa11"),
        _row(sni=None, cert_fp=None),
    ])))
    assert findings[0].evidence["cert_visible_share"] == pytest.approx(0.5)


def test_event_time_evidence_accepts_the_zero_epoch() -> None:
    findings = ssl_detector.run(_ctx(_frame([_row(sni=None, ts=0.0)])))
    ev = findings[0].evidence
    assert ev["first_seen"] == "1970-01-01T00:00:00+00:00"
    assert ev["span_seconds"] == 0.0


# ── the x509 join ─────────────────────────────────────────────────────────────

def _x509(**over):
    base = {
        "ts": 1784000000.0, "fingerprint": "aa11",
        "not_valid_before": 1780000000.0, "not_valid_after": 1790000000.0,
        "self_signed": True, "key_alg": "rsaEncryption", "key_length": 2048,
    }
    base.update(over)
    return base


def test_x509_join_emits_all_five_certificate_facts() -> None:
    findings = ssl_detector.run(_ctx(
        _frame([_row(validation_status="self signed certificate")]),
        x509=pd.DataFrame([_x509()]),
    ))
    ev = findings[0].evidence
    for key in ("cert_validity_days", "cert_key_alg", "cert_key_length",
                "cert_self_signed", "cert_age_at_first_use_days"):
        assert key in ev
    assert ev["cert_key_length"] == 2048
    assert ev["cert_self_signed"] is True


def test_x509_join_emits_none_of_the_five_when_a_fact_is_unmeasured() -> None:
    findings = ssl_detector.run(_ctx(
        _frame([_row(validation_status="self signed certificate")]),
        x509=pd.DataFrame([_x509(not_valid_after=None)]),
    ))
    ev = findings[0].evidence
    for key in ("cert_validity_days", "cert_key_alg", "cert_key_length",
                "cert_self_signed", "cert_age_at_first_use_days"):
        assert key not in ev


def test_x509_absent_degrades_silently() -> None:
    findings = ssl_detector.run(
        _ctx(_frame([_row(validation_status="self signed certificate")]))
    )
    assert findings[0].evidence["cert_count"] == 1
    assert "cert_validity_days" not in findings[0].evidence


# ── grain, ordering, config ───────────────────────────────────────────────────

def test_one_finding_per_pair_across_many_rows() -> None:
    rows = [_row(sni=None) for _ in range(12)] + [_row(sni=None, dst="203.0.113.7")]
    findings = ssl_detector.run(_ctx(_frame(rows)))
    assert len(findings) == 2
    assert {f.title for f in findings} == {
        "192.0.2.10 → 198.51.100.20", "192.0.2.10 → 203.0.113.7",
    }


def test_findings_sort_by_severity_then_volume_then_pair() -> None:
    rows = (
        [_row(sni=None, dst="203.0.113.7") for _ in range(5)]
        + [_row(sni=None, dst="203.0.113.8")]
        + [_row(sni=None, validation_status="certificate has expired", dst="203.0.113.9")]
    )
    findings = ssl_detector.run(_ctx(_frame(rows)))
    assert findings[0].severity is Severity.MEDIUM
    assert [f.evidence["conn_count"] for f in findings[1:]] == [5, 1]


def test_min_connections_gates_the_pair() -> None:
    rows = [_row(sni=None), _row(sni=None, dst="203.0.113.7")]
    findings = ssl_detector.run(
        _ctx(_frame(rows), config={"min_connections": 2})
    )
    assert findings == []


def test_default_config_validates_clean() -> None:
    ssl_detector.validate_config(dict(ssl_detector.DEFAULT_CONFIG))


@pytest.mark.parametrize("bad", [True, 0, -1, "1", 1.5, None])
def test_invalid_min_connections_is_rejected(bad) -> None:
    with pytest.raises(ValueError, match=r"\[detectors\.ssl\]\.min_connections"):
        ssl_detector.validate_config({"min_connections": bad})


def test_the_detector_is_opt_in_and_declares_a_house_method() -> None:
    assert ssl_detector.IN_DEFAULT_HUNT is False
    assert ssl_detector.STATUS == "available"
    assert ssl_detector.DETECTOR_METHOD.named is False


def test_report_voice() -> None:
    findings = ssl_detector.run(_ctx(_frame([
        _row(sni=None), _row(validation_status="self signed certificate"),
    ])))
    assert_report_voice(findings)


def test_next_steps_carry_exactly_one_literal_command() -> None:
    """One command per finding: a wall of pasteable lines is read as a script
    to run rather than as pivots to choose between."""
    steps = ssl_detector._pair_next_steps("192.0.2.10")
    commands = [s for s in steps if "zeek-cut" in s or "whois " in s or "grep " in s]
    assert len(commands) == 1


def test_next_steps_quote_a_hostile_log_derived_value() -> None:
    """The parse gate keeps a hostile address out of the frame, so the quoting
    is proved at the composition site - where a future caller could pass one."""
    for hostile in (
        "192.0.2.10; rm -rf /",
        "192.0.2.10 $(id)",
        "192.0.2.10 `whoami`",
        "--output=/etc/passwd",
        "192.0.2.10\nsecond-command",
    ):
        joined = " ".join(ssl_detector._pair_next_steps(hostile))
        quoted = shlex.quote(hostile)
        assert quoted in joined, f"{hostile!r} reached the command unquoted"
        # Nothing hostile survives OUTSIDE the quoted span.
        remainder = joined.replace(quoted, "")
        for token in ("; rm", "$(", "`", "--output="):
            assert token not in remainder


def test_severity_and_basis_come_from_one_call() -> None:
    """The ladder returns both, so a caller cannot build a basis that disagrees
    with the severity it asked for."""
    assert ssl_detector._severity_for(True, False) == (Severity.LOW, ["sni_absent"])
    assert ssl_detector._severity_for(False, True) == (Severity.LOW, ["validation"])
    severity, basis = ssl_detector._severity_for(True, True)
    assert severity is Severity.MEDIUM and basis == ["sni_absent", "validation"]
    assert all(
        ssl_detector._severity_for(a, b)[0] is not Severity.HIGH
        for a in (True, False) for b in (True, False)
    )
    for a in (True, False):
        for b in (True, False):
            sev, bas = ssl_detector._severity_for(a, b)
            assert (len(bas) == 2) is (sev is Severity.MEDIUM)


def test_x509_join_ignores_rows_without_a_finite_timestamp() -> None:
    """The representative is the EARLIEST row; a row that cannot be ordered
    cannot be chosen, and with none left there is no fact to emit."""
    findings = ssl_detector.run(_ctx(
        _frame([_row(validation_status="self signed certificate")]),
        x509=pd.DataFrame([_x509(ts=float("nan"))]),
    ))
    assert "cert_validity_days" not in findings[0].evidence


def test_x509_join_picks_the_earliest_finite_row_regardless_of_order() -> None:
    rows = pd.DataFrame([
        _x509(ts=float("nan"), key_length=4096),
        _x509(ts=1784000000.0, key_length=2048),
        _x509(ts=1786000000.0, key_length=1024),
    ])
    findings = ssl_detector.run(_ctx(
        _frame([_row(validation_status="self signed certificate")]), x509=rows,
    ))
    assert findings[0].evidence["cert_key_length"] == 2048


def test_a_two_leg_description_stays_within_two_sentences() -> None:
    """The population clause rides leg B as a trailing clause, so a finding
    that fires both legs keeps the two-sentence description shape."""
    findings = ssl_detector.run(_ctx(_frame([
        _row(sni=None),
        _row(validation_status="self signed certificate"),
    ])))
    description = findings[0].description
    assert len(re.findall(r"\.(?:\s|$)", description)) == 2


def test_description_carries_the_measured_status_and_the_population() -> None:
    findings = ssl_detector.run(_ctx(
        _frame([_row(validation_status="self signed certificate")])
    ))
    description = findings[0].description
    assert "(self signed certificate)" in description
    assert "only the sessions that presented one" in description
    assert "TLS 1.3 encrypts the certificate" in description
    # The mechanism is stated, never a measurement taken somewhere else.
    assert "reference estate" not in description
    for identity in ("192.0.2.10", "198.51.100.20", "service.example.com", "aa11"):
        assert identity not in description


def test_result_set_is_verbosity_invariant() -> None:
    frame = _frame([_row(sni=None)])
    first = ssl_detector.run(_ctx(frame))
    second = ssl_detector.run(_ctx(frame))
    assert [f.title for f in first] == [f.title for f in second]
