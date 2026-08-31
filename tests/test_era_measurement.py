"""Era measurement-receipt contracts."""

from __future__ import annotations

import pytest

from sigwood.era import (
    EraMeasurementOutcome,
    EraResourceReceipt,
    normalized_maxrss_bytes,
    not_measured_receipt,
)
from sigwood.runner import (
    EraHarnessReceipt,
    EraOracleReceipt,
    _run_era_oracle_measurement,
    _run_era_resource_measurement,
)


def test_not_measured_names_the_missing_route_precondition() -> None:
    receipt = not_measured_receipt(
        route_identity="era-planner-loader-reducer",
        archive_content_identity="fixture",
        candidate_cap=2_000_000,
        missing_precondition="route-unavailable",
    )
    assert receipt.outcome is EraMeasurementOutcome.NOT_MEASURED
    assert receipt.missing_precondition == "route-unavailable"
    assert receipt.raw_maxrss is None


def test_receipt_rejects_an_unbounded_not_measured_claim() -> None:
    with pytest.raises(ValueError, match="named missing precondition"):
        EraResourceReceipt(
            outcome=EraMeasurementOutcome.NOT_MEASURED,
            route_identity="route",
            archive_content_identity="content",
            candidate_cap=2_000_000,
            platform="fixture",
            raw_maxrss=None,
            normalized_maxrss_bytes=None,
            rss_limit_bytes=1,
            elapsed_seconds=None,
        )


def test_normalizes_darwin_and_linux_maxrss_units() -> None:
    assert normalized_maxrss_bytes(12, system="Darwin") == 12
    assert normalized_maxrss_bytes(12, system="Linux") == 12 * 1024


def test_ledger_measurement_names_an_unreachable_real_consumer_route() -> None:
    receipt = _run_era_resource_measurement({"sigwood": {}}, archive_root_candidates=[])

    assert receipt.outcome is EraMeasurementOutcome.NOT_MEASURED
    assert receipt.route_identity == "era-planner-loader-domain-ledger"
    assert receipt.missing_precondition == "corpus-unreachable"


def test_oracle_measurement_has_a_distinct_whole_product_route() -> None:
    harness = EraHarnessReceipt(
        outcome="MEASURED",
        population_basis="raw_pre_allowlist",
        record_counts=(("conn", 1),),
        consumed_span=None,
        missing_baseline_dates=(),
        post_baseline_dates=(),
        cards_present=(1,),
        rendered_cards="era / zeek",
        frozen_input_identity="fixture-identity",
    )
    oracle = EraOracleReceipt(
        outcome="MEASURED",
        archive_content_identity="fixture-identity",
        record_counts=harness.record_counts,
        cards_present=harness.cards_present,
        missing_baseline_dates=(),
        post_baseline_dates=(),
        warning_census=(),
        rendered_deck_sha256="a" * 64,
        rendered_deck_byte_length=10,
        closure_payload_sha256="b" * 64,
    )

    receipt = _run_era_oracle_measurement(
        {"sigwood": {}},
        archive_root_candidates=[],
        cli_options={"private": True},
        display_timezone="UTC",
        partition_zone="UTC",
        tldextract_version="fixture",
        effective_psl_snapshot=b"fixture",
        _oracle_receipt=oracle,
    )

    assert receipt.outcome in {
        EraMeasurementOutcome.PASS,
        EraMeasurementOutcome.COMPLETED_RSS_OVER_LIMIT,
    }
    assert receipt.route_identity == "era-planner-loader-fold-render-oracle"
    assert receipt.archive_content_identity == "fixture-identity"
    assert receipt.route_identity != "era-planner-loader-domain-ledger"
