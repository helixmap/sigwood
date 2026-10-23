"""Era archive orchestration and private measurement receipts."""
from __future__ import annotations

from typing import Any
from collections import Counter
from sigwood.common.errors import ExportAborted
from typing import Mapping
from pathlib import Path
from typing import Sequence
from sigwood.common.display import cursor_visible
from dataclasses import dataclass
from datetime import date
from datetime import datetime
import hashlib
from sigwood.common.display import human_bytes
import resource
import sys
import time
from datetime import timedelta
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sigwood.era.report import EraCard, SelectionEvidence, SpanHonesty


@dataclass(frozen=True)
class EraHarnessReceipt:
    """Private aggregate receipt for the runner-owned era archive harness."""

    outcome: str
    population_basis: str
    record_counts: tuple[tuple[str, int], ...]
    consumed_span: tuple[datetime, datetime] | None
    missing_baseline_dates: tuple[date, ...]
    post_baseline_dates: tuple[date, ...]
    cards_present: tuple[int, ...]
    rendered_cards: str | None
    peak_minute: datetime | None = None
    peak_minute_neighborhood: tuple[int, ...] = ()
    peak_minute_date_relation: str | None = None
    duration_tail_counts: tuple[tuple[int, int], ...] = ()
    longest_duration_start: datetime | None = None
    longest_duration_end: datetime | None = None
    temporal_daily_counts: tuple[tuple[date, int], ...] = ()
    card_six_selection: str | None = None
    card_nine_winner_score: float | None = None
    card_nine_runner_up_score: float | None = None
    card_nine_admissible_candidates: int = 0
    card_nine_refused_candidates: int = 0
    card_nine_tie: bool = False
    card_eight_winner_score: float | None = None
    card_eight_runner_up_score: float | None = None
    card_eight_speaking_weeks: int = 0
    card_eight_subfloor_weeks: int = 0
    card_eight_tie: bool = False
    card_ten_span_weeks: int = 0
    card_ten_maturity: int | None = None
    card_ten_reason: str | None = None
    card_ten_ledger_cap: int = 0
    card_ten_ledger_cap_exceeded: bool = False
    card_ten_psl_available: bool = True
    card_ten_exclusions: tuple[tuple[str, int], ...] = ()
    footprint_facts: tuple[tuple[str, int, int, int, str], ...] = ()
    warning_census: tuple[tuple[str, int], ...] = ()
    missing_precondition: str | None = None
    frozen_input_identity: str | None = None
    family: str = "zeek"
    cards: tuple[EraCard, ...] = ()
    span_honesty: SpanHonesty | None = None
    selection_evidence: SelectionEvidence | None = None


@dataclass(frozen=True)
class EraOracleReceipt:
    """Private whole-route record for the full planner-to-render product route.

    Rendered deck text may contain a safe, quoted inspect handoff, which in turn
    can carry an operator provenance directory.  The receipt therefore retains
    only its hash and byte length; detached-run artifacts own the bytes.
    """

    outcome: str
    archive_content_identity: str | None
    record_counts: tuple[tuple[str, int], ...]
    cards_present: tuple[int, ...]
    missing_baseline_dates: tuple[date, ...]
    post_baseline_dates: tuple[date, ...]
    warning_census: tuple[tuple[str, int], ...]
    rendered_deck_sha256: str | None
    rendered_deck_byte_length: int | None
    closure_payload_sha256: str | None


def _era_warning_class(warning: object) -> str:
    """Reduce loader warning prose to a path-free, deterministic cause class."""
    text = str(warning).lower()
    if "permission" in text or "denied" in text:
        return "permission-denied"
    if "corrupt" in text or "unexpected end" in text or "eof" in text:
        return "read-corruption"
    if "parse" in text or "malformed" in text or "no records" in text:
        return "parse-contained"
    if "snapshot" in text or "changed" in text:
        return "source-mutated"
    return "other-loader-warning"


def _era_closure_config(config: Mapping[str, Any]) -> dict[str, Any]:
    """Drop loader-only provenance sidecars from the closure's resolved config input."""
    return {key: value for key, value in config.items() if key != "__user_set__"}


def _run_era_identity_oracle(
    config: Mapping[str, Any],
    *,
    archive_root_candidates: Sequence[Path],
    cli_options: Mapping[str, Any],
    display_timezone: str,
    partition_zone: str,
    tldextract_version: str,
    effective_psl_snapshot: bytes,
    _planner_factory: Any = None,
) -> EraOracleReceipt:
    """Measure the complete private Era route and bind it to the closure identity.

    This wrapper deliberately delegates every source operation to the harness;
    it neither scans archive paths nor calls the reducer directly.  Its receipt
    is aggregate/provenance-only, so it stores a rendered-deck digest rather
    than the deck bytes that belong in a private detached-run artifact.
    """
    from sigwood.era.report import canonical_identity_payload, era_identity_cli_options

    harness = runner._run_era_harness(
        config,
        archive_root_candidates=archive_root_candidates,
        _planner_factory=_planner_factory,
    )
    if (
        harness.outcome != "MEASURED"
        or harness.frozen_input_identity is None
        or harness.rendered_cards is None
    ):
        return EraOracleReceipt(
            outcome=harness.outcome,
            archive_content_identity=harness.frozen_input_identity,
            record_counts=harness.record_counts,
            cards_present=harness.cards_present,
            missing_baseline_dates=harness.missing_baseline_dates,
            post_baseline_dates=harness.post_baseline_dates,
            warning_census=harness.warning_census,
            rendered_deck_sha256=None,
            rendered_deck_byte_length=None,
            closure_payload_sha256=None,
        )
    payload = canonical_identity_payload(
        archive_content_identity={"sha256": harness.frozen_input_identity},
        resolved_config=_era_closure_config(config),
        cli_options=era_identity_cli_options(cli_options),
        display_timezone=display_timezone,
        partition_zone=partition_zone,
        tldextract_version=tldextract_version,
        effective_psl_snapshot=effective_psl_snapshot,
    )
    deck = harness.rendered_cards.encode("utf-8")
    return EraOracleReceipt(
        outcome="MEASURED",
        archive_content_identity=harness.frozen_input_identity,
        record_counts=harness.record_counts,
        cards_present=harness.cards_present,
        missing_baseline_dates=harness.missing_baseline_dates,
        post_baseline_dates=harness.post_baseline_dates,
        warning_census=harness.warning_census,
        rendered_deck_sha256=hashlib.sha256(deck).hexdigest(),
        rendered_deck_byte_length=len(deck),
        closure_payload_sha256=hashlib.sha256(payload).hexdigest(),
    )


def _era_horizon_abstaining_cards(
    conn_eligible_weeks: int, dns_eligible_weeks: int
) -> tuple[int, ...]:
    """Return only cards whose frozen 12-week gate caused abstention.

    Card 9's conn-week floor and Card 10's DNS-week floor are deterministic
    span gates.  Other abstentions remain card-local: they can be caused by
    candidate refusals, record floors, classification, or PSL availability.
    """
    return tuple(
        card
        for card, eligible_weeks in ((9, conn_eligible_weeks), (10, dns_eligible_weeks))
        if eligible_weeks < 12
    )


def _run_era_harness(
    config: Mapping[str, Any],
    *,
    archive_root_candidates: Sequence[Path],
    skip_confirm: bool = True,
    _planner_factory: Any = None,
    _archive_plan: Any = None,
) -> EraHarnessReceipt:
    """Measure a registered archive through the registered loader only.

    This is intentionally runner-private: callers inject candidate roots, while
    the planner owns calendar semantics and this function alone owns loader
    windows and sink plans.  The aggregate receipt deliberately contains no
    root path or source filename.
    """
    home_net = runner.resolve_home_net(config)
    from sigwood.common import loader
    from sigwood.era.harness import EraFoldState, make_era_fold_sink
    from sigwood.era.observation import (
        Availability,
        Completeness,
        FamilyDayObservation,
        ParseUsability,
    )
    from sigwood.era.planner import ERA_FAMILIES, ArchivePlanner
    from sigwood.era.report import (
        EraReducer,
        FootprintFact,
        ReportInterval,
        SpanHonesty,
        activity_card,
        build_selection_evidence,
        busiest_minute_card,
        calendar_card,
        domain_arrival_card,
        eligible_week_count,
        footprint_card,
        largest_outbound_card,
        longest_connection_card,
        render_text_report,
        sustained_shift_card,
        transport_share_card,
        weekday_shape_card,
    )

    planner_factory = _planner_factory or ArchivePlanner
    candidates = ([] if _archive_plan is not None else [
        planner_factory(Path(root)).plan()
        for root in archive_root_candidates
    ])
    archive_plan = _archive_plan or next(
        (plan for plan in candidates if not plan.reconciliation.missing_dates), None
    )
    if archive_plan is None or archive_plan.span is None:
        reconciliation = candidates[0].reconciliation if candidates else None
        return EraHarnessReceipt(
            outcome="NOT_MEASURED",
            population_basis="raw_pre_allowlist",
            record_counts=(),
            consumed_span=None,
            missing_baseline_dates=(
                reconciliation.missing_dates if reconciliation is not None else ()
            ),
            post_baseline_dates=(
                reconciliation.post_baseline_dates if reconciliation is not None else ()
            ),
            cards_present=(),
            rendered_cards=None,
            missing_precondition="archive-root-unreachable",
        )

    interval = ReportInterval(*archive_plan.span)
    reducer = EraReducer.from_archive_plan(archive_plan, interval, home_net=home_net)
    inventory = dict(archive_plan.inventory)
    pre_prompted = False
    cfg_sigwood = config.get("sigwood", {})
    if not skip_confirm and runner._warn_above(cfg_sigwood) > 0:
        previews = {}
        for group in archive_plan.groups:
            families = {entry.family: entry for entry in inventory[group.canonical_date]}
            for family, pattern in ERA_FAMILIES:
                files = tuple(families[family].files)
                previews[f"{group.canonical_date}:{pattern}"] = loader.PatternPreview(
                    source="zeek_dir", discovered=files, selected=files,
                )
        estimates = loader.estimate_population(previews)
        pre_prompted = runner._confirm_large_dataset(
            sum(item.records for item in estimates.values()), cfg_sigwood,
            skip_confirm=False, estimate=tuple(estimates.values()),
        )
    prepared_snapshots: dict[tuple[date, str], Any] = {}
    frozen_identities: list[str] = []
    # Freeze every loader-selected file before the first reduction pass.  The
    # later loader call receives these exact snapshots and re-verifies each
    # item as it opens it, so a mutable archive fails closed rather than
    # silently mixing source versions into one receipt.
    for group in archive_plan.groups:
        families = {entry.family: entry for entry in inventory[group.canonical_date]}
        for family, pattern in ERA_FAMILIES:
            snapshot = loader.build_source_snapshot(
                families[family].files, "zeek_dir", scan_interval=group.interval
            )
            prepared_snapshots[(group.canonical_date, pattern)] = snapshot
            frozen_identities.append(snapshot.content_identity_sha256)
    frozen_input_identity = hashlib.sha256(
        "".join(frozen_identities).encode("ascii")
    ).hexdigest()
    counts: Counter[str] = Counter()
    warning_census: Counter[str] = Counter()
    earliest: datetime | None = None
    latest: datetime | None = None

    for group in archive_plan.groups:
        source_dirs = {"zeek_dir": list(group.directories)}
        for family, pattern in ERA_FAMILIES:
            sink = make_era_fold_sink(
                family,
                reducer_factory=lambda: EraReducer.from_archive_plan(
                    archive_plan, interval, home_net=home_net
                ),
            )
            load_result = loader.load_required_logs(
                {pattern: "zeek_dir"},
                source_dirs,
                *group.interval,
                show_progress=False,
                sink_plans={pattern: loader.SinkPlan((sink,), preserve_frame=False)},
                dual_windows={pattern: loader.DualWindow(group.interval)},
                prepared_snapshots={
                    pattern: prepared_snapshots[(group.canonical_date, pattern)]
                },
            )
            # Loader warnings can include selected-path labels.  The oracle
            # keeps a complete aggregate census by stable cause class only.
            for warning in load_result.warnings:
                warning_census[_era_warning_class(warning)] += 1
            # A selected archive family can be empty after the loader's
            # source-specific routing.  In that case the loader has no fold
            # channel to report, but the harness still needs the reducer's
            # identity element rather than treating a valid empty population
            # as a failed measurement.
            state: EraFoldState = load_result.fold_results[pattern].get(
                sink.channel, sink.seed_run()
            )
            if family == "conn":
                entry = next(
                    item for item in inventory[group.canonical_date] if item.family == "conn"
                )
                state.reducer.set_conn_day_observation(
                    group.canonical_date,
                    present=entry.state.value == "present",
                    usable=(entry.state.value == "present" and state.rows > 0),
                )
            elif family == "dns":
                entry = next(
                    item for item in inventory[group.canonical_date] if item.family == "dns"
                )
                state.reducer.set_dns_day_observation(
                    group.canonical_date,
                    present=entry.state.value == "present",
                    usable=(entry.state.value == "present" and state.rows > 0),
                )
            reducer = reducer.merge(state.reducer)
            counts[family] += state.rows
            if state.earliest is not None:
                earliest = state.earliest if earliest is None else min(earliest, state.earliest)
            if state.latest is not None:
                latest = state.latest if latest is None else max(latest, state.latest)

    if not pre_prompted:
        runner._confirm_large_dataset(sum(counts.values()), cfg_sigwood, skip_confirm=skip_confirm)
    observations = {
        family: FamilyDayObservation(
            Availability.PRESENT if counts[family] else Availability.ABSENT,
            ParseUsability.USABLE if counts[family] else ParseUsability.UNKNOWN,
            Completeness.UNKNOWN,
            counts[family],
        )
        for family, _pattern in ERA_FAMILIES
    }
    footprint = tuple(
        FootprintFact(
            family=entry.family,
            compressed_bytes=entry.compressed_bytes,
            files_summed=entry.successful_stat_files,
            files_present=len(entry.files),
            inventory_state=entry.state.value,
        )
        for _day, entries in archive_plan.inventory
        for entry in entries
    )
    # The footprint contract is totals-by-family across canonical date groups.
    footprint_totals: dict[str, list[Any]] = {}
    for fact in footprint:
        total = footprint_totals.setdefault(fact.family, [0, 0, 0, fact.inventory_state])
        total[0] += fact.compressed_bytes
        total[1] += fact.files_summed
        total[2] += fact.files_present
        if fact.inventory_state != "present":
            total[3] = fact.inventory_state
    footprint_card_facts = tuple(
        FootprintFact(family, values[0], values[1], values[2], values[3])
        for family, values in sorted(footprint_totals.items())
    )
    card_six = weekday_shape_card(reducer)
    card_eight, transport_evidence = transport_share_card(reducer)
    card_nine, temporal_evidence = sustained_shift_card(reducer)
    card_ten, domain_evidence = domain_arrival_card(reducer)
    conn_eligible_weeks = eligible_week_count(reducer, family="conn")
    dns_eligible_weeks = eligible_week_count(reducer, family="dns")
    span_honesty = SpanHonesty(
        conn_eligible_weeks=conn_eligible_weeks,
        dns_eligible_weeks=dns_eligible_weeks,
        horizon_abstaining_cards=_era_horizon_abstaining_cards(
            conn_eligible_weeks, dns_eligible_weeks
        ),
    )
    cards = tuple(
        card
        for card in (
            calendar_card(observations),
            activity_card(reducer),
            busiest_minute_card(reducer),
            longest_connection_card(reducer),
            largest_outbound_card(reducer),
            card_six,
            footprint_card(footprint_card_facts),
            card_eight,
            card_nine,
            card_ten,
        )
        if card is not None
    )
    reconciliation = archive_plan.reconciliation
    peak_minute, peak_neighborhood, duration_tails, duration_winner = (
        reducer.aggregate_review_evidence()
    )
    if peak_minute is None or not reconciliation.expected_dates:
        peak_relation = None
    elif peak_minute.date() in reconciliation.post_baseline_dates:
        peak_relation = "post-baseline-date"
    else:
        peak_relation = "baseline-date"
    duration_start = duration_winner[1] if duration_winner is not None else None
    duration_end = (
        duration_start + timedelta(seconds=duration_winner[0])
        if duration_winner is not None and duration_start is not None
        else None
    )
    family = "zeek"
    selection_evidence = build_selection_evidence(
        card_eight_speaking_weeks=transport_evidence.admissible_candidates,
        card_eight_subfloor_weeks=transport_evidence.refused_candidates,
        card_eight_tie=transport_evidence.tie,
        card_nine_admissible_candidates=temporal_evidence.admissible_candidates,
        card_nine_refused_candidates=temporal_evidence.refused_candidates,
        card_nine_tie=temporal_evidence.tie,
        card_ten_reason=domain_evidence.reason,
    )
    return EraHarnessReceipt(
        outcome="MEASURED",
        population_basis="raw_pre_allowlist",
        record_counts=tuple((family, counts[family]) for family, _ in ERA_FAMILIES),
        consumed_span=(earliest, latest) if earliest is not None and latest is not None else None,
        missing_baseline_dates=reconciliation.missing_dates,
        post_baseline_dates=reconciliation.post_baseline_dates,
        cards_present=tuple(int(card.title.split(".", 1)[0]) for card in cards),
        rendered_cards=render_text_report(cards, family=family, span_honesty=span_honesty),
        peak_minute=peak_minute,
        peak_minute_neighborhood=peak_neighborhood,
        peak_minute_date_relation=peak_relation,
        duration_tail_counts=duration_tails,
        longest_duration_start=duration_start,
        longest_duration_end=duration_end,
        temporal_daily_counts=reducer.temporal_daily_counts(),
        card_six_selection="none" if card_six is not None else None,
        card_nine_winner_score=temporal_evidence.winner_score,
        card_nine_runner_up_score=temporal_evidence.runner_up_score,
        card_nine_admissible_candidates=selection_evidence.card_nine_admissible_candidates,
        card_nine_refused_candidates=selection_evidence.card_nine_refused_candidates,
        card_nine_tie=selection_evidence.card_nine_tie,
        card_eight_winner_score=transport_evidence.winner_score,
        card_eight_runner_up_score=transport_evidence.runner_up_score,
        card_eight_speaking_weeks=selection_evidence.card_eight_speaking_weeks,
        card_eight_subfloor_weeks=selection_evidence.card_eight_subfloor_weeks,
        card_eight_tie=selection_evidence.card_eight_tie,
        card_ten_span_weeks=domain_evidence.span_weeks,
        card_ten_maturity=domain_evidence.maturity,
        card_ten_reason=selection_evidence.card_ten_reason,
        card_ten_ledger_cap=domain_evidence.ledger.cap,
        card_ten_ledger_cap_exceeded=domain_evidence.ledger.cap_exceeded,
        card_ten_psl_available=domain_evidence.ledger.psl_available,
        card_ten_exclusions=domain_evidence.ledger.excluded,
        footprint_facts=tuple(
            (fact.family, fact.compressed_bytes, fact.files_summed, fact.files_present, fact.inventory_state)
            for fact in footprint_card_facts
        ),
        warning_census=tuple(sorted(warning_census.items())),
        frozen_input_identity=frozen_input_identity,
        family=family,
        cards=cards,
        span_honesty=span_honesty,
        selection_evidence=selection_evidence,
    )


def _confirm_era_work(compressed_bytes: int, *, skip_confirm: bool) -> None:
    """Confirm the planner's compressed-byte estimate before Era loads data."""
    if compressed_bytes < runner._ERA_CONFIRM_COMPRESSED_BYTES or skip_confirm:
        return
    try:
        with cursor_visible():
            answer = input(
                f"{human_bytes(compressed_bytes)} compressed archive data found. "
                "The reference 122-day archive takes about an hour. Continue? [y/N] "
            )
    except (EOFError, KeyboardInterrupt):
        answer = ""
    if answer.strip().lower() not in ("y", "yes"):
        raise ExportAborted("sigwood: aborted by user")


def run_era(
    config: Mapping[str, Any],
    *,
    archive_root: Path,
    stream: Any | None = None,
    dry_run: bool = False,
    skip_confirm: bool = False,
    quiet: bool = False,
    verbose_level: int = 0,
) -> EraHarnessReceipt | None:
    """Run the public Era route without the hunt allowlist seam.

    The planner is the sole source of the whole-archive calendar and its
    inventory is reused by the fold.  No matcher is built and no loaded frame
    is suppressed: Era intentionally measures raw pre-allowlist traffic.
    """
    from sigwood.era.planner import ArchivePlanner
    from sigwood.era.report import compose_text_presentation

    if dry_run and stream is None:
        raise ValueError("era dry run needs an output stream")

    archive_plan = ArchivePlanner(archive_root).plan()
    calendar_days = len(archive_plan.groups)
    if archive_plan.span is None:
        raise ValueError(f"no usable dated archive at {archive_root}")
    estimate = archive_plan.work_estimate
    if calendar_days < runner._ERA_SHORT_CALENDAR_DAYS and not quiet:
        print(
            f"archive calendar spans {calendar_days} days; era's long-horizon cards "
            "need 12+ eligible weeks and may abstain; the deck states what it could measure",
            file=sys.stderr,
        )
    if dry_run:
        print("sigwood  ·  era  ·  dry run", file=stream)
        print(f"  calendar: {calendar_days} canonical days", file=stream)
        print(
            f"  work estimate: {human_bytes(estimate.compressed_bytes)} compressed, "
            f"{estimate.files:,} files",
            file=stream,
        )
        if calendar_days < runner._ERA_SHORT_CALENDAR_DAYS:
            print("  preflight: long-horizon cards may abstain on this short calendar", file=stream)
        print("  would run: cards 1-10 (raw pre-allowlist)", file=stream)
        return None
    runner._confirm_era_work(estimate.compressed_bytes, skip_confirm=skip_confirm)
    receipt = runner._run_era_harness(
        config,
        archive_root_candidates=[archive_root],
        skip_confirm=True,
        _archive_plan=archive_plan,
    )
    if receipt.outcome != "MEASURED" or receipt.rendered_cards is None:
        raise ValueError(receipt.missing_precondition or "measurement unavailable")
    if stream is not None:
        stream.write(compose_text_presentation(
            receipt.rendered_cards,
            receipt.selection_evidence if verbose_level else None,
        ))
    return receipt


def _run_era_resource_measurement(
    config: Mapping[str, Any],
    *,
    archive_root_candidates: Sequence[Path],
    _planner_factory: Any = None,
    _harness_receipt: EraHarnessReceipt | None = None,
) -> Any:
    """Measure the real Card 10 ledger route or return an explicit non-result.

    This private gate deliberately delegates all archive access to the same
    planner/loader/harness route as the card.  Its receipt retains no root,
    source name, query, or domain identity.
    """
    from sigwood.era.domains import DOMAIN_CAP
    from sigwood.era.measurement import (
        ERA_RSS_LIMIT_BYTES,
        EraMeasurementOutcome,
        EraResourceReceipt,
        normalized_maxrss_bytes,
        not_measured_receipt,
    )

    route_identity = "era-planner-loader-domain-ledger"
    code_hasher = hashlib.sha256()
    for module in (
        Path(__file__),
        Path(__file__).parents[1] / "era" / "domains.py",
        Path(__file__).parents[1] / "era" / "harness.py",
        Path(__file__).parents[1] / "era" / "report.py",
    ):
        code_hasher.update(module.read_bytes())
    code_identity = code_hasher.hexdigest()
    started = time.monotonic()
    try:
        receipt = _harness_receipt or runner._run_era_harness(
            config,
            archive_root_candidates=archive_root_candidates,
            _planner_factory=_planner_factory,
        )
    except Exception:
        return not_measured_receipt(
            route_identity=route_identity,
            archive_content_identity="unavailable",
            candidate_cap=DOMAIN_CAP,
            missing_precondition="measurement-harness-failed",
            code_identity=code_identity,
        )
    if receipt.outcome != "MEASURED" or receipt.frozen_input_identity is None:
        return not_measured_receipt(
            route_identity=route_identity,
            archive_content_identity="unavailable",
            candidate_cap=DOMAIN_CAP,
            missing_precondition="corpus-unreachable",
            code_identity=code_identity,
        )
    raw = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    normalized = normalized_maxrss_bytes(raw)
    return EraResourceReceipt(
        outcome=(
            EraMeasurementOutcome.PASS
            if normalized <= ERA_RSS_LIMIT_BYTES
            else EraMeasurementOutcome.COMPLETED_RSS_OVER_LIMIT
        ),
        route_identity=route_identity,
        archive_content_identity=receipt.frozen_input_identity,
        candidate_cap=DOMAIN_CAP,
        platform=sys.platform,
        raw_maxrss=raw,
        normalized_maxrss_bytes=normalized,
        rss_limit_bytes=ERA_RSS_LIMIT_BYTES,
        elapsed_seconds=time.monotonic() - started,
        code_identity=code_identity,
    )


def _run_era_oracle_measurement(
    config: Mapping[str, Any],
    *,
    archive_root_candidates: Sequence[Path],
    cli_options: Mapping[str, Any],
    display_timezone: str,
    partition_zone: str,
    tldextract_version: str,
    effective_psl_snapshot: bytes,
    _planner_factory: Any = None,
    _oracle_receipt: EraOracleReceipt | None = None,
) -> Any:
    """Measure the whole-product oracle route, never reusing the ledger receipt."""
    from sigwood.era.domains import DOMAIN_CAP
    from sigwood.era.measurement import (
        ERA_RSS_LIMIT_BYTES,
        EraMeasurementOutcome,
        EraResourceReceipt,
        normalized_maxrss_bytes,
        not_measured_receipt,
    )

    route_identity = "era-planner-loader-fold-render-oracle"
    code_hasher = hashlib.sha256()
    for module in (
        Path(__file__),
        Path(__file__).parents[1] / "era" / "harness.py",
        Path(__file__).parents[1] / "era" / "report.py",
        Path(__file__).parents[1] / "era" / "measurement.py",
    ):
        code_hasher.update(module.read_bytes())
    code_identity = code_hasher.hexdigest()
    started = time.monotonic()
    try:
        oracle = _oracle_receipt or _run_era_identity_oracle(
            config,
            archive_root_candidates=archive_root_candidates,
            cli_options=cli_options,
            display_timezone=display_timezone,
            partition_zone=partition_zone,
            tldextract_version=tldextract_version,
            effective_psl_snapshot=effective_psl_snapshot,
            _planner_factory=_planner_factory,
        )
    except Exception:
        return not_measured_receipt(
            route_identity=route_identity,
            archive_content_identity="unavailable",
            candidate_cap=DOMAIN_CAP,
            missing_precondition="measurement-harness-failed",
            code_identity=code_identity,
        )
    if oracle.outcome != "MEASURED" or oracle.archive_content_identity is None:
        return not_measured_receipt(
            route_identity=route_identity,
            archive_content_identity="unavailable",
            candidate_cap=DOMAIN_CAP,
            missing_precondition="corpus-unreachable",
            code_identity=code_identity,
        )
    raw = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    normalized = normalized_maxrss_bytes(raw)
    return EraResourceReceipt(
        outcome=(
            EraMeasurementOutcome.PASS
            if normalized <= ERA_RSS_LIMIT_BYTES
            else EraMeasurementOutcome.COMPLETED_RSS_OVER_LIMIT
        ),
        route_identity=route_identity,
        archive_content_identity=oracle.archive_content_identity,
        candidate_cap=DOMAIN_CAP,
        platform=sys.platform,
        raw_maxrss=raw,
        normalized_maxrss_bytes=normalized,
        rss_limit_bytes=ERA_RSS_LIMIT_BYTES,
        elapsed_seconds=time.monotonic() - started,
        code_identity=code_identity,
    )


import sigwood.runner as runner
