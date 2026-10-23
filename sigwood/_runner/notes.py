"""Compose runner disclosures from loader, plan and detector facts."""
from __future__ import annotations

import math
from dataclasses import dataclass, replace
from datetime import timedelta
from pathlib import Path
from typing import Any, Mapping, Sequence

import pandas as pd

from sigwood.common.config import DEFAULT_DETECT_SPEC, get_detector_config
from sigwood.common.display import (
    fmt_window, fmt_compact_span, plural, human_bytes, _suppression_pct,
    compact_path_list as _compact_path_list,
)
from sigwood.common.loader import (
    DiscoveryFact, DiscoveryFactKind, RootFact, RootFactKind, DirectorySkipInfo,
    JournalCaptureOutcome, CoverageLane,
)
from sigwood.common.sources import (
    SyslogIntent, SyslogProviderDecision, SyslogProvider, SyslogDecisionReason,
    declared_source_patterns as _declared_source_patterns,
)
from sigwood.common.sanitize import strip_control


NOTE_KINDS = (
    "coverage", "eligibility", "provider", "window", "nudge", "opt-in", "home-net",
    "allowlist", "preparation", "rotation", "permission", "directory", "overlap",
    "arbitration", "summary",
)


@dataclass(frozen=True)
class Note:
    """One disclosure's family, exact operator text and primary fact owner."""

    kind: str
    text: str
    provenance: str

    def __post_init__(self) -> None:
        if self.kind not in NOTE_KINDS:
            raise ValueError(f"unknown note kind: {self.kind!r}")


def flatten_notes(notes: Sequence[Note]) -> list[str]:
    """Return only the operator text, preserving order and duplicates."""
    return [note.text for note in notes]


def _emit_syslog_decision_warnings(decision: SyslogProviderDecision) -> None:
    """Emit completeness warnings without applying the quiet status gate."""
    if (
        decision.reason is SyslogDecisionReason.AUTO_FAILURE
        and decision.diagnostic
    ):
        runner._estderr(f"system journal: {decision.diagnostic}")
    for warning in decision.warnings:
        runner._estderr(warning)


def _derive_data_sources(
    needed_logs: dict[str, str],
    record_counts: dict[str, int],
) -> list[str]:
    """Return sorted data_source labels for patterns that produced non-empty data."""
    from sigwood.common.loader import _log_type

    labels: set[str] = set()
    for pattern, count in record_counts.items():
        if count <= 0:
            continue
        source = needed_logs.get(pattern)
        if source is None:
            continue
        if source == "zeek_dir":
            lt = _log_type(pattern)
            if lt is not None:
                labels.add(f"zeek_{lt}")
        elif source == "syslog_dir":
            labels.add("syslog_raw")
        elif source == "pihole_dir":
            labels.add("dnsmasq_dns")
        elif source == "cloudtrail_dir":
            labels.add("cloudtrail_raw")
        elif source == "journal":
            labels.add("syslog_journal")
    return sorted(labels)


def _pattern_human_label(source_key: str, pattern: str) -> str:
    """Operator-language label for one (source_key, pattern) tuple.

    USED BY: source-coverage, directory-skip, and file-permission disclosure
    notes (``_zero_window_coverage_notes`` / ``_directory_skip_notes`` /
    ``_permission_skip_notes``).
    DISTINCT FROM: ``_derive_data_sources``, which emits internal
    ``data_sources`` tokens (``"zeek_dns"`` / ``"dnsmasq_dns"`` / ``"syslog_raw"``
    / ``"cloudtrail_raw"``) consumed by the Zeek-evangelization nudge matcher and
    other internal channels - those token strings stay byte-identical there.

    Labels: ``Pi-hole`` / ``syslog`` / ``CloudTrail`` / ``Zeek <log_type>``.
    """
    from sigwood.common.loader import _log_type

    if source_key == "pihole_dir":
        return "Pi-hole"
    if source_key == "syslog_dir":
        return "syslog"
    if source_key == "cloudtrail_dir":
        return "CloudTrail"
    if source_key == "journal":
        return "system journal"
    if source_key == "zeek_dir":
        lt = _log_type(pattern)
        return f"Zeek {lt}" if lt is not None else "Zeek"
    return source_key


def _zero_window_coverage_notes(
    load_result: "loader.LoadResult",
    plan: runner.RunPlan,
    *,
    load_all: bool = False,
) -> list[Note]:
    """Return disclosure notes for planned sources that contributed 0 in-window rows.

    Honesty rail - coverage counts VALID-ts rows only:
      - ``full_rows > 0`` → SPAN note (count + span + widen suggestion), or
        count-only when no valid span survived (degenerate; defensive).
      - ``full_rows is None`` and ``source_key == "zeek_dir"`` → BARE note
        ("files found, 0 records …"). The BARE arm is **zeek_dir-only**: for
        syslog/pihole/cloudtrail, "no files read" means a wrong-family skip
        or an empty directory - neither is a window gap the operator can fix
        with ``--since/--days``, and the existing per-source warnings already
        cover it.
      - ``full_rows == 0`` → NO note (parse gap; widen advice would mislead).
      - Pattern not loaded at all (source unconfigured) → NO note (the
        loader already warns ``"{source} not configured - {pattern} not loaded"``).
    """
    out: list[str] = []
    widen = "" if load_all else " - widen with --since/--days, or --all"
    for pattern, source_key in plan.needed_logs.items():
        if load_result.record_counts.get(pattern, 0) != 0:
            continue
        if pattern not in load_result.logs:
            # Source unconfigured for this pattern - loader already warned.
            continue
        cov = load_result.coverage.get(pattern)
        # Parse gap → silent (would otherwise tell the operator to widen
        # the window on a file with no valid timestamps - misleading).
        if cov is not None and cov.full_rows == 0:
            continue
        label = _pattern_human_label(source_key, pattern)
        if cov is None or cov.full_rows is None:
            if source_key != "zeek_dir":
                continue
            out.append(
                f"{label}: files found, 0 records in the selected window{widen}"
            )
            continue
        if cov.full_span is not None:
            start, end = cov.full_span
            out.append(
                f"{label}: {cov.full_rows:,} {plural(cov.full_rows, 'row')} "
                f"loaded, 0 in the selected window; data spans "
                f"{fmt_window((start, end))}{widen}"
            )
        else:
            out.append(
                f"{label}: {cov.full_rows:,} {plural(cov.full_rows, 'row')} "
                f"loaded, 0 in the selected window{widen}"
            )
    return [Note('coverage', line, 'loader') for line in out]


def _permission_skip_notes(
    load_result: "loader.LoadResult",
    plan: runner.RunPlan,
) -> list[Note]:
    """Return report notes for permission-denied files in a partial run."""
    out: list[str] = []
    for pattern, source_key in plan.needed_logs.items():
        info = load_result.permission_skips.get(pattern)
        if info is None or info.denied <= 0:
            continue
        label = _pattern_human_label(source_key, pattern)
        paths = _compact_path_list(info.paths)
        if info.denied == info.discovered:
            n = info.discovered
            out.append(
                f"{label}: all {n} discovered {plural(n, 'file')} "
                "permission denied - no rows loaded from this source "
                f"({paths})"
            )
        else:
            out.append(
                f"{label}: {info.denied} of {info.discovered} discovered "
                f"{plural(info.discovered, 'file')} permission denied - "
                f"those rows are missing from this run ({paths})"
            )
    return [Note('permission', line, 'loader') for line in out]


def _directory_skip_notes(plan: runner.RunPlan) -> list[Note]:
    """Return one bounded report note per unlistable source family."""
    return [Note('directory', line, 'plan') for line in _render_directory_skips(plan.directory_skips)]


def _render_directory_skips(
    records: Mapping[tuple[str, Path], DirectorySkipInfo],
) -> list[str]:
    """One bounded note per source family over the given denial records."""
    grouped: dict[str, list[Path]] = {}
    for info in records.values():
        grouped.setdefault(info.source_key, []).append(info.path)

    out: list[str] = []
    for source_key, paths in grouped.items():
        label = _pattern_human_label(source_key, "")
        rendered = _compact_path_list(paths)
        if len(paths) == 1:
            out.append(
                f"{label}: directory could not be listed "
                "(permission denied) - its contents are absent from this run "
                f"({rendered})"
            )
        else:
            out.append(
                f"{label}: {len(paths)} directories could not be listed "
                "(permission denied) - their contents are absent from this run "
                f"({rendered})"
            )
    return out


def _qualify_unsearched(
    fact: DiscoveryFact, selected_reals: Sequence[Path],
) -> DiscoveryFact:
    """Count the listed children that are, or contain, another input of the run.

    Neither count claims the child was searched: another input starting at or
    below a child says nothing about the rest of that child's subtree.
    """
    own_real = runner._safe_real(fact.root)
    others = [real for real in selected_reals if real != own_real]
    also_selected = 0
    contains_selected = 0
    for child in fact.paths:
        real = runner._safe_real(child)
        if real in others:
            also_selected += 1
        elif any(real in other.parents for other in others):
            contains_selected += 1
    return replace(
        fact, also_selected=also_selected, contains_selected=contains_selected,
    )


def _merge_facts(facts: Sequence[DiscoveryFact]) -> list[DiscoveryFact]:
    """Merge same-kind facts about one root and cause into one, keeping order."""
    merged: dict[tuple[Any, ...], DiscoveryFact] = {}
    for fact in facts:
        if fact.kind in (
            DiscoveryFactKind.UNSEARCHED_CHILDREN,
            DiscoveryFactKind.EMPTY_DIRECTORY,
            DiscoveryFactKind.UNSUPPORTED_FILES,
            DiscoveryFactKind.MISSING_INPUT,
        ):
            key: tuple[Any, ...] = (fact.kind, fact.source_key, fact.root, id(fact))
        else:
            key = (fact.kind, fact.source_key, fact.root, fact.detail)
        prior = merged.get(key)
        if prior is None:
            merged[key] = fact
            continue
        paths = tuple(dict.fromkeys((*prior.paths, *fact.paths)))
        merged[key] = replace(prior, paths=paths, count=len(paths))
    return list(merged.values())


def _render_coverage_fact(fact: DiscoveryFact) -> str:
    """One bounded, control-safe coverage line for one fact."""
    label = _pattern_human_label(fact.source_key, "")
    root = _compact_path_list([fact.root])
    n = fact.count
    kind = fact.kind
    cause = f" ({strip_control(fact.detail)})" if fact.detail else ""
    if kind is DiscoveryFactKind.EMPTY_DIRECTORY:
        return f"{label}: {root} is empty - nothing to read there"
    if kind is DiscoveryFactKind.UNSUPPORTED_FILES:
        return (
            f"{label}: {root} holds {n:,} {plural(n, 'file')}, none recognized "
            f"as {label} logs"
        )
    if kind is DiscoveryFactKind.MISSING_INPUT:
        return f"{label}: {root} was not found - its contents are absent from this run"
    if kind is DiscoveryFactKind.UNSEARCHED_CHILDREN:
        names = _compact_path_list([Path(child.name) for child in fact.paths])
        qualifiers = []
        if fact.also_selected:
            verb = "is" if fact.also_selected == 1 else "are"
            qualifiers.append(f"{fact.also_selected} {verb} also an input of this run")
        if fact.contains_selected:
            verb = "contains" if fact.contains_selected == 1 else "contain"
            qualifiers.append(f"{fact.contains_selected} {verb} another input")
        qualifier = "; " + ", ".join(qualifiers) if qualifiers else ""
        return (
            f"{label}: {root} has {n:,} {plural(n, 'subdirectory', 'subdirectories')} "
            f"this run did not search ({names}{qualifier}) - pass a subdirectory or "
            "its files directly to include them"
        )
    rel = _compact_path_list([runner._relative_to(p, fact.root) for p in fact.paths])
    if kind is DiscoveryFactKind.LISTING_ERROR:
        if fact.paths == (fact.root,):
            return (
                f"{label}: {root} could not be read{cause} - its contents are "
                "absent from this run"
            )
        return (
            f"{label}: {n:,} {plural(n, 'subdirectory', 'subdirectories')} under "
            f"{root} could not be read{cause} - their contents are absent from "
            f"this run ({rel})"
        )
    if kind is DiscoveryFactKind.ENTRY_ERROR:
        return (
            f"{label}: {n:,} {plural(n, 'entry', 'entries')} under {root} could not "
            f"be inspected{cause} - not read ({rel})"
        )
    if kind is DiscoveryFactKind.NONREGULAR_MATCH:
        verb = "is" if n == 1 else "are"
        return (
            f"{label}: skipped {n:,} {plural(n, 'entry', 'entries')} under {root} "
            f"that {verb} not a regular file ({rel})"
        )
    if kind is DiscoveryFactKind.BROKEN_LINK:
        return (
            f"{label}: skipped {n:,} broken {plural(n, 'link')} under {root} ({rel})"
        )
    if kind is DiscoveryFactKind.LINKED_DIRECTORY_OMITTED:
        return (
            f"{label}: did not follow {n:,} linked "
            f"{plural(n, 'subdirectory', 'subdirectories')} under {root} ({rel}) - "
            "pass a linked directory directly to include it"
        )
    if kind is DiscoveryFactKind.ZEEK_DEEPER_THAN_LAYOUT:
        verb = "sits" if n == 1 else "sit"
        return (
            f"{label}: {n:,} {plural(n, 'file')} under dated directory {root} "
            f"{verb} deeper than its dated layout reads - not read as {label} "
            f"({rel})"
        )
    if kind is DiscoveryFactKind.ZEEK_ROOT_FILES_EXCLUDED:
        verb = "is" if n == 1 else "are"
        return (
            f"{label}: {n:,} {plural(n, 'file')} at the top of dated directory "
            f"{root} {verb} not read - a dated layout reads only its "
            f"subdirectories ({rel})"
        )
    return f"{label}: {root} has an unrecognized coverage fact"


def _discovery_coverage_lines(
    discovery: Any,
    plan: runner.RunPlan,
    source_map: Mapping[str, Sequence[Path]],
    *,
    default_span: timedelta | None = None,
    dry_run: bool = False,
    recursive_retry: str | None = None,
) -> list[Note]:
    """The run's directory coverage lines, one per fact, in input order.

    Covers every input of every source a selected detector declares, which is
    exactly what planning observed; a family no selected detector reads is
    never reported. Nothing here lists a directory or reads a file beyond what
    the inventory already observed.

    A recursive run first states what each positional walk could not read or
    use, owned by the root the operator supplied, and after the family facts
    names any flat logical root that sends a family to the full-read policy
    (``default_span`` set only when the default window governs) and any file
    two in-plan families both hold as a candidate.

    ``recursive_retry`` is the CLI's checked retry command. It is offered once,
    after every notice, when at least one kept notice says an input the
    invocation supplied has subdirectories this run did not search; a
    configured input's notice never offers it.
    """
    inventory = discovery.inventory
    lines: list[str] = []
    retry_applies = False
    if discovery.recursive:
        lines.extend(_root_fact_lines(inventory.root_facts(), plan, dry_run=dry_run))
    declared = _declared_source_patterns(plan.selected, plan.detectors)
    selected_reals = [
        runner._safe_real(path)
        for source in declared
        if inventory.supports(source)
        for path in source_map.get(source, [])
    ]
    facts: list[DiscoveryFact] = []
    for source, patterns in declared.items():
        if not inventory.supports(source):
            continue
        inputs = list(source_map.get(source, []))
        loaded = next(
            (p for p, s in plan.needed_logs.items() if s == source), None,
        ) if plan.will_run else None
        for path in inputs:
            invocation = discovery.provenance(source, path) != "configured"
            for fact in inventory.input_facts(
                source, path, patterns, invocation=invocation,
            ):
                kind = fact.kind
                if kind is DiscoveryFactKind.MISSING_INPUT and len(inputs) == 1 and any(
                    reason == runner._not_found_reason(source, path)
                    for reason in plan.skipped.values()
                ):
                    continue  # the single-input skip reason states it
                if (
                    kind is DiscoveryFactKind.UNSUPPORTED_FILES
                    and loaded is not None
                    and inventory.silent_miss_states(source, path, loaded, inputs)
                ):
                    continue  # the loader's silent-miss warning states it
                if kind is DiscoveryFactKind.UNSEARCHED_CHILDREN:
                    fact = _qualify_unsearched(fact, selected_reals)
                    retry_applies = retry_applies or invocation
                facts.append(fact)
    lines.extend(_render_coverage_fact(fact) for fact in _merge_facts(facts))
    if discovery.recursive:
        lines.extend(_layout_policy_lines(inventory, plan, source_map, default_span))
        lines.extend(_shared_candidate_lines(inventory, plan, source_map))
    if recursive_retry is not None and retry_applies:
        lines.append(
            "discovery: to search those subdirectories as well, rerun with "
            f"--recursive: {recursive_retry}"
        )
    return [Note('coverage', line, 'inventory') for line in lines]


def _root_fact_lines(
    facts: Sequence[RootFact], plan: runner.RunPlan, *, dry_run: bool,
) -> list[str]:
    """Render positional-root facts, minus what a canonical owner states here.

    A listing denial that a declared family also met is that family's
    ``DirectorySkipInfo``, which every route renders: the report note on a
    successful run, stderr on a dry or all-skipped run. A file a family's gate
    kept despite a failed read is the load's to disclose, but only on a route
    that loads that family.
    """
    denied = {key[1] for key in plan.directory_skips}
    loads = set(plan.needed_logs.values()) if plan.will_run and not dry_run else set()
    out: list[str] = []
    for fact in facts:
        if fact.kind is RootFactKind.ROOT_UNLISTABLE and runner._safe_real(fact.root) in denied:
            continue
        if fact.kind is RootFactKind.SUBDIRS_UNLISTABLE and fact.permission_denied:
            kept = tuple(p for p in fact.paths if runner._safe_real(p) not in denied)
            if not kept:
                continue
            fact = replace(fact, paths=kept, count=len(kept))
        if fact.kind is RootFactKind.UNREADABLE_FILES and fact.family in loads:
            continue
        out.append(_render_root_fact(fact, dry_run=dry_run))
    return out


def _unselected_retained_lines(
    discovery: Any, plan: runner.RunPlan, load_result: "loader.LoadResult",
) -> list[Note]:
    """Kept-but-unreadable files the load never selected, stated after it.

    A file a family's gate kept despite a failed read belongs to the load once
    the load selects it: it then states the denial or the corruption on its own
    route. A file the run's time window left unselected has no such owner, so
    the failure discovery observed is stated here, with that disposition and no
    claim about rows in the selected window.
    """
    loads = set(plan.needed_logs.values()) if plan.will_run else set()
    selected = {
        runner._safe_real(fact.path)
        for pattern in plan.needed_logs
        for fact in load_result.availability.get(pattern, ())
    }
    out: list[str] = []
    for fact in discovery.inventory.root_facts():
        if fact.kind is not RootFactKind.UNREADABLE_FILES or fact.family not in loads:
            continue
        kept = tuple(path for path in fact.paths if runner._safe_real(path) not in selected)
        if kept:
            out.append(_render_root_fact(
                replace(fact, paths=kept, count=len(kept)), dry_run=False, unselected=True,
            ))
    return [Note('coverage', line, 'inventory') for line in out]


def _layout_policy_lines(
    inventory: Any,
    plan: runner.RunPlan,
    source_map: Mapping[str, Sequence[Path]],
    default_span: timedelta | None,
) -> list[str]:
    """Name the flat logical roots that send a family to the full-read policy.

    Read from the same contribution result the window and every load pass use,
    over the final plan's patterns, so a duplicate flat root or a pattern no
    detector loads cannot claim the policy.
    """
    if default_span is None:
        return []
    out: list[str] = []
    span = fmt_compact_span(default_span)
    for source in dict.fromkeys(plan.needed_logs.values()):
        patterns = [p for p, s in plan.needed_logs.items() if s == source]
        contribution = inventory.layout_contribution(
            source, list(source_map.get(source, [])), patterns,
        )
        if not (contribution.dated and contribution.flat):
            continue
        label = _pattern_human_label(source, "")
        n = len(contribution.flat)
        noun = "flat directory sits" if n == 1 else "flat directories sit"
        out.append(
            f"{label}: {n:,} {noun} beside dated directories "
            f"({_compact_path_list(list(contribution.flat))}) - all {label} logs "
            f"load in full and only the newest {span} is kept after loading"
        )
    return out


def _shared_candidate_lines(
    inventory: Any,
    plan: runner.RunPlan,
    source_map: Mapping[str, Sequence[Path]],
) -> list[str]:
    """Files that two in-plan families both hold as candidates.

    Membership is window-blind, so the line says candidates: a window may still
    keep either family from reading a shared file.
    """
    out: list[str] = []
    for first, second, paths in inventory.shared_candidates(plan.needed_logs, source_map):
        n = len(paths)
        noun = "file is a candidate" if n == 1 else "files are candidates"
        out.append(
            f"shared files: {n:,} {noun} for both "
            f"{_pattern_human_label(first, '')} and {_pattern_human_label(second, '')} "
            f"({_compact_path_list(list(paths))})"
        )
    return out


def _render_root_fact(
    fact: RootFact, *, dry_run: bool, unselected: bool = False,
) -> str:
    """One bounded, control-safe line for one positional-root fact."""
    root = _compact_path_list([fact.root])
    n = fact.count
    rel = _compact_path_list([runner._relative_to(p, fact.root) for p in fact.paths])
    cause = "permission denied" if fact.permission_denied else strip_control(fact.cause or "")
    one = n == 1
    kind = fact.kind
    if kind is RootFactKind.ROOT_UNLISTABLE:
        return (
            f"discovery: {root} could not be listed ({cause}) - nothing beneath "
            "it was searched"
        )
    if kind is RootFactKind.SUBDIRS_UNLISTABLE:
        noun = plural(n, "subdirectory", "subdirectories")
        whose = "its contents are" if one else "their contents are"
        return (
            f"discovery: {n:,} {noun} under {root} could not be listed ({cause}) - "
            f"{whose} absent from this run ({rel})"
        )
    if kind is RootFactKind.ENTRY_ERROR:
        return (
            f"discovery: {n:,} {plural(n, 'entry', 'entries')} under {root} could "
            f"not be inspected ({cause}) - not read ({rel})"
        )
    if kind is RootFactKind.UNREADABLE_FILES:
        head = (
            f"discovery: {n:,} {plural(n, 'file')} under {root} could not be "
            f"read ({cause})"
        )
        if fact.family is None:
            tail = (
                "its log type is unknown, so it was not loaded" if one
                else "their log type is unknown, so they were not loaded"
            )
            return f"{head} - {tail} ({rel})"
        label = _pattern_human_label(fact.family, "")
        kept = f"kept as {'a possible' if one else 'possible'} {label} {plural(n, 'file')}"
        if dry_run:
            return f"{head} - {kept} for a full run to try ({rel})"
        if unselected:
            it = "it" if one else "them"
            return f"{head} - {kept}, but this run's time window did not select {it} ({rel})"
        return f"{head} - {kept}, but no detector that reads them ran ({rel})"
    if kind is RootFactKind.LINKED_DIRECTORY_OMITTED:
        return (
            f"discovery: did not follow {n:,} linked "
            f"{plural(n, 'subdirectory', 'subdirectories')} under {root} ({rel}) - "
            "pass a linked directory directly to include it"
        )
    if kind is RootFactKind.BROKEN_LINK:
        return f"discovery: skipped {n:,} broken {plural(n, 'link')} under {root} ({rel})"
    if kind is RootFactKind.NONREGULAR_MATCH:
        verb = "is" if one else "are"
        return (
            f"discovery: skipped {n:,} {plural(n, 'entry', 'entries')} under {root} "
            f"that {verb} not a regular file ({rel})"
        )
    if kind is RootFactKind.UNRECOGNIZED_FILES:
        verb = "is" if one else "are"
        return (
            f"discovery: {n:,} {plural(n, 'file')} under {root} {verb} not "
            f"recognized as any log this run reads ({rel})"
        )
    if kind is RootFactKind.REJECTED_FILES:
        label = _pattern_human_label(fact.family or "", "")
        patterns = strip_control(", ".join(fact.patterns))
        looks = "looks" if one else "look"
        names = "its name does" if one else "their names do"
        return (
            f"discovery: {n:,} {plural(n, 'file')} under {root} {looks} like "
            f"{label} logs, but {names} not match {patterns} ({rel})"
        )
    if kind is RootFactKind.LINKED_LAYOUT_NOT_READ:
        label = _pattern_human_label(fact.family or "", "")
        verb = f"is not a {label} log" if one else f"are not {label} logs"
        was = "was" if one else "were"
        return (
            f"discovery: {n:,} {plural(n, 'file')} in linked {label} subdirectories "
            f"under {root} {verb} this run reads and {was} not read ({rel}) - pass "
            "the linked directory directly to include it"
        )
    if kind is RootFactKind.NO_FILES:
        if fact.incomplete:
            return (
                f"discovery: no files were found under {root} in the parts that "
                "could be searched - nothing to read there"
            )
        return f"discovery: {root} holds no files - nothing to read there"
    if kind is RootFactKind.NOTHING_READ:
        parts = [
            f"{count:,} {runner._OUTCOME_PHRASES[outcome][0 if count == 1 else 1]}"
            for outcome, count in fact.parts
        ]
        joined = (
            parts[0] if len(parts) == 1
            else ", ".join(parts[:-1]) + " and " + parts[-1]
        )
        where = " in the parts that could be searched" if fact.incomplete else ""
        return (
            f"discovery: nothing under {root} is read by this run - it holds "
            f"{joined}{where}"
        )
    return f"discovery: {root} has an unrecognized coverage fact"


def _denial_owned_keys(
    plan: runner.RunPlan, source_map: Mapping[str, Sequence[Path]],
) -> set[tuple[str, Path]]:
    """Denial records a detector skip reason already states, by sink key.

    ``_directory_denial_reason`` names the denied configured inputs of one
    source; when that exact reason is a skip reason, those records are owned.
    """
    owned: set[tuple[str, Path]] = set()
    for source, paths in source_map.items():
        reason = runner._directory_denial_reason(source, list(paths), plan.directory_skips)
        if reason is None or reason not in plan.skipped.values():
            continue
        configured: set[Path] = set()
        for path in paths:
            try:
                configured.add(path.resolve())
            except OSError:
                configured.add(path)
        owned.update(
            key for key in plan.directory_skips
            if key[0] == source and key[1] in configured
        )
    return owned


def _unowned_directory_skip_lines(
    plan: runner.RunPlan, source_map: Mapping[str, Sequence[Path]],
) -> list[Note]:
    """Directory-denial notes for a run that renders no report.

    On a successful run the report carries ``_directory_skip_notes``. When no
    detector can run, or on a dry run, there is no report, so the same notes go
    to stderr, minus the denials a skip reason already names.
    """
    owned = _denial_owned_keys(plan, source_map)
    remaining = {
        key: info for key, info in plan.directory_skips.items() if key not in owned
    }
    return [Note('directory', line, 'plan') for line in _render_directory_skips(remaining)]


def _rotation_fallback_line(label: str, info: "loader.RotationSkipInfo") -> str:
    """The one fallback-disclosure string, shared by the report note
    (``_rotation_skip_notes``) and the post-load stderr signal
    (``_rotation_fallback_lines``) - so the two surfaces are byte-identical.

    The two CONTENT-overlap reasons additionally warn of double-counting:
    rotation dedup is by path, not content, so a full read may count
    overlapping / duplicate rows twice (inflating syslog rarity/burst + digest
    stats). Gross disorder ("rotation order not monotonic") reorders without
    duplicating, so it does NOT get the clause.
    """
    if info.fallback_reason == "overlapping export windows":
        return (
            f"{label}: overlapping export windows - read the full archive "
            "(windowing skipped; overlapping rows may be counted twice)"
        )
    if info.fallback_reason == "duplicate rotation files":
        return (
            f"{label}: duplicate rotation files - read the full archive "
            "(windowing skipped; duplicate rows may be counted twice)"
        )
    return (  # "rotation order not monotonic" or None → existing wording
        f"{label}: rotation order not monotonic - read the full archive "
        "(windowing skipped)"
    )


def _rotation_skip_notes(
    load_result: "loader.LoadResult",
    plan: runner.RunPlan,
) -> list[Note]:
    """Return disclosure notes (the REPORT surface) for flat patterns windowed by
    rotation-peek.

    The loader records a ``RotationSkipInfo`` per windowed pattern; the runner
    formats the prose (the loader never imports the runner). Reuses
    ``_pattern_human_label`` for the operator-language source name.

    - ``fallback`` → the shared ``_rotation_fallback_line`` (also fed to the
      post-load stderr signal, so report and stderr cannot drift). Fallback WINS:
      it is data-true at the pattern level (``skipped == 0``), so the skip-summary
      cannot also fire.
    - else ``skipped > 0`` → "loaded L of L+S rotation files; S skipped outside
      the selected window (by rotation order)." NEUTRAL "outside" is truthful
      for both the ``--since`` older-tail skip and the ``--until`` too-new
      leading skip (a bounded run can skip both under one count).
    - else → no note.
    """
    out: list[str] = []
    for pattern, info in load_result.rotation_skips.items():
        label = _pattern_human_label(plan.needed_logs[pattern], pattern)
        if info.fallback:
            out.append(_rotation_fallback_line(label, info))
        elif info.skipped > 0:
            out.append(
                f"{label}: loaded {info.loaded} of {info.loaded + info.skipped} "
                f"rotation files; {info.skipped} skipped outside the selected "
                "window (by rotation order)"
            )
    return [Note('rotation', line, 'loader') for line in out]


def _rotation_fallback_lines(
    load_result: "loader.LoadResult",
    plan: runner.RunPlan,
) -> list[str]:
    """Just the FALLBACK lines (every ``info.fallback`` reason), for the post-load
    stderr "why did this read the whole archive" signal. Shares
    ``_rotation_fallback_line`` with the report note. The normal prune stays
    report-only - its per-file counts are too verbose for the live stream.
    """
    out: list[str] = []
    for pattern, info in load_result.rotation_skips.items():
        if info.fallback:
            label = _pattern_human_label(plan.needed_logs[pattern], pattern)
            out.append(_rotation_fallback_line(label, info))
    return out


def _bounded_warning_rider(warnings: Sequence[str]) -> str | None:
    """Render one producer warning plus a bounded omitted-warning count."""
    if not warnings:
        return None
    first = strip_control(warnings[0])[:512]
    if len(warnings) > 1:
        first += f" (+{len(warnings) - 1} more)"
    return first


def _syslog_provider_note(
    decision: SyslogProviderDecision,
    intent: SyslogIntent,
    plan: runner.RunPlan,
) -> Note | None:
    """Return the one bounded system-log provider disclosure for the report."""
    if not intent.report_local_lane:
        return None
    paths = _compact_path_list(intent.flat_paths)
    fallback = f"{paths} fallback not loaded" if paths else "no file fallback configured"
    warning = _bounded_warning_rider(decision.warnings)

    if decision.provider is SyslogProvider.OFF:
        return Note('provider', "system logs: off", 'syslog-provider')
    if decision.provider is SyslogProvider.JOURNAL:
        if decision.reason is SyslogDecisionReason.AUTO_JOURNAL:
            if decision.legacy_migrated:
                detail = (
                    "auto from legacy config; set syslog_source=\"files\" to keep "
                    f"file-only behavior; {fallback}"
                )
            else:
                detail = f"auto; {fallback}"
        elif decision.reason is SyslogDecisionReason.EXPLICIT_JOURNAL:
            detail = f"explicit; {fallback}"
        else:
            detail = f"configured; {fallback}"
        if decision.capture_outcome is JournalCaptureOutcome.CLEAN_EMPTY:
            detail += "; journal had no entries in the selected window"
        elif decision.capture_outcome is JournalCaptureOutcome.NO_USABLE:
            detail += "; journal had no usable entries in the selected window"
        if warning:
            detail += f"; {warning}"
        return Note('provider', f"system logs: journal ({detail})", 'syslog-provider')

    base = f"system logs: files {paths}" if paths else "system logs: files"
    if decision.reason in (
        SyslogDecisionReason.EXPLICIT_PATH_FILES,
        SyslogDecisionReason.EXPLICIT_FILES,
    ):
        detail = "explicit"
    elif decision.reason is SyslogDecisionReason.CONFIGURED_FILES:
        detail = "configured"
    elif decision.reason is SyslogDecisionReason.AUTO_MISSING:
        detail = "auto; journal unavailable"
    elif decision.reason is SyslogDecisionReason.AUTO_CLEAN_EMPTY:
        detail = "auto; journal had no entries in the selected window"
    elif decision.reason is SyslogDecisionReason.AUTO_NO_USABLE:
        detail = "auto; journal had no usable entries in the selected window"
    else:
        detail = "auto; journal unavailable"
        if decision.diagnostic:
            detail += f" - {strip_control(decision.diagnostic)[:512]}"
    if "syslog_dir" not in plan.needed_logs.values():
        detail += "; no eligible syslog files found"
    if warning:
        detail += f"; {warning}"
    return Note('provider', f"{base} ({detail})", 'syslog-provider')


def _dns_nudge(data_sources: list[str]) -> Note | None:
    """Return the Zeek evangelization note when only low-fidelity DNS data was loaded."""
    ds = set(data_sources)
    if "dnsmasq_dns" in ds and ds.isdisjoint(runner._RICH_DNS_SOURCES):
        return (
            Note('nudge', "running on Pi-hole/dnsmasq logs - RTT, TTL, and connection correlation "
            "unavailable. Add Zeek for richer DNS analysis and conn.log correlation.", 'loader')
        )
    return None


def _default_opt_in_remainder(
    plan: runner.RunPlan,
    selection: runner.DetectorSelection,
    detect_spec: object | None,
) -> list[str]:
    """Return opt-in detectors omitted by a default-participating selection.

    Explicit exclusions are operator intent and never read as curation. This
    pre-loop disclosure helper is defensive: optional module metadata cannot
    abort an otherwise valid hunt.
    """
    if not selection.used_default:
        return []
    try:
        tokens = runner._spec_tokens(str(detect_spec or DEFAULT_DETECT_SPEC))
        exclusions = {
            token[1:] for token in tokens if token.startswith("!")
        }
        return sorted(
            name
            for name, mod in plan.detectors.items()
            if not getattr(mod, "IN_DEFAULT_HUNT", False)
            and name not in plan.selected
            and name not in exclusions
        )
    except Exception:
        return []


def _default_opt_in_note(
    plan: runner.RunPlan,
    selection: runner.DetectorSelection,
    detect_spec: object | None,
) -> Note | None:
    """Build the default-hunt opt-in disclosure for RunSummary.notes."""
    try:
        remainder = _default_opt_in_remainder(plan, selection, detect_spec)
        if not remainder:
            return None
        action = "run it" if len(remainder) == 1 else "run them"
        names = ", ".join(remainder)
    except Exception:
        return None
    return (
        Note('opt-in', f"default hunt - not run: {names} "
        f"(opt-in; {action} by name or with --detect=all)", 'plan')
    )


def _dnsblock_cap_note(cause: str) -> str | None:
    for token, axis, limit in runner._DNSBLOCK_CAP_NOTES:
        if token in cause:
            return (
                f"dnsblock: analysis stopped: {axis} exceeded its bound "
                f"({limit}); no findings emitted this run"
            )
    return None


def _format_dnsblock_summary_notes(prepared: Any) -> list[Note]:
    """Project detector-owned dnsblock facts into the stable runner note order."""
    lines: list[Note] = []
    preflight = prepared.preflight
    if preflight.coverage_lane is CoverageLane.WEAK:
        lines.append(
            Note('coverage', "these logs cannot prove how complete each day is, so counts use the "
            "days that carry data; burst and recurring activity were not evaluated", 'dnsblock')
        )
    analysis = prepared.analysis
    cap_line = _dnsblock_cap_note(preflight.cause)
    if analysis is None:
        if cap_line:
            lines.append(Note('eligibility', cap_line, 'dnsblock'))
        return lines
    facts = analysis.notes
    if facts.insufficient_context_periods is not None:
        lines.append(
            Note('eligibility', "dnsblock: first-activity reporting needs "
            f"{facts.arrival_history_required} earlier days of history and this "
            f"window has {facts.insufficient_context_periods}; nothing is wrong, "
            "it will report once the archive is longer", 'dnsblock')
        )
    elif facts.insufficient_history_pairs:
        count = facts.insufficient_history_pairs
        lines.append(
            Note('eligibility', f"dnsblock: {count} candidate {plural(count, 'pair')} not reported: "
            "not enough earlier history in this window to call them new", 'dnsblock')
        )
    if facts.insufficient_arrival_coverage is not None:
        day_kind = (
            "covered days"
            if preflight.coverage_lane is CoverageLane.STRONG
            else "days with data"
        )
        lines.append(
            Note('eligibility', "dnsblock: first-activity reporting needs "
            f"{facts.arrival_days_required} {day_kind} and this window has "
            f"{facts.insufficient_arrival_coverage}", 'dnsblock')
        )
    if (
        preflight.coverage_lane is CoverageLane.STRONG
        and facts.burst_status.value == "ABSTAINED"
        and facts.burst_cause == "insufficient_coverage"
    ):
        lines.append(
            Note('eligibility', "dnsblock: burst reporting needs "
            f"{facts.burst_active_required} covered days and this window has "
            f"{facts.burst_eligible_periods}", 'dnsblock')
        )
    if (
        preflight.coverage_lane is CoverageLane.STRONG
        and facts.recurring_status.value == "ABSTAINED"
        and facts.recurring_cause == "incomplete_strong_coverage"
    ):
        lines.append(
            Note('eligibility', "dnsblock: recurring reporting needs every day of the report fully "
            f"covered; {facts.recurring_missing_periods} of "
            f"{facts.recurring_periods_total} were not", 'dnsblock')
        )
    if facts.synchronized_pairs:
        count = facts.synchronized_pairs
        lines.append(
            Note('eligibility', f"dnsblock: {count} first {plural(count, 'appearance')} not reported: "
            f"{facts.synchronized_addresses} addresses reached the same group in "
            "one day, so the arrival is not distinctive to any one of them", 'dnsblock')
        )
    if cap_line:
        lines.append(Note('eligibility', cap_line, 'dnsblock'))
    suppressed_report = (
        facts.raw_block_report_rows - facts.filtered_block_report_rows
    )
    suppressed_context = (
        facts.raw_block_context_rows - facts.filtered_block_context_rows
    )
    if (
        suppressed_report >= 0
        and suppressed_context >= 0
        and (suppressed_report or suppressed_context)
    ):
        lines.append(
            Note('allowlist', "dnsblock: your allowlist removed "
            f"{suppressed_report} blocked-query "
            f"{plural(suppressed_report, 'row')} before analysis, and "
            f"{suppressed_context} from the earlier history", 'dnsblock')
        )
    if (
        not cap_line
        and facts.entity_findings == 0
        and facts.context_findings == 0
    ):
        raw_blocks = facts.raw_block_report_rows + facts.raw_block_context_rows
        filtered_blocks = (
            facts.filtered_block_report_rows + facts.filtered_block_context_rows
        )
        if facts.raw_query_rows == 0:
            lines.append(Note('summary', "dnsblock: this window contains no Pi-hole query rows at all", 'dnsblock'))
        elif raw_blocks == 0:
            lines.append(
                Note('summary', "dnsblock: Pi-hole logged no blocked names in this window, so "
                "there was nothing to analyse", 'dnsblock')
            )
        elif filtered_blocks == 0:
            lines.append(
                Note('summary', "dnsblock: every blocked-name row in this window was removed by "
                "your allowlist before analysis", 'dnsblock')
            )
        else:
            lines.append(
                Note('summary', "dnsblock: blocked-name activity was examined and nothing met "
                "the reporting bar", 'dnsblock')
            )
    return lines


def _format_auth_summary_notes(facts: Any) -> list[Note]:
    """Render count-only auth facts without exposing log-derived identities."""
    observations = int(facts.observation_count)
    eligible = int(facts.eligible_count)
    identities = int(facts.identity_group_count)
    services = int(facts.service_count)
    remote_sources = int(facts.remote_source_count)
    prefix = f"auth: {observations:,} {plural(observations, 'log observation')}"
    record_disclosure = (
        "counts are decision records as each source logged them; a host reporting "
        "through more than one source can record one event in each"
    )

    if eligible <= 0:
        notes = [
            Note('summary', f"{prefix}; no eligible authentication records in the loaded window - "
            "detector abstained; requires at least one supported authentication "
            f"success or failure; {record_disclosure}", 'auth')
        ]
    else:
        magnitudes = (
            f"{prefix}; {eligible:,} "
            f"{plural(eligible, 'eligible authentication record')} across "
            f"{identities:,} {plural(identities, 'identity group')} and "
            f"{services:,} {plural(services, 'service')}"
        )
        if facts.positive_window:
            notes = [
                Note('summary', f"{magnitudes} - five lenses evaluated; {record_disclosure}", 'auth')
            ]
        else:
            notes = [
                Note('summary', f"{magnitudes} - concentration, landing, and host-spread evaluated; "
                "source-volume and account-volume abstained because the loaded "
                f"window has no positive duration; {record_disclosure}", 'auth')
            ]

    if remote_sources > 0:
        remote_source_label = plural(
            remote_sources, "remote source address", "remote source addresses",
        )
        notes.append(
            Note('allowlist', f"auth allowlist: {remote_sources:,} "
            f"{remote_source_label} extracted; "
            "system-log suppression covers whole hosts, not individual source addresses", 'auth')
        )
    return notes


def _aws_below_floor_note(
    plan: runner.RunPlan,
    logs: dict[str, pd.DataFrame],
    config: dict[str, Any],
) -> Note | None:
    """RunSummary note disclosing principals below the aws min_events floor.

    Pure derivation from the loaded CloudTrail frame via the detector's
    public ``below_floor_count`` helper. Called BEFORE the detector loop -
    detector-side state (a module cache populated inside run()) would be
    stale at this point. Returns None when aws is not in the plan, when the
    helper is missing (defensive), when no frame is loaded, or when count == 0.
    """
    if "aws" not in plan.will_run:
        return None
    mod = plan.detectors.get("aws")
    if mod is None or not hasattr(mod, "below_floor_count"):
        return None
    df = logs.get("*.json*")
    if df is None or df.empty:
        return None
    aws_cfg = get_detector_config(config, "aws", getattr(mod, "DEFAULT_CONFIG", {}))
    default_min = getattr(mod, "DEFAULT_CONFIG", {}).get("min_events", 50)
    min_events = aws_cfg.get("min_events", default_min)
    count = mod.below_floor_count(df, min_events)
    if count <= 0:
        return None
    return (
        Note('eligibility', f"aws: {count} interactive {plural(count, 'principal')} below the "
        f"min_events floor {plural(count, 'was', 'were')} not scored - the quiet "
        "tail of low-volume actors was not examined", 'aws')
    )


def _aws_window_note(
    plan: runner.RunPlan, *, cloudtrail_narrowed: bool = False
) -> Note | None:
    """First-seen labels are relative to the loaded window - name the limitation.

    Fires whenever aws ran, regardless of whether any bursts were emitted. The
    methodology limitation is worth knowing even if this run produced no
    burst findings, because the absence is itself window-dependent.

    The ``--all`` rider is keyed to CLOUDTRAIL ACTUALLY being narrowed (an
    explicit --since/--until), NOT run-level default-window activity: CloudTrail
    opts out of the auto-default window, so on a mixed unqualified run
    (dns/syslog windowed) it loaded FULL and widening would not help. Rides the
    EXISTING note (no new note, no position change).
    """
    if "aws" not in plan.will_run:
        return None
    note = (
        "aws: first-seen actions are first-seen within this loaded window - an "
        "action that is routinely used but absent earlier in the window reads "
        "as first-seen."
    )
    if cloudtrail_narrowed:
        note += " Run with --all for a full-baseline analysis."
    return Note('window', note, 'plan')


def _aws_no_interactive_note(
    plan: runner.RunPlan,
    logs: dict[str, pd.DataFrame],
    *,
    cloudtrail_narrowed: bool,
) -> Note | None:
    """Disclose the silent aws "nothing" when events loaded but zero are
    interactive-lane (aws.run returns [] with no finding).

    Pure derivation via the detector's public ``interactive_count`` helper
    (mirrors ``_aws_below_floor_note``). Fires when aws is planned, the
    ``*.json*`` frame is non-empty, and no event is interactive-lane. The
    ``--all`` suffix is conditional on ``cloudtrail_narrowed`` - widening only
    helps when an explicit window narrowed the load; on an unqualified run
    CloudTrail already loaded full, so widening cannot surface interactive
    events that do not exist.
    """
    if "aws" not in plan.will_run:
        return None
    mod = plan.detectors.get("aws")
    if mod is None or not hasattr(mod, "interactive_count"):
        return None
    df = logs.get("*.json*")
    if df is None or df.empty:
        return None
    if mod.interactive_count(df) != 0:
        return None
    note = (
        f"aws: {len(df)} CloudTrail {plural(len(df), 'event')} loaded but none are "
        "interactive-lane - aws scores only interactive activity, so nothing was analyzed"
    )
    if cloudtrail_narrowed:
        note += " - run with --all for full history"
    return Note('eligibility', note, 'aws')


def _ssl_facts(
    plan: runner.RunPlan,
    logs: dict[str, pd.DataFrame],
    home_net: list[str],
) -> dict[str, Any] | None:
    """The ssl detector's own eligibility facts, or None when unavailable.

    One accessor for both notes, so the two can never describe different
    populations. Defensive by contract: this runs pre-loop, OUTSIDE per-detector
    containment, and the contained loop reports a real preparation failure
    independently.
    """
    if "ssl" not in plan.will_run:
        return None
    mod = plan.detectors.get("ssl")
    if mod is None or not hasattr(mod, "eligibility"):
        return None
    df = logs.get("ssl*.log*")
    if df is None or df.empty:
        return None
    try:
        return mod.eligibility(df, home_net)
    except Exception:
        return None


def _ssl_visibility_line(facts: dict[str, Any]) -> str | None:
    """Disclose how much of the outbound population presented a certificate.

    The denominator is the SAME eligible-outbound population the detector
    scores, so this percentage and a finding's ``cert_visible_share`` are one
    measurement rather than two that can disagree on screen. Counts only - no
    address, name, or fingerprint reaches a note.
    """
    eligible = int(facts.get("rows_eligible", 0))
    if eligible < 1:
        return None
    visible = int(facts.get("cert_visible_rows", 0))
    # The two honesty guards ride the shared owner: a nonzero count that rounds
    # to zero reads "<1%", never a misleading "(0%)".
    pct = _suppression_pct(visible, eligible)
    share = f" ({pct})" if pct is not None else ""
    return (
        f"ssl: a server certificate was visible on {visible:,} of {eligible:,} "
        f"outbound {plural(eligible, 'session')}{share} - the validation leg "
        "covers only those"
    )


def _ssl_zero_findings_line(facts: dict[str, Any]) -> str | None:
    """Name the cause when ssl loaded rows but can score none of them.

    Three distinguishable causes, each a fact the detector measured. A run that
    scores rows says nothing here - the report's own emptiness is then the
    accurate answer, and inventing an explanation for it would be worse.
    """
    if int(facts.get("rows_eligible", 0)) > 0:
        return None

    missing = tuple(facts.get("missing_columns", ()))
    if missing:
        return (
            "ssl: no sessions analyzed - the loaded rows carry no "
            f"{', '.join(missing)} {plural(len(missing), 'column')}"
        )

    total = int(facts.get("rows_total", 0))
    after_local = int(facts.get("rows_after_local", 0))
    outside_home = int(facts.get("rows_dst_outside_home", 0))
    after_external = int(facts.get("rows_after_external", 0))

    # Two mutually exclusive destination causes. An operator acts differently on
    # each - one says the traffic never left home_net, the other says it left
    # and went nowhere routable - so one sentence covering both is no help.
    if outside_home > 0 and after_external == 0:
        return (
            f"ssl: no sessions analyzed - all {outside_home:,} "
            f"{plural(outside_home, 'row')} leaving home_net reached a "
            "non-routable destination"
        )
    if after_local > 0 and outside_home == 0:
        return (
            f"ssl: no sessions analyzed - all {after_local:,} outbound-candidate "
            f"{plural(after_local, 'row')} reached a destination inside home_net"
        )
    return (
        f"ssl: no sessions analyzed - none of the {total:,} loaded "
        f"{plural(total, 'row')} is an outbound session from home_net"
    )


def _ssl_eligibility_notes(
    plan: runner.RunPlan,
    logs: dict[str, pd.DataFrame],
    home_net: list[str],
) -> list[Note]:
    """Render ssl's disclosures from ONE eligibility measurement.

    Both lines describe the same population by construction: the facts are
    computed once here and handed to two pure renderers, so a second call can
    never return a different funnel and put two numbers about one run on one
    screen.
    """
    facts = _ssl_facts(plan, logs, home_net)
    if facts is None:
        return []
    return [Note('eligibility', line, 'ssl') for line in [
        line
        for line in (_ssl_visibility_line(facts), _ssl_zero_findings_line(facts))
        if line
    ]]


def _exfil_eligibility_notes(
    plan: runner.RunPlan,
    logs: dict[str, pd.DataFrame],
    home_net: list[str],
    config: dict[str, Any],
) -> list[Note]:
    """Render Exfil's post-allowlist fidelity and partial-measurement notes.

    The detector owns the eligibility and reconstruction calculations.  This
    runner seam owns only user-facing wording and reduces identity-bearing pair
    facts to an aggregate count and excluded outbound mass.
    """
    if "exfil" not in plan.will_run:
        return []
    mod = plan.detectors.get("exfil")
    if mod is None or not hasattr(mod, "eligibility"):
        return []
    df = logs.get("conn*.log*")
    if df is None or df.empty:
        return []
    try:
        det_cfg = get_detector_config(
            config, "exfil", getattr(mod, "DEFAULT_CONFIG", {}),
        )
        facts = mod.eligibility(df, home_net, det_cfg)
        rows_total = int(facts.get("rows_total", 0))
        missing = tuple(facts.get("missing_columns", ()))
        if missing:
            return [Note('eligibility', line, 'exfil') for line in [
                f"exfil: did not score {rows_total} loaded "
                f"{plural(rows_total, 'connection')} - required conn.log columns missing: "
                f"{', '.join(missing)}"
            ]]

        notes: list[str] = []
        rows_after_external = int(facts.get("rows_after_external", 0))
        rows_after_bytes = int(facts.get("rows_after_byte_pairing", 0))
        if rows_after_external > 0 and rows_after_bytes == 0:
            notes.append(
                f"exfil: {rows_after_external} loaded "
                f"{plural(rows_after_external, 'connection')} passed the parse, "
                "local-origin, and external gates but carried no usable complete byte "
                "pairs - none were scored"
            )

        material_count = 0
        excluded_mass = 0.0
        partial_pairs = facts.get("partial_pairs", {})
        if isinstance(partial_pairs, Mapping):
            for pair_fact in partial_pairs.values():
                if not isinstance(pair_fact, Mapping):
                    continue
                if pair_fact.get("surfaced") or not pair_fact.get("best_case_surfaces"):
                    continue
                try:
                    mass = float(pair_fact.get("excluded_orig", 0.0))
                except (TypeError, ValueError):
                    continue
                if not math.isfinite(mass) or mass < 0:
                    continue
                material_count += 1
                excluded_mass += mass
        if material_count:
            notes.append(
                f"exfil: {material_count} {plural(material_count, 'connection pair')} "
                "may have met the measured byte gates if responder bytes were recorded "
                f"({human_bytes(excluded_mass)} outbound bytes excluded)"
            )
        return [Note('eligibility', line, 'exfil') for line in notes]
    except Exception:
        return []


def _beacon_eligibility_notes(
    plan: runner.RunPlan,
    logs: dict[str, pd.DataFrame],
    home_net: list[str],
) -> list[Note]:
    """Render Beacon failure-cause notes from its post-allowlist conn view.

    The detector owns the predicates and returns plain counts in one scan; the runner
    owns wording. This is called before the detector loop, so every seam is defensive.
    """
    if "beacon" not in plan.will_run:
        return []
    mod = plan.detectors.get("beacon")
    if mod is None or not hasattr(mod, "scoring_eligibility"):
        return []
    df = logs.get("conn*.log*")
    if df is None:
        return []
    try:
        facts = mod.scoring_eligibility(df, home_net)
        notes: list[str] = []
        missing = tuple(facts.get("missing_columns", ()))
        rows_total = int(facts.get("rows_total", 0))
        if missing:
            notes.append(
                f"beacon: did not score {rows_total} loaded "
                f"{plural(rows_total, 'connection')} - required conn.log columns missing: "
                f"{', '.join(missing)}"
            )
            return [Note('eligibility', line, 'beacon') for line in notes]

        rows_before_bytes = int(facts.get("rows_before_bytes", 0))
        rows_after_bytes = int(facts.get("rows_after_bytes", 0))
        if rows_before_bytes > 0 and rows_after_bytes == 0:
            notes.append(
                f"beacon: {rows_before_bytes} loaded "
                f"{plural(rows_before_bytes, 'connection')} passed the state, address, "
                "and local-origin gates but carried no originator bytes - none were scored"
            )

        rows_before_keys = int(facts.get("rows_before_keys", 0))
        rows_after_keys = int(facts.get("rows_after_keys", 0))
        excluded = rows_before_keys - rows_after_keys
        if excluded > 0:
            notes.append(
                f"beacon: {excluded} loaded {plural(excluded, 'connection')} passed the "
                "earlier gates but had null src/dst/port/proto grouping keys and were not scored"
            )
        return [Note('eligibility', line, 'beacon') for line in notes]
    except Exception:
        return []


def _beacon_min_connections_note(
    plan: runner.RunPlan,
    config: dict[str, Any],
) -> Note | None:
    """Disclose a valid configured floor below Beacon's scorer-owned hard floor."""
    if "beacon" not in plan.will_run:
        return None
    mod = plan.detectors.get("beacon")
    if mod is None or not hasattr(mod, "_MIN_SCORABLE_SAMPLES"):
        return None
    try:
        det_cfg = get_detector_config(
            config, "beacon", getattr(mod, "DEFAULT_CONFIG", {})
        )
        configured = det_cfg.get("min_connections")
        floor = mod._MIN_SCORABLE_SAMPLES
    except Exception:
        return None
    if (
        isinstance(configured, bool)
        or not isinstance(configured, int)
        or configured < 1
        or not isinstance(floor, int)
        or floor < 1
        or configured >= floor
    ):
        return None
    return (
        Note('eligibility', f"beacon: configured min_connections is below the scorer floor of {floor} - "
        "smaller groups are not scored", 'beacon')
    )


def _beacon_non_established_note(
    plan: runner.RunPlan,
    logs: dict[str, pd.DataFrame],
) -> Note | None:
    """Disclose when beacon's established-only gate excluded most loaded connections.

    Pure derivation via the detector's public ``non_established_share`` helper, which is
    defensive on a conn_state-absent frame. Called BEFORE the detector loop - outside the
    detector's error containment - so it must not raise. The row floor is checked BEFORE the
    share so an empty or tiny frame never divides into a spurious ratio.
    """
    if "beacon" not in plan.will_run:
        return None
    mod = plan.detectors.get("beacon")
    if mod is None or not hasattr(mod, "non_established_share"):
        return None
    if not hasattr(mod, "_NON_ESTABLISHED_NOTE_MIN_ROWS") or not hasattr(
        mod, "_NON_ESTABLISHED_NOTE_SHARE"
    ):
        return None
    df = logs.get("conn*.log*")
    if df is None or df.empty:
        return None
    non_est, total = mod.non_established_share(df)
    if total < mod._NON_ESTABLISHED_NOTE_MIN_ROWS:
        return None
    if non_est / total < mod._NON_ESTABLISHED_NOTE_SHARE:
        return None
    pct = 100.0 * non_est / total
    return (
        Note('eligibility', f"beacon: {non_est} of {total} loaded "
        f"{plural(total, 'connection')} ({pct:.0f}%) were "
        "outside the Zeek SF/S1 states beacon analyzes and were not scored - periodic "
        "retry and reset patterns are not detected", 'beacon')
    )


def _beacon_span_note(
    plan: runner.RunPlan,
    logs: dict[str, pd.DataFrame],
    requested_span: timedelta | None,
) -> Note | None:
    """Disclose when the analyzed conn span is too short to resolve a jittered beacon.

    Resolving a jittered periodic beacon needs roughly a week of span; the
    runner reads beacon's ``_MIN_RELIABLE_SPAN_DAYS`` and the defensive
    ``analyzed_span_seconds`` helper. Called BEFORE the detector loop - outside the
    detector's error containment - so it must not raise; the helper returns its 0.0
    no-measurement sentinel on any unreadable frame.

    Fires only on a POSITIVE analyzed span below the floor: a 0.0 span (absent / malformed
    / single-row ts) stays silent. The narrowed/unbounded fork mirrors ``_aws_window_note``'s
    --all rider - a bounded lookback (requested_span set) can be widened; an unbounded run
    already loaded all it has.
    """
    if "beacon" not in plan.will_run:
        return None
    mod = plan.detectors.get("beacon")
    if mod is None or not hasattr(mod, "analyzed_span_seconds"):
        return None
    if not hasattr(mod, "_MIN_RELIABLE_SPAN_DAYS"):
        return None
    df = logs.get("conn*.log*")
    if df is None or df.empty:
        return None
    span_s = mod.analyzed_span_seconds(df)
    if span_s <= 0.0:
        return None
    days = mod._MIN_RELIABLE_SPAN_DAYS
    if span_s >= days * 86400:
        return None
    span = fmt_compact_span(timedelta(seconds=span_s))
    if requested_span is not None:
        return (
            Note('window', f"beacon: the loaded connections span {span} - resolving a jittered beacon needs "
            f"about {days} {plural(days, 'day')} of span; widen with --all or a longer lookback", 'beacon')
        )
    return (
        Note('window', f"beacon: the loaded connections span only {span} - resolving a jittered beacon needs "
        f"about {days} {plural(days, 'day')} of span", 'beacon')
    )


def _home_net_note(
    plan: runner.RunPlan,
    config: dict[str, Any],
    home_net: list[str],
) -> Note | None:
    """RunSummary note disclosing the internal networks in effect for scan.

    Fires only when scan is in plan.will_run. Distinguishes default-vs-declared
    by reading the ``__user_set__`` provenance sidecar attached by the config
    loader - a pure value comparison would misclassify a user who declares the
    RFC1918 list verbatim as "default". When the operator did not declare
    home_net (no config file, or config file omits the key), the parenthetical
    fires; when they did declare it, the note states their value plainly.
    ``home_net`` is already resolved by the runner entry point; this projector
    performs no config validation of its own.
    """
    if "scan" not in plan.will_run:
        return None
    if not home_net:
        return None
    rendered = ", ".join(home_net)
    user_set = config.get("__user_set__", {}).get("sigwood", set())
    if "home_net" in user_set:
        return Note('home-net', f"internal networks: {rendered}", 'config')
    return (
        Note('home-net', f"internal networks: {rendered} "
        "(RFC1918 default - set home_net in config to override)", 'config')
    )


def _source_overlap_notes(
    source_dirs: dict[str, list[Path]], plan: runner.RunPlan,
) -> list[Note]:
    """RunSummary notes when two IN-PLAN source families resolve to one directory.

    The contamination vector: flat discovery globs overlap (``syslog`` discovers
    with the catch-all ``*.log*``), so a directory shared by two families has its
    files parsed by each front-end - one log can surface as another's finding.
    This is a plan-time disclosure, derived from already-resolved sources (same
    posture as ``_home_net_note``), not a load-time check.

    Binding rails:

    - **Eligibility = in-plan families only.** Derived from
      ``set(plan.needed_logs.values())``, NOT every non-empty resolved bucket.
      A family configured-and-resolved but not selected (no detector in the run
      reads it) cannot contaminate, so two dirs colliding while only one family
      is planned does NOT warn. Optional multi-source detectors add only their
      satisfiable patterns to ``needed_logs``, so the note follows what the
      loader will actually read.
    - **Directories only.** Explicit FILE inputs are out of scope - the vector
      is dir-glob overlap, not a shared named file. Per-family duplicate inputs
      collapse (a key is recorded once per directory).
    - **Equal-dir ONLY (v1).** Flat discovery is non-recursive, so the shipped
      default (``syslog_dir=/var/log`` containing ``zeek_dir=/var/log/zeek``)
      does NOT contaminate and MUST NOT warn - nesting is deliberately out of
      scope. (CloudTrail's ``rglob`` makes nested cloudtrail an acknowledged
      deferred edge.)
    - **Deterministic ordering.** ``source_dirs`` is built in canonical key order
      by ``run`` (zeek, syslog, pihole, cloudtrail); first-seen preservation here
      keeps the rendered family list deterministic. ≥3 families at one dir → one
      note listing all.
    """
    in_plan = set(plan.needed_logs.values())
    by_dir: dict[Path, list[str]] = {}
    for key, paths in source_dirs.items():
        if key not in in_plan:
            continue
        for p in paths:
            if not p.is_dir():            # explicit files out of scope
                continue
            try:
                resolved = p.resolve()
            except OSError:
                continue
            families = by_dir.setdefault(resolved, [])
            if key not in families:       # collapse per-family duplicate inputs
                families.append(key)

    notes: list[str] = []
    for resolved, families in by_dir.items():
        if len(families) >= 2:
            notes.append(
                f"{', '.join(families)} resolve to the same directory "
                f"({resolved}): files there matching more than one source's "
                "patterns are parsed by each, which can surface one log as "
                "another's finding. Point them at separate directories - global "
                "exports now auto-segment per source."
            )
    return [Note('overlap', line, 'plan') for line in notes]


import sigwood.runner as runner
