"""The analyze discovery inventory: one observation per (family, input), shared.

One analyze invocation asks the same discovery question in several places: plan
satisfiability, default-window resolution, every load pass and the dry-run
preview, once per detector and per log pattern. The inventory answers all of
them from a single observation of each input, made the first time any of them
asks, and then publishes those observations to the loader as source-checked
populations.

Observation is lazy on purpose. The runner first asks after the system-log
provider is decided, so a configured flat-syslog root is never even listed on a
run the journal serves, and nothing here ever holds the journal's private
capture. The inventory has no knowledge of families: each registered strategy
that declares ``observe`` and ``select_observed`` supplies its own.

With recursion enabled, directories this invocation supplied are walked when
they are registered (before provider arbitration, because routing needs their
families), and every later question about them is answered from those walks
through ``recursive``'s views. Configured inputs stay shallow and lazy.

Layering: imports the registry from ``pipeline``, the observation helpers from
``discovery`` and the walks from ``recursive``; nothing in the loader imports
this module.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping, Sequence
from dataclasses import replace
from datetime import datetime
from pathlib import Path

from sigwood.common.loader.discovery import (
    _INPUT_DIRECTORY,
    _INPUT_ERROR,
    _INPUT_FILE,
    _INPUT_MISSING,
    InputObservation,
    ObservedCoverage,
    _errno_name,
    apply_observation_denials,
)
from sigwood.common.loader.io import _safe_resolve
from sigwood.common.loader.pipeline import _SOURCE_LOADERS
from sigwood.common.loader.provenance import (
    is_reserved_provenance_path,
    reject_explicit_reserved_path,
)
from sigwood.common.loader.recursive import (
    _READ_FAILURES,
    DECLARED,
    PARTITION,
    LayoutContribution,
    RecursiveIndex,
)
from sigwood.common.loader.types import (
    CandidatePopulation,
    DirectorySkipInfo,
    DiscoveryFact,
    DiscoveryFactKind,
    RootFact,
)


class DiscoveryInventory:
    """Memoized observations for one analyze invocation.

    Keys are ``(source_key, input path)`` with the path exactly as the source
    resolver produced it, so every consumer that holds the run's resolved inputs
    finds the same observation. Insertion order is the order inputs were first
    observed, which keeps every derived report deterministic.
    """

    def __init__(self) -> None:
        self._observations: dict[tuple[str, Path], InputObservation] = {}
        self._recursion: RecursiveIndex | None = None
        self._contributions: dict[tuple, LayoutContribution] = {}

    # ── recursion ───────────────────────────────────────────────────────────

    def enable_recursion(self, declared_patterns: Mapping[str, Sequence[str]]) -> None:
        """Walk this invocation's directories, reading for these (source, patterns)."""
        self._recursion = RecursiveIndex(declared_patterns)

    @property
    def recursive(self) -> bool:
        """Whether this invocation walks its supplied directories."""
        return self._recursion is not None

    def _resolve(self, path: Path) -> Path:
        """Resolved identity, memoized by the recursion index when one exists."""
        if self._recursion is not None:
            return self._recursion.resolve(path)
        return _safe_resolve(path)

    def _index(self) -> RecursiveIndex:
        if self._recursion is None:
            raise RuntimeError("recursion is not enabled for this inventory")
        return self._recursion

    def register_partition_root(self, raw: str, path: Path) -> None:
        """Walk one positional directory and partition its files into families."""
        self._index().register(raw, path, mode=PARTITION)

    def register_declared_root(self, source_key: str, raw: str, path: Path) -> None:
        """Walk one ``--<family>-dir`` directory under its own family's gate."""
        self._index().register(raw, path, mode=DECLARED, source=source_key)

    def register_supplied_input(self, source_key: str, path: Path) -> None:
        """Note an explicit file this run will read, before ownership is decided.

        Only an input the run actually reads supplies its content: its family is
        one the selected detectors read, that family's own explicit-file
        selection takes it, and no load-time guard of that family would skip it.
        An input the run will not read never hides another name's omission.
        """
        if self._recursion is None:
            return
        patterns = self._recursion.permitted.get(source_key)
        strategy = _SOURCE_LOADERS.get(source_key)
        if (
            not patterns
            or strategy is None
            or strategy.observe is None
            or strategy.select_observed is None
            or is_reserved_provenance_path(path)
        ):
            return
        obs = strategy.observe(path)
        if obs.kind != _INPUT_FILE or not any(
            strategy.select_observed(obs, pattern, None, None) for pattern in patterns
        ):
            return
        for guard in (strategy.warn_skip, strategy.should_skip):
            if guard is None:
                continue
            try:
                if guard(path):
                    return
            except _READ_FAILURES:
                return  # the load will report what it cannot read
        self._recursion.register_supplied(path)

    def close_recursion(self) -> None:
        """Resolve layouts across every registered walk; views exist only after."""
        self._index().close()

    def root_families(self, path: Path) -> tuple[str, ...]:
        """The families one positional directory supplied files to."""
        return self._index().families(path)

    def partition_files(self, source_key: str) -> tuple[Path, ...]:
        """Every file positional partitions gave to ``source_key``."""
        if self._recursion is None:
            return ()
        return self._recursion.partition_files(source_key)

    def root_facts(self) -> list[RootFact]:
        """Family-neutral coverage facts of the positional directories walked."""
        if self._recursion is None:
            return []
        return self._recursion.root_facts()

    def layout_contribution(
        self, source_key: str, paths: Sequence[Path], patterns: Sequence[str],
    ) -> LayoutContribution:
        """Which logical roots of a family add files, decided once per plan.

        Explicit files and non-recursive inputs are supplied first; then each
        recursive input's logical roots are decided in a fixed order, so the
        window, every load pass and the coverage text all read one answer.
        """
        key = (source_key, tuple(paths), tuple(patterns))
        cached = self._contributions.get(key)
        if cached is not None:
            return cached
        result = LayoutContribution()
        if self._recursion is not None and self.supports(source_key):
            select = _SOURCE_LOADERS[source_key].select_observed
            assert select is not None
            seed: set[Path] = set()
            views: list[InputObservation] = []
            for path in paths:
                obs = self.observe(source_key, path)
                if obs.mode is not None:
                    if obs.logical:
                        views.append(obs)
                    continue
                for pattern in patterns:
                    seed.update(
                        self._resolve(item) for item in select(obs, pattern, None, None)
                    )
            if views:
                result = self._recursion.contribution(views, seed, patterns, select)
        self._contributions[key] = result
        return result

    def shared_candidates(
        self,
        needed_logs: Mapping[str, str],
        source_dirs: Mapping[str, Sequence[Path]],
    ) -> list[tuple[str, str, tuple[Path, ...]]]:
        """Files that are candidates of two in-plan families, by family pair.

        Candidate membership is window-blind: a shared candidate may still be
        pruned by a time window before either family reads it.
        """
        members: dict[str, dict[Path, Path]] = {}
        for pattern, source_key in needed_logs.items():
            if not self.supports(source_key):
                continue
            found = members.setdefault(source_key, {})
            for path in source_dirs.get(source_key) or []:
                for item in self.candidates(source_key, path, pattern):
                    found.setdefault(self._resolve(item), item)
        families = list(members)
        out: list[tuple[str, str, tuple[Path, ...]]] = []
        for i, first in enumerate(families):
            for second in families[i + 1:]:
                shared = sorted(
                    members[first][key] for key in members[first]
                    if key in members[second]
                )
                if shared:
                    out.append((first, second, tuple(shared)))
        return out

    @staticmethod
    def supports(source_key: str) -> bool:
        """Whether ``source_key`` is a family the inventory may observe."""
        if source_key == "journal":
            return False
        strategy = _SOURCE_LOADERS.get(source_key)
        return strategy is not None and strategy.observes

    def observe(self, source_key: str, path: Path) -> InputObservation:
        """Return the observation of one input, enumerating it on first use."""
        if not self.supports(source_key):
            raise ValueError(f"{source_key!r} inputs are not observed by the inventory")
        key = (source_key, path)
        obs = self._observations.get(key)
        if obs is None:
            reject_explicit_reserved_path(path)
            view = (
                self._recursion.view(source_key, path)
                if self._recursion is not None else None
            )
            if view is None:
                observe = _SOURCE_LOADERS[source_key].observe
                assert observe is not None
                view = observe(path)
            obs = view
            self._observations[key] = obs
        return obs

    def candidates(
        self,
        source_key: str,
        path: Path,
        pattern: str,
        since: datetime | None = None,
        until: datetime | None = None,
        *,
        _directory_skips: dict[tuple[str, Path], DirectorySkipInfo] | None = None,
    ) -> list[Path]:
        """Select one input's candidates for ``pattern`` from its observation.

        Every directory-listing denial the observation holds, at the root or
        below it, is recorded in ``_directory_skips``; recording is idempotent,
        so repeated queries cannot multiply a record.
        """
        obs = self.observe(source_key, path)
        select = _SOURCE_LOADERS[source_key].select_observed
        assert select is not None
        files = select(obs, pattern, since, until)
        apply_observation_denials(obs, _directory_skips)
        return files

    def populations(
        self,
        needed_logs: Mapping[str, str],
        source_dirs: Mapping[str, Sequence[Path]],
    ) -> dict[str, CandidatePopulation]:
        """Build the loader's populations for a final, post-arbitration plan.

        Each value names its pattern's source and carries one observation per
        input of that source, in the run's input order. Patterns whose source
        the inventory does not observe (the journal, custom strategies) are left
        out, so the loader discovers them as it always has.
        """
        out: dict[str, CandidatePopulation] = {}
        for pattern, source_key in needed_logs.items():
            if not self.supports(source_key):
                continue
            paths = list(source_dirs.get(source_key) or [])
            family_patterns = [p for p, s in needed_logs.items() if s == source_key]
            restricted = self._contributing_views(source_key, paths, family_patterns)
            out[pattern] = CandidatePopulation(
                source_key,
                tuple(
                    (path, restricted.get(path, None) or self.observe(source_key, path))
                    for path in paths
                ),
            )
        return out

    def _contributing_views(
        self, source_key: str, paths: Sequence[Path], patterns: Sequence[str],
    ) -> dict[Path, InputObservation]:
        """Recursive inputs reduced to the logical roots that contribute.

        A logical root whose files an explicit file or an earlier root already
        supplies is dropped here, so it cannot change the family window.
        """
        contribution = self.layout_contribution(source_key, paths, patterns)
        out: dict[Path, InputObservation] = {}
        for path in paths:
            obs = self.observe(source_key, path)
            if obs.mode is None or not obs.logical:
                continue
            out[path] = replace(obs, logical=tuple(
                view for view in obs.logical
                if self._resolve(view.path) in contribution.identities
            ))
        return out

    def coverage(
        self, source_key: str, path: Path, patterns: Sequence[str],
    ) -> ObservedCoverage:
        """What the family's own selection left unread in one observed input."""
        obs = self.observe(source_key, path)
        coverage = _SOURCE_LOADERS[source_key].coverage
        return coverage(obs, patterns) if coverage is not None else ObservedCoverage()

    def input_facts(
        self,
        source_key: str,
        path: Path,
        patterns: Sequence[str],
        *,
        invocation: bool,
    ) -> list[DiscoveryFact]:
        """Every coverage fact one input contributes, its own state first.

        ``invocation`` says the operator supplied this input on this run. Such
        an input reports being empty, holding no supported files, and leaving
        children unsearched; a configured input reports unsearched children
        only when it supplied no candidates, so a healthy configured root stays
        quiet. A directory-listing denial is not a fact here: it is a
        ``DirectorySkipInfo`` record with its own renderer. Callers that own a
        statement already (a skip reason, a loader warning) drop the matching
        fact themselves.
        """
        obs = self.observe(source_key, path)
        if obs.mode == PARTITION:
            # A positional partition's walk facts belong to its root; the family
            # states only its own layout decisions.
            return list(self.coverage(source_key, path, patterns).facts)
        if obs.kind == _INPUT_MISSING:
            return [DiscoveryFact(
                DiscoveryFactKind.MISSING_INPUT, source_key, path, (path,), 1,
            )]
        if obs.kind == _INPUT_ERROR:
            detail = _errno_name(obs.error) if obs.error is not None else None
            return [DiscoveryFact(
                DiscoveryFactKind.LISTING_ERROR, source_key, path, (path,), 1, detail,
            )]
        if obs.kind != _INPUT_DIRECTORY:
            return []
        coverage = self.coverage(source_key, path, patterns)
        has_candidates = any(
            self.candidates(source_key, path, pattern) for pattern in patterns
        )
        facts: list[DiscoveryFact] = []
        # A walked tree is empty only if every part of it was searched.
        searched = obs.mode != DECLARED or not (
            obs.denied_dirs or any(
                fact.kind in (
                    DiscoveryFactKind.LISTING_ERROR,
                    DiscoveryFactKind.LINKED_DIRECTORY_OMITTED,
                )
                for fact in obs.facts
            )
        )
        if invocation and not obs.entries and searched:
            facts.append(DiscoveryFact(
                DiscoveryFactKind.EMPTY_DIRECTORY, source_key, path, (path,), 1,
            ))
        if invocation and coverage.regular_files and not has_candidates:
            facts.append(DiscoveryFact(
                DiscoveryFactKind.UNSUPPORTED_FILES, source_key, path,
                coverage.regular_files, len(coverage.regular_files),
            ))
        if coverage.unsearched and (invocation or not has_candidates):
            facts.append(DiscoveryFact(
                DiscoveryFactKind.UNSEARCHED_CHILDREN, source_key, path,
                coverage.unsearched, len(coverage.unsearched),
            ))
        facts.extend(coverage.facts)
        return facts

    def silent_miss_states(
        self,
        source_key: str,
        path: Path,
        pattern: str,
        inputs: Sequence[Path],
    ) -> bool:
        """Whether the loader's silent-miss warning will state this input's content.

        That warning belongs to the flat-family load arm (strategies with a
        rotation ``window_select``) and fires when no directory input yields a
        candidate for the loaded pattern; it then names exactly the inputs its
        family's coverage marks as covered. The caller decides whether the
        pattern loads at all.
        """
        strategy = _SOURCE_LOADERS[source_key]
        if strategy.window_select is None:
            return False
        if not self.coverage(source_key, path, [pattern]).silent_miss_covered:
            return False
        return not any(
            self.candidates(source_key, item, pattern)
            for item in inputs
            if item.is_dir()
        )

    def observation(self, source_key: str, path: Path) -> InputObservation | None:
        """The observation for one input if it has been made, else None."""
        return self._observations.get((source_key, path))

    def observed(self) -> Iterator[tuple[str, Path, InputObservation]]:
        """Every observation made so far, in first-observation order."""
        for (source_key, path), obs in self._observations.items():
            yield source_key, path, obs

    def observe_count(self) -> int:
        """How many distinct (family, input) observations have been made."""
        return len(self._observations)
