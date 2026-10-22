"""Transactional template indexing and candidate selection for local syslog."""
from __future__ import annotations

import copy
import sys
import weakref
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

import numpy as np
import pandas as pd

from sigwood.common.finding import Declined, DeclineReason, Preparation
from sigwood.common.loader.types import AdmitSink, FoldDelta, FoldSink, PreparedState, SinkPlan
from sigwood.common.loader.fold import FoldAbstention
from sigwood.common.loader.limits import (
    MAX_CHUNK_ROWS, MAX_DECLARED_FILE_DELTA_BYTES, MAX_LOGICAL_RECORD_BYTES,
)
from sigwood.common.loader.types import _SYSLOG_COLUMNS

# Maximum (container bytes minus empty bytes) / entries for sizes 1..9999:
# CPython 3.11.17: dict 160, set 107.790; 3.14.7: dict 160, set 107.790.
# Round upward and use the largest across interpreters. Referents are separate.
DICT_SLOT_BYTES = 160
SET_SLOT_BYTES = 108
# One chunk's distinct identities per container; arbitrarily many repeated keys
# remain eligible. A string may hold a whole maximum logical record in four-byte
# Unicode storage, including the largest supported string header allowance.
MAX_DELTA_IDENTITY_KEYS = MAX_CHUNK_ROWS
MAX_IDENTITY_KEY_BYTES = 4 * MAX_LOGICAL_RECORD_BYTES + 80
_INT32_STOP = 2**31
_COLUMNS = (*_SYSLOG_COLUMNS, 'template_id', 'template_str')
# Ordered 800k-row mixtures: prepared/ordinary peak RSS was 0.89660 at
# 50% and 1.02566 at 70%, interpolating parity near 66%. Use 60% with a
# six-percentage-point margin. This calibrates memory, not elapsed time or
# every input shape.
DENSE_CANDIDATE_SHARE = 0.60
# On two hosts, the smallest contiguous safe-prefix crossing under a 128 MiB
# memory-saving bar was high-cardinality syslog at 200k rows, 14,887,199 bytes
# (14.20 MiB). Round down to a whole MiB. Compressed or unsized selections
# have no proven bound
# and retain the prepared route. The bound describes measured shapes only.
SMALL_INPUT_BYTES = 14 * 1024 * 1024


@dataclass
class _File:
    arrays: list[tuple[np.ndarray, np.ndarray]] = field(default_factory=list)
    key: str | None = None
    counts: Counter = field(default_factory=Counter)
    pairs: Counter = field(default_factory=Counter)
    hosts: Counter = field(default_factory=Counter)
    arbitration: set = field(default_factory=set)
    seen: set[int] = field(default_factory=set)
    identity_bytes: int = 0
    array_bytes: int = 0
    rows: int = 0

    def retain(self, container: Any, key: Any) -> None:
        """Account every retained identity at its single insertion boundary."""
        if key not in container:
            strings = key if isinstance(key, tuple) else (key,)
            if any(sys.getsizeof(value) > MAX_IDENTITY_KEY_BYTES for value in strings):
                raise FoldAbstention('identity key exceeds the byte limit')
            if len(container) >= MAX_DELTA_IDENTITY_KEYS:
                raise FoldAbstention('identity count exceeds the per-file limit')
            if isinstance(key, tuple):
                self.identity_bytes += sys.getsizeof(key)
            for value in strings:
                if id(value) not in self.seen:
                    self.seen.add(id(value))
                    self.identity_bytes += sys.getsizeof(value)
            self.identity_bytes += SET_SLOT_BYTES if isinstance(container, set) else DICT_SLOT_BYTES
        if isinstance(container, set):
            container.add(key)
        else:
            container[key] += 1


@dataclass
class _Facts:
    miner: Any
    texts: list[str] = field(default_factory=list)
    index: dict[str, int] = field(default_factory=dict)
    arrays: dict[str, tuple[np.ndarray, np.ndarray]] = field(default_factory=dict)
    counts: Counter = field(default_factory=Counter)
    pairs: Counter = field(default_factory=Counter)
    hosts: Counter = field(default_factory=Counter)
    arbitration: set = field(default_factory=set)
    checkpoint: Any = None
    checkpoint_len: int = 0
    delta_bytes: dict[str, int] = field(default_factory=dict)
    aborted_files: frozenset[str] = frozenset()
    committed_files: frozenset[str] | None = None

    def mine(self, message: Any) -> tuple[int, int]:
        result = self.miner.add_log_message(str(message))
        tid = result['cluster_id']
        if not 0 <= tid < _INT32_STOP:
            raise FoldAbstention('template id range')
        text = result['template_mined']
        version = self.index.get(text)
        if version is None:
            version = len(self.texts)
            if version >= _INT32_STOP:
                raise FoldAbstention('template version range')
            self.index[text] = version
            self.texts.append(text)
        return tid, version


@dataclass(frozen=True)
class SyslogPrepared:
    zeek: pd.DataFrame | None
    threshold: int
    freq: dict[int, int]
    rare_ids: set[int]
    program_totals: dict
    host_totals: dict


def _identity(value: Any) -> Any:
    return 'unknown' if pd.isna(value) else value


def templates_sink(host: Any, facts: _Facts) -> FoldSink:
    """Build a transactional miner sink whose ordinals cover every decoded row."""
    def seed_file() -> FoldDelta:
        with host.timer('checkpoint'):
            facts.checkpoint = copy.deepcopy(facts.miner.drain)
            facts.checkpoint_len = len(facts.texts)
        return FoldDelta(_File(), 0)

    def consume(delta: FoldDelta, chunk: Any, mask: Any) -> FoldDelta:
        value = delta.value
        if value.key is None:
            value.key = chunk.file_key
        if value.key != chunk.file_key or value.rows != chunk.first_ordinal:
            raise ValueError('template ordinal mismatch')
        ids = np.full(len(chunk.frame), -1, dtype=np.int32)
        versions = np.full(len(chunk.frame), -1, dtype=np.int32)
        with host.timer('reduce'):
            for i, row in enumerate(chunk.frame.itertuples(index=False)):
                if not chunk.report_mask[i]:
                    continue
                host_id = _identity(row.host)
                # Match the runner's string conversion, including NaN -> "nan".
                value.retain(value.arbitration, str(row.host).lower())
                if not mask.keep[i]:
                    continue
                ids[i], versions[i] = facts.mine(row.message)
                value.counts[int(ids[i])] += 1
                program = _identity(row.program)
                value.retain(value.pairs, (host_id, program))
                value.retain(value.hosts, host_id)
        value.arrays.append((ids, versions))
        value.rows += len(chunk.frame)
        value.array_bytes += ids.nbytes + versions.nbytes
        return FoldDelta(value, value.array_bytes + value.identity_bytes)

    def commit(run: _Facts, delta: FoldDelta) -> _Facts:
        value = delta.value
        if value.key is not None:
            run.arrays[value.key] = tuple(
                np.concatenate([pair[column] for pair in value.arrays]) for column in (0, 1)
            )
            run.delta_bytes[value.key] = delta.resident_bytes
        run.counts.update(value.counts)
        run.pairs.update(value.pairs)
        run.hosts.update(value.hosts)
        run.arbitration.update(value.arbitration)
        run.checkpoint = None
        return run

    def abort(run: _Facts) -> _Facts:
        run.miner.drain = run.checkpoint
        for text in run.texts[run.checkpoint_len:]:
            del run.index[text]
        del run.texts[run.checkpoint_len:]
        run.checkpoint = None
        return run

    return FoldSink('syslog.templates', seed_file, consume, lambda: facts,
                    commit, host.mask, abort_file=abort,
                    max_file_delta_bytes=MAX_DECLARED_FILE_DELTA_BYTES)


def candidates(facts: _Facts, envelope: set[int]) -> AdmitSink:
    """Keep every potentially rare, reboot or transaction row in source order."""
    from sigwood.parsers.syslog import (
        REBOOT_SIGNALS_RE, ADMIN_SESSION_OPEN_RE, ADMIN_SESSION_CLOSE_RE,
        ADMIN_SESSION_ENRICHER_RE, UPDATE_RUN_ANCHOR_RE,
    )
    grammars = (REBOOT_SIGNALS_RE, ADMIN_SESSION_OPEN_RE, ADMIN_SESSION_CLOSE_RE,
                ADMIN_SESSION_ENRICHER_RE, UPDATE_RUN_ANCHOR_RE)
    # Preparation owns the facts through finish. The registration must not keep
    # the miner and its indexes alive during downstream detector processing.
    facts = weakref.proxy(facts)

    def admit(chunk: Any) -> pd.DataFrame:
        if chunk.file_key in facts.aborted_files:
            return pd.DataFrame(columns=_COLUMNS)
        ids, versions = facts.arrays[chunk.file_key]
        start, stop = chunk.first_ordinal, chunk.first_ordinal + len(chunk.frame)
        ids, versions = ids[start:stop], versions[start:stop]
        if len(ids) != len(chunk.frame):
            raise ValueError('template admission ordinal mismatch')
        keep = np.isin(ids, list(envelope))
        messages = chunk.frame['message'].astype(str)
        for grammar in grammars:
            keep |= messages.str.contains(grammar, na=False).to_numpy()
        keep &= (ids >= 0) & np.asarray(chunk.report_mask, dtype=bool)
        frame = chunk.frame.loc[keep].copy()
        frame['template_id'] = ids[keep].astype(np.int64)
        frame['template_str'] = [facts.texts[int(version)] for version in versions[keep]]
        return frame

    return AdmitSink('syslog.candidates', admit, _COLUMNS)


def finish(facts: _Facts, host: Any, context: Any, final: Any) -> SyslogPrepared:
    """Mine the remaining feed last and resolve rarity over the full population."""
    from sigwood.detectors import syslog
    with host.timer('finish'):
        # The runner compares outcomes before finish; retain this invariant guard.
        if facts.committed_files is not None and (
            final.file_outcomes is None or
            final.file_outcomes.committed != facts.committed_files
        ):
            raise ValueError('committed file set changed')
        zeek = context.logs.get('syslog*.log*')
        counts, pairs, hosts = facts.counts.copy(), facts.pairs.copy(), facts.hosts.copy()
        if zeek is not None and not zeek.empty:
            zeek = zeek.copy()
            ids, texts = [], []
            for row in zeek.itertuples(index=False):
                tid, version = facts.mine(row.message)
                ids.append(tid)
                texts.append(facts.texts[version])
                counts[tid] += 1
                identity = _identity(row.host)
                pairs[identity, _identity(row.program)] += 1
                hosts[identity] += 1
            zeek['template_id'] = np.asarray(ids, dtype=np.int64)
            zeek['template_str'] = texts
        cfg = context.config
        threshold, rare = syslog._rarity_threshold(
            counts, cfg.get('rarity_pct', syslog.DEFAULT_CONFIG['rarity_pct']),
            cfg.get('max_count', syslog.DEFAULT_CONFIG['max_count']),
        )
        return SyslogPrepared(zeek, threshold, dict(counts), rare, dict(pairs), dict(hosts))


def prepare(host: Any) -> Preparation | Declined:
    """Register candidate loading only for a complete, independent local window."""
    from sigwood.detectors import syslog
    if host.sibling_needs_frame:
        return Declined(DeclineReason.INELIGIBLE, 'a sibling consumes the pattern')
    if not host.exact_window:
        return Declined(DeclineReason.INELIGIBLE, 'default window pending')
    if not host.local_files:
        return Declined(DeclineReason.INELIGIBLE, 'no local files')
    if (host.upper_bound_bytes is not None and
            host.upper_bound_bytes <= SMALL_INPUT_BYTES):
        return Declined(DeclineReason.INELIGIBLE, 'small input')
    cfg = host.config
    facts = _Facts(syslog._new_miner(
        cfg.get('sim_thresh', syslog.DEFAULT_CONFIG['sim_thresh']),
        cfg.get('depth', syslog.DEFAULT_CONFIG['depth']),
        cfg.get('parametrize_numeric', syslog.DEFAULT_CONFIG['parametrize_numeric']),
        syslog._template_masks(),
    ))
    window = host.report_window
    result = host.fold(SinkPlan((templates_sink(host, facts),), preserve_frame=False),
                       window, tail_policy='whole')
    status = result.prepared_status.get('syslog.templates')
    if status is None:
        return Declined(DeclineReason.FAILED, 'template index unavailable')
    if status.state is not PreparedState.READY:
        reason = DeclineReason.ABSTAINED if status.state is PreparedState.ABSTAINED else DeclineReason.FAILED
        return Declined(reason, status.cause)
    max_count = cfg.get('max_count', syslog.DEFAULT_CONFIG['max_count'])
    outcomes = result.file_outcomes[host.pattern]
    facts.aborted_files = outcomes.aborted
    facts.committed_files = outcomes.committed
    population = sum(facts.counts.values())
    envelope_rows = sum(count for count in facts.counts.values() if count <= max_count)
    if population and envelope_rows / population >= DENSE_CANDIDATE_SHARE:
        # No admission is registered. Drop both owners before ordinary loading.
        del result, facts
        return Declined(DeclineReason.INELIGIBLE, 'dense candidates')
    envelope = {tid for tid, count in facts.counts.items() if count <= max_count}
    host.final(SinkPlan(admit=candidates(facts, envelope)), window,
               prepared_snapshot=result.snapshots[host.pattern])
    def finish_once(context: Any, final: Any) -> SyslogPrepared:
        nonlocal facts
        try:
            return finish(facts, host, context, final)
        finally:
            facts = None

    return Preparation(finish_once, facts.arbitration, facts.committed_files)
