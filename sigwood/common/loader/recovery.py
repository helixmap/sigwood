"""Replace a failed pattern using accounting captured by the loader."""
from dataclasses import replace

from sigwood.common.loader.types import LoadResult, SinkPlan, _population_metadata


def replace_pattern_load(
    result: LoadResult, pattern: str, plan: SinkPlan, reload: LoadResult,
) -> LoadResult:
    """Replace one pattern and rebuild aggregates without reading retained inputs."""
    if pattern not in result.contributions or pattern not in reload.contributions:
        raise ValueError("pattern recovery requires captured load contributions")
    for value in (result, reload):
        if not set(value.logs).issubset(value.contributions):
            raise ValueError("pattern recovery requires complete load contributions")
        if value.data_size_bytes != sum(c.data_size_bytes for c in value.contributions.values()):
            raise ValueError("pattern recovery byte accounting is incomplete")
        if value.warnings != [w for c in value.contributions.values() for w in c.warnings]:
            raise ValueError("pattern recovery warning accounting is incomplete")
    changes = {}
    for name in (
        "logs", "coverage", "rotation_skips", "permission_skips", "file_spans",
        "quality", "snapshots", "fold_results", "availability", "population", "contributions",
        "file_outcomes",
    ):
        values = getattr(result, name).copy()
        replacement = getattr(reload, name)
        if pattern in replacement:
            values[pattern] = replacement[pattern]
        else:
            values.pop(pattern, None)
        changes[name] = values
    channels = {sink.channel for sink in plan.folds}
    if plan.admit is not None:
        channels.add(plan.admit.channel)
    changes["prepared_status"] = {
        key: value for key, value in result.prepared_status.items() if key not in channels
    }
    counts, window = _population_metadata(changes["logs"], changes["population"])
    contributions = changes["contributions"]
    return replace(
        result, **changes, record_counts=counts, data_window=window,
        data_size_bytes=sum(c.data_size_bytes for c in contributions.values()),
        warnings=[w for c in contributions.values() for w in c.warnings],
    )
