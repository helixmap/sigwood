"""Single-ownership source resolution for sigwood.

One owner of positional→source and config-fallback resolution, so the CLI
seams cannot drift. Invariants:

- ``None`` means strictly "no override," NEVER "scoped out - don't load this";
  ``scope`` is the only scoping signal. Overloading ``None`` for both would let
  a config fallback fill a scoped-out ``None`` back and undo CLI scoping
  (``sigwood syslog ./flat.log`` must NOT then also load configured Zeek
  ``syslog*.log*`` on a default install) - the explicit ``scope`` below
  prevents that.
- ``resolve_sources`` is the analyze resolver; ``resolve_digest_source`` is the
  digest resolver; ``_resolve_one`` is the ONLY site where a source-dir string
  becomes a resolved ``Path`` (CLI seams pass raw strings or ``None`` and the
  runner threads them straight in).
- One generic content-sniff router, ``route_positional_source``: a file
  content-sniffs to its family, a directory runs a bounded content vote and
  falls back to the detector's declared source on an inconclusive result - no
  per-verb ladder, no ``detector_name`` special case.

Layering: this module imports ``common.paths`` and ``common.loader``
(content sniffing). It MUST NOT import from ``sigwood.detectors`` -
``route_positional_source`` takes an already-imported detector module
as a parameter; the CLI does the ``importlib`` work.
"""

from __future__ import annotations

import fnmatch
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

from sigwood.common.loader import discover_for_source_key, sniff_format_detailed
from sigwood.common.paths import effective_root, resolve_path

_ALL_KEYS: tuple[str, ...] = (
    "zeek_dir", "syslog_dir", "pihole_dir", "cloudtrail_dir",
)

_DIR_SNIFF_SAMPLE_LIMIT = 32
_DIR_ORIGIN_PRIORITY: tuple[str, ...] = (
    "zeek", "pihole", "syslog", "cloudtrail",
)
_PERMISSION_FILENAME_HINTS: tuple[tuple[str, str], ...] = (
    ("pihole*.log*", "pihole"),
)


@dataclass(frozen=True)
class GraphKindSpec:
    """One graphable source kind and its loader/sniff contract.

    ``source_key`` and ``pattern`` are consumed by the generic loader-owned
    discovery seam. ``sniff_schema`` and ``sniff_origin`` map a positional
    file's existing detailed-sniff result to this kind. Keeping the four facts
    together makes adding a graph kind an append-only declaration instead of a
    coordinated edit across CLI, runner, and discovery ladders.
    """

    kind: str
    source_key: str
    pattern: str
    sniff_schema: str
    sniff_origin: str


@dataclass(frozen=True)
class GraphProbeIssue:
    """One graph input that could not join a renderable bucket."""

    path: Path
    message: str
    permission: bool = False


@dataclass(frozen=True)
class GraphProbeResult:
    """Graph source buckets plus non-fatal routing/disclosure sidecars."""

    buckets: dict[str, list[Path]]
    issues: tuple[GraphProbeIssue, ...]
    multi_kinds: dict[str, tuple[str, ...]]
    mixed_votes: dict[str, dict[str, int]]


# Ordered public graph-kind declaration. The order is the supported-kind
# narration order and remains stable as new graphable families are added.
GRAPH_KINDS: tuple[GraphKindSpec, ...] = (
    GraphKindSpec(
        kind="conn",
        source_key="zeek_dir",
        pattern="conn*.log*",
        sniff_schema="conn",
        sniff_origin="zeek",
    ),
    GraphKindSpec(
        kind="dns",
        source_key="zeek_dir",
        pattern="dns*.log*",
        sniff_schema="dns",
        sniff_origin="zeek",
    ),
)


def graph_kind_for_sniff(
    schema: str | None,
    origin: str | None,
) -> GraphKindSpec | None:
    """Return the graph kind matching a detailed-sniff schema/origin pair.

    A detailed sniff recognizes more formats than graph supports. ``None`` is
    therefore the normal unsupported result rather than an error for the CLI
    to translate into its graph-to-digest refusal.
    """
    for spec in GRAPH_KINDS:
        if spec.sniff_schema == schema and spec.sniff_origin == origin:
            return spec
    return None


def discover_graph_kinds(directory: str | Path) -> dict[str, list[Path]]:
    """Return non-empty graph-kind buckets discovered under one directory.

    Iteration follows ``GRAPH_KINDS`` order. A directory can therefore yield
    both conn and dns buckets, while a kind with no matching files does not
    create an empty bucket for the CLI to mistake for a graphable source.
    """
    root = Path(directory).expanduser()
    buckets: dict[str, list[Path]] = {}
    for spec in GRAPH_KINDS:
        files = discover_for_source_key(spec.source_key, root, spec.pattern)
        if files:
            buckets[spec.kind] = files
    return buckets


def graph_kind_spec(kind: str) -> GraphKindSpec:
    """Return the declared graph kind or an actionable unsupported-kind error."""
    for spec in GRAPH_KINDS:
        if spec.kind == kind:
            return spec
    supported = ", ".join(spec.kind for spec in GRAPH_KINDS)
    raise ValueError(f"graph kind {kind!r} is not supported (supported: {supported})")


def graph_supported_kinds() -> tuple[str, ...]:
    """Return graph kind labels in the public declaration order."""
    return tuple(spec.kind for spec in GRAPH_KINDS)


def _present(value: object) -> bool:
    """An override counts only when it carries a real value.

    The CLI parser stores a bare ``--zeek-dir=`` (no value after the ``=``) as
    the EMPTY STRING - not None, not rejected. ``None``-vs-``""`` is a
    falsy-vs-None ambiguity: treating ``""`` as "present" makes
    ``_resolve_one("", …)`` return None and silently suppresses config fallback,
    so a configured ``[sigwood].zeek_dir`` is ignored when the operator passes
    a bare flag. Truthiness semantics (``if cli_val:``) at the boundary avoid
    this: any falsy override (None, "", empty Path string) is "no override."

    Used by the digest resolver, which stays scalar-shaped (digest is
    card-per-file; multi-input union does not apply). The analyze resolver
    uses ``_normalize_overrides`` instead, which handles scalar / list /
    None uniformly under the same falsy-is-absent rule.
    """
    return bool(value)


def _permission_hint_origin(path: Path) -> str | None:
    """Return a narrow source-family hint for an unreadable filename."""
    for pattern, origin in _PERMISSION_FILENAME_HINTS:
        if fnmatch.fnmatch(path.name, pattern):
            return origin
    return None


def _directory_vote_tally(path: Path) -> dict[str, int]:
    """Tally source origins over a bounded directory sample.

    One tally feeds both the winner pick and the mixed-sample disclosure so the
    two can never disagree. Empty dict = nothing recognizable sampled.
    """
    try:
        children = sorted(path.iterdir(), key=lambda p: p.name)
    except OSError:
        return {}

    votes: dict[str, int] = {}
    sampled = 0
    for child in children:
        try:
            if not child.is_file():
                continue
        except OSError:
            continue
        sampled += 1
        if sampled > _DIR_SNIFF_SAMPLE_LIMIT:
            break
        try:
            result = sniff_format_detailed(child)
        except PermissionError:
            origin = _permission_hint_origin(child)
        except OSError:
            origin = None
        else:
            origin = result.origin
        if origin in _DIR_ORIGIN_PRIORITY:
            votes[origin] = votes.get(origin, 0) + 1
    return votes


def _directory_vote_origin(
    path: Path, *, _vote_sink: dict[str, dict[str, int]] | None = None,
) -> str | None:
    """Return the dominant source origin from a bounded directory sample.

    ``_vote_sink`` is an optional caller-owned sink (the ``discover_detectors``
    ``_failures`` shape): when the sample holds MORE THAN ONE recognizable
    family, the full tally is recorded under the directory's string path so the
    caller can disclose that the losing families will not load as their own
    kind. A single-family or empty sample records nothing.
    """
    votes = _directory_vote_tally(path)
    if not votes:
        return None
    if _vote_sink is not None and len(votes) > 1:
        _vote_sink[str(path)] = dict(
            sorted(votes.items(), key=lambda kv: (-kv[1], kv[0]))
        )
    return max(
        votes,
        key=lambda origin: (
            votes[origin],
            -_DIR_ORIGIN_PRIORITY.index(origin),
        ),
    )


def _normalize_overrides(
    value: str | Path | Sequence[str | Path] | None,
) -> list[str | Path]:
    """Normalize an override value to a list of truthy scalar inputs.

    The widened contract for ``runner.run``'s four source-dir kwargs is
    ``str | Path | Sequence[str | Path] | None``. This function is the SINGLE
    rule:

    - ``None`` → ``[]`` (absent - signal config fallback within scope)
    - scalar truthy ``str`` / ``Path`` → ``[scalar]`` (one-element list - the
      degenerate case that keeps programmatic scalar callers byte-identical)
    - scalar falsy (``""`` / empty Path string) → ``[]`` (absent - same
      ``_present`` semantics, just expressed at the list boundary)
    - sequence → ``[v for v in value if v]`` - drop falsy members FIRST so
      ``["", "/x"]`` and ``["/x"]`` are equivalent, PRESERVE order

    Dedup is intentionally NOT here. Cross-input dedup by ``.resolve()``
    happens at the loader file-union site (``_union_dedupe``), not at the
    string layer; doing it here would collapse two CLI inputs whose strings
    differ but resolve to the same file BEFORE the user sees them rendered
    in ``_print_dry_run``.
    """
    if value is None:
        return []
    if isinstance(value, (str, Path)):
        return [value] if value else []
    return [v for v in value if v]


@dataclass(frozen=True)
class ResolvedSources:
    """The four source-dir buckets, resolved once by ``resolve_sources``.

    Each field is the LIST of resolved ``Path`` inputs the runner should
    load from for that family - positionals contributed by the CLI,
    explicit ``--<family>-dir`` flag values, and config fallback (within
    scope). An EMPTY LIST means the source is neither overridden nor
    configured, or is scoped out of the run.

    Single-input shape is the degenerate one-element list: scalar
    programmatic callers (``runner.run(zeek_dir="/x")``) flow through
    ``_normalize_overrides`` and land here as ``[Path("/x")]`` -
    byte-identical downstream behavior with the prior scalar shape.
    """

    zeek_dir: list[Path]
    syslog_dir: list[Path]
    pihole_dir: list[Path]
    cloudtrail_dir: list[Path]


@dataclass(frozen=True)
class DigestSource:
    """The single source chosen by ``resolve_digest_source`` for a digest schema.

    Attributes:
        source_key: One of ``zeek_dir`` / ``syslog_dir`` / ``pihole_dir`` /
            ``cloudtrail_dir`` - the key ``run_digest`` looks up its
            (pattern, empty_columns) mapping against.
        directory: Resolved directory ``Path`` to load from.
        feed: Schema-specific feed identifier - ``"zeek"`` / ``"pihole"`` /
            ``"syslog"`` for the fidelity-aware schemas (dns, syslog), or
            ``None`` for the single-source schemas (conn, cloudtrail).
    """

    source_key: str
    directory: Path
    feed: str | None


def _resolve_one(
    override: str | Path | None,
    cfg_value: Any,
    root: str,
) -> Path | None:
    """Single-key atom - the ONE site that converts a source-dir string to a Path.

    A non-None ``override`` is treated as a CLI/explicit value and goes
    through ``resolve_path(str(override), "")`` - shell semantics: ``~``
    expansion, no SIGWOOD_ROOT prefix (CLI-supplied paths resolve against CWD as
    shells expect). A None ``override`` falls back to ``cfg_value`` resolved
    via SIGWOOD_ROOT (``resolve_path(cfg_value, root)``). Either branch returning
    a falsy string yields ``None``.

    ``str(override)`` so a ``Path`` override round-trips identically - only
    the resulting absolute-or-relative string semantics matter to
    ``resolve_path``.
    """
    if override is not None:
        resolved = resolve_path(str(override), "")
    else:
        resolved = resolve_path(cfg_value, root)
    return Path(resolved) if resolved else None


def resolve_sources(
    config: dict[str, Any],
    *,
    overrides: dict[str, str | Path | Sequence[str | Path] | None],
    scope: frozenset[str] | None,
) -> ResolvedSources:
    """Resolve all four source dirs for an analyze run, list-shaped.

    Per-key truth table (after ``_normalize_overrides`` → ``list[str | Path]``):

    +------------------------+----------------------------------+--------------------------------------------------+
    | override list          | scope                            | result                                           |
    +========================+==================================+==================================================+
    | non-empty              | any                              | ``[_resolve_one(o, None, root) for o in list]``  |
    +------------------------+----------------------------------+--------------------------------------------------+
    | empty                  | ``None`` or ``key in scope``     | ``[_resolve_one(None, cfg_value, root)]``        |
    +------------------------+----------------------------------+--------------------------------------------------+
    | empty                  | ``key not in scope``             | ``[]`` - NEVER config-filled                     |
    +------------------------+----------------------------------+--------------------------------------------------+

    An override outside ``scope`` still applies - that is the operator
    widening the run deliberately.

    Single-element override lists give byte-identical downstream behavior
    with the prior scalar shape, so ``runner.run(zeek_dir="/x")`` callers
    (~35 sites + ``tests/test_root_provenance.py``) remain unchanged at
    their call site - the normalization layer accepts either form.

    Config fallback resolves a single config string per key (config-supplied
    list shapes are NOT a v1 feature - out of scope here; revisit when the
    config surface advertises a list form). The resulting one-element
    list keeps the bucket non-empty so the loader sees it as present.
    """
    cfg_sigwood = config.get("sigwood", {})
    root = effective_root(config)
    resolved: dict[str, list[Path]] = {}
    for key in _ALL_KEYS:
        override_list = _normalize_overrides(overrides.get(key))
        if override_list:
            resolved[key] = [
                p for p in (_resolve_one(o, None, root) for o in override_list)
                if p is not None
            ]
        elif scope is None or key in scope:
            cfg_path = _resolve_one(None, cfg_sigwood.get(key), root)
            resolved[key] = [cfg_path] if cfg_path is not None else []
        else:
            resolved[key] = []
    return ResolvedSources(**resolved)


def resolve_graph_source(
    config: dict[str, Any],
    kind: str,
    *,
    inputs: str | Path | Sequence[str | Path] | None = None,
) -> tuple[GraphKindSpec, list[Path]]:
    """Resolve one graph kind's raw inputs through the shared source owner.

    Graph has one source family per kind today, but it must not grow its own
    path resolver. ``inputs`` follows the runner's established override shape:
    a truthy value is an explicit CLI/programmatic input, while ``None`` falls
    back to the declared source key in config. The returned paths deliberately
    retain both directories and explicit files so the runner can use the same
    combined shape for default-window boundedness and trusted-file loading.
    """
    spec = graph_kind_spec(kind)
    resolved = resolve_sources(
        config,
        overrides={spec.source_key: inputs},
        scope=frozenset({spec.source_key}),
    )
    return spec, list(getattr(resolved, spec.source_key))


def graph_has_explicit_inputs(
    inputs: str | Path | Sequence[str | Path] | None,
) -> bool:
    """Return whether graph source resolution retains an explicit override.

    Graph's trusted-file bypass is allowed only for an input that survived the
    shared override normalization.  Falsy scalar and sequence members fall
    through to config just as they do in :func:`resolve_graph_source`, so they
    must not accidentally make a config file trusted at the runner seam.
    """
    return bool(_normalize_overrides(inputs))


def _graph_path_kind(path: Path) -> str:
    """Classify a graph input without swallowing a permission failure."""
    try:
        mode = path.stat().st_mode
    except FileNotFoundError as exc:
        raise ValueError("not found") from exc
    except PermissionError:
        raise
    except OSError as exc:
        raise ValueError("could not inspect graph input") from exc
    if stat.S_ISREG(mode):
        return "file"
    if stat.S_ISDIR(mode):
        return "directory"
    raise ValueError("graph input is not a regular file or directory")


def _graph_unsupported_message(path: Path) -> str:
    """Return the one actionable unsupported-input status message."""
    supported = ", ".join(graph_supported_kinds())
    return (
        f"can't graph {path.name} - graph supports {supported}; "
        "try 'sigwood digest PATH'"
    )


def _graph_config_filename_message(path: Path, spec: GraphKindSpec) -> str:
    """Explain why a configured file cannot receive positional trust."""
    return (
        f"can't graph {path.name} from config - it does not match "
        f"{spec.pattern} discovery; pass it as a PATH to graph its sniffed "
        f"{spec.kind} data"
    )


def _probe_graph_directory(path: Path) -> tuple[dict[str, list[Path]], dict[str, int]]:
    """Probe a readable directory through graph discovery and the mixed vote."""
    # ``iterdir`` is deliberately touched before discovery: Path.glob can turn
    # a denied directory into an empty match set, which would lie as clean-empty
    # instead of preserving the strict graph permission outcome.
    try:
        next(iter(path.iterdir()), None)
    except PermissionError:
        raise
    except OSError as exc:
        raise ValueError("could not inspect graph input") from exc
    return discover_graph_kinds(path), _directory_vote_tally(path)


def _append_bucket(
    buckets: dict[str, list[Path]], kind: str, path: Path,
) -> None:
    """Append one input while retaining declaration-order bucket assembly."""
    buckets.setdefault(kind, []).append(path)


def probe_graph_inputs(
    config: dict[str, Any],
    inputs: Sequence[str | Path] | None = None,
) -> GraphProbeResult:
    """Resolve graph inputs without letting one bad path abort sibling buckets.

    The result preserves graphable same-kind buckets plus typed probe issues.
    The CLI owns narration and final exit precedence, so a bad or denied input
    can be reported while a valid sibling still produces its artifact. Directory
    probing remains loader-owned and the bounded directory vote is retained only
    to disclose non-graphable families that graph intentionally skips.
    """
    buckets: dict[str, list[Path]] = {}
    issues: list[GraphProbeIssue] = []
    multi_kinds: dict[str, tuple[str, ...]] = {}
    mixed_votes: dict[str, dict[str, int]] = {}
    graph_origins = {spec.sniff_origin for spec in GRAPH_KINDS}

    def _issue(path: Path, exc: Exception) -> None:
        if isinstance(exc, PermissionError):
            issues.append(GraphProbeIssue(
                path,
                "permission denied - grant your user read access and retry",
                permission=True,
            ))
        else:
            issues.append(GraphProbeIssue(path, str(exc)))

    def _record_directory(path: Path, discovered: dict[str, list[Path]], tally: dict[str, int]) -> None:
        for kind in discovered:
            _append_bucket(buckets, kind, path)
        if len(discovered) > 1:
            multi_kinds[str(path)] = tuple(discovered)
        non_graph_votes = {
            origin: count for origin, count in tally.items()
            if origin not in graph_origins
        }
        if non_graph_votes:
            mixed_votes[str(path)] = dict(tally)

    raw_inputs = list(inputs or ())
    if raw_inputs:
        root = effective_root(config)
        for raw in raw_inputs:
            path = _resolve_one(raw, None, root)
            if path is None:
                continue
            try:
                kind = _graph_path_kind(path)
                if kind == "file":
                    sniff = sniff_format_detailed(path)
                    spec = graph_kind_for_sniff(sniff.schema, sniff.origin)
                    if spec is None:
                        raise ValueError(_graph_unsupported_message(path))
                    _append_bucket(buckets, spec.kind, path)
                    continue
                discovered, tally = _probe_graph_directory(path)
                if discovered:
                    _record_directory(path, discovered, tally)
                elif tally:
                    raise ValueError(_graph_unsupported_message(path))
                else:
                    # An empty explicit directory is a selected source with no
                    # renderable rows, not an unconfigured-source error.
                    for spec in GRAPH_KINDS:
                        _append_bucket(buckets, spec.kind, path)
            except (PermissionError, ValueError, OSError) as exc:
                _issue(path, exc)
    else:
        # Resolve one configured source family at a time. When a configured
        # directory has no graphable files, retain empty buckets for that family
        # so runner.run_graph can return the honest GraphEmpty control signal.
        seen_sources: set[tuple[str, Path]] = set()
        for spec in GRAPH_KINDS:
            _, candidates = resolve_graph_source(config, spec.kind)
            for path in candidates:
                source_id = (spec.source_key, path)
                if source_id in seen_sources:
                    continue
                seen_sources.add(source_id)
                family_specs = tuple(
                    item for item in GRAPH_KINDS if item.source_key == spec.source_key
                )
                try:
                    kind = _graph_path_kind(path)
                    if kind == "file":
                        sniff = sniff_format_detailed(path)
                        matched = graph_kind_for_sniff(sniff.schema, sniff.origin)
                        if matched is not None and matched.source_key == spec.source_key:
                            if discover_for_source_key(
                                matched.source_key, path, matched.pattern,
                            ):
                                _append_bucket(buckets, matched.kind, path)
                            else:
                                raise ValueError(
                                    _graph_config_filename_message(path, matched)
                                )
                        else:
                            raise ValueError(_graph_unsupported_message(path))
                        continue
                    discovered, tally = _probe_graph_directory(path)
                    matching = {
                        item.kind: files
                        for item, files in (
                            (item, discovered.get(item.kind, []))
                            for item in family_specs
                        )
                        if files
                    }
                    if matching:
                        _record_directory(path, matching, tally)
                    else:
                        for item in family_specs:
                            _append_bucket(buckets, item.kind, path)
                    non_graph_votes = {
                        origin: count for origin, count in tally.items()
                        if origin not in graph_origins
                    }
                    if non_graph_votes:
                        mixed_votes[str(path)] = dict(tally)
                except (PermissionError, ValueError, OSError) as exc:
                    _issue(path, exc)

    ordered = {
        spec.kind: buckets[spec.kind]
        for spec in GRAPH_KINDS
        if spec.kind in buckets
    }
    return GraphProbeResult(
        buckets=ordered,
        issues=tuple(issues),
        multi_kinds=multi_kinds,
        mixed_votes=mixed_votes,
    )


def graph_buckets_for_inputs(
    config: dict[str, Any],
    inputs: Sequence[str | Path] | None = None,
    *,
    _mixed_sink: dict[str, tuple[str, ...]] | None = None,
) -> dict[str, list[Path]]:
    """Compatibility wrapper returning buckets or surfacing the first issue."""
    result = probe_graph_inputs(config, inputs)
    if result.issues:
        issue = result.issues[0]
        if issue.permission:
            raise PermissionError(issue.message)
        raise ValueError(issue.message)
    if _mixed_sink is not None:
        _mixed_sink.update(result.multi_kinds)
    return result.buckets


# Per-schema candidate ladder + feed mapping for the digest resolver.
# Order = preference: first non-None config value wins on fallback.
_DIGEST_CANDIDATES: dict[str, tuple[str, ...]] = {
    "conn":       ("zeek_dir",),
    "dns":        ("zeek_dir", "pihole_dir"),
    "syslog":     ("syslog_dir", "zeek_dir"),
    "cloudtrail": ("cloudtrail_dir",),
}

_DIGEST_FEED: dict[tuple[str, str], str | None] = {
    ("conn",       "zeek_dir"):       None,
    ("dns",        "zeek_dir"):       "zeek",
    ("dns",        "pihole_dir"):     "pihole",
    ("syslog",    "syslog_dir"):      "syslog",
    ("syslog",    "zeek_dir"):        "zeek",
    ("cloudtrail", "cloudtrail_dir"): None,
}

# Error strings for the digest source resolvers, kept stable for callers that
# match on them. The wrong-key message is templated; the XOR and not-configured
# messages are static per schema.
_DIGEST_XOR_MSG: dict[str, str] = {
    "dns":    "digest dns: cannot use both --zeek-dir and --pihole-dir",
    "syslog": "digest syslog: cannot use both zeek_dir and syslog_dir",
}

_DIGEST_NOT_CONFIGURED_MSG: dict[str, str] = {
    "conn": (
        "digest: zeek_dir not configured - pass a PATH or set "
        "[sigwood].zeek_dir in your config"
    ),
    "dns": (
        "digest dns: zeek_dir or pihole_dir not configured - "
        "pass a PATH, --zeek-dir/--pihole-dir, or set one in config"
    ),
    "syslog": (
        "digest syslog: no syslog source configured - pass a PATH, "
        "--zeek-dir, or set [sigwood].syslog_dir / "
        "[sigwood].zeek_dir in your config"
    ),
    "cloudtrail": (
        "digest cloudtrail: cloudtrail_dir not configured - pass a PATH, "
        "--cloudtrail-dir, or set [sigwood].cloudtrail_dir in your config"
    ),
}


def _wrong_key_msg(schema: str, key: str) -> str:
    """Templated wrong-source error message - byte-equal to the prior text."""
    return f"digest {schema}: {key} is not valid for the {schema} schema"


def resolve_digest_source(
    config: dict[str, Any],
    schema: str,
    *,
    overrides: dict[str, str | Path | None],
) -> DigestSource:
    """Resolve the SINGLE source for a digest schema.

    Same ``None``-contract as ``resolve_sources``: an override is present
    only when its value is non-None. Raises ordinary ``ValueError`` on:

    - any non-None override OUTSIDE the schema's candidate set (wrong-key);
    - more than one non-None override INSIDE the candidate set (XOR);
    - no source resolved (not-configured).

    Error strings are byte-preserved from the previous ``run_digest``
    ladder so user-facing wording does not drift.
    """
    candidates = _DIGEST_CANDIDATES[schema]
    candidate_set = set(candidates)
    cfg_sigwood = config.get("sigwood", {})
    root = effective_root(config)

    for key in _ALL_KEYS:
        if key in candidate_set:
            continue
        if _present(overrides.get(key)):
            raise ValueError(_wrong_key_msg(schema, key))

    present_overrides = [
        k for k in candidates if _present(overrides.get(k))
    ]
    if len(present_overrides) > 1:
        raise ValueError(_DIGEST_XOR_MSG[schema])

    if present_overrides:
        chosen: str | None = present_overrides[0]
        directory = _resolve_one(overrides[chosen], None, root)
    else:
        chosen = None
        directory = None
        for k in candidates:
            d = _resolve_one(None, cfg_sigwood.get(k), root)
            if d is not None:
                chosen = k
                directory = d
                break

    if chosen is None or directory is None:
        raise ValueError(_DIGEST_NOT_CONFIGURED_MSG[schema])

    return DigestSource(
        source_key=chosen,
        directory=directory,
        feed=_DIGEST_FEED[(schema, chosen)],
    )


def route_positional_source(
    path: str | Path,
    *,
    detector_module: Any | None,
    _vote_sink: dict[str, dict[str, int]] | None = None,
) -> str:
    """Decide which source-dir key a positional PATH routes to.

    Generic - no detector-name special cases. ``_vote_sink`` (caller-owned,
    optional) receives the per-directory family tally whenever a DIRECTORY
    vote sampled more than one recognizable family - the caller discloses
    that the losing families are not loaded as their own kind.

    **Named-module mode** (``detector_module`` is an imported detector module):
    ``REQUIRED_LOGS`` carriers (beacon, scan, duration, aws, …) route to
    ``REQUIRED_LOGS[0]["source"]``. Two-source detectors (dns, syslog)
    content-sniff a file, or run the bounded directory vote for a directory,
    and route to the matching ``OPTIONAL_LOGS`` source; on miss or sniff
    ``OSError``, they fall back to ``OPTIONAL_LOGS[0]["source"]``.
    ``OPTIONAL_LOGS[0]`` reproduces both defaults:
    ``dns → zeek_dir`` and ``syslog → syslog_dir``.

    **None mode** (``detector_module is None``): for detect=all / unknown
    selectors. Content-sniff the positional and map ``origin → {origin}_dir``
    (cloudtrail → cloudtrail_dir, syslog → syslog_dir, zeek → zeek_dir,
    pihole → pihole_dir). Directories use the bounded vote helper. Falls back
    to ``zeek_dir`` on an unrecognized sniff, no directory votes, or a sniff
    ``OSError`` - the analyze default for unrecognized inputs. NOTE:
    ``common/sources.py`` MUST NOT import ``detectors/`` - the named-module
    branch still receives the imported module from the CLI.
    """
    path_obj = Path(path).expanduser()

    if detector_module is None:
        if path_obj.is_dir():
            origin = _directory_vote_origin(path_obj, _vote_sink=_vote_sink)
            candidate = f"{origin}_dir" if origin else None
            return candidate if candidate in _ALL_KEYS else "zeek_dir"
        try:
            result = sniff_format_detailed(path_obj)
        except OSError:
            return "zeek_dir"
        origin = result.origin
        candidate = f"{origin}_dir" if origin else None
        return candidate if candidate in _ALL_KEYS else "zeek_dir"

    required = getattr(detector_module, "REQUIRED_LOGS", [])
    if required:
        # ``.get("source", "zeek_dir")`` instead of ``["source"]`` - defensive
        # against a third-party / new detector whose REQUIRED_LOGS[0] omits
        # the source key. The error-boundary rail says lower layers raise
        # actionable exceptions, not bare KeyErrors. None of the six shipped
        # detectors trip this, but the default keeps the router callable
        # against malformed metadata.
        return required[0].get("source", "zeek_dir")
    optional = [
        o.get("source", "zeek_dir")
        for o in getattr(detector_module, "OPTIONAL_LOGS", [])
    ]
    default = optional[0] if optional else "zeek_dir"

    if path_obj.is_dir():
        origin = _directory_vote_origin(path_obj, _vote_sink=_vote_sink)
        candidate = f"{origin}_dir" if origin else None
        return candidate if candidate in optional else default
    try:
        result = sniff_format_detailed(path_obj)
    except OSError:
        return default

    origin = result.origin
    candidate = f"{origin}_dir" if origin else None
    return candidate if candidate in optional else default
