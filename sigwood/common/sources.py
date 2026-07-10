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
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

from sigwood.common.loader import sniff_format_detailed
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


def _directory_vote_origin(path: Path) -> str | None:
    """Return the dominant source origin from a bounded directory sample."""
    try:
        children = sorted(path.iterdir(), key=lambda p: p.name)
    except OSError:
        return None

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

    if not votes:
        return None
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
) -> str:
    """Decide which source-dir key a positional PATH routes to.

    Generic - no detector-name special cases.

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
            origin = _directory_vote_origin(path_obj)
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
        origin = _directory_vote_origin(path_obj)
        candidate = f"{origin}_dir" if origin else None
        return candidate if candidate in optional else default
    try:
        result = sniff_format_detailed(path_obj)
    except OSError:
        return default

    origin = result.origin
    candidate = f"{origin}_dir" if origin else None
    return candidate if candidate in optional else default
