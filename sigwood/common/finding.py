"""Finding dataclass and Severity enum - the shared contract between detectors and outputs.

Detectors produce list[Finding]. Output handlers consume list[Finding].
Nothing else crosses that boundary.

DigestCard and DigestSlot are peer types to Finding/RunSummary - used by the
digest verb to render an orient-before-the-hunt card. They carry no severity,
no evidence, no next_steps; digest never produces a verdict.
"""

from __future__ import annotations

import copy
import enum
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import pandas as pd

    from sigwood.common.allowlist import AllowlistMatcher


class Severity(enum.Enum):
    """Detection severity levels, rendered as bracketed tags in text output."""

    HIGH = "H"
    MEDIUM = "M"
    LOW = "L"
    INFO = "I"

    def __str__(self) -> str:
        return f"[{self.value}]"

    def __lt__(self, other: "Severity") -> bool:
        _order = [Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        return _order.index(self) < _order.index(other)


@dataclass
class Finding:
    """A single detection result produced by a detector.

    Detectors return list[Finding]. Output handlers render them.
    The evidence dict is detector-specific - no fixed schema.
    description and next_steps are only shown in verbose output.
    """

    detector: str
    severity: Severity
    title: str
    description: str
    evidence: dict[str, Any]
    next_steps: list[str]
    ts_generated: datetime
    data_window: tuple[datetime, datetime]


@dataclass(frozen=True)
class MethodTag:
    """Per-detector method label, surfaced in the run-summary banner.

    ``named=True`` marks a published algorithm (FFT, drain3, fast-HDBSCAN) -
    rendered with parentheses and painted by the text handler. ``named=False``
    marks an honest house badge (pattern, heuristics, statistical) - rendered
    in plain brackets, never painted. The parens-vs-brackets carry 100% of
    the meaning; color is enhancement only.
    """

    label: str
    named: bool


@dataclass(frozen=True)
class SuppressionSummary:
    """Per-run allowlist coverage, surfaced on the run-summary banner.

    ``enabled`` is the effective master state for THIS run (false when
    ``--no-allowlist`` or a false master switch). ``connections`` / ``domains`` /
    ``host_rows`` are scope-blind counts of rows the allowlist covers across the
    loaded frames - "how much of the data the allowlist suppresses", not a
    per-detector view. ``connection_total`` / ``domain_total`` / ``host_total``
    are the row totals of eligible frames per kind. The first two are denominators
    behind the banner percentages; host coverage is disclosed as rows and
    distinct matched hosts.
    """

    enabled: bool
    connections: int
    domains: int
    connection_total: int = 0
    domain_total: int = 0
    host_rows: int = 0
    host_total: int = 0
    hosts_matched: int = 0


@dataclass
class RunSummary:
    """Metadata about a sigwood run, printed before analysis begins and passed to output handlers."""

    # None = no loaded rows establish a window; renderers answer "none"/null
    # rather than inventing a span.
    data_window: tuple[datetime, datetime] | None
    record_counts: dict[str, int]
    data_size_bytes: int
    detectors_run: list[str]
    detectors_skipped: dict[str, str]  # name → reason
    notes: list[str] = field(default_factory=list)
    data_sources: list[str] = field(default_factory=list)
    detector_methods: dict[str, "MethodTag | None"] = field(default_factory=dict)
    # The window the operator asked for (default-window spec, explicit since/until
    # span, or since→now), used by the text handler's data-found underfill
    # parenthetical. None = unconstrained (--all / until-only / bounded full-load).
    requested_span: timedelta | None = None
    # Per-run allowlist coverage for the banner's `allowlist:` line. The runner
    # always provides it on the detect path; None elsewhere (no line rendered).
    suppression: "SuppressionSummary | None" = None
    # Detectors that were selected and started but did not complete - name →
    # "prep error - <first line>" / "detector error - <first line>" (the phase
    # prefix distinguishes a runner-prep failure from a detector-side raise;
    # the reason never embeds the detector name - renderers prefix it). The ONE
    # field written DURING the detector loop: it records loop outcomes, so
    # begin()-time surfaces (the text banner) never read it - it is consumed by
    # end()-time renderers (json, the html header, the text report tail).
    # Failed names REMAIN in detectors_run (run = selected and attempted);
    # a failed detector contributed zero findings.
    detectors_failed: dict[str, str] = field(default_factory=dict)


@dataclass
class DigestSlot:
    """One row in a DigestCard's fields block.

    Bi-state:

    - SPEAKING: cells (pre-formatted column strings) AND
      entity/magnitude/ratio (raw values) are populated together. Cells and
      raw values come from the same source numbers; keeping the raw values
      lets insight selection sort by salience without parsing "3.7x" back
      out of a display string.

    - NON-SPEAKING (applicable but nothing notable, or feed cannot compute):
      all four value fields are None. The renderer never sees these slots
      - the summariser filters them out before handing fields to the card.
    """

    label: str                       # "conn-share", "fan-out", ...
    statistic: str                   # "cliff" | "tail" | "rate" | "share" | "dist"
    cells: list[str] | None = None
    entity: str | None = None
    magnitude: float | None = None
    ratio: float | None = None


@dataclass
class DigestCard:
    """A digest's per-schema rendered body. Peer to Finding, not a subclass.

    Carries the spine-derived ambient facts (window, record count, histogram,
    bytes) plus the summariser-derived ``zone1_extras`` ambient block,
    ``insights`` (prose sentences mechanically derived from speaking gated
    slots), and ``fields`` (the display-ready, already-filtered speaking
    non-insight slots). Selection happens in the summariser; the renderer
    is dumb.

    ``data_window`` may be ``(None, None)`` when timestamps in the loaded
    frame are unparseable below the confidence floor; the renderer renders
    identity line 2 as a bare ``-`` and the histogram line as
    ``(timeline unavailable)``.

    ``timeline_unavailable`` is the explicit sentinel for the histogram-
    suppression path. Without it, an empty ``histogram_counts`` could also
    mean "no events in window" (the valid empty-frame case) - a renderer
    looking only at counts cannot disambiguate.

    ``default_window_note``, when set, is the optional 4th identity-block
    line (rendered after ``schema · N lines · size``) disclosing that an
    unqualified Zeek digest truncated to the configured ``default_window``.
    Set ONLY when the loader resolved a default window; vanish-don't-dash -
    ``None`` renders no line. Reuses ``display.default_window_advisory`` so
    it never drifts from the analyze pre-load advisory.
    """

    schema: str
    source_name: str                  # identity-line-1; basename of source file or dir
    data_window: tuple[datetime | None, datetime | None]
    record_count: int
    histogram_counts: list[int]
    histogram_unit: str               # "hr" | "day"
    histogram_peak: int
    zone1_extras: list[tuple[str, str]] = field(default_factory=list)
    insights: list[str] = field(default_factory=list)
    fields: list[DigestSlot] = field(default_factory=list)
    data_size_bytes: int = 0
    timeline_unavailable: bool = False
    default_window_note: str | None = None


@dataclass
class BlobCard:
    """Unrecognized-source panel for the blob digest path. Peer to DigestCard,
    not a subclass. Carries the description-of-bytes-as-bytes panel the blob
    renderer needs - no slots, no histogram, no data_window - by design.

    The blob path describes bytes and never extracts fields. No timestamp is
    read, no schema is assumed. ``line_length_shape`` is exactly ``"uniform"``
    or ``"varied"`` when set. The char-class fractions are computed over RAW
    sampled BYTES (before UTF-8 decode) so binary-looking input shows up as
    low ``printable_pct`` rather than being masked by ``errors="replace"``.

    Vanish-don't-dash: optional fields default to None when their slot does
    not apply (binary terminal magic, drain3 dormant, freeform-no-structure
    template floor). The renderer omits the row entirely - no "-", no
    placeholder. Required fields are sample-derived facts that always exist
    for any input the profiler can read.

    O(sample) rail: every field is computed from the bounded sample. The only
    whole-file fact is ``byte_size`` (a stat). ``sampled_line_count`` is the
    line count over the sample, NEVER a whole-file total.
    """

    # always present - sample-derived facts that exist for any input
    source_name: str                     # identity-line-1; basename of the source path
    byte_size: int                       # on-disk size from stat (compressed for .gz)
    sampled_line_count: int
    sample_read_count: int               # 1 head + K seeks (plain); 1 (compressed head-only)
    is_compressed: bool
    printable_pct: float
    nonprintable_pct: float
    utf8_clean: bool                     # strict-decode probe over the sample

    # identification - exactly one of file_type_guess or shape_guess set
    file_type_guess: str | None = None    # terminal magic label (e.g. "PNG image")
    file_type_magic: bytes | None = None  # matched magic bytes for the Bytes row repr
    shape_guess: str | None = None        # text-shape cascade result

    # text slots - None on binary terminal hit
    mean_line_length: float | None = None
    median_line_length: float | None = None
    line_length_p95: int | None = None
    max_line_length: int | None = None
    line_length_stdev: float | None = None
    line_length_shape: str | None = None  # "uniform" | "varied" | None

    top_tokens: list[tuple[str, int]] | None = None

    # JSON shape-guess only - first-seen union of top-level object keys
    # across the sample. None on binary, on non-JSON text, and on top-
    # level-array/scalar JSON (no object keys to list). When set, the
    # renderer emits a `fields:` row in place of `tokens:` - names-no-
    # values, structurally describing the shape one rung deeper than the
    # `shape: JSON` label.
    json_field_names: list[str] | None = None

    # templates - None on binary / freeform-no-structure / drain3 dormant
    distinct_templates: int | None = None
    top_template_coverage_pct: float | None = None
    top_template_n: int | None = None
    singleton_template_count: int | None = None


@dataclass
class DetectorContext:
    """Everything a detector needs to do its job.

    The framework constructs this and passes it to each detector's run() function.
    Detectors never open files, read config, or format output directly.

    home_net is run/environment metadata (operator-declared internal networks
    for traffic-direction classification) - peer to data_window and data_sources,
    not detector tuning. Empty list means "not supplied"; detectors that need
    direction classification may apply a sensible fallback in that case.

    Verbosity is intentionally absent: the result set is verbosity-invariant
    by construction. Level-aware filtering happens at the text handler,
    not in detector ``run()``.
    """

    logs: dict[str, "pd.DataFrame"]
    config: dict[str, Any]
    allowlist: "AllowlistMatcher"
    data_window: tuple[datetime, datetime]
    data_sources: list[str] = field(default_factory=list)
    home_net: list[str] = field(default_factory=list)
