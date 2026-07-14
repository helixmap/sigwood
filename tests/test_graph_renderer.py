"""Security and packaged-asset contracts for the graph HTML renderer."""

from __future__ import annotations

import json
import math
import re
from importlib import resources

import pytest

from sigwood.outputs.graph import _MARKER, _embed_payload, render_graph_html


def _player_template() -> str:
    return (
        resources.files("sigwood.outputs")
        .joinpath("graph_player.html")
        .read_text(encoding="utf-8")
    )


def _payload() -> dict[str, object]:
    return {
        "meta": {
            "generator": "sigwood",
            "display_utc": True,
            "default_window_note": "showing the default 7d window",
            "hunt_hint": None,
            "source": "192.0.2.40/conn.log",
        },
        "srcNodes": ["192.0.2.40"],
        "dstNodes": ["198.51.100.24"],
        "svcNodes": ["443/tcp"],
        "flows": [],
    }


def _data_script_blob(html: str) -> str:
    """Return the JSON text from the dedicated first data script."""
    prefix = "const DATA = "
    _, after_prefix = html.split(prefix, 1)
    blob, _ = after_prefix.split(";</script>", 1)
    return blob


@pytest.mark.parametrize(
    ("template", "count"),
    [
        ("<script>const DATA = null;</script>", 0),
        (f"{_MARKER} then {_MARKER}", 2),
    ],
)
def test_embed_payload_requires_one_marker(template: str, count: int) -> None:
    with pytest.raises(ValueError, match=rf"exactly one payload marker \(found {count}\)"):
        _embed_payload(_payload(), template)


def test_marker_valued_log_data_is_preserved_after_single_replacement() -> None:
    payload = {"host": "192.0.2.44", "note": _MARKER}

    rendered = _embed_payload(payload, f"before:{_MARKER}:after")

    assert rendered == f'before:{{"host":"192.0.2.44","note":"{_MARKER}"}}:after'


def test_hostile_script_tokens_cannot_close_the_data_script() -> None:
    hostile = "< / </script><script>alert('192.0.2.55')</script>"
    payload = {"host": "192.0.2.55", "label": hostile}
    rendered = _embed_payload(payload, f"<script>const DATA = {_MARKER};</script>")
    blob = _data_script_blob(rendered)

    assert "<" not in blob
    assert r"\u003c / \u003c/script>\u003cscript>" in blob
    assert rendered.count("</script>") == 1
    assert json.loads(blob) == payload


@pytest.mark.parametrize("nonfinite", [math.nan, math.inf, -math.inf])
def test_embed_payload_rejects_nonfinite_values(nonfinite: float) -> None:
    with pytest.raises(ValueError):
        _embed_payload({"metric": nonfinite}, _MARKER)


def test_renderer_loads_the_packaged_player_resource() -> None:
    template = _player_template()
    artifact = render_graph_html(_payload())

    assert template.count(_MARKER) == 1
    assert _MARKER not in artifact
    assert json.loads(_data_script_blob(artifact)) == _payload()


def test_player_labeled_readout_display_and_window_metadata_contracts() -> None:
    template = _player_template()

    for label in ("source", "records", "entities", "bin"):
        assert f'<span class="readout-label">{label}</span>' in template
    assert '<span class="readout-label" id="meta-derivation-label">derivation</span>' in template
    assert '<span class="readout-label" id="meta-window-label">window</span>' in template
    assert '$("meta-source").textContent = source;' in template
    assert '$("meta-source").title = source;' in template
    assert '$("meta-source-dir").textContent = commonDir;' in template
    assert '$("meta-source-dir").title = commonDir;' in template
    assert '`${sample} + ${otherCount} ${otherCount === 1 ? "other" : "others"}`' in template
    assert '$("meta-kind").textContent = M.kind || "graph";' in template
    assert '$("meta-entities-cell").hidden = !hasEntities;' in template
    assert '.replace(/\\s+seen$/i, "").trim()' in template
    assert 'entityNoun.toLowerCase() === "entities"' in template
    assert '? fmtN(M.distinct_hosts)' in template
    assert ': `${fmtN(M.distinct_hosts)} ${entityNoun}`;' in template
    assert '$("meta-derivation-cell").hidden = !hasDerivation && !hasDegrade;' in template
    assert '$("meta-derivation-label").textContent = hasDerivation ? "derivation" : "note";' in template
    assert 'if (hasDerivation) $("meta-derivation").textContent = M.metric_note;' in template
    assert 'if (hasDegrade) $("meta-degrade").textContent = M.degrade_note;' in template
    assert ".readout-value[hidden], .readout-sub[hidden] { display: none; }" in template
    assert '$("meta-window-label").textContent = `window (${fmtDur(Math.round(M.t1 - M.t0))})`;' in template
    assert '$("meta-window-start").textContent = fmtStamp(M.t0);' in template
    assert '$("meta-window-end").textContent = fmtStamp(M.t1);' in template
    assert (
        "grid-template-columns: max-content minmax(160px,3fr)\n"
        "    repeat(3,minmax(78px,auto)) minmax(120px,1fr);"
    ) in template
    readout = template.split('<div class="readout-grid">', 1)[1].split(
        "</div>\n    <div class=\"readout-foot\"", 1,
    )[0]
    assert readout.index('class="readout-cell window"') < readout.index(
        'class="readout-cell source"'
    )
    assert "border-bottom: 1px solid var(--border);" in template
    assert "padding: 10px 18px 8px 18px;" in template
    assert "meta-window-note" not in template
    assert "meta-generator" not in template
    assert "M.default_window_note" not in template
    assert 'ctx.fillText(M.generator || "sigwood", W - 10, H - 8);' in template
    assert "srcmeta" not in template
    assert "winnote" not in template
    assert 'const clockPart = (d, local, utc) => M.display_utc ? d[utc]() : d[local]();' in template
    assert "const fmtStamp = sec => {" in template
    assert "${fmtStamp(M.t0)} → ${fmtStamp(M.t1)} ${TZ_LABEL}" not in template
    assert template.count("${TZ_LABEL}") == 1
    assert 'if (M.display_utc) d.setUTCHours(0, 0, 0, 0);' in template
    assert 'if (M.display_utc) return "UTC";' in template

    # A downloaded replay is part of the rendered operator surface. Its date
    # must obey the same display-timezone switch as its clock fields.
    clip_start = template.index("const name = `sigwood-graph_clip_")
    clip_end = template.index(";", clip_start)
    clip_name = template[clip_start:clip_end]
    assert 'clockPart(d, "getFullYear", "getUTCFullYear")' in clip_name
    assert 'clockPart(d, "getMonth", "getUTCMonth")' in clip_name
    assert 'clockPart(d, "getDate", "getUTCDate")' in clip_name


def test_player_polish_tokens_cover_the_full_theme_and_speed_contract() -> None:
    """Every player theme and initial-control rule stays coordinated."""
    template = _player_template()

    assert template.count("--sother:#0d9f9f;") == 2
    assert template.count("--sother:#38c0c0;") == 2
    assert template.count("--clock: #0a6e2e;") == 2
    assert template.count("--clock: #7dff58;") == 2
    assert template.count("--wordmark: #8a5320;") == 2
    assert template.count("--wordmark: #e38e30;") == 2
    assert "color: var(--clock)" in template
    assert "color: var(--wordmark)" in template
    assert '<span class="wm">sigwood</span>' in template
    assert '<span class="kind-chip" id="meta-kind"></span>' in template
    hleft = template.split('<div class="hleft">', 1)[1].split("</div>\n  <div class=\"readout\">", 1)[0]
    assert hleft.count('id="meta-kind"') == 1
    assert '<div class="mark"><span class="wm">sigwood</span><span class="dim">·</span><span>graph</span></div>' in hleft
    assert '<div id="bigclock"><span id="bc-time">-:-:-</span></div>' in hleft
    assert '<span id="bc-cal"><span id="bc-day"></span><span id="bc-sub"></span></span>' in hleft
    assert "display: grid; grid-template-columns: auto auto; justify-content: start;" in template
    assert "grid-column: 2; grid-row: 1; justify-self: start;" in template
    assert "grid-column: 2; grid-row: 2;" in template
    assert "border: 1.5px solid var(--accent)" in template
    assert 'font-family: Georgia, "Bookman Old Style", "Times New Roman", serif;' in template
    assert '$("bc-day").textContent = WEEKDAYS[clockPart(d, "getDay", "getUTCDay")];' in template
    assert "--sother:#a5adb8;" not in template
    assert "--sother:#4a545f;" not in template
    assert "let radius = 1;" in template
    assert "Math.max(2, Math.round(B / 160))" not in template
    assert "[60, 120, 300, 600, 900, 1800" in template
    assert "span / r >= 4 && (r >= 300 || span / r <= 1800)" in template
    assert "Math.max(60, Math.round(span / 240))" in template
    assert "Math.abs(span / b - 240) < Math.abs(span / a - 240)" in template


def test_player_radius_cap_uses_validated_numeric_sink_and_clips_keep_meta() -> None:
    template = _player_template()

    assert "const naturalRadius = Math.max(6, Math.round(B / 12));" in template
    assert "Number.isInteger(M.max_radius) && M.max_radius >= 6" in template
    assert "? M.max_radius : naturalRadius;" in template
    assert "winEl.max = Math.min(naturalRadius, radiusCap);" in template
    assert "winEl.max = Math.max(6, Math.round(B / 12));" not in template
    assert "meta: { ...M," in template
    assert "max_radius:" not in template.split("meta: { ...M,", 1)[1].split("},", 1)[0]
    assert "degrade_note:" not in template.split("meta: { ...M,", 1)[1].split("},", 1)[0]


def test_player_hunt_copy_uses_clipboard_with_selectable_fallback() -> None:
    template = _player_template()

    assert '$("meta-hunt-foot").hidden = !M.hunt_hint;' in template
    assert ".readout-foot[hidden] { display: none; }" in template
    assert "sigwood hunt PATH" not in template
    assert "async function copyHunt()" in template
    assert "const attempt = ++copyAttempt;" in template
    assert "if (attempt !== copyAttempt) return;" in template
    assert "await navigator.clipboard.writeText(M.hunt_hint);" in template
    assert 'const area = document.createElement("textarea");' in template
    assert "area.value = text;" in template
    assert 'area.style.position = "fixed";' in template
    assert 'area.style.left = "-10000px";' in template
    assert "area.focus(); area.select(); area.setSelectionRange(0, area.value.length);" in template
    assert 'document.execCommand("copy")' in template
    assert "area.remove();" in template
    assert 'button.textContent = copied ? "copied" : "copy failed";' in template
    assert 'button.textContent = "copy hunt";' in template


def test_clip_export_reuses_the_data_script_escape_before_reembedding() -> None:
    """The downloaded replay cannot reintroduce a closing script token."""
    template = _player_template()
    payload = {"label": "</script><script>alert('x')</script>"}

    # Pin the executable clip boundary, not merely the server-side renderer.
    assert r'const blob = JSON.stringify(payload).replace(/</g, "\\u003c");' in template
    blob = json.dumps(payload, separators=(",", ":"), ensure_ascii=True).replace(
        "<", "\\u003c",
    )
    rebuilt = f"<script>const DATA = {blob};</script>"

    assert "<" not in blob
    assert rebuilt.count("</script>") == 1
    assert json.loads(blob) == payload


def test_player_preserves_fractional_counts_in_every_weighted_surface() -> None:
    """Weighted query mass remains visible in the replay and downloaded clip."""
    template = _player_template()

    assert 'if (n > 0 && n < 0.1) return "<0.1";' in template
    assert 'if (Number.isInteger(n)) return Math.round(n).toLocaleString("en-US");' in template
    assert 'minimumFractionDigits:1, maximumFractionDigits:1' in template
    assert 'minimumFractionDigits:2, maximumFractionDigits:2' in template
    assert '$("st-cps").textContent = fmtN(cps);' in template
    assert 'fmtN(M.weighted ? nConns : Math.floor(nConns))' in template
    assert 'fmtN(e.v / BIN) + "/s"' in template
    assert 'fmtN(v / BIN) + "/s"' in template
    assert "rows, clip: true," in template
    assert "totB: [...ntotB], totC: [...ntotC]," in template
    assert "Math.round(db[x])" not in template
    assert "Math.round(dc[x])" not in template


def test_player_round_two_controls_and_draw_contracts_stay_coordinated() -> None:
    template = _player_template()

    # Timeline: lines and labels have separate clamped cadences, O(1) anchoring,
    # theme-aware text, and a date branch for the weekly fallback.
    assert "const TL_UNITS = [1, 5, 15, 30, 60, 300, 900, 1800, 3600, 86400, 604800];" in template
    assert "return TL_UNITS[TL_UNITS.length - 1];" in template
    assert "return ladder.find(value => value >= k) ?? ladder[ladder.length - 1];" in template
    font = template.index('tctx.font = "9px ui-monospace')
    measure = template.index("tctx.measureText(sample)", font)
    assert font < measure
    assert "let idx = Math.ceil((M.t0 - tick) / unit);" in template
    assert "while (tick < M.t0)" not in template
    assert "unit >= 86400" in template
    assert "unit === 86400" in template
    assert "tctx.fillStyle = TH.muted;" in template
    assert "tctx.globalAlpha = 1;" in template

    # Tile ratios are identity-keyed and the mobile reset matches compound
    # selector specificity.
    assert "repeat(auto-fit, minmax(32px, 1fr))" in template
    assert ".tile.w-med { grid-column: span 4; }" in template
    assert ".tile.w-wide { grid-column: span 5; }" in template
    assert ".tile, .tile.w-med, .tile.w-wide { grid-column: auto; }" in template
    assert 'class="tile w-med" id="tile-rate"' in template
    assert template.count('class="tile w-wide"') == 2

    # Fill styles share one renderer without changing the blend default.
    assert 'let ribbonStyle = "blend";' in template
    assert 'const cacheKey = (hard ? "H" : "") + key;' in template
    assert "g.addColorStop(0.5, c0); g.addColorStop(0.5, c1);" in template
    assert 'ribbonStyle === "split"' in template
    assert 'ribbonStyle === "src"' in template
    assert 'ribbonStyle === "dst"' in template
    assert 'const restA = ribbonStyle === "blend" ? 0.66 : 0.85;' in template
    assert "r.hot ? 0.85 : baseA" in template

    # `(other)` recedes at draw time only; the breathe mechanism is inert at 0.
    assert "const OTHER_RIBBON_DIM = 0.45, OTHER_BAR_ALPHA = 0.55;" in template
    assert template.count("? OTHER_RIBBON_DIM : 1") == 3
    assert "if (id === OTHER) ctx.globalAlpha = OTHER_BAR_ALPHA;" in template
    assert "const glow = id !== OTHER;" in template
    assert "let robustPeak = { b: 1, c: 1 };" in template
    floor = template.index("floorRate[m] =")
    filtered_peak = template.index("fPeak[m] =", floor)
    robust = template.index("robustPeak[m] =", filtered_peak)
    assert floor < filtered_peak < robust
    assert "let breathe = 0;" in template
    assert "const target = breathe > 0" in template
    assert "Math.pow(targetFill, 1 - breathe) * Math.pow(targetAbs, breathe)" in template
    assert " ^ " not in template
    assert 'seg("fill", b => { ribbonStyle = b.dataset.f; });' in template
    assert 'seg("breathe", b => { breathe = +b.dataset.breathe; snapScale = true; });' in template


def test_player_is_self_contained_and_has_no_stale_poc_or_dash_residue() -> None:
    template = _player_template()
    for forbidden in (
        r"https?://",
        r"(?<!:)//[a-z0-9][a-z0-9.-]*(?:[/:?#]|$)",
        r"<\s*link\b",
        r"<\s*script\s+[^>]*\bsrc\s*=",
        r"<\s*(?:iframe|object|embed|source|img|video|audio|track)\b",
        r"<[^>]*\b(?:src|href|poster|data)\s*=",
        r"@import\b",
        r"(?<![a-z0-9_])url\s*\(",
        r"data\s*:",
        r"fetch\s*\(",
        r"xmlhttprequest\b",
        r"websocket\b",
        r"navigator\s*\.\s*sendbeacon\b",
        r"import\s*\(",
        r"innerhtml\b",
        r"insertadjacenthtml\b",
        r"document\s*\.\s*write\s*\(",
        r"eval\s*\(",
        r"new\s+function\b",
        r"new\s+worker\s*\(",
        r"new\s+eventsource\s*\(",
        r"importscripts\s*\(",
        r"serviceworker\b",
    ):
        assert re.search(forbidden, template, flags=re.IGNORECASE) is None, forbidden

    # The player intentionally creates a local Blob download through DOM
    # properties. Attribute checks above are tag-scoped so this path remains
    # allowed without permitting external resource markup.
    assert "URL.createObjectURL(new Blob(" in template
    assert "link.href = url; link.download = name" in template

    lowered = template.lower()
    for stale in ("poc", "newton", "\u2013", "\u2014"):
        assert stale not in lowered


@pytest.mark.parametrize(
    ("pattern", "variant"),
    [
        (r"fetch\s*\(", "fetch (target)"),
        (r"new\s+function\b", "new\nFunction(code)"),
        (r"<\s*script\s+[^>]*\bsrc\s*=", "<script\n src = target>"),
        (r"<[^>]*\b(?:src|href|poster|data)\s*=", "<img\n src = target>"),
        (r"(?<![a-z0-9_])url\s*\(", "url (target)"),
        (r"new\s+worker\s*\(", "new\nWorker (target)"),
    ],
)
def test_player_resource_patterns_cover_whitespace_variants(
    pattern: str, variant: str,
) -> None:
    """The self-containment patterns catch spacing changes in sink syntax."""
    assert re.search(pattern, variant, flags=re.IGNORECASE) is not None
