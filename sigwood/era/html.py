"""Self-contained HTML presentation for already-measured Era cards."""

from __future__ import annotations

from html import escape

from sigwood.common.sanitize import strip_control
from sigwood.era.report import EraCard, SelectionEvidence, SpanHonesty, render_masthead_lines


def _text(value: str) -> str:
    """Return untrusted data as quoted, inert HTML text."""
    return escape(strip_control(value), quote=True)


def _styles() -> str:
    return """
:root { --bg:#ffffff; --fg:#17202a; --muted:#59636f; --border:#d5dbe2; --card:#f8fafc; --wordmark: #8a5320; }
@media (prefers-color-scheme: dark) { :root { --bg:#14181d; --fg:#e6eaef; --muted:#9aa4b1; --border:#2a3038; --card:#1c222a; --wordmark: #e38e30; } }
* { box-sizing: border-box; }
body { max-width: 1040px; margin: 0 auto; padding: 32px; color:var(--fg); background:var(--bg); font-family: system-ui, -apple-system, sans-serif; line-height:1.45; }
header { border-bottom:2px solid var(--border); margin-bottom:24px; padding-bottom:16px; }
.wordmark { font-size:22px; font-weight:700; margin-bottom:8px; }
.brand { font-family: Georgia, "Bookman Old Style", "Times New Roman", serif; color:var(--wordmark); }
.masthead { color:var(--muted); margin:3px 0; }
.card { background:var(--card); border:1px solid var(--border); border-radius:8px; margin:14px 0; padding:16px; break-inside:avoid; }
h2 { font-size:17px; margin:0 0 10px; }
dl { display:grid; grid-template-columns:minmax(11rem, 30%) 1fr; gap:6px 14px; margin:0; }
dt { color:var(--muted); } dd { margin:0; overflow-wrap:anywhere; }
pre { white-space:pre-wrap; overflow-wrap:anywhere; margin:8px 0 0; font: 13px ui-monospace, SFMono-Regular, Menlo, monospace; }
.evidence { border-top:1px solid var(--border); margin-top:24px; padding-top:16px; }
@media print { @page { margin:1.5cm; } body { max-width:none; padding:0; } .card { break-inside:avoid; -webkit-print-color-adjust:exact; print-color-adjust:exact; } }
""".strip()


def render_html_report(
    cards: tuple[EraCard, ...],
    *,
    family: str,
    span_honesty: SpanHonesty | None = None,
    selection_evidence: SelectionEvidence | None = None,
) -> str:
    """Render cards as an inert, self-contained document without I/O."""
    masthead = [f'<div class="masthead">{_text(line)}</div>' for line in render_masthead_lines(family, span_honesty)]
    rendered_cards = []
    for card in cards:
        facts = "".join(f"<dt>{_text(label)}</dt><dd>{_text(value)}</dd>" for label, value in card.facts)
        slots = "".join(f"<pre>{_text(slot.when)}: {_text(slot.inspect_command)}</pre>" for slot in card.slots)
        rendered_cards.append(f'<section class="card"><h2>{_text(card.title)}</h2><dl>{facts}</dl>{slots}</section>')
    evidence = ""
    if selection_evidence is not None:
        rows = [
            f"card 8: speaking weeks {selection_evidence.card_eight_speaking_weeks}; below floor {selection_evidence.card_eight_subfloor_weeks}; tie {selection_evidence.card_eight_tie}",
            f"card 9: admissible {selection_evidence.card_nine_admissible_candidates}; refused {selection_evidence.card_nine_refused_candidates}; tie {selection_evidence.card_nine_tie}",
        ]
        if selection_evidence.card_ten_reason:
            rows.append(f"card 10: {selection_evidence.card_ten_reason}")
        evidence = '<section class="evidence"><h2>selection evidence</h2><pre>' + _text("\n".join(rows)) + "</pre></section>"
    return (
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
        "<title>sigwood era</title><style>" + _styles() + "</style></head><body>"
        '<header><div class="wordmark"><span class="brand">sigwood</span> · era</div>'
        + "".join(masthead) + "</header><main>" + "".join(rendered_cards) + evidence
        + "</main></body></html>\n"
    )
