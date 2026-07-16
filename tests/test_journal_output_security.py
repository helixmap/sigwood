"""Adversarial journal provider-note and multiline-finding output audit."""

from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

import pytest

import sigwood.cli as cli
from sigwood.common.loader import journal
from sigwood.outputs import pdf as pdf_mod


_MESSAGE = "first <script>alert(1)</script>\nsecond\tsegment\x1b[31m"


def _executable(tmp_path: Path) -> str:
    record = {
        "__REALTIME_TIMESTAMP": "1760000000000000",
        "MESSAGE": _MESSAGE,
        "_HOSTNAME": "host.example",
        "SYSLOG_IDENTIFIER": "placeholderd",
        "_PID": "7",
    }
    body = (
        "import json, sys\n"
        f"print(json.dumps({record!r}))\n"
        "sys.stderr.write('child\\x1b[31m\\nforged\\n')\n"
    )
    path = tmp_path / "journalctl"
    path.write_text(f"#!{sys.executable}\n{body}", encoding="utf-8")
    path.chmod(0o755)
    return str(path)


def _config(tmp_path: Path) -> Path:
    prefix = str(tmp_path).replace("\\", "\\\\").replace('"', '\\"')
    path = tmp_path / "config.toml"
    path.write_text(
        "[sigwood]\n"
        'root = ""\n'
        'detect = "syslog"\n'
        f'syslog_dir = "{prefix}/fallback\\u001b[31m\\nforged"\n'
        'syslog_source = "journal"\n'
        'zeek_dir = ""\n',
        encoding="utf-8",
    )
    return path


def _run(config: Path, target: Path, output_format: str) -> None:
    assert cli._main([
        "syslog", f"--config={config}", "--syslog-source=journal", "--all",
        "--quiet", f"--format={output_format}", f"--out={target}",
    ]) == 0


def test_provider_note_and_multiline_finding_are_safe_across_all_outputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    executable = _executable(tmp_path)
    monkeypatch.setattr(journal, "resolve_journalctl", lambda: executable)
    config = _config(tmp_path)

    captured_pdf_html: list[str] = []

    def fake_pdf(html: str) -> bytes:
        captured_pdf_html.append(html)
        return b"%PDF-fake"

    monkeypatch.setattr(pdf_mod, "_render_pdf_bytes", fake_pdf)

    text_path = tmp_path / "report.txt"
    json_path = tmp_path / "report.json"
    html_path = tmp_path / "report.html"
    pdf_path = tmp_path / "report.pdf"
    csv_path = tmp_path / "report.csv"
    _run(config, text_path, "text")
    _run(config, json_path, "json")
    _run(config, html_path, "html")
    _run(config, pdf_path, "pdf")
    _run(config, csv_path, "csv")

    stderr = capsys.readouterr().err
    assert "\x1b" not in stderr
    assert "\t" not in stderr
    assert "sigwood-journal-" not in stderr
    assert "journalctl: child[31m" in stderr
    assert "journalctl: forged" in stderr

    text = text_path.read_text(encoding="utf-8")
    compact_text = " ".join(text.split())
    assert "\x1b" not in text
    assert "\t" not in text
    assert "sigwood-journal-" not in text
    assert "fallback[31mforged fallback not loaded" in compact_text
    assert "first <script>alert(1)</script>secondsegment[31m" in text
    assert sum("system logs: journal" in line for line in text.splitlines()) == 1

    json_source = json_path.read_text(encoding="utf-8")
    assert "\x1b" not in json_source
    assert "sigwood-journal-" not in json_source
    payload = json.loads(json_source)
    provider_notes = [
        note for note in payload["run_summary"]["notes"]
        if note.startswith("system logs:")
    ]
    assert len(provider_notes) == 1
    assert "\x1b" not in provider_notes[0]
    assert "\n" not in provider_notes[0]
    assert payload["findings"][0]["title"] == _MESSAGE

    html = html_path.read_text(encoding="utf-8")
    assert "\x1b" not in html
    assert "\t" not in html
    assert "sigwood-journal-" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "fallback[31mforged fallback not loaded" in html

    assert pdf_path.read_bytes() == b"%PDF-fake"
    report_pdf_html = captured_pdf_html[-1]
    assert "\x1b" not in report_pdf_html
    assert "\t" not in report_pdf_html
    assert "sigwood-journal-" not in report_pdf_html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in report_pdf_html
    assert "fallback[31mforged fallback not loaded" in report_pdf_html

    csv_source = csv_path.read_text(encoding="utf-8")
    assert "\x1b" not in csv_source
    assert "\t" not in csv_source
    assert "sigwood-journal-" not in csv_source
    with csv_path.open("r", encoding="utf-8", newline="") as stream:
        rows = list(csv.DictReader(stream))
    assert len(rows) == 1
    assert rows[0]["finding"] == _MESSAGE.replace("\t", "").replace("\x1b", "")
    assert "system logs" not in rows[0]
    assert "provider" not in rows[0]
