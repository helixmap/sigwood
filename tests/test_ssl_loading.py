"""Loader-side wiring for the Zeek ssl / x509 log types.

Covers normalizer dispatch by pattern, the rename-collision containment (a
warning plus a column-stable empty frame, never a raise), the schema warning,
and an end-to-end load in which a collision-bearing file yields no rows while
the run completes and a sibling source still loads. Addresses are RFC 5737
documentation space.
"""

from __future__ import annotations

import json
from pathlib import Path

import pandas as pd

from sigwood.common import loader
from sigwood.common.loader.diagnostics import _schema_warning
from sigwood.common.loader.pipeline import _zeek_normalize
from sigwood.parsers.zeek import _SSL_COLUMNS, _X509_COLUMNS


def _ssl_frame() -> pd.DataFrame:
    return pd.DataFrame(
        {
            "ts": [1787201941.1],
            "id.orig_h": ["192.0.2.10"],
            "id.resp_h": ["198.51.100.20"],
            "id.resp_p": [443],
            "version": ["TLSv12"],
            "cert_chain_fps": [["aa11"]],
        }
    )


def test_zeek_normalize_dispatches_the_ssl_pattern() -> None:
    out = _zeek_normalize(_ssl_frame(), "ssl*.log*")
    assert list(out.columns) == ["ts", "src", "dst", "port", "version", "cert_fp"]


def test_zeek_normalize_dispatches_the_x509_pattern() -> None:
    df = pd.DataFrame({"ts": [1.0], "fingerprint": ["aa11"], "certificate.key_length": [2048]})
    out = _zeek_normalize(df, "x509*.log*")
    assert list(out.columns) == ["ts", "fingerprint", "key_length"]


def test_ssl_rename_collision_warns_and_yields_a_column_stable_empty_frame() -> None:
    """The collision cannot raise: normalize runs post-concat, OUTSIDE the
    per-file parse containment, so a raise would abort the whole run."""
    df = _ssl_frame()
    df["src"] = ["192.0.2.10"]
    warnings: list[str] = []
    out = _zeek_normalize(df, "ssl*.log*", warnings=warnings)
    assert out.empty
    assert list(out.columns) == list(_SSL_COLUMNS)
    assert len(warnings) == 1
    assert "ssl.log" in warnings[0]
    assert "1" in warnings[0]


def test_x509_rename_collision_warns_and_yields_a_column_stable_empty_frame() -> None:
    df = pd.DataFrame(
        {"ts": [1.0], "fingerprint": ["aa11"], "certificate.key_alg": ["rsaEncryption"], "key_alg": ["x"]}
    )
    warnings: list[str] = []
    out = _zeek_normalize(df, "x509*.log*", warnings=warnings)
    assert out.empty
    assert list(out.columns) == list(_X509_COLUMNS)
    assert len(warnings) == 1
    assert "x509.log" in warnings[0]


def test_ssl_rename_collision_without_a_sink_is_silent_but_still_empties() -> None:
    df = _ssl_frame()
    df["src"] = ["192.0.2.10"]
    out = _zeek_normalize(df, "ssl*.log*")
    assert out.empty
    assert list(out.columns) == list(_SSL_COLUMNS)


def test_schema_warning_names_the_ssl_log_for_a_missing_flow_field() -> None:
    df = pd.DataFrame({"ts": [1.0], "src": ["192.0.2.10"], "port": [443]})
    warning = _schema_warning("ssl*.log*", df)
    assert warning is not None
    assert "ssl.log" in warning
    assert "dst" in warning


def test_schema_warning_stays_quiet_for_absent_optional_ssl_fields() -> None:
    df = pd.DataFrame(
        {"ts": [1.0], "src": ["192.0.2.10"], "dst": ["198.51.100.20"], "port": [443]}
    )
    assert _schema_warning("ssl*.log*", df) is None


def test_schema_warning_names_the_x509_log_for_a_missing_fingerprint() -> None:
    df = pd.DataFrame({"ts": [1.0], "key_length": [2048]})
    warning = _schema_warning("x509*.log*", df)
    assert warning is not None
    assert "x509.log" in warning
    assert "fingerprint" in warning


def _write_ndjson(path: Path, rows: list[dict]) -> None:
    path.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")


def test_a_collision_bearing_ssl_file_empties_while_the_run_completes(tmp_path: Path) -> None:
    """The whole point of containment: one pathological file yields no rows and
    one warning, and a sibling source in the same run still loads."""
    zeek_dir = tmp_path / "zeek"
    zeek_dir.mkdir()
    _write_ndjson(
        zeek_dir / "ssl.log",
        [
            {
                "_path": "ssl",
                "ts": 1787201941.1,
                "id.orig_h": "192.0.2.10",
                "src": "192.0.2.10",
                "id.resp_h": "198.51.100.20",
                "id.resp_p": 443,
            }
        ],
    )
    _write_ndjson(
        zeek_dir / "conn.log",
        [
            {
                "_path": "conn",
                "ts": 1787201941.1,
                "id.orig_h": "192.0.2.10",
                "id.resp_h": "198.51.100.20",
                "id.resp_p": 443,
                "proto": "tcp",
            }
        ],
    )
    result = loader.load_required_logs(
        {"ssl*.log*": "zeek_dir", "conn*.log*": "zeek_dir"},
        {"zeek_dir": [zeek_dir]},
        show_progress=False,
    )
    assert result.logs["ssl*.log*"].empty
    assert len(result.logs["conn*.log*"]) == 1
    assert any("ssl.log" in w for w in result.warnings)


def test_digest_profiles_a_recognized_but_cardless_log_and_says_so(
    tmp_path: Path, capsys
) -> None:
    """Recognizing a log type is not a promise of a card. ssl routes to the
    byte-profile floor - the rail's existing behavior for a recognized file
    with no usable summariser - and digest states why on stderr."""
    from sigwood.cli import main

    path = tmp_path / "ssl.log"
    _write_ndjson(
        path,
        [
            {
                "_path": "ssl",
                "ts": 1787201941.1,
                "id.orig_h": "192.0.2.10",
                "id.resp_h": "198.51.100.20",
                "id.resp_p": 443,
                "version": "TLSv12",
            }
        ],
    )
    rc = main(["digest", str(path)])
    captured = capsys.readouterr()
    assert (rc or 0) == 0
    assert "no digest card for ssl yet" in captured.err
    assert "ssl.log" in captured.out


def test_sniff_orchestrator_reports_ssl_with_a_zeek_origin(tmp_path: Path) -> None:
    """Positional routing reads origin, not schema: an ssl.log must land on
    zeek_dir, which requires the orchestrator to carry the Zeek origin."""
    from sigwood.common.loader.sniff import sniff_format_detailed

    path = tmp_path / "ssl.log"
    _write_ndjson(
        path,
        [{"_path": "ssl", "ts": 1.0, "id.orig_h": "192.0.2.10",
          "id.resp_h": "198.51.100.20", "id.resp_p": 443}],
    )
    result = sniff_format_detailed(path)
    assert result.schema == "ssl"
    assert result.origin == "zeek"


def test_a_cardless_schema_discloses_without_being_named_in_any_roster(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    """The disclosure must not depend on a hand-kept list of cardless schemas:
    a recognizer claim digest has no route for is disclosed by construction,
    or a future log type slides into the byte profile silently."""
    import sigwood.cli as cli_module
    from sigwood.common.loader.sniff import SniffResult

    path = tmp_path / "future.log"
    path.write_text('{"_path":"future","ts":1.0}\n', encoding="utf-8")
    # _run_digest imports the sniffer from the loader facade at call time.
    monkeypatch.setattr(
        loader,
        "sniff_format_detailed",
        lambda _p: SniffResult(state="ok", schema="future", origin="zeek"),
    )
    rc = cli_module.main(["digest", str(path)])
    captured = capsys.readouterr()
    assert (rc or 0) == 0
    assert "no digest card for future yet" in captured.err
    assert "future.log" in captured.out
