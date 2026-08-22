"""Zeek ssl.log / x509.log normalization to the canonical apertures.

Covers the exact column apertures, absence handling, the certificate-chain
leaf derivation, self-signed derivation from measured identity strings, and
the rename-collision predicate. Addresses are RFC 5737 documentation space.
"""

from __future__ import annotations

import pandas as pd

from sigwood.parsers.zeek import (
    _SSL_COLUMNS,
    _SSL_COLUMN_MAP,
    _X509_COLUMNS,
    _X509_COLUMN_MAP,
    _has_rename_collision,
    _normalize_ssl_df,
    _normalize_x509_df,
)


def _full_ssl_frame() -> pd.DataFrame:
    return pd.DataFrame(
        {
            "ts": [1787201941.1],
            "uid": ["CabCdE1"],
            "id.orig_h": ["192.0.2.10"],
            "id.orig_p": [51234],
            "id.resp_h": ["198.51.100.20"],
            "id.resp_p": [443],
            "version": ["TLSv12"],
            "cipher": ["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"],
            "curve": ["secp256r1"],
            "server_name": ["service.example.com"],
            "resumed": [False],
            "established": [True],
            "ssl_history": ["CsxIi"],
            "next_protocol": ["h2"],
            "validation_status": ["ok"],
            "sni_matches_cert": [True],
            "cert_chain_fps": [["aa11", "bb22"]],
            "client_cert_chain_fps": [[]],
            "last_alert": [None],
        }
    )


def test_ssl_normalizer_yields_the_exact_ordered_aperture() -> None:
    out = _normalize_ssl_df(_full_ssl_frame())
    assert list(out.columns) == list(_SSL_COLUMNS)


def test_ssl_normalizer_renames_and_carries_values() -> None:
    out = _normalize_ssl_df(_full_ssl_frame()).iloc[0]
    assert out["src"] == "192.0.2.10"
    assert out["dst"] == "198.51.100.20"
    assert out["port"] == 443
    assert out["sni"] == "service.example.com"
    assert out["alpn"] == "h2"
    assert out["validation_status"] == "ok"
    assert bool(out["established"]) is True
    assert bool(out["resumed"]) is False


def test_ssl_normalizer_drops_every_unread_zeek_field() -> None:
    out = _normalize_ssl_df(_full_ssl_frame())
    for dropped in (
        "uid",
        "id.orig_p",
        "ssl_history",
        "sni_matches_cert",
        "client_cert_chain_fps",
        "last_alert",
        "cert_chain_fps",
    ):
        assert dropped not in out.columns


def test_ssl_normalizer_never_fabricates_an_absent_optional_column() -> None:
    minimal = pd.DataFrame(
        {
            "ts": [1787201941.1],
            "id.orig_h": ["192.0.2.10"],
            "id.resp_h": ["198.51.100.20"],
            "id.resp_p": [443],
        }
    )
    out = _normalize_ssl_df(minimal)
    assert list(out.columns) == ["ts", "src", "dst", "port"]


def test_ssl_cert_fp_takes_the_chain_leaf() -> None:
    out = _normalize_ssl_df(_full_ssl_frame())
    assert out.loc[0, "cert_fp"] == "aa11"


def test_ssl_cert_fp_is_null_for_an_empty_or_unusable_chain() -> None:
    df = _full_ssl_frame()
    df["cert_chain_fps"] = [[]]
    assert pd.isna(_normalize_ssl_df(df).loc[0, "cert_fp"])
    df2 = _full_ssl_frame()
    df2["cert_chain_fps"] = [None]
    assert pd.isna(_normalize_ssl_df(df2).loc[0, "cert_fp"])
    df3 = _full_ssl_frame()
    df3["cert_chain_fps"] = [[123]]
    assert pd.isna(_normalize_ssl_df(df3).loc[0, "cert_fp"])


def test_ssl_cert_fp_column_absent_when_the_chain_column_is_absent() -> None:
    df = _full_ssl_frame().drop(columns=["cert_chain_fps"])
    assert "cert_fp" not in _normalize_ssl_df(df).columns


def _full_x509_frame() -> pd.DataFrame:
    return pd.DataFrame(
        {
            "ts": [1787201900.0],
            "fingerprint": ["aa11"],
            "certificate.subject": ["CN=service.example.com"],
            "certificate.issuer": ["CN=Example Issuing CA"],
            "certificate.not_valid_before": [1780000000.0],
            "certificate.not_valid_after": [1790000000.0],
            "certificate.key_alg": ["rsaEncryption"],
            "certificate.key_length": [2048],
            "certificate.sig_alg": ["sha256WithRSAEncryption"],
            "certificate.serial": ["0A0B"],
            "san.dns": [["service.example.com"]],
            "basic_constraints.ca": [False],
            "host_cert": [True],
            "client_cert": [False],
        }
    )


def test_x509_normalizer_yields_the_exact_ordered_aperture() -> None:
    out = _normalize_x509_df(_full_x509_frame())
    assert list(out.columns) == list(_X509_COLUMNS)


def test_x509_normalizer_drops_identity_and_unread_fields() -> None:
    out = _normalize_x509_df(_full_x509_frame())
    for dropped in (
        "certificate.subject",
        "certificate.issuer",
        "certificate.sig_alg",
        "certificate.serial",
        "san.dns",
        "basic_constraints.ca",
        "host_cert",
        "client_cert",
    ):
        assert dropped not in out.columns


def test_x509_self_signed_is_measured_string_equality() -> None:
    df = _full_x509_frame()
    assert _normalize_x509_df(df).loc[0, "self_signed"] is False or (
        _normalize_x509_df(df).loc[0, "self_signed"] == False  # noqa: E712
    )
    same = _full_x509_frame()
    same["certificate.issuer"] = same["certificate.subject"]
    assert bool(_normalize_x509_df(same).loc[0, "self_signed"]) is True


def test_x509_self_signed_is_unknown_when_identity_is_not_measured() -> None:
    """A missing identity string yields NA, never False - False would assert
    'not self-signed' about a certificate whose identities were never read."""
    for bad in (None, float("nan"), 17):
        df = _full_x509_frame()
        df["certificate.issuer"] = [bad]
        out = _normalize_x509_df(df)
        assert pd.isna(out.loc[0, "self_signed"])


def test_x509_self_signed_absent_when_identity_columns_are_absent() -> None:
    df = _full_x509_frame().drop(
        columns=["certificate.subject", "certificate.issuer"]
    )
    assert "self_signed" not in _normalize_x509_df(df).columns


def test_rename_collision_predicate_covers_both_new_maps() -> None:
    ssl_collide = set(_full_ssl_frame().columns) | {"src"}
    assert _has_rename_collision(ssl_collide, _SSL_COLUMN_MAP) is True
    assert _has_rename_collision(set(_full_ssl_frame().columns), _SSL_COLUMN_MAP) is False
    x_collide = set(_full_x509_frame().columns) | {"key_length"}
    assert _has_rename_collision(x_collide, _X509_COLUMN_MAP) is True
    assert _has_rename_collision(set(_full_x509_frame().columns), _X509_COLUMN_MAP) is False


# ── the aperture's three declarations ─────────────────────────────────────────

def _documented_aperture(heading: str) -> list[str]:
    """The column names a docs/SCHEMA.md fenced block declares, in order."""
    import pathlib

    text = (
        pathlib.Path(__file__).resolve().parents[1] / "docs" / "SCHEMA.md"
    ).read_text(encoding="utf-8")
    body = text.split(heading, 1)[1].split("```", 2)[1]
    return [
        line.split(" ", 1)[0].strip()
        for line in body.strip().splitlines()
        if line.strip() and not line.startswith(" ")
    ]


def test_ssl_aperture_declarations_stay_in_lockstep() -> None:
    """Three places declare this aperture - the normalizer's ordered tuple, the
    public schema, and the required/optional contract. Checking two of them
    against each other by hand is how a field goes missing from the third."""
    documented = _documented_aperture("### Canonical TLS-session schema (Zeek ssl.log)")
    assert documented == list(_SSL_COLUMNS)

    from sigwood.parsers.zeek import _OPTIONAL_COLUMNS, _REQUIRED_COLUMNS

    assert _REQUIRED_COLUMNS["ssl"] == set(_SSL_COLUMNS)
    assert _OPTIONAL_COLUMNS["ssl"] == set(_SSL_COLUMNS) - {"ts", "src", "dst", "port"}


def test_x509_aperture_declarations_stay_in_lockstep() -> None:
    documented = _documented_aperture(
        "### Canonical certificate-fact schema (Zeek x509.log)"
    )
    assert sorted(documented) == sorted(_X509_COLUMNS)

    from sigwood.parsers.zeek import _OPTIONAL_COLUMNS, _REQUIRED_COLUMNS

    assert _REQUIRED_COLUMNS["x509"] == set(_X509_COLUMNS)
    assert _OPTIONAL_COLUMNS["x509"] == set(_X509_COLUMNS) - {"ts", "fingerprint"}


def test_every_dropped_ssl_field_is_named_in_the_public_schema() -> None:
    """A field the normalizer sheds must be listed as dropped, or a reader
    reasonably concludes the parser simply never saw it."""
    import pathlib

    text = (
        pathlib.Path(__file__).resolve().parents[1] / "docs" / "SCHEMA.md"
    ).read_text(encoding="utf-8")
    shed = set(_full_ssl_frame().columns) - set(_SSL_COLUMN_MAP) - set(_SSL_COLUMNS)
    for field in shed:
        assert f"`{field}`" in text, f"{field} is dropped but not documented"
