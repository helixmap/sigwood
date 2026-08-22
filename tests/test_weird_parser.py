"""Zeek weird.log normalization to the canonical card aperture.

Addresses are RFC 5737 documentation space.
"""

from __future__ import annotations

import pandas as pd

from sigwood.parsers.zeek import (
    _WEIRD_COLUMN_MAP,
    _WEIRD_COLUMNS,
    _has_rename_collision,
    _normalize_weird_df,
)


def _full_frame() -> pd.DataFrame:
    return pd.DataFrame({
        "ts": [1785000000.0],
        "uid": ["CabCdE1"],
        "id.orig_h": ["192.0.2.10"],
        "id.orig_p": [51000],
        "id.resp_h": ["198.51.100.20"],
        "id.resp_p": [443],
        "name": ["window_recision"],
        "addl": [""],
        "notice": [False],
        "peer": ["zeek-worker-1"],
        "source": ["TCP"],
    })


def test_weird_normalizer_yields_the_exact_ordered_aperture() -> None:
    assert list(_normalize_weird_df(_full_frame()).columns) == list(_WEIRD_COLUMNS)


def test_weird_normalizer_renames_the_origin_host() -> None:
    out = _normalize_weird_df(_full_frame()).iloc[0]
    assert out["src"] == "192.0.2.10"
    assert out["name"] == "window_recision"
    assert out["source"] == "TCP"


def test_weird_normalizer_drops_every_unread_field() -> None:
    out = _normalize_weird_df(_full_frame())
    for dropped in ("uid", "id.orig_p", "id.resp_h", "id.resp_p", "peer",
                    "addl", "notice"):
        assert dropped not in out.columns


def test_weird_normalizer_never_fabricates_an_absent_column() -> None:
    minimal = pd.DataFrame({"ts": [1785000000.0], "name": ["fragment_overlap"]})
    assert list(_normalize_weird_df(minimal).columns) == ["ts", "name"]


def test_weird_rename_collision_is_detected() -> None:
    collide = set(_full_frame().columns) | {"src"}
    assert _has_rename_collision(collide, _WEIRD_COLUMN_MAP) is True
    assert _has_rename_collision(set(_full_frame().columns), _WEIRD_COLUMN_MAP) is False


def test_weird_aperture_declarations_stay_in_lockstep() -> None:
    """The same three-place declaration the ssl aperture carries."""
    import pathlib

    from sigwood.parsers.zeek import _OPTIONAL_COLUMNS, _REQUIRED_COLUMNS

    text = (
        pathlib.Path(__file__).resolve().parents[1] / "docs" / "SCHEMA.md"
    ).read_text(encoding="utf-8")
    body = text.split("### Canonical weird schema (Zeek weird.log)", 1)[1].split("```", 2)[1]
    documented = [
        line.split(" ", 1)[0].strip()
        for line in body.strip().splitlines()
        if line.strip() and not line.startswith(" ")
    ]
    assert documented == list(_WEIRD_COLUMNS)
    assert _REQUIRED_COLUMNS["weird"] == set(_WEIRD_COLUMNS)
    assert _OPTIONAL_COLUMNS["weird"] == {"src", "source"}
