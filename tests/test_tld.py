"""Tests for common offline Public Suffix List helpers."""

from __future__ import annotations

import subprocess
import sys
import textwrap

import pytest

from sigwood.common.tld import roll_domain


def test_tld_factory_requests_an_offline_cacheless_extractor(monkeypatch):
    from sigwood.common import tld

    marker = object()
    captured = {}

    def _constructor(**kwargs):
        captured.update(kwargs)
        return marker

    monkeypatch.setattr(tld.tldextract, "TLDExtract", _constructor)

    assert tld._new_tld_extract() is marker
    assert captured == {"suffix_list_urls": (), "cache_dir": None}


@pytest.mark.parametrize(
    ("name", "level", "expected"),
    [
        ("WWW.Example.Co.Uk.", "domain", "example.co.uk"),
        ("WWW.Example.Co.Uk.", "tld", "co.uk"),
        ("LOCALHOST.", "domain", "localhost"),
        ("LOCALHOST.", "tld", "localhost"),
    ],
)
def test_roll_domain_normalizes_and_falls_back(name, level, expected):
    assert roll_domain(name, level) == expected


def test_roll_domain_rejects_unknown_level():
    with pytest.raises(ValueError, match="domain.*tld"):
        roll_domain("example.test", "host")


def test_tld_cold_import_and_first_lookup_cannot_open_a_socket() -> None:
    """A fresh process proves the offline pin holds before extractor caching."""
    script = textwrap.dedent(
        """
        import socket
        import ssl

        def blocked(*args, **kwargs):
            raise AssertionError("network access attempted")

        socket.socket = blocked
        socket.create_connection = blocked
        socket.getaddrinfo = blocked

        from sigwood.common.tld import roll_domain

        assert roll_domain("www.example.co.uk.", "domain") == "example.co.uk"
        print("offline lookup OK")
        """
    )
    result = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True,
    )

    assert result.returncode == 0, result.stderr
    assert "offline lookup OK" in result.stdout
