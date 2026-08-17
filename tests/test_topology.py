"""Truth cells for shared topology classification."""

from __future__ import annotations

import pytest

from sigwood.common.topology import classify_address, parse_address


_HOME = ["10.0.0.0/8"]


@pytest.mark.parametrize(
    ("value", "local", "external", "public_global"),
    [
        ("10.0.0.10", True, False, False),
        ("198.51.100.20", False, True, False),
        ("100.64.0.10", False, True, False),
        ("224.0.0.251", False, False, True),
        ("127.0.0.1", False, False, False),
        ("fe80::1", False, False, False),
        ("0.0.0.0", False, False, False),
        ("255.255.255.255", False, False, False),
        ("2001:db8::1", False, True, False),
    ],
)
def test_external_and_public_global_are_distinct_facts(
    value: str,
    local: bool,
    external: bool,
    public_global: bool,
) -> None:
    fact = classify_address(value, _HOME)

    assert fact is not None
    assert (fact.local, fact.external, fact.public_global) == (
        local,
        external,
        public_global,
    )


def test_mapped_ipv6_normalizes_once_before_home_net_membership() -> None:
    fact = classify_address("::ffff:10.0.0.12", _HOME)

    assert fact is not None
    assert str(fact.address) == "10.0.0.12"
    assert fact.local is True
    assert fact.external is False


def test_unparseable_address_has_no_classification() -> None:
    assert parse_address("not-an-ip") is None
    assert classify_address("not-an-ip", _HOME) is None
