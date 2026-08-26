"""Pure address-topology classification shared by detectors and era cards.

The owner normalizes address spelling at its parsing boundary and keeps three
facts separate: operator-local membership, external destination status, and
the stricter public/global classification.  Consumers select the fact their
contract needs; ``external`` is deliberately not a synonym for public/global.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from functools import lru_cache
from typing import Iterable


IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


def parse_address(value: object) -> IPAddress | None:
    """Parse one address and normalize a mapped IPv6 value to IPv4 once."""
    try:
        parsed = ipaddress.ip_address(str(value))
    except (TypeError, ValueError):
        return None
    if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped is not None:
        return parsed.ipv4_mapped
    return parsed


IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


@lru_cache(maxsize=64)
def _parsed_home_net(networks: tuple[str, ...]) -> tuple[IPNetwork, ...]:
    """Parse operator topology ONCE per distinct declaration.

    home_net is a small constant for the life of a run, but membership is asked
    per row, so parsing inside the membership loop rebuilt the same few networks
    millions of times. Config-backed runs validate before reaching this helper;
    the unparseable-entry skip remains a defensive rail for direct callers.
    """
    parsed: list[IPNetwork] = []
    for network in networks:
        try:
            parsed.append(ipaddress.ip_network(network, strict=False))
        except ValueError:
            continue
    return tuple(parsed)


def in_home_net(address: IPAddress, home_net: Iterable[str]) -> bool:
    """Return whether one already-normalized address is in operator topology."""
    for network in _parsed_home_net(tuple(home_net)):
        if address in network:
            return True
    return False


def is_non_routable(address: IPAddress) -> bool:
    """Return whether an address cannot be an external destination."""
    return (
        address.is_multicast
        or address.is_link_local
        or address.is_loopback
        or address.is_unspecified
        or (address.version == 4 and str(address) == "255.255.255.255")
    )


@dataclass(frozen=True)
class AddressTopology:
    """Classified address facts without a detector-specific source policy."""

    address: IPAddress
    local: bool
    non_routable: bool
    external: bool
    public_global: bool


def classify_address(value: object, home_net: Iterable[str]) -> AddressTopology | None:
    """Classify one address against a home network without guessing on failure."""
    address = parse_address(value)
    if address is None:
        return None
    local = in_home_net(address, home_net)
    non_routable = is_non_routable(address)
    return AddressTopology(
        address=address,
        local=local,
        non_routable=non_routable,
        external=not local and not non_routable,
        public_global=address.is_global,
    )
