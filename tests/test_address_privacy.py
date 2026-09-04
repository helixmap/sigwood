"""No real network's addresses ship in the tracked tree.

The domain scanner in ``test_fixture_privacy`` reads names, and only under
``tests/``. This one reads addresses, over everything git tracks, because the two
ways a real network leaks are a hostname and an address.

The rule cannot be "private addresses are fine": every home network is RFC 1918,
so that permits exactly the leak worth catching. Instead each address must fall in
documentation space, in a range reserved for a role rather than assigned to anyone,
or in the small set of private ranges the fixtures agreed to share. A real internal
range is then a finding because it is not on the list, not because it looks unusual.
"""

from __future__ import annotations

import ipaddress
import re
import subprocess
from pathlib import Path

import pytest


_REPO = Path(__file__).resolve().parents[1]

# Documentation space (RFC 5737 and RFC 3849) plus RFC 6598 shared space, which is
# reserved for carrier NAT and so is assigned to no organization. Fixtures needing
# an address that is neither ours nor anyone else's use that range.
_DOCUMENTATION = (
    "192.0.2.0/24",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "100.64.0.0/10",
    "2001:db8::/32",
)

# Addresses reserved for a role. None of them names a host on anyone's network.
_ROLE = (
    "0.0.0.0/8",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "224.0.0.0/4",
    "255.255.255.255/32",
)

# Private ranges the fixtures and the demo corpus share. Keep this list short: every
# entry is a range a reader could mistake for somebody's real network, so it earns
# its place by being used, and a new fixture picks one of these rather than adding
# to them.
_PLACEHOLDER = (
    "10.0.0.0/24",
    "10.1.0.0/24",
    "10.1.2.0/24",
    "10.2.0.0/24",
    "10.9.0.0/24",
    "192.168.1.0/24",
    "192.168.2.0/24",
)

# Ranges allowed only as the exact token, because each is wider than anything on the
# lists above and matching them by containment would permit most of the address space.
# Two kinds qualify. The RFC 1918 ranges are the shipped `home_net` defaults and name no
# host. The other two are supernets the exfil and beacon folds compute by masking a
# documentation address to a fixed prefix, so they appear in tests as expected output
# and cannot be narrowed without changing the fold.
_EXACT_TOKENS = frozenset(
    {
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "192.0.2.0/23",
        "198.51.96.0/20",
    }
)

_ALLOWED = tuple(
    ipaddress.ip_network(value) for value in (*_DOCUMENTATION, *_ROLE, *_PLACEHOLDER)
)

# IPv6 is judged by a different rule, because the registries divide it differently.
# Only 2000::/3 is handed out to organizations, so an address outside it is reserved
# or unassigned and names nobody. The exception is ULA space, where each site draws
# its own random prefix: that prefix identifies the site, so it is treated like an
# RFC 1918 range and has to be listed rather than waved through.
_V6_ASSIGNABLE = ipaddress.ip_network("2000::/3")
_V6_SITE_LOCAL = ipaddress.ip_network("fc00::/7")

_IPV4 = re.compile(r"(?<![\w.])(\d{1,3}(?:\.\d{1,3}){3})(?:/(\d{1,2}))?(?![\w.])")

# A loose candidate shape; anything that does not parse as an address is dropped. The
# slice syntax that reads like an address (``values[1::2]``) is excluded here rather
# than after parsing, because ``::`` and ``1::2`` are both valid addresses and there is
# nothing about the parsed value to tell the two uses apart.
_IPV6 = re.compile(
    r"(?<![\w:.\[])([0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,}(?:\.\d{1,3}){0,4})"
    r"(?:/(\d{1,3}))?(?![\w:.\]])"
)

# This module names the ranges it polices, so it cannot scan itself.
_EXEMPT = frozenset({"tests/test_address_privacy.py"})


def _permitted(token: str) -> bool:
    """True when the token is documentation, role, or sanctioned placeholder space."""
    if token in _EXACT_TOKENS:
        return True
    try:
        network = ipaddress.ip_network(token, strict=False)
    except ValueError:
        return False
    if network.version == 6:
        mapped = network.network_address.ipv4_mapped
        if mapped is not None:
            # An IPv4-mapped address carries a v4 address, and that is the part that
            # could name a real host, so it is judged by the v4 rule.
            return _permitted(str(mapped))
        if not network.overlaps(_V6_ASSIGNABLE) and not network.overlaps(_V6_SITE_LOCAL):
            return True
    # Containment, never overlap: a range merely touching documentation space is not
    # documentation space. 192.0.0.0/16 contains 192.0.2.0/24 and must still fail.
    return any(
        network.version == allowed.version and network.subnet_of(allowed)
        for allowed in _ALLOWED
    )


def _tracked_text_files() -> list[str]:
    # --others matters as much as --cached: a listing of staged files alone cannot
    # see a file that is not staged yet, so a leak would sit in the working tree
    # through a green suite and go public in the commit that adds the file.
    # --exclude-standard keeps the ignored trees out.
    listed = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
        cwd=_REPO, capture_output=True, text=True, check=True,
    ).stdout.split()
    keep = []
    for name in listed:
        if name in _EXEMPT:
            continue
        path = _REPO / name
        try:
            path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        keep.append(name)
    return keep


def _offenders() -> dict[str, set[str]]:
    found: dict[str, set[str]] = {}
    for name in _tracked_text_files():
        text = (_REPO / name).read_text(encoding="utf-8")
        for pattern in (_IPV4, _IPV6):
            for match in pattern.finditer(text):
                token = match.group(0)
                try:
                    ipaddress.ip_address(match.group(1))
                except ValueError:
                    continue
                if not _permitted(token):
                    found.setdefault(token, set()).add(name)
    return found


def test_tracked_files_carry_no_address_outside_reserved_space() -> None:
    offenders = _offenders()
    assert not offenders, "addresses outside reserved space: " + "; ".join(
        f"{token} in {sorted(paths)}" for token, paths in sorted(offenders.items())
    )


def test_the_inventory_is_not_empty() -> None:
    """A scan over no files passes for the wrong reason."""
    files = _tracked_text_files()
    assert len(files) > 100
    assert "README.md" in files


@pytest.mark.parametrize(
    "token",
    [
        "172.23.8.0/24",  # the shape this scan exists to catch: a real internal range
        "172.23.16.9",
        "192.168.99.4",  # private, but not one of the shared placeholder ranges
        "10.5.5.5",
        "8.8.8.8",  # assigned to an organization
        "1.1.1.1",
        "11.0.0.1",
        "192.0.0.0/16",  # contains documentation space without being contained by it
        "10.0.0.0/9",
        "2606:4700::1111",  # assigned: inside the 2000::/3 global unicast range
        "2001:db9::1",
        "fd12:3456:789a::1",  # a site's own ULA prefix identifies that site
        "::ffff:172.23.8.1",  # the v4-mapped form of a real internal address
    ],
)
def test_the_scan_rejects_a_real_network(token: str) -> None:
    assert not _permitted(token)


@pytest.mark.parametrize(
    "token",
    [
        "192.0.2.1",
        "198.51.100.20",
        "203.0.113.0/24",
        "198.51.96.0/20",  # a /20 the exfil fold derives from documentation space
        "100.64.0.10",
        "127.0.0.1",
        "169.254.1.2",
        "255.255.255.255",
        "192.168.1.37",  # the demo corpus host
        "10.0.0.0/8",  # a shipped home_net default, allowed as the exact token
        "172.16.0.0/12",
        "2001:db8::1",
        "fe80::1",  # link-local, outside the range registries hand out
        "ff02::1",
        "::1",
        "::ffff:192.0.2.7",  # v4-mapped, judged by the address it carries
    ],
)
def test_the_scan_accepts_reserved_and_sanctioned_space(token: str) -> None:
    assert _permitted(token)
