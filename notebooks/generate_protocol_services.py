#!/usr/bin/env python3
"""Generate sigwood's protocol expectation table from a pinned Zeek release.

The registered tier is extracted from Analyzer::register_for_ports calls.  The
small conventional tier and analyzer-behavior flags below are reviewed policy;
they are deliberately kept separate from the source-derived registrations.
"""

from __future__ import annotations

import argparse
import re
import subprocess
from collections import defaultdict
from dataclasses import dataclass
from datetime import date
from pathlib import Path


GENERATOR = "notebooks/generate_protocol_services.py"
PORT_RE = re.compile(r"(?<![\w.])(\d+)/(tcp|udp)(?![\w.])")
CONST_RE = re.compile(
    r"(?:\bconst|\bglobal)\s+(\w+)\s*(?::[^=;]+)?=\s*\{(.*?)\}\s*(?:&\w+\s*)*;",
    re.DOTALL,
)
REGISTER_RE = re.compile(
    r"Analyzer::register_for_ports\s*\(\s*Analyzer::(ANALYZER_[A-Z0-9_]+)\s*,\s*(.*?)\)\s*;",
    re.DOTALL,
)
MODULE_RE = re.compile(r"\bmodule\s+([A-Za-z][A-Za-z0-9_]*)\s*;")


@dataclass(frozen=True, order=True)
class Entry:
    service: str
    port: int
    proto: str
    tier: str
    reason: str | None = None


# These entries are conventions, not Zeek activation defaults.
CONVENTIONAL = (
    Entry("dns", 853, "tcp", "conventional", "DNS over TLS convention"),
    Entry("ssl", 853, "tcp", "conventional", "DNS over TLS convention"),
    Entry("ssl", 8443, "tcp", "conventional", "HTTPS alternate-port convention"),
)

# Flag-only services can lack a registered port. Values are carrier labels only
# for dependent_on; the other flag kinds intentionally have no values.
FLAGS: dict[str, dict[str, tuple[str, ...]]] = {
    "ayiya": {"encapsulation": ()},
    "dce_rpc": {"negotiated": ()},
    "ftp-data": {"negotiated": ()},
    "gssapi": {"dependent_on": ("dce_rpc", "smb")},
    "gtp": {"encapsulation": ()},
    "krb": {"dependent_on": ("dce_rpc", "gssapi")},
    "ntlm": {"dependent_on": ("dce_rpc", "http", "smb")},
    "rtp": {"negotiated": ()},
    "sip": {"negotiated": ()},
    "ssl": {
        "dependent_on": ("ftp", "http", "imap", "pop3", "quic", "smtp", "xmpp")
    },
    "teredo": {"encapsulation": ()},
    "websocket": {"dependent_on": ("http",)},
}

# A source-shape tripwire for the defaults explicitly reviewed in the design.
EXPECTED_REGISTRATIONS = {
    "dns": {"53/tcp", "53/udp", "137/udp", "5353/udp", "5355/udp"},
    "dtls": {"443/udp"},
    "http": {
        "80/tcp", "81/tcp", "631/tcp", "1080/tcp", "3128/tcp",
        "8000/tcp", "8080/tcp", "8888/tcp",
    },
    "ssh": {"22/tcp"},
    "ssl": {
        "443/tcp", "465/tcp", "563/tcp", "585/tcp", "614/tcp", "636/tcp",
        "989/tcp", "990/tcp", "992/tcp", "993/tcp", "995/tcp",
        "5223/tcp",
    },
}

ANALYZER_LABEL_OVERRIDES = {
    "DCE_RPC": "dce_rpc",
    "DNP3_TCP": "dnp3",
    "KRB_TCP": "krb",
    "LDAP_TCP": "ldap",
    "LDAP_UDP": "ldap",
    "RDPEUDP": "rdp",
}


def _without_comments(text: str) -> str:
    return re.sub(r"#.*$", "", text, flags=re.MULTILINE)


def _ports(expression: str) -> set[tuple[int, str]]:
    return {(int(port), proto) for port, proto in PORT_RE.findall(expression)}


def _service_label(analyzer: str) -> str:
    name = analyzer.removeprefix("ANALYZER_")
    return ANALYZER_LABEL_OVERRIDES.get(name, name.lower())


def _verify_tag(root: Path, requested_tag: str) -> None:
    try:
        actual = subprocess.run(
            ["git", "-C", str(root), "describe", "--tags", "--exact-match"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ValueError(f"Zeek root is not checked out at an exact git tag: {root}") from exc
    if actual != requested_tag:
        raise ValueError(f"requested Zeek tag {requested_tag!r}, checkout is {actual!r}")


def extract_registered(zeek_root: Path, zeek_tag: str) -> set[Entry]:
    _verify_tag(zeek_root, zeek_tag)
    protocol_root = zeek_root / "scripts" / "base" / "protocols"
    if not protocol_root.is_dir():
        raise ValueError(f"missing Zeek base protocol script tree: {protocol_root}")

    entries: set[Entry] = set()
    unresolved: list[str] = []
    registrations = 0
    for source in sorted(protocol_root.rglob("*.zeek")):
        text = _without_comments(source.read_text(encoding="utf-8"))
        module_match = MODULE_RE.search(text)
        module = module_match.group(1) if module_match else None
        variables: dict[str, set[tuple[int, str]]] = {}
        for name, expression in CONST_RE.findall(text):
            values = _ports(expression)
            if values:
                variables[name] = values
                if module:
                    variables[f"{module}::{name}"] = values

        for analyzer, expression in REGISTER_RE.findall(text):
            registrations += 1
            values = _ports(expression)
            identifiers = re.findall(r"(?:[A-Za-z][A-Za-z0-9_]*::)?[A-Za-z][A-Za-z0-9_]*", expression)
            missing_identifiers = []
            for identifier in identifiers:
                if identifier in {"set", "tcp", "udp"}:
                    continue
                resolved = variables.get(identifier, set())
                if not resolved and "::" in identifier:
                    resolved = variables.get(identifier.rsplit("::", 1)[1], set())
                if resolved:
                    values.update(resolved)
                else:
                    missing_identifiers.append(identifier)
            if not values or missing_identifiers:
                suffix = f"; unknown={','.join(missing_identifiers)}" if missing_identifiers else ""
                unresolved.append(
                    f"{source.relative_to(zeek_root)}: {analyzer}, {expression.strip()}{suffix}"
                )
                continue
            service = _service_label(analyzer)
            entries.update(Entry(service, port, proto, "registered") for port, proto in values)

    if registrations == 0:
        raise ValueError("no Analyzer::register_for_ports calls found")
    if unresolved:
        detail = "\n  ".join(unresolved)
        raise ValueError(f"unresolved register_for_ports expressions:\n  {detail}")
    _tripwire(entries)
    return entries


def _tripwire(entries: set[Entry]) -> None:
    observed: dict[str, set[str]] = defaultdict(set)
    for entry in entries:
        observed[entry.service].add(f"{entry.port}/{entry.proto}")
    errors = []
    for service, expected in EXPECTED_REGISTRATIONS.items():
        if observed[service] != expected:
            errors.append(
                f"{service}: expected {sorted(expected)}, observed {sorted(observed[service])}"
            )
    if errors:
        raise ValueError("Zeek registration shape changed:\n  " + "\n  ".join(errors))


def render(entries: set[Entry], zeek_tag: str, generated_on: str) -> str:
    lines = [
        "# sigwood protocol service expectations",
        f"# zeek_tag={zeek_tag}",
        f"# generated_on={generated_on}",
        f"# generator={GENERATOR}",
        "# fields: service port/proto # tier=<registered|conventional> [reason=<text>]",
    ]
    for entry in sorted(entries | set(CONVENTIONAL)):
        metadata = f"tier={entry.tier}"
        if entry.reason:
            metadata += f" reason={entry.reason}"
        lines.append(f"{entry.service:<16} {entry.port}/{entry.proto:<3} # {metadata}")

    lines.append("# flags: service kind [values=comma-separated-carriers]")
    for service in sorted(FLAGS):
        for kind in sorted(FLAGS[service]):
            values = FLAGS[service][kind]
            suffix = f" values={','.join(values)}" if values else ""
            lines.append(f"# flag service={service} kind={kind}{suffix}")
    return "\n".join(lines) + "\n"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--zeek-root", required=True, type=Path)
    parser.add_argument("--zeek-tag", required=True)
    parser.add_argument("--generated-on", required=True, help="explicit YYYY-MM-DD")
    parser.add_argument("--output", required=True, type=Path)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    try:
        date.fromisoformat(args.generated_on)
    except ValueError as exc:
        raise SystemExit(f"invalid --generated-on date: {args.generated_on!r}") from exc
    entries = extract_registered(args.zeek_root.resolve(), args.zeek_tag)
    output = render(entries, args.zeek_tag, args.generated_on)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(output, encoding="utf-8")
    print(f"wrote {len(output.encode('utf-8'))} bytes and {len(entries)} registered rows to {args.output}")


if __name__ == "__main__":
    main()
