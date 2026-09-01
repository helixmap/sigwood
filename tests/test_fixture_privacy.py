"""Real-TLD tripwire over the test tree.

Test sources and fixture data carry only RFC 5737 address space and
reserved-namespace names (``.test`` / ``.example`` / ``.invalid`` / ``.local``,
``example.com/net/org``). A realistic registrable domain under a real public
suffix inside a fixture is invisible to every behavioral test - the suite
exercises what the fixture drives, never what its identifiers point at - so
this module scans the tree itself: every domain-shaped token in Python string
literals, comments, and docstrings, plus every line of non-Python fixture
files, is checked against the bundled Public Suffix List through the shared
offline extractor. A token whose suffix the PSL recognizes is a violation
unless a documented allowance below covers it.

Allowances, each deliberately narrow:

- policy names: ``example.<suffix>`` under any real suffix (the reserved-label
  placeholder family), ``*.arpa`` special-use shapes, artifact-extension
  suffixes matched on the WHOLE suffix (so ``x.zip`` passes while a real
  ``x.com.py`` domain is still caught), and a short list of sanctioned exact
  registrable domains (the CloudTrail event grammar, the project's own
  repository URLs, the wizard's Zeek pointer);
- quoted code: exact tokens that are tool-authored code fragments whose final
  label collides with a vanity gTLD (``ctx.save``, ``runner.run``), plus
  dotted identifier chains rooted at a known Python package name;
- grandfathered placeholders: real-TLD placeholder names, allowed ONLY in the
  file that carries them. This table only shrinks - a new fixture uses
  reserved space instead of extending it.

Disclosed residuals: binary and compressed fixture files are not decoded (the
NUL guard skips them); tokens broken by ``_`` or other non-hostname bytes scan
as their fragments; and this module exempts its own file, since the allowance
tables above are themselves domain-bearing.
"""

from __future__ import annotations

import re
import token as token_mod
import tokenize
from pathlib import Path

from sigwood.common.tld import TLD_EXTRACT

TESTS_DIR = Path(__file__).resolve().parent
_SELF_NAME = Path(__file__).name

# Hostname-shaped: two or more dot-joined LDH labels, final label alphabetic.
# `_` is not in the label class, so snake_case identifier chains never token.
_DOMAIN_TOKEN_RE = re.compile(
    r"\b[A-Za-z0-9](?:[A-Za-z0-9-]{0,62})"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}))*"
    r"\.[A-Za-z]{2,63}\b"
)

# Sanctioned exact registrable domains (compared lowercased).
_ALLOWED_REGISTRABLE = frozenset(
    {
        # CloudTrail's own event grammar: eventSource values are
        # <service>.amazonaws.com, so CloudTrail fixtures require the name.
        "amazonaws.com",
        # Shipped common allowlist: Route 53 nameserver regression.
        "awsdns-56.org",
        # Shipped common allowlist: Azure DNS nameserver regression.
        "azure-dns.com",
        # Shipped common allowlist: Azure cloudapp tenant regression.
        "azure.com",
        # Shipped common allowlist: Azure Edge tenant regression.
        "azureedge.net",
        # Shipped common allowlist: Azure Front Door tenant regression.
        "azurefd.net",
        # Shipped common allowlist: Azure Websites tenant regression.
        "azurewebsites.net",
        # Shipped common allowlist: CloudFront tenant regression.
        "cloudfront.net",
        # Shipped common allowlist: CloudNS nameserver regression.
        "cloudns.net",
        # Shipped common allowlist: Constellix nameserver regression.
        "constellix.com",
        # Shipped common allowlist: DigiCert DNS nameserver regression.
        "digicertdns.net",
        # Shipped common allowlist: DomainControl nameserver regression.
        "domaincontrol.com",
        # The canonical repository URL in shipped copy and doc-link checks.
        "github.com",
        "githubusercontent.com",
        # Shipped common allowlist: Google API control/tenant regressions.
        "googleapis.com",
        # Shipped common allowlist: Google user-content tenant regression.
        "googleusercontent.com",
        # Shipped common allowlist: Global Accelerator tenant regression.
        "awsglobalaccelerator.com",
        # Shipped common allowlist: OVH nameserver regression.
        "ovh.net",
        # Shipped common allowlist: Azure Traffic Manager tenant regression.
        "trafficmanager.net",
        # Shipped common allowlist: Azure Front Door traffic-manager regression.
        "tm-azurefd.net",
        # Shipped common allowlist: UltraDNS nameserver regression.
        "ultradns.net",
        # Shipped common allowlist: Windows control/tenant regressions.
        "windows.net",
        # The init wizard's shipped Zeek pointer.
        "zeek.org",
    }
)

# File extensions this tree writes that are also real TLDs. Matched against
# the WHOLE PSL suffix: `report.zip` (suffix `zip`) passes, while a real
# domain under a multi-label suffix such as `evil.com.py` is still caught.
_ARTIFACT_EXTENSION_SUFFIXES = frozenset({"py", "md", "sh", "zip", "so"})

# Dotted identifier chains rooted at these labels are code references
# (`sigwood.runner.run`, `gzip.open`). A frozen set, never importability
# probing: what a host happens to have installed must not decide the scan.
_CODE_ROOT_LABELS = frozenset({"sigwood", "tests", "builtins", "gzip", "lzma"})

# Exact tool-authored code fragments whose final label collides with a vanity
# gTLD. Each is a quoted piece of shipped source, player JavaScript, CSS, or
# prose about a Python attribute - never fixture data.
_CODE_REFERENCE_TOKENS = frozenset(
    {
        "area.select",
        "ctx.save",
        "detectors.aws",
        "dns.run",
        "g.bv",
        "link.download",
        "lk.lv",
        "mod.run",
        "particle.live",
        "path.name",
        "r.hot",
        "rawdenseb.map",
        "runner.run",
        "td.data",
    }
)

# Real-TLD placeholder names already carried by a specific file, allowed there
# and nowhere else (keyed by basename, values are registrable domains). Shrink
# only - a new fixture uses reserved space.
_GRANDFATHERED_FIXTURE_DOMAINS: dict[str, frozenset[str]] = {
    # The suffix-trap and apex-probe pattern matrix.
    "test_allowlist_matcher.py": frozenset({"notexample.com", "foo.net"}),
    # Tail of the shell-metacharacter fixture `example;id.com` - the quoting
    # proof needs the metacharacter, and the run after `;` scans as a domain.
    "test_dns_detector.py": frozenset({"id.com"}),
    # Distinct-family placeholder apexes in the burst/recurring fixtures.
    "test_dnsblock_burst_recurring.py": frozenset(
        {"alpha.com", "beta.net", "gamma.org", "delta.io"}
    ),
    # qclass-drop fixture queries.
    "test_loader.py": frozenset({"other.com", "null-class.com"}),
}

_FSTRING_MIDDLE = getattr(token_mod, "FSTRING_MIDDLE", None)
_SCANNED_TOKEN_TYPES = frozenset(
    {tokenize.STRING, tokenize.COMMENT}
    | ({_FSTRING_MIDDLE} if _FSTRING_MIDDLE is not None else set())
)

_STRING_PREFIX_RE = re.compile(r"[A-Za-z]*")
_BRACE_FIELD_RE = re.compile(r"\{[^{}]*\}")


def _blank_span(match: re.Match[str]) -> str:
    """Replace a span with spaces, keeping newlines so line math holds."""
    return "".join("\n" if ch == "\n" else " " for ch in match.group(0))


def _normalized_string_text(tok: tokenize.TokenInfo) -> str:
    """Return string-token text with f-string replacement fields blanked.

    Runtimes that tokenize f-strings as single STRING tokens include the
    replacement-field source in the token text; newer runtimes emit the
    fields as ordinary code tokens this scan never sees. Blanking the fields
    (and doubled-brace escapes) makes the scan report the same tokens on
    every supported runtime. Only f-prefixed tokens are normalized: literal
    braces in a plain string stay scannable.
    """
    text = tok.string
    prefix = _STRING_PREFIX_RE.match(text).group(0)
    if "f" not in prefix.lower():
        return text
    text = text.replace("{{", "  ").replace("}}", "  ")
    while True:
        blanked = _BRACE_FIELD_RE.sub(_blank_span, text)
        if blanked == text:
            return blanked
        text = blanked


def _real_tld_violation(raw_token: str, file_name: str) -> str | None:
    """Return the offending registrable domain, or None when sanctioned."""
    low = raw_token.lower()
    if low in _CODE_REFERENCE_TOKENS:
        return None
    labels = low.split(".")
    if labels[0] in _CODE_ROOT_LABELS and all(
        label.isidentifier() for label in labels
    ):
        return None
    extracted = TLD_EXTRACT(low)
    suffix = extracted.suffix
    if not suffix:
        return None
    if suffix == "arpa" or suffix.endswith(".arpa"):
        return None
    if suffix in _ARTIFACT_EXTENSION_SUFFIXES:
        return None
    registrable = extracted.top_domain_under_public_suffix
    if not registrable:
        # The token IS a public suffix (`co.uk`): it names no host, and the
        # suffix-mechanics fixtures must be able to spell one.
        return None
    if registrable in _ALLOWED_REGISTRABLE:
        return None
    if registrable == f"example.{suffix}":
        return None
    if registrable in _GRANDFATHERED_FIXTURE_DOMAINS.get(file_name, frozenset()):
        return None
    return registrable


def _scan_text(
    text: str, *, file_name: str, first_lineno: int
) -> list[tuple[int, str, str]]:
    """Scan one text block, returning (lineno, token, registrable) hits."""
    hits = []
    for match in _DOMAIN_TOKEN_RE.finditer(text):
        registrable = _real_tld_violation(match.group(0), file_name)
        if registrable is not None:
            lineno = first_lineno + text.count("\n", 0, match.start())
            hits.append((lineno, match.group(0), registrable))
    return hits


def _scan_python_file(path: Path) -> list[tuple[int, str, str]]:
    """Scan a Python file's strings, comments, and docstrings."""
    hits = []
    with path.open("rb") as fh:
        for tok in tokenize.tokenize(fh.readline):
            if tok.type not in _SCANNED_TOKEN_TYPES:
                continue
            text = (
                _normalized_string_text(tok)
                if tok.type == tokenize.STRING
                else tok.string
            )
            hits.extend(
                _scan_text(text, file_name=path.name, first_lineno=tok.start[0])
            )
    return hits


def _scan_data_file(path: Path) -> list[tuple[int, str, str]]:
    """Scan a non-Python fixture file as text; binary content is skipped."""
    data = path.read_bytes()
    if b"\x00" in data:
        return []
    return _scan_text(
        data.decode("utf-8", errors="replace"),
        file_name=path.name,
        first_lineno=1,
    )


def scan_tree(root: Path) -> list[tuple[Path, int, str, str]]:
    """Scan every file under ``root``, returning sorted violation records."""
    violations = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or "__pycache__" in path.parts:
            continue
        if path.name == _SELF_NAME:
            continue
        scan = _scan_python_file if path.suffix == ".py" else _scan_data_file
        for lineno, tok, registrable in scan(path):
            violations.append((path, lineno, tok, registrable))
    return violations


def test_test_tree_carries_no_real_tld_domains() -> None:
    violations = scan_tree(TESTS_DIR)
    formatted = "\n".join(
        f"  {path.relative_to(TESTS_DIR)}:{lineno}: {tok!r} -> {registrable}"
        for path, lineno, tok, registrable in violations
    )
    assert not violations, (
        "real-TLD registrable domains in test sources or fixtures - use "
        "RFC 5737 space and reserved names (.test/.example/.invalid, "
        "example.com/net/org), or extend a documented allowance in "
        f"{_SELF_NAME}:\n{formatted}"
    )


def _seed_and_scan(tmp_path: Path, name: str, content: str) -> list:
    (tmp_path / name).write_text(content, encoding="utf-8")
    return scan_tree(tmp_path)


def test_scanner_catches_string_comment_and_docstring_domains(tmp_path) -> None:
    hits = _seed_and_scan(
        tmp_path,
        "test_seeded.py",
        '"""Fixture notes mention doc-c2.net here."""\n'
        'HOST = "beacon.bad-fixture.com"\n'
        "# staging box lives at internal.corp-example.io\n",
    )
    assert [(h[1], h[3]) for h in hits] == [
        (1, "doc-c2.net"),
        (2, "bad-fixture.com"),
        (3, "corp-example.io"),
    ]


def test_scanner_skips_sanctioned_shapes(tmp_path) -> None:
    hits = _seed_and_scan(
        tmp_path,
        "test_seeded.py",
        'A = "sub.example.com"\n'
        'B = "one.example.co.uk"\n'
        'C = "svc.alpha.test"\n'
        'D = "3.2.1.in-addr.arpa"\n'
        'E = "report.zip"\n'
        'F = "sigwood.common.loader.io"\n'
        'G = "s3.amazonaws.com"\n'
        'H = "python 3.11 and conn.log rotate as conn.2026-01-01.log.gz"\n'
        'I = "co.uk"\n'
        "# the runner.run seam is mocked nowhere\n",
    )
    assert hits == []


def test_scanner_blanks_fstring_fields_but_not_literal_braces(tmp_path) -> None:
    # The f-string replacement field must not report on any supported
    # runtime; the identical text in a plain string's literal braces must.
    hits = _seed_and_scan(
        tmp_path,
        "test_seeded.py",
        'A = f"prefix {plan.data.run} suffix"\n'
        'B = "prefix {braced-fixture.com} suffix"\n',
    )
    assert [(h[1], h[3]) for h in hits] == [(2, "braced-fixture.com")]


def test_fstring_normalization_blanks_fields_in_string_tokens() -> None:
    # Runtimes without PEP 701 tokenization deliver an f-string as ONE
    # STRING token whose text includes the replacement-field source; newer
    # runtimes never produce that shape, so this drives it directly and the
    # branch is exercised on every supported runtime.
    fstring = tokenize.TokenInfo(
        tokenize.STRING,
        'f"a {plan.data.run} b {{c.d}} w {val:{width}.run} z"',
        (1, 0),
        (1, 52),
        "",
    )
    text = _normalized_string_text(fstring)
    assert _DOMAIN_TOKEN_RE.search(text) is None
    assert text.count("\n") == fstring.string.count("\n")
    plain = tokenize.TokenInfo(
        tokenize.STRING, '"a {braced-fixture.com} b"', (1, 0), (1, 26), ""
    )
    assert "braced-fixture.com" in _normalized_string_text(plain)


def test_scanner_catches_domain_in_data_fixture(tmp_path) -> None:
    hits = _seed_and_scan(
        tmp_path,
        "queries.txt",
        "query example.com ok\nquery sneaky-apex.org bad\n",
    )
    assert [(h[1], h[3]) for h in hits] == [(2, "sneaky-apex.org")]


def test_scanner_catches_multi_label_suffix_behind_extension(tmp_path) -> None:
    # The extension allowance keys on the whole suffix: a registrable domain
    # under a multi-label suffix whose tail matches an extension still fails.
    hits = _seed_and_scan(tmp_path, "test_seeded.py", 'A = "portal.evil.com.py"\n')
    assert [(h[3]) for h in hits] == ["evil.com.py"]


def test_grandfathered_allowance_is_file_scoped(tmp_path) -> None:
    line = 'PATTERN = "x.foo.net"\n'
    assert _seed_and_scan(tmp_path, "test_allowlist_matcher.py", line) == []
    hits = _seed_and_scan(tmp_path, "test_elsewhere.py", line)
    assert [(h[0].name, h[3]) for h in hits] == [("test_elsewhere.py", "foo.net")]


def test_scanner_exempts_its_own_module_file(tmp_path) -> None:
    # The allowance tables above are domain-bearing, so the scan skips this
    # module's own file name; the exemption is pinned here so it stays a
    # deliberate, visible choice.
    assert _seed_and_scan(tmp_path, _SELF_NAME, 'A = "own-file.com"\n') == []
