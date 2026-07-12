"""Offline Public Suffix List helpers shared by DNS consumers."""

from __future__ import annotations

import tldextract


def _new_tld_extract() -> tldextract.TLDExtract:
    """Build the shared extractor without any network or cache dependency."""
    return tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)


TLD_EXTRACT = _new_tld_extract()


def roll_domain(name: str, level: str) -> str:
    """Return the requested registrable-domain or public-suffix rollup."""
    normalized = name.lower().rstrip(".")
    extracted = TLD_EXTRACT(normalized)

    if level == "domain":
        return extracted.top_domain_under_public_suffix or normalized
    if level == "tld":
        return extracted.suffix or normalized
    raise ValueError(
        f"domain level must be 'domain' or 'tld' (got {level!r})"
    )
