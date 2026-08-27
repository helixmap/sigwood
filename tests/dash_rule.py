#!/usr/bin/env python3
"""The hyphen-only dash rule, and the one place it is defined.

sigwood writes an ASCII hyphen. Figure dash, en dash, em dash and horizontal
bar are banned from every file in the repository, from staged content, and from
commit messages. U+2212 MINUS SIGN is deliberately NOT banned: it is a mathematical
operator in expressions such as ``f_max - span``, and one occurrence is the
test-pinned toggle glyph in the html report's CSS. Banning it would break a
shipped, separately-pinned rendering decision.

This module is the rule's single owner. The suite imports it; the git hooks in
``.githooks/`` shell to it. It lives beside the suite that enforces it rather
than in ``tools/``, which is the operator-facing surface. A second copy of these patterns would drift, and the
drift would be invisible until a dash reached GitHub.

Banning a character in four written forms means naming those forms, so this
module contains the ban list. It needs no exemption to pass its own rule: the
codepoints are built arithmetically and every pattern is escaped such that its
own source text cannot satisfy it. The suite proves that rather than trusting it.

Stdlib only, so a git hook can run it without the project's virtualenv.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

# Figure dash, en dash, em dash, horizontal bar.
DASH_CODEPOINTS = tuple(range(0x2012, 0x2016))
DASH_CHARS = tuple(chr(cp) for cp in DASH_CODEPOINTS)

# Forms that render a banned dash without the literal ever appearing in the
# file. Each of these shipped in this tree at least once, and a search for the
# literal character alone found none of them - including two strings that
# sigwood printed to operators.
CONSTRUCTION_PATTERNS = (
    r"\\u201[2-5]",
    r"\\U0000201[2-5]",
    r"\\N\{[^}]*(?:DASH|HORIZONTAL BAR)[^}]*\}",
    r"chr\(\s*(?:0[xX]201[2-5]|821[0-3])\s*\)",
    r"&(?:mdash|ndash);",
    r"&#821[0-3];",
    r"&#[xX]201[2-5];",
)
CONSTRUCTION_REGEXES = tuple(re.compile(p) for p in CONSTRUCTION_PATTERNS)

ADVICE = "dash punctuation is banned in this repo; write an ASCII hyphen"

# Derived from this file, not the working directory: a git hook and an operator
# invoke this from different places, and both mean this repository.
_REPO_ROOT = Path(__file__).resolve().parent.parent


def violations(label: str, text: str) -> list[str]:
    """Every banned dash in ``text``, as ``label:line: what`` strings."""
    found: list[str] = []
    for lineno, line in enumerate(text.split("\n"), 1):
        for ch in DASH_CHARS:
            if ch in line:
                found.append(f"{label}:{lineno}: literal U+{ord(ch):04X}")
        for rx in CONSTRUCTION_REGEXES:
            for match in rx.finditer(line):
                found.append(f"{label}:{lineno}: {match.group(0)!r}")
    return found


def _git(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args], cwd=root, capture_output=True, text=True, check=True
    )


def in_git_work_tree(root: Path) -> bool:
    """Whether ``root`` sits in a repository at all.

    A tracked-file export carries no repository. That is out of scope rather
    than broken: its contents came from a repository this rule already gated.
    A repository that is present but whose git cannot be run is NOT this case,
    and callers must fail there rather than skip.
    """
    try:
        _git(root, "rev-parse", "--is-inside-work-tree")
    except (OSError, subprocess.CalledProcessError):
        return False
    return True


def _decode_or_none(raw: bytes) -> str | None:
    """Text, or None for a blob that is not UTF-8.

    Binary files are not decoded and so are not scanned. Disclosed, and the
    same treatment the fixture-privacy scanner gives the same class.
    """
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None


def repo_text_files(root: Path) -> list[tuple[str, str]]:
    """Every file that is in the repository or would be added to it, as
    ``(relpath, text)``, decoded as UTF-8.

    The inventory comes from git, never a filesystem glob, and the difference
    matters. A working tree can hold entries that are deliberately kept out of
    the repository, including symlinks that point outside it, so a glob would
    pull untracked material into an assertion about repository content. Git's
    own inventory cannot, because ``--exclude-standard`` honors every exclude
    file that keeps those entries out.

    ``--others`` alongside ``--cached`` is deliberate. A scan of tracked files
    alone cannot see a brand new file, so a dash could sit in the working tree
    through a green suite and become public in the commit that adds it. What
    the rule is about is what reaches the published repository, and an
    untracked, unignored file is one commit away from that.
    """
    listing = _git(
        root, "ls-files", "-z", "--cached", "--others", "--exclude-standard"
    ).stdout
    out: list[tuple[str, str]] = []
    for rel in filter(None, listing.split("\0")):
        try:
            raw = (root / rel).read_bytes()
        except OSError:
            continue
        text = _decode_or_none(raw)
        if text is not None:
            out.append((rel, text))
    return out


def staged_text_files(root: Path) -> list[tuple[str, str]]:
    """Every added, copied, modified or renamed path, at its STAGED content.

    Staged content, not the working tree: what the commit will actually carry
    is what the gate must judge.
    """
    listing = _git(
        root, "diff", "--cached", "--name-only", "-z", "--diff-filter=ACMR"
    ).stdout
    out: list[tuple[str, str]] = []
    for rel in filter(None, listing.split("\0")):
        blob = subprocess.run(
            ["git", "show", f":{rel}"],
            cwd=root,
            capture_output=True,
            check=False,
        )
        if blob.returncode != 0:
            continue
        text = _decode_or_none(blob.stdout)
        if text is not None:
            out.append((rel, text))
    return out


def message_body(text: str) -> str:
    """A commit message with its comment lines removed.

    git strips lines beginning with ``#`` before recording the message, so
    scanning them would reject a dash the commit never carries - including the
    dashes in git's own status template.
    """
    return "\n".join(
        line for line in text.split("\n") if not line.startswith("#")
    )


def _report(found: list[str], what: str) -> int:
    if not found:
        return 0
    print(f"{ADVICE}\nfound in {what}:", file=sys.stderr)
    for item in found:
        print(f"  {item}", file=sys.stderr)
    return 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--repo", action="store_true", help="scan repository files")
    group.add_argument("--staged", action="store_true", help="scan staged content")
    group.add_argument("--message-file", help="scan a commit message file")
    parser.add_argument(
        "--root",
        default=str(_REPO_ROOT),
        help="repository root (defaults to this file's own repository)",
    )
    args = parser.parse_args(argv)

    root = Path(args.root).resolve()

    if args.message_file:
        path = Path(args.message_file)
        try:
            raw = path.read_bytes()
        except OSError as exc:
            print(f"cannot read commit message: {exc}", file=sys.stderr)
            return 1
        text = _decode_or_none(raw)
        if text is None:
            print("commit message is not valid UTF-8", file=sys.stderr)
            return 1
        return _report(violations("commit message", message_body(text)), "the commit message")

    if not in_git_work_tree(root):
        print(f"{root} is not a git work tree", file=sys.stderr)
        return 1

    scanned = staged_text_files(root) if args.staged else repo_text_files(root)
    found: list[str] = []
    for rel, text in scanned:
        found.extend(violations(rel, text))
    what = "staged content" if args.staged else "repository files"
    return _report(found, what)


if __name__ == "__main__":
    raise SystemExit(main())
