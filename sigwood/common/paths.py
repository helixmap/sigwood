"""Path resolution and private artifact creation shared across sigwood.

One function (``be_like_water``) decides whether a user-supplied target string
points to a FILE or a DIRECTORY, via a gated ladder. The trailing-slash gate is
evaluated BEFORE any disk check so an explicit trailing slash can never be
overridden by what happens to exist on disk.

A second helper (``resolve_path``) resolves a config-supplied path string
against the SIGWOOD_ROOT base. ``effective_root`` reads the active root from env or
config. CLI-supplied paths never get root applied; only config-file values do.

The private-write helpers are the single owner of modes for files and directories
sigwood creates. They enforce private modes independently of the ambient umask while
leaving every pre-existing directory untouched.
"""

from __future__ import annotations

import errno
import os
from pathlib import Path
from typing import Any, NamedTuple, TextIO


class ResolvedTarget(NamedTuple):
    """Verdict from be_like_water: where to write, and whether it's a file or directory.

    Attributes:
        path: For FILE mode, the exact file path. For DIRECTORY mode, the
            directory; caller auto-names inside it.
        is_file: True for FILE, False for DIRECTORY.
    """

    path: Path
    is_file: bool


def private_mkdir(
    path: str | os.PathLike[str], *, private: bool = True,
) -> None:
    """Create ``path`` and missing parents without touching existing modes.

    Private components are created and then set to ``0700``. Public components
    request ``0777`` and remain governed by the ambient umask. Only a component
    successfully created by this call is eligible for chmod; a directory created
    concurrently by another process is accepted but never mode-touched.
    """
    target = Path(path)
    if target.is_dir():
        return
    if target.exists():
        raise FileExistsError(errno.EEXIST, os.strerror(errno.EEXIST), str(target))

    missing: list[Path] = []
    current = target
    while not current.exists():
        missing.append(current)
        parent = current.parent
        if parent == current:
            break
        current = parent

    requested_mode = 0o700 if private else 0o777
    for component in reversed(missing):
        try:
            os.mkdir(component, requested_mode)
        except FileExistsError:
            if component.is_dir():
                continue
            raise
        if private:
            os.chmod(component, 0o700)


def _write_fd(path: str | os.PathLike[str], *, private: bool) -> int:
    """Open one write-truncate fd and apply the selected permission policy."""
    requested_mode = 0o600 if private else 0o666
    fd = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
        requested_mode,
    )
    try:
        if private:
            os.fchmod(fd, 0o600)
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        raise
    return fd


def private_open(
    path: str | os.PathLike[str], *, private: bool = True,
    encoding: str = "utf-8", newline: str | None = None,
) -> TextIO:
    """Open a write-truncate text stream under the selected permission policy."""
    fd = _write_fd(path, private=private)
    try:
        return os.fdopen(fd, "w", encoding=encoding, newline=newline)
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        raise


def private_write_text(
    path: str | os.PathLike[str], text: str, *, private: bool = True,
    encoding: str = "utf-8", newline: str | None = None,
) -> None:
    """Write one text value through :func:`private_open`."""
    with private_open(
        path, private=private, encoding=encoding, newline=newline,
    ) as stream:
        stream.write(text)


def private_write_bytes(
    path: str | os.PathLike[str], data: bytes, *, private: bool = True,
) -> None:
    """Write one byte value through the shared write-truncate fd path."""
    fd = _write_fd(path, private=private)
    try:
        stream = os.fdopen(fd, "wb")
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        raise
    with stream:
        stream.write(data)


def be_like_water(target: str) -> ResolvedTarget:
    """Resolve a target string to a (path, is_file) verdict via a gated ladder.

    Gates evaluated in order - a winning gate decides without falling through:

      Step 0 (gate): trailing slash -> DIRECTORY. No disk consult.
                     Explicit user intent overrides anything that happens to
                     exist on disk by that name.

    For targets without a trailing slash, conform to disk first:

      Step 1: exists and is_file() -> FILE (use as-is; overwrite silently at write).
      Step 2: exists and is_dir()  -> DIRECTORY (auto-name inside).
      Step 3: does not exist       -> FILE. Parent will be mkdir-p'd at write;
                                      basename IS the filename whatever it looks like
                                      (no suffix inspection).

    Exotic fs objects (dangling symlinks, FIFOs, devices) fall through to step 3
    and let the real open() surface the error via the CLI actionable-error
    boundary. We do not special-case exotic fs objects.

    Pure-ish: reads disk for exists/is_file/is_dir but does NOT create
    directories. Callers mkdir at write time.

    Args:
        target: Raw path string, NOT a Path. Path normalizes trailing slashes
            away, so the raw user intent must be preserved end-to-end.

    Returns:
        ResolvedTarget(path, is_file) - path is expanduser'd; caller decides
        when to mkdir.
    """
    if target.endswith("/"):
        return ResolvedTarget(Path(target).expanduser(), is_file=False)
    p = Path(target).expanduser()
    if p.is_file():
        return ResolvedTarget(p, is_file=True)
    if p.is_dir():
        return ResolvedTarget(p, is_file=False)
    return ResolvedTarget(p, is_file=True)


def unique_path(directory: Path, basename: str) -> Path:
    """Return a non-colliding path inside ``directory`` for ``basename``.

    Tries ``directory / basename``; on collision appends ``-1``, ``-2``, …
    before the extension until a free name is found.

    For AUTO-NAMED DIRECTORY-verdict targets ONLY (``--out=dir/`` / report_dir).
    An EXPLICIT FILE verdict is used as-is and MUST NEVER be routed here - the
    output-target rail keeps explicit file paths exact (overwrite-or-fail per the
    writer), and adding collision suffixing to them would be a new no-clobber
    behavior we do not want. TOCTOU race acceptable for a local single-user tool.
    """
    candidate = directory / basename
    if not candidate.exists():
        return candidate
    stem, suffix = candidate.stem, candidate.suffix
    n = 1
    while True:
        c = directory / f"{stem}-{n}{suffix}"
        if not c.exists():
            return c
        n += 1


def resolve_path(value: str | os.PathLike[str] | None, root: str | os.PathLike[str]) -> str | None:
    """Resolve a config-supplied path value against the SIGWOOD_ROOT base.

    Returns a STRING (trailing slash preserved) or None - never a Path, so
    output-dir callers can still hand the result to ``be_like_water`` without
    Path() stripping the directory-intent slash.

      None / ""        -> None              (key unset)
      "/var/log/zeek"  -> as-is             (absolute: root ignored)
      "~/x/exports"    -> expanduser(value) (~-anchored: root ignored)
      "exports"        -> join(expanduser(root), value) if root else value

    Pure path helper - validates path-like value types, with no URL handling
    or suffix sniffing.
    Apply to CONFIG-supplied paths only; CLI-supplied paths take ``root=""``
    so they get ``~``-expansion but resolve relative to CWD as shell semantics
    demand.
    """
    if value is None or value == "":
        return None
    if isinstance(value, os.PathLike):
        value = os.fspath(value)
    if not isinstance(value, str):
        raise ValueError("configured path must be a string")
    if isinstance(root, os.PathLike):
        root = os.fspath(root)
    if not isinstance(root, str):
        raise ValueError("[sigwood].root must be a string")
    if os.path.isabs(value):
        return value
    if value.startswith("~"):
        return os.path.expanduser(value)
    if root:
        return os.path.join(os.path.expanduser(root), value)
    return value


def effective_root(config: dict[str, Any]) -> str:
    """Return the active SIGWOOD_ROOT - env wins, then config, then empty."""
    return os.environ.get("SIGWOOD_ROOT") or config.get("sigwood", {}).get("root", "")
