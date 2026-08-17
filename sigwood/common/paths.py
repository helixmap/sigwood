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
import itertools
import os
import stat
from pathlib import Path
from typing import Any, NamedTuple, TextIO


_TEMP_COUNTER = itertools.count()


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


def _validate_followed_directory(fd: int, component: str, path: object) -> None:
    """Accept a symlinked path component only when it cannot be attacker-chosen.

    Validation reads the OPENED DESCRIPTOR, never the name: a check against the
    path could be invalidated between the check and the open, whereas fstat
    describes exactly the directory that was opened. Accepted owners are the
    running user and root; a group- or world-writable directory is refused
    because any account able to write it can substitute what sits beneath it.
    """
    info = os.fstat(fd)
    if info.st_uid not in (os.geteuid(), 0):
        raise ValueError(
            f"{path}: the directory component {component!r} is a symbolic link to a "
            "directory owned by another user - refusing to write through it; "
            "point it somewhere you own or write to a different location"
        )
    shared = bool(info.st_mode & (stat.S_IWGRP | stat.S_IWOTH))
    # The STICKY bit is what separates a shared directory from a hostile one: in a
    # sticky directory another account may create its own names but cannot remove or
    # replace one it does not own, which is the standard safe-shared pattern and what
    # `/tmp` relies on. Refusing every group- or world-writable target would reject
    # `/tmp` outright - on macOS it is a symlink to a 1777 `/private/tmp` - and that
    # is an ordinary place to write, not an attack. The ownership test above is what
    # actually rejects an attacker-chosen destination.
    if shared and not info.st_mode & stat.S_ISVTX:
        raise ValueError(
            f"{path}: the directory component {component!r} is a symbolic link to a "
            "group- or world-writable directory without the sticky bit - refusing to "
            "write through it; tighten its permissions or write to a different location"
        )


def _open_parent_dirfd(path: str | os.PathLike[str]) -> tuple[int | None, str]:
    """Open the containing directory component-by-component, and the leaf name.

    ``O_NOFOLLOW`` on the final name protects the file that is opened; it says
    nothing about the directories walked to reach it, so a substituted PARENT
    would still receive the write. Each component is therefore opened with
    ``O_DIRECTORY | O_NOFOLLOW`` and, when that reports a link, followed only
    after :func:`_validate_followed_directory` accepts what it opened.

    A relocated directory is an ordinary and supported setup, so a symlink the
    operator owns is followed; only one another account could have chosen is
    refused. Returns ``(None, str(path))`` where the platform cannot open
    relative to a descriptor, preserving the previous single-open behaviour.
    """
    target = Path(path)
    name = target.name
    if not name:
        raise ValueError(f"{path}: no file name to write")
    if os.open not in os.supports_dir_fd:
        return None, str(target)

    parent = target.parent
    parts = list(parent.parts)
    if not parts:
        return None, str(target)

    anchor = parts[0]
    try:
        dir_fd = os.open(anchor, os.O_RDONLY | os.O_DIRECTORY)
    except OSError:
        return None, str(target)

    try:
        for component in parts[1:]:
            try:
                nxt = os.open(
                    component,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=dir_fd,
                )
            except OSError as exc:
                # Refusing to follow a symlinked directory surfaces differently by
                # platform: ELOOP on Linux, ENOTDIR on macOS, because O_DIRECTORY
                # sees a non-directory once O_NOFOLLOW declines the link. ENOTDIR is
                # ALSO the honest error for a component that is a regular file, so
                # the link is confirmed by lstat rather than inferred from errno.
                if exc.errno not in (errno.ELOOP, errno.ENOTDIR):
                    raise
                try:
                    is_link = stat.S_ISLNK(
                        os.lstat(component, dir_fd=dir_fd).st_mode
                    )
                except OSError:
                    is_link = False
                if not is_link:
                    raise
                nxt = os.open(component, os.O_RDONLY | os.O_DIRECTORY, dir_fd=dir_fd)
                try:
                    _validate_followed_directory(nxt, component, path)
                except BaseException:
                    os.close(nxt)
                    raise
            os.close(dir_fd)
            dir_fd = nxt
    except BaseException:
        os.close(dir_fd)
        raise
    return dir_fd, name


def _open_through_walked_parent(
    path: str | os.PathLike[str], flags: int, mode: int,
) -> int:
    """Open one leaf relative to a freshly walked parent, retrying a lost parent once.

    The walk holds a descriptor to the containing directory while the leaf is
    opened, so a concurrent writer that removes and recreates that directory in
    between leaves the descriptor pointing at the unlinked inode and the create
    fails ENOENT. Resolving the whole path at open time never saw this, because
    each open re-resolved the name. One re-walk covers the race; a parent that is
    genuinely absent fails the second walk with its own error rather than looping.
    """
    last: OSError | None = None
    for attempt in range(2):
        dir_fd, leaf = _open_parent_dirfd(path)
        try:
            return os.open(leaf, flags, mode, dir_fd=dir_fd)
        except OSError as exc:
            last = exc
            if not (exc.errno == errno.ENOENT and dir_fd is not None and attempt == 0):
                raise
        finally:
            if dir_fd is not None:
                try:
                    os.close(dir_fd)
                except OSError:
                    pass
    raise last  # pragma: no cover - the loop either returns or raises above


def _write_fd(path: str | os.PathLike[str], *, private: bool) -> int:
    """Open one write-truncate fd, refuse a symlink leaf, and apply its mode."""
    requested_mode = 0o600 if private else 0o666
    try:
        fd = _open_through_walked_parent(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW,
            requested_mode,
        )
    except OSError as exc:
        if exc.errno != errno.ELOOP:
            raise
        try:
            leaf_is_symlink = stat.S_ISLNK(os.lstat(path).st_mode)
        except OSError:
            leaf_is_symlink = False
        if not leaf_is_symlink:
            raise
        raise ValueError(
            f"{path} is a symbolic link - refusing to write through it; "
            "remove it or choose another target"
        ) from exc
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


def _atomic_replace_write(
    path: str | os.PathLike[str], payload: bytes, *, private: bool,
) -> None:
    """Write one complete value to a fresh name and rename it over the target.

    Opening the destination with ``O_TRUNC`` empties it before anything is known
    about it, so a HARD LINK at that name has its contents destroyed: the second
    name refers to the same inode, and truncation reaches it. Creating a new name
    with ``O_EXCL`` and renaming over the target never opens what is already
    there, so a hard-linked victim keeps its contents and simply loses one of its
    names.

    Only whole-value writers use this. A streaming writer holds its handle across
    partial writes and rotation, and the export provenance LOCK must keep opening
    its own inode in place or two writers would each lock a private temporary and
    both believe they hold it.
    """
    target = Path(path)
    for attempt in range(2):
        try:
            _atomic_replace_once(target, payload, private=private)
            return
        except OSError as exc:
            # Same lost-parent race the truncate path retries: a concurrent writer
            # can remove and recreate the containing directory while its descriptor
            # is held. One re-walk covers it; a genuinely absent parent fails again.
            if exc.errno != errno.ENOENT or attempt == 1:
                raise


def _atomic_replace_once(
    target: Path, payload: bytes, *, private: bool,
) -> None:
    """One attempt at the fresh-name write and rename."""
    dir_fd, leaf = _open_parent_dirfd(target)
    try:
        # Preserve the operator-facing refusal: a symlink destination is reported
        # rather than silently replaced. Renaming could not follow the link in any
        # case, so this is a message, never the safety property.
        try:
            existing = (
                os.lstat(leaf, dir_fd=dir_fd) if dir_fd is not None else os.lstat(leaf)
            )
        except OSError:
            existing = None
        if existing is not None and stat.S_ISLNK(existing.st_mode):
            raise ValueError(
                f"{path} is a symbolic link - refusing to write through it; "
                "remove it or choose another target"
            )

        requested_mode = 0o600 if private else 0o666
        temporary = f".{Path(leaf).name}.sigwood-{os.getpid()}-{next(_TEMP_COUNTER)}"
        fd = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            requested_mode,
            dir_fd=dir_fd,
        )
        try:
            if private:
                os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(payload)
        except BaseException:
            try:
                os.close(fd)
            except OSError:
                pass
            _unlink_quietly(temporary, dir_fd)
            raise
        try:
            os.rename(temporary, leaf, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
        except BaseException:
            _unlink_quietly(temporary, dir_fd)
            raise
    finally:
        if dir_fd is not None:
            try:
                os.close(dir_fd)
            except OSError:
                pass


def _unlink_quietly(name: str, dir_fd: int | None) -> None:
    """Remove a temporary that never became the artifact."""
    try:
        os.unlink(name, dir_fd=dir_fd)
    except OSError:
        pass


def private_write_text(
    path: str | os.PathLike[str], text: str, *, private: bool = True,
    encoding: str = "utf-8", newline: str | None = None,
) -> None:
    """Write one text value, replacing the destination rather than emptying it."""
    if newline is None:
        payload = text.replace("\n", os.linesep) if os.linesep != "\n" else text
    elif newline == "":
        payload = text
    else:
        payload = text.replace("\n", newline)
    _atomic_replace_write(path, payload.encode(encoding), private=private)


def private_write_bytes(
    path: str | os.PathLike[str], data: bytes, *, private: bool = True,
) -> None:
    """Write one byte value, replacing the destination rather than emptying it."""
    _atomic_replace_write(path, data, private=private)


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
