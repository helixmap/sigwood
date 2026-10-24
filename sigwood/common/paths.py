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
import fcntl
import grp
import itertools
import os
import pwd
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
    """Create missing directories without changing pre-existing modes.

    New private directories finish at 0700. Recovering owner access removed by
    the umask requires a trusted containing directory. Public directories keep
    the ambient umask's mode.
    """
    target = Path(path)
    if target.is_dir():
        return
    if target.exists():
        raise FileExistsError(errno.EEXIST, os.strerror(errno.EEXIST), str(target))
    if os.open not in os.supports_dir_fd or os.mkdir not in os.supports_dir_fd:
        _mkdir_without_dirfd(target, private=private)
        return

    dir_fd, components = _open_directory_anchor(target, path)
    try:
        for component in components:
            try:
                nxt = _descend(dir_fd, component, path)
            except FileNotFoundError:
                try:
                    os.mkdir(component, 0o700 if private else 0o777, dir_fd=dir_fd)
                except FileExistsError:
                    nxt = _descend(dir_fd, component, path)
                else:
                    nxt = _open_created_directory(dir_fd, component, path, private=private)
            os.close(dir_fd)
            dir_fd = nxt
    finally:
        os.close(dir_fd)


def _mkdir_without_dirfd(target: Path, *, private: bool) -> None:
    """Use pathname creation only where descriptor-relative calls are absent."""
    missing: list[Path] = []
    current = target
    while not current.exists():
        missing.append(current)
        parent = current.parent
        if parent == current:
            break
        current = parent
    for component in reversed(missing):
        try:
            os.mkdir(component, 0o700 if private else 0o777)
        except FileExistsError:
            if component.is_dir():
                continue
            raise
        if private:
            os.chmod(component, 0o700)


def _directory_trust_failure(info: os.stat_result) -> str | None:
    """Return the reason other accounts may control entries, or None."""
    if info.st_uid not in (os.geteuid(), 0):
        return "directory owned by another user"
    shared = info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    if not shared or info.st_mode & stat.S_ISVTX:
        return None
    if info.st_mode & stat.S_IWOTH:
        return "group- or world-writable directory without the sticky bit"
    try:
        primary_gid = pwd.getpwuid(os.geteuid()).pw_gid
    except KeyError:
        return "group-writable directory whose account group cannot be resolved"
    if info.st_gid != primary_gid:
        return "group-writable directory outside your primary group"
    try:
        members = grp.getgrgid(info.st_gid).gr_mem
    except KeyError:
        return "group-writable directory whose group cannot be resolved"
    if members:
        return "group-writable directory whose group lists other members"
    # Supplementary membership does not reveal other accounts' primary groups.
    return None


def _directory_trusted(info: os.stat_result) -> bool:
    """Assess trust using the shared owner, mode and account-group policy."""
    return _directory_trust_failure(info) is None


def _validate_followed_directory(fd: int, component: str, path: object) -> None:
    """Validate the opened target of a followed directory link."""
    reason = _directory_trust_failure(os.fstat(fd))
    if reason is not None:
        raise ValueError(
            f"{path}: the directory component {component!r} is a symbolic link to a "
            f"{reason} - refusing to write through it; "
            "tighten its permissions or write to a different location"
        )


def _descend(dir_fd: int, component: str, path: object) -> int:
    """Open one component, following only a trusted directory relocation."""
    try:
        return os.open(
            component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dir_fd,
        )
    except OSError as exc:
        if exc.errno not in (errno.ELOOP, errno.ENOTDIR):
            raise
        try:
            link = os.lstat(component, dir_fd=dir_fd)
        except OSError:
            raise exc
        if not stat.S_ISLNK(link.st_mode):
            raise
        reason = _directory_trust_failure(os.fstat(dir_fd))
        if reason is not None:
            raise ValueError(
                f"{path}: the directory component {component!r} is a symbolic link "
                f"inside a directory other accounts can modify ({reason}) - "
                "refusing to follow it; write to a different location"
            ) from exc
        if link.st_uid not in (os.geteuid(), 0):
            raise ValueError(
                f"{path}: the directory component {component!r} is a symbolic link "
                "owned by another user - refusing to follow it; "
                "remove it or choose another target"
            ) from exc
        nxt = os.open(component, os.O_RDONLY | os.O_DIRECTORY, dir_fd=dir_fd)
        try:
            _validate_followed_directory(nxt, component, path)
        except BaseException:
            os.close(nxt)
            raise
        return nxt


def _open_directory_anchor(directory: Path, path: object) -> tuple[int, list[str]]:
    """Open a known anchor without falling back after an access failure."""
    parts = list(directory.parts)
    anchor = directory.anchor if directory.is_absolute() else "."
    components = parts[1:] if directory.is_absolute() else parts
    try:
        fd = os.open(anchor, os.O_RDONLY | os.O_DIRECTORY)
    except OSError as exc:
        if exc.errno not in (errno.EACCES, errno.EPERM):
            raise
        raise ValueError(
            f"{path}: cannot open the directory {anchor!r} to write safely - "
            "make it readable or write to a different location"
        ) from exc
    return fd, components


def _recover_created_directory(dir_fd: int, component: str, path: object) -> None:
    """Restore owner access only while a trusted container stabilizes the name."""
    info = os.lstat(component, dir_fd=dir_fd)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
        raise ValueError(
            f"{path}: directory component {component!r} is not a directory you own - "
            "refusing to change its permissions; choose another target"
        )
    if not _directory_trusted(os.fstat(dir_fd)):
        raise ValueError(
            f"{path}: cannot recover private permissions on directory component "
            f"{component!r} inside a directory other accounts can modify; "
            "use a umask that preserves owner read and search access, "
            "or write to a different location"
        )
    os.chmod(component, 0o700, dir_fd=dir_fd)


def _open_created_directory(
    dir_fd: int, component: str, path: object, *, private: bool,
) -> int:
    """Bind mode changes to a new owned directory, with one access recovery."""
    for attempt in range(2):
        try:
            fd = os.open(
                component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=dir_fd,
            )
        except OSError as exc:
            if private and exc.errno == errno.EACCES and attempt == 0:
                _recover_created_directory(dir_fd, component, path)
                continue
            if exc.errno in (errno.ELOOP, errno.ENOTDIR):
                try:
                    is_link = stat.S_ISLNK(os.lstat(component, dir_fd=dir_fd).st_mode)
                except OSError:
                    is_link = False
                if is_link:
                    raise ValueError(
                        f"{path}: directory component {component!r} is a symbolic link - "
                        "refusing to change its permissions; choose another target"
                    ) from exc
            raise
        try:
            info = os.fstat(fd)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
                raise ValueError(
                    f"{path}: directory component {component!r} is not a directory "
                    "you own - refusing to change its permissions; choose another target"
                )
            if private:
                os.fchmod(fd, 0o700)
        except BaseException:
            os.close(fd)
            raise
        return fd
    raise RuntimeError("directory access recovery did not finish")  # pragma: no cover


def _open_parent_dirfd(path: str | os.PathLike[str]) -> tuple[int | None, str]:
    """Open every parent component relative to a held directory descriptor.

    Relocations require a trusted containing directory, a link owned by the
    user or root, and a trusted opened target. The private-group trust arm
    cannot identify other accounts sharing that group as their primary gid.
    Platforms without descriptor-relative open retain pathname behavior.
    """
    target = Path(path)
    name = target.name
    if not name:
        raise ValueError(f"{path}: no file name to write")
    if os.open not in os.supports_dir_fd:
        return None, str(target)
    dir_fd, components = _open_directory_anchor(target.parent, path)
    try:
        for component in components:
            nxt = _descend(dir_fd, component, path)
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
    """Open one regular write-truncate fd without blocking and apply its mode."""
    requested_mode = 0o600 if private else 0o666
    try:
        fd = _open_through_walked_parent(
            path,
            (
                os.O_WRONLY
                | os.O_CREAT
                | os.O_TRUNC
                | os.O_NOFOLLOW
                | os.O_NONBLOCK
            ),
            requested_mode,
        )
    except OSError as exc:
        if exc.errno == errno.ENXIO:
            raise _safe_open_leaf_refusal(path) from exc
        if exc.errno != errno.ELOOP:
            raise
        try:
            leaf_is_symlink = stat.S_ISLNK(os.lstat(path).st_mode)
        except OSError:
            leaf_is_symlink = False
        if not leaf_is_symlink:
            raise
        raise _symlink_leaf_refusal(path) from exc
    try:
        _require_regular_fd(path, fd)
        descriptor_flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, descriptor_flags & ~os.O_NONBLOCK)
        if private:
            os.fchmod(fd, 0o600)
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        raise
    return fd


def _symlink_leaf_refusal(path: str | os.PathLike[str]) -> ValueError:
    return ValueError(
        f"{path} is a symbolic link - refusing to write through it; "
        "remove it or choose another target"
    )


def _safe_open_leaf_refusal(path: str | os.PathLike[str]) -> ValueError:
    return ValueError(
        f"{path} could not be opened safely - refusing to write to it; "
        "choose a regular file or directory"
    )


def _nonregular_leaf_refusal(path: str | os.PathLike[str]) -> ValueError:
    return ValueError(
        f"{path} is not a regular file - refusing to write to it; "
        "choose a regular file or directory"
    )


def _require_regular_fd(path: str | os.PathLike[str], fd: int) -> None:
    """Make the leaf-type decision from an opened descriptor."""
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        raise _nonregular_leaf_refusal(path)


def _validate_existing_regular_leaf(
    path: Path, leaf: str, dir_fd: int | None,
) -> os.stat_result | None:
    """Classify an atomic-replace destination without accessing its inode."""
    try:
        existing = (
            os.lstat(leaf, dir_fd=dir_fd) if dir_fd is not None else os.lstat(leaf)
        )
    except OSError as exc:
        if exc.errno == errno.ENOENT:
            return
        raise
    if stat.S_ISLNK(existing.st_mode):
        raise _symlink_leaf_refusal(path)
    if not stat.S_ISREG(existing.st_mode):
        raise _nonregular_leaf_refusal(path)
    return existing


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


def private_open_lock(
    path: str | os.PathLike[str], *, encoding: str = "utf-8",
) -> TextIO:
    """Open a stable regular lock inode without changing existing bytes or mode.

    Only an inode exclusively created by this call is tightened to 0600. The
    returned stream is used for locking, never for writing lock contents.
    """
    flags = os.O_WRONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    created = False
    try:
        try:
            fd = _open_through_walked_parent(
                path, flags | os.O_CREAT | os.O_EXCL, 0o600,
            )
            created = True
        except FileExistsError:
            fd = _open_through_walked_parent(path, flags, 0o600)
    except OSError as exc:
        if exc.errno == errno.ENXIO:
            raise _safe_open_leaf_refusal(path) from exc
        if exc.errno != errno.ELOOP:
            raise
        try:
            is_link = stat.S_ISLNK(os.lstat(path).st_mode)
        except OSError:
            is_link = False
        if not is_link:
            raise
        raise _symlink_leaf_refusal(path) from exc
    try:
        _require_regular_fd(path, fd)
        descriptor_flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, descriptor_flags & ~os.O_NONBLOCK)
        if created:
            os.fchmod(fd, 0o600)
        return os.fdopen(fd, "w", encoding=encoding)
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        raise


def _atomic_replace_write(
    path: str | os.PathLike[str], payload: bytes, *, private: bool,
    mode: int | None = None,
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
    if private and mode is not None:
        raise ValueError("explicit modes require the public permission policy")
    target = Path(path)
    for attempt in range(2):
        try:
            _atomic_replace_once(target, payload, private=private, mode=mode)
            return
        except OSError as exc:
            # Same lost-parent race the truncate path retries: a concurrent writer
            # can remove and recreate the containing directory while its descriptor
            # is held. One re-walk covers it; a genuinely absent parent fails again.
            if exc.errno != errno.ENOENT or attempt == 1:
                raise


def _atomic_replace_once(
    target: Path, payload: bytes, *, private: bool, mode: int | None = None,
) -> None:
    """One attempt at the fresh-name write and rename."""
    if private and mode is not None:
        raise ValueError("explicit modes require the public permission policy")
    dir_fd, leaf = _open_parent_dirfd(target)
    try:
        existing = _validate_existing_regular_leaf(target, leaf, dir_fd)

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
            elif mode is not None:
                os.fchmod(fd, mode & 0o777)
            elif existing is not None:
                os.fchmod(fd, stat.S_IMODE(existing.st_mode) & 0o777)
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
            _validate_existing_regular_leaf(target, leaf, dir_fd)
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
    mode: int | None = None,
) -> None:
    """Replace one text value with private or preserved public permissions.

    An explicit public mode overrides the existing ordinary permission bits.
    A fresh public file without an explicit mode follows the ambient umask.
    """
    if newline is None:
        payload = text.replace("\n", os.linesep) if os.linesep != "\n" else text
    elif newline == "":
        payload = text
    else:
        payload = text.replace("\n", newline)
    _atomic_replace_write(path, payload.encode(encoding), private=private, mode=mode)


def private_write_bytes(
    path: str | os.PathLike[str], data: bytes, *, private: bool = True,
    mode: int | None = None,
) -> None:
    """Replace one byte value using the same mode policy as private_write_text."""
    _atomic_replace_write(path, data, private=private, mode=mode)


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
