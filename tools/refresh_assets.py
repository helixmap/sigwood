#!/usr/bin/env python3
"""Refresh the checked-in report, terminal-demo, and explicit graph assets.

This is a developer tool, not a runtime dependency.  ``--check`` compares
semantic source-output oracles and deliberately does not launch Chrome,
asciinema, termsvg, gifski, or ffmpeg.  The graph is intentionally outside
the default refresh, stamps, and check surface because its source is private.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import pty
import random
import re
import select
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import termios
import time
from typing import Callable, Iterable, Mapping, Sequence
import unicodedata
import zlib


REPO_ROOT = Path(__file__).resolve().parents[1]
REPORT_ASSET = REPO_ROOT / "docs" / "img" / "report.png"
DEMO_ASSET = REPO_ROOT / "docs" / "img" / "demo.svg"
GRAPH_ASSET = REPO_ROOT / "docs" / "img" / "graph.gif"
STAMP_PATH = REPO_ROOT / "docs" / "img" / "assets.stamp.json"
DEMO_CONFIG = REPO_ROOT / "demo" / "sigwood.toml"
CORPUS_GENERATOR = REPO_ROOT / "demo" / "gen_corpus.py"

SEED = 3759
ANCHOR = "2026-06-01T00:00:00"
TZ = "UTC"
COLS, ROWS = 120, 44
GRAPH_WIDTH, GRAPH_HEIGHT = 760, 788
GRAPH_FPS = 8
GRAPH_SECONDS = 4
GRAPH_TOP_HOSTS = 30
DIGEST_DWELL_SECONDS = 4.0
HUNT_DWELL_SECONDS = 2.2
SCHEMA_VERSION = 1
REPORT_ORACLE = "finding-rows/sha256"
DEMO_ORACLE = "text-output/sha256"
COMMANDS = (
    ("digest", "-q", "~/zeek/dns.log"),
    ("hunt", "-q"),
)
PROMPT = "›".encode() + b"\x1b[0m "


class AssetError(RuntimeError):
    """A real refresh/check failure."""


class AssetSkip(RuntimeError):
    """A missing optional renderer caused one asset to be skipped."""

    def __init__(self, tool: str, asset: str) -> None:
        super().__init__(f"skipped {asset}: missing {tool}")
        self.tool = tool
        self.asset = asset


class RunResult:
    def __init__(
        self,
        returncode: int,
        stdout: str = "",
        stderr: str = "",
        *,
        timed_out: bool = False,
    ) -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.timed_out = timed_out


Runner = Callable[[Sequence[str], Path, Mapping[str, str], float], RunResult]


def _text(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value)


def run_process(
    argv: Sequence[str], cwd: Path, env: Mapping[str, str], timeout: float
) -> RunResult:
    """Run a bounded child, retaining partial output on timeout."""
    try:
        completed = subprocess.run(
            list(argv),
            cwd=cwd,
            env=dict(env),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return RunResult(
            124,
            _text(exc.stdout),
            _text(exc.stderr),
            timed_out=True,
        )
    return RunResult(completed.returncode, completed.stdout, completed.stderr)


def run_process_until_artifact(
    argv: Sequence[str],
    cwd: Path,
    env: Mapping[str, str],
    timeout: float,
    artifact: Path,
) -> RunResult:
    """Stop a lingering renderer once its finished artifact is stable."""
    process = subprocess.Popen(
        list(argv),
        cwd=cwd,
        env=dict(env),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    deadline = time.monotonic() + timeout
    stable_size: int | None = None
    stable_since: float | None = None
    timed_out = False
    while time.monotonic() < deadline:
        returncode = process.poll()
        if artifact.is_file():
            try:
                size = artifact.stat().st_size
            except FileNotFoundError:
                size = -1
            if size > 0 and size == stable_size:
                if stable_since is not None and time.monotonic() - stable_since >= 0.2:
                    break
            else:
                stable_size = size
                stable_since = time.monotonic()
        if returncode is not None:
            break
        time.sleep(0.05)
    else:
        timed_out = True
    if process.poll() is None:
        process.terminate()
    try:
        stdout, stderr = process.communicate(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()
        stdout, stderr = process.communicate()
    return RunResult(
        process.returncode if process.returncode is not None else 124,
        stdout,
        stderr,
        timed_out=timed_out,
    )


def _run_checked(
    runner: Runner,
    argv: Sequence[str],
    cwd: Path,
    env: Mapping[str, str],
    timeout: float,
    label: str,
) -> RunResult:
    result = runner(argv, cwd, env, timeout)
    if result.timed_out or result.returncode:
        detail = result.stderr.strip() or result.stdout.strip() or "no child output"
        raise AssetError(f"{label} failed ({result.returncode}): {detail}")
    return result


def controlled_env(home: Path | None = None) -> dict[str, str]:
    env = dict(os.environ)
    env["TZ"] = TZ
    env.pop("SIGWOOD_ROOT", None)
    if home is not None:
        env["HOME"] = str(home)
    sigwood = find_sigwood()
    env["PATH"] = os.pathsep.join(
        [str(sigwood.parent), env.get("PATH", os.defpath)]
    )
    return env


def recording_env(home: Path) -> dict[str, str]:
    """Return a deterministic color-capable environment for the demo PTY."""
    env = controlled_env(home)
    env.pop("NO_COLOR", None)
    env["TERM"] = "xterm-256color"
    env["COLORTERM"] = "truecolor"
    return env


def find_sigwood() -> Path:
    local = REPO_ROOT / ".venv" / "bin" / "sigwood"
    if local.is_file() and os.access(local, os.X_OK):
        return local
    found = shutil.which("sigwood")
    if found:
        return Path(found).resolve()
    raise AssetError("required sigwood CLI is not executable")


def find_optional_tool(name: str, *, explicit: str | None = None) -> Path | None:
    if explicit is not None:
        candidate = Path(explicit).expanduser()
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate.resolve()
        return None
    found = shutil.which(name)
    return Path(found).resolve() if found else None


def find_browser(explicit: str | None = None) -> Path | None:
    if explicit is not None:
        return find_optional_tool("browser", explicit=explicit)
    for name in ("google-chrome", "google-chrome-stable", "chromium", "chromium-browser"):
        found = find_optional_tool(name)
        if found:
            return found
    for candidate in (
        Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
        Path("/Applications/Chromium.app/Contents/MacOS/Chromium"),
    ):
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate
    return None


def atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, raw_tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    tmp = Path(raw_tmp)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    finally:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass


def _write_text(path: Path, text: str, *, mode: int | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    if mode is not None:
        path.chmod(mode)


def _generate_corpus(target: Path, runner: Runner, env: Mapping[str, str]) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    _run_checked(
        runner,
        (
            sys.executable,
            str(CORPUS_GENERATOR),
            str(target),
            "--seed",
            str(SEED),
            "--anchor",
            ANCHOR,
        ),
        target.parent,
        env,
        90,
        "demo corpus generation",
    )


def build_sandbox(work_dir: Path, runner: Runner = run_process) -> Path:
    """Own the sole HOME/config/corpus used by demo recording and its oracle."""
    home = work_dir / "sandbox"
    home.mkdir(parents=True, exist_ok=True)
    env = controlled_env(home)
    _generate_corpus(home, runner, env)
    config = """[sigwood]
root = ""
zeek_dir = "~/zeek"
syslog_dir = "~/syslog"
default_window = "all"
detect = "dns, beacon, exfil, syslog"
"""
    _write_text(home / ".sigwood" / "config.toml", config, mode=0o600)
    rc = r"""export PS1='\[\033[38;5;13m\]›\[\033[0m\] '
export TERM=xterm-256color
"""
    _write_text(home / ".castrc", rc, mode=0o600)
    home.chmod(0o700)
    return home


class FindingRowsParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._table_depth = 0
        self._row: list[str] | None = None
        self._cell: list[str] | None = None
        self.rows: list[list[str]] = []

    @staticmethod
    def _classes(attrs: Iterable[tuple[str, str | None]]) -> set[str]:
        for key, value in attrs:
            if key == "class" and value:
                return set(value.split())
        return set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "table" and "findings-table" in self._classes(attrs):
            self._table_depth += 1
            return
        if not self._table_depth:
            return
        if tag == "table":
            self._table_depth += 1
        elif tag == "tr" and self._row is None:
            self._row = []
        elif tag in ("td", "th") and self._row is not None and self._cell is None:
            self._cell = []

    def handle_endtag(self, tag: str) -> None:
        if not self._table_depth:
            return
        if tag in ("td", "th") and self._cell is not None and self._row is not None:
            self._row.append(" ".join("".join(self._cell).split()))
            self._cell = None
        elif tag == "tr" and self._row is not None:
            self.rows.append(self._row)
            self._row = None
        elif tag == "table":
            self._table_depth -= 1

    def handle_data(self, data: str) -> None:
        if self._cell is not None:
            self._cell.append(data)


def report_oracle(html: str) -> str:
    parser = FindingRowsParser()
    parser.feed(html)
    parser.close()
    if not parser.rows:
        raise AssetError("report HTML has no findings-table rows")
    canonical = "\n".join("\x1f".join(row) for row in parser.rows)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


_ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def _drop_demo_banners(output: str) -> str:
    kept: list[str] = []
    dropping = False
    for raw_line in output.splitlines():
        plain = _ANSI.sub("", raw_line)
        stripped = plain.strip()
        if re.match(r"^(generated|as)\s*:", stripped, re.IGNORECASE):
            dropping = True
            continue
        if dropping and plain[:1].isspace() and stripped:
            continue
        dropping = False
        kept.append(raw_line)
    return "\n".join(kept)


def demo_oracle(outputs: Sequence[str]) -> str:
    canonical = "\n".join(_drop_demo_banners(output) for output in outputs)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def generate_report_html(work_dir: Path, runner: Runner = run_process) -> tuple[str, str]:
    report_root = work_dir / "report"
    report_root.mkdir(parents=True, exist_ok=True)
    report_root.chmod(0o700)
    corpus = report_root / "demo" / "corpus"
    env = controlled_env()
    local_config = report_root / "demo" / "sigwood.toml"
    local_config.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(DEMO_CONFIG, local_config)
    _generate_corpus(corpus, runner, env)
    output = report_root / "report.html"
    sigwood = find_sigwood()
    result = _run_checked(
        runner,
        (
            str(sigwood), "hunt", "-q", "--config=demo/sigwood.toml",
            "--format=html", "--out=report.html",
        ),
        report_root,
        env,
        300,
        "report generation",
    )
    if not output.is_file():
        raise AssetError(
            "report generation did not create HTML"
            + (f": {result.stdout.strip()}" if result.stdout.strip() else "")
        )
    html = output.read_text(encoding="utf-8")
    return html, report_oracle(html)


def generate_demo_outputs(
    home: Path, runner: Runner = run_process
) -> list[str]:
    env = controlled_env(home)
    sigwood = find_sigwood()
    outputs: list[str] = []
    for args in COMMANDS:
        result = _run_checked(
            runner,
            (str(sigwood), *args),
            home,
            env,
            300,
            f"demo oracle command {' '.join(args)}",
        )
        outputs.append(result.stdout)
    return outputs


def generate_demo_oracle(home: Path, runner: Runner = run_process) -> str:
    return demo_oracle(generate_demo_outputs(home, runner))


def _display_columns(text: str) -> int:
    width = 0
    for char in text.expandtabs(8):
        if unicodedata.combining(char):
            continue
        width += 2 if unicodedata.east_asian_width(char) in ("W", "F") else 1
    return width


def derive_pty_rows(hunt_output: str, *, cols: int = COLS) -> int:
    """Size the final frame for the hunt command, all output, and prompt."""
    if cols < 1:
        raise AssetError("PTY columns must be positive")
    plain = _ANSI.sub("", hunt_output)
    rows = 0
    for raw_line in plain.splitlines():
        # A carriage return repaints the current terminal row; only its final
        # state contributes to the held frame.
        line = raw_line.rsplit("\r", 1)[-1]
        columns = _display_columns(line)
        rows += max(1, (columns + cols - 1) // cols)
    if not rows:
        raise AssetError("hunt output is empty; cannot derive PTY height")
    # One row for the echoed command and one for the final shell prompt.
    return max(ROWS, rows + 2)


def generate_demo_state(
    home: Path, runner: Runner = run_process
) -> tuple[str, int]:
    outputs = generate_demo_outputs(home, runner)
    return demo_oracle(outputs), derive_pty_rows(outputs[1])


def _prepare_print_html(html: str) -> str:
    command_pattern = re.compile(
        r'(<span class="meta-label">as</span><span class="meta-value">)'
        r'.*?'
        r'(</span>)'
    )
    matches = command_pattern.findall(html)
    if len(matches) != 1:
        raise AssetError("report HTML does not have exactly one command metadata row")
    source = "@media (prefers-color-scheme: dark)"
    if source not in html:
        raise AssetError("report dark-media rule was not found")
    rendered = html.replace(source, "@media all")
    probe = (
        '<script>document.title="H="+'
        'document.documentElement.scrollHeight;</script>'
    )
    marker = "</body>"
    if marker not in rendered:
        raise AssetError("report HTML has no closing body tag")
    return rendered.replace(marker, probe + marker, 1)


def _chrome_call(
    browser: Path,
    args: Sequence[str],
    work_dir: Path,
    profile: Path,
    timeout: float,
    runner: Runner,
) -> RunResult:
    env = controlled_env()
    argv = (
        str(browser), "--headless=new", "--disable-gpu", "--no-first-run",
        "--no-default-browser-check", f"--user-data-dir={profile}", *args,
    )
    try:
        return runner(argv, work_dir, env, timeout)
    finally:
        # Chrome may leave a process tree after producing a valid artifact.
        subprocess.run(
            ("/usr/bin/pkill", "-f", str(profile)),
            capture_output=True,
            check=False,
        )


def render_report_png(
    html: str,
    work_dir: Path,
    browser: Path,
    runner: Runner = run_process,
) -> bytes:
    printable = work_dir / "print.html"
    _write_text(printable, _prepare_print_html(html))
    profile = work_dir / f"chrome-profile-{os.getpid()}-{time.time_ns()}"
    probe = _chrome_call(
        browser,
        ("--dump-dom", printable.resolve().as_uri()),
        work_dir,
        profile,
        45,
        runner,
    )
    match = re.search(r"<title>\s*H=(\d+)\s*</title>", probe.stdout, re.IGNORECASE)
    if match is None:
        detail = probe.stderr.strip() or f"exit {probe.returncode}"
        raise AssetError(f"Chrome height probe did not return H: {detail}")
    height = int(match.group(1))
    if not 1 <= height <= 100_000:
        raise AssetError(f"Chrome height probe returned implausible H={height}")
    png = work_dir / "report.png"
    shot = _chrome_call(
        browser,
        (
            f"--screenshot={png}", f"--window-size=1110,{height}",
            "--force-device-scale-factor=2", printable.resolve().as_uri(),
        ),
        work_dir,
        profile,
        60,
        runner,
    )
    # A valid finished file is authoritative: Chrome can linger and time out.
    if not png.is_file():
        detail = shot.stderr.strip() or f"exit {shot.returncode}"
        raise AssetError(f"Chrome did not create report PNG: {detail}")
    data = png.read_bytes()
    validate_png(data, expected_width=2220, expected_height=height * 2)
    return data


def validate_png(data: bytes, *, expected_width: int, expected_height: int) -> None:
    signature = b"\x89PNG\r\n\x1a\n"
    if not data.startswith(signature):
        raise AssetError("PNG signature is invalid")
    pos = len(signature)
    seen_ihdr = False
    seen_iend = False
    while pos < len(data):
        if len(data) - pos < 12:
            raise AssetError("PNG is truncated")
        length = struct.unpack(">I", data[pos:pos + 4])[0]
        chunk_type = data[pos + 4:pos + 8]
        end = pos + 12 + length
        if end > len(data):
            raise AssetError("PNG chunk is truncated")
        payload = data[pos + 8:pos + 8 + length]
        stored_crc = struct.unpack(">I", data[pos + 8 + length:end])[0]
        actual_crc = zlib.crc32(chunk_type + payload) & 0xFFFFFFFF
        if stored_crc != actual_crc:
            raise AssetError(f"PNG {chunk_type.decode('ascii', 'replace')} CRC is invalid")
        if chunk_type == b"IHDR":
            if seen_ihdr or pos != 8 or length != 13:
                raise AssetError("PNG IHDR structure is invalid")
            width, height = struct.unpack(">II", payload[:8])
            if (width, height) != (expected_width, expected_height):
                raise AssetError(
                    f"PNG dimensions are {width}x{height}, expected "
                    f"{expected_width}x{expected_height}"
                )
            seen_ihdr = True
        elif chunk_type == b"IEND":
            if length:
                raise AssetError("PNG IEND is not empty")
            seen_iend = True
            if end != len(data):
                raise AssetError("PNG has trailing bytes after IEND")
            pos = end
            break
        pos = end
    if not seen_ihdr:
        raise AssetError("PNG has no IHDR")
    if not seen_iend:
        raise AssetError("PNG has no terminal IEND")


def generate_graph_html(
    source: Path,
    work_dir: Path,
    *,
    top_hosts: int = GRAPH_TOP_HOSTS,
    runner: Runner = run_process,
) -> str:
    """Render one scrubbed source through a neutral path and throwaway config."""
    if top_hosts < 1:
        raise AssetError("graph top-hosts must be positive")
    source = source.expanduser().resolve()
    if not source.is_file():
        raise AssetError("graph source does not exist")
    graph_root = work_dir / "graph-work"
    graph_root.mkdir(parents=True, exist_ok=True)
    graph_root.chmod(0o700)
    home = graph_root / "home"
    neutral_source = graph_root / "source" / "conn.log.gz"
    neutral_source.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, neutral_source)
    config = f'''[sigwood]
root = ""
default_window = "all"
home_net = ["192.168.1.0/24", "192.168.2.0/24"]

[graph]
top_hosts = {top_hosts}
'''
    config_path = home / ".sigwood" / "config.toml"
    _write_text(config_path, config, mode=0o600)
    home.chmod(0o700)
    output = graph_root / "graph.html"
    sigwood = find_sigwood()
    result = _run_checked(
        runner,
        (
            str(sigwood),
            "graph",
            "-q",
            "-y",
            "-a",
            "--utc",
            f"--config={config_path}",
            "--out=graph.html",
            str(neutral_source.relative_to(graph_root)),
        ),
        graph_root,
        controlled_env(home),
        600,
        "graph generation",
    )
    if not output.is_file():
        detail = result.stderr.strip() or result.stdout.strip() or "no child output"
        raise AssetError(f"graph generation did not create HTML: {detail}")
    html = output.read_text(encoding="utf-8")
    if 'id="sankey"' not in html:
        raise AssetError("graph HTML has no Sankey canvas")
    private_values = [str(source)]
    if source.name != neutral_source.name:
        private_values.append(source.name)
    for private_value in private_values:
        if private_value in html:
            raise AssetError("graph HTML retained the private source path")
    return html


def _capture_graph_frames(
    html: str,
    work_dir: Path,
    browser: Path,
    runner: Runner,
) -> list[Path]:
    work_dir.mkdir(parents=True, exist_ok=True)
    page = work_dir / "graph.html"
    _write_text(page, html)
    frames: list[Path] = []
    frame_count = GRAPH_FPS * GRAPH_SECONDS
    for index in range(frame_count):
        frame = work_dir / f"frame-{index:04d}.png"
        try:
            frame.unlink()
        except FileNotFoundError:
            pass
        profile = work_dir / f"chrome-profile-{index:04d}"
        budget_ms = max(1, round((index + 1) * 1000 / GRAPH_FPS))
        frame_runner = runner
        if runner is run_process:
            frame_runner = lambda argv, cwd, env, timeout, path=frame: run_process_until_artifact(
                argv, cwd, env, timeout, path
            )
        result = _chrome_call(
            browser,
            (
                "--hide-scrollbars",
                f"--window-size={GRAPH_WIDTH},{GRAPH_HEIGHT}",
                "--force-device-scale-factor=1",
                f"--virtual-time-budget={budget_ms}",
                f"--screenshot={frame}",
                page.resolve().as_uri(),
            ),
            work_dir,
            profile,
            45,
            frame_runner,
        )
        if not frame.is_file():
            detail = result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}"
            raise AssetError(f"Chrome did not create graph frame {index + 1}: {detail}")
        validate_png(
            frame.read_bytes(),
            expected_width=GRAPH_WIDTH,
            expected_height=GRAPH_HEIGHT,
        )
        frames.append(frame)
    return frames


def validate_gif(
    data: bytes,
    *,
    expected_width: int = GRAPH_WIDTH,
    expected_height: int = GRAPH_HEIGHT,
    minimum_frames: int = 2,
) -> int:
    """Validate GIF structure and require more than one distinct image frame."""
    if len(data) < 14 or data[:6] not in (b"GIF87a", b"GIF89a"):
        raise AssetError("GIF signature is invalid")
    width, height = struct.unpack("<HH", data[6:10])
    if (width, height) != (expected_width, expected_height):
        raise AssetError(
            f"GIF dimensions are {width}x{height}, expected "
            f"{expected_width}x{expected_height}"
        )
    packed = data[10]
    pos = 13
    if packed & 0x80:
        pos += 3 * (2 ** ((packed & 0x07) + 1))
    images: list[bytes] = []

    def subblocks(start: int) -> tuple[int, bytes]:
        chunks = bytearray()
        cursor = start
        while True:
            if cursor >= len(data):
                raise AssetError("GIF sub-blocks are truncated")
            size = data[cursor]
            cursor += 1
            if size == 0:
                return cursor, bytes(chunks)
            end = cursor + size
            if end > len(data):
                raise AssetError("GIF sub-block is truncated")
            chunks.extend(data[cursor:end])
            cursor = end

    trailer = False
    while pos < len(data):
        marker = data[pos]
        pos += 1
        if marker == 0x3B:
            trailer = True
            if pos != len(data):
                raise AssetError("GIF has trailing bytes after trailer")
            break
        if marker == 0x21:
            if pos >= len(data):
                raise AssetError("GIF extension is truncated")
            label = data[pos]
            pos += 1
            if label == 0xF9:
                if pos + 6 > len(data) or data[pos] != 4 or data[pos + 5] != 0:
                    raise AssetError("GIF graphic-control extension is invalid")
                pos += 6
            else:
                pos, _ = subblocks(pos)
            continue
        if marker != 0x2C:
            raise AssetError("GIF contains an unknown block marker")
        if pos + 9 > len(data):
            raise AssetError("GIF image descriptor is truncated")
        descriptor = data[pos:pos + 9]
        pos += 9
        local_packed = descriptor[8]
        local_table = b""
        if local_packed & 0x80:
            size = 3 * (2 ** ((local_packed & 0x07) + 1))
            if pos + size > len(data):
                raise AssetError("GIF local color table is truncated")
            local_table = data[pos:pos + size]
            pos += size
        if pos >= len(data):
            raise AssetError("GIF image data is truncated")
        lzw_minimum = data[pos:pos + 1]
        pos += 1
        pos, payload = subblocks(pos)
        images.append(descriptor + local_table + lzw_minimum + payload)
    if not trailer:
        raise AssetError("GIF has no trailer")
    if len(images) < minimum_frames:
        raise AssetError(f"GIF has {len(images)} frame(s), expected at least {minimum_frames}")
    if len(set(images)) < 2:
        raise AssetError("GIF frames are not a nontrivial animation")
    return len(images)


def _encoded_graph_gif(
    frames: Sequence[Path],
    work_dir: Path,
    runner: Runner,
) -> bytes:
    output = work_dir / "graph.gif"
    candidates: list[tuple[str, Path | None, tuple[str, ...]]] = []
    gifski = find_optional_tool("gifski")
    candidates.append(
        (
            "gifski",
            gifski,
            (
                "--fps",
                str(GRAPH_FPS),
                "--quality",
                "90",
                "--width",
                str(GRAPH_WIDTH),
                "--height",
                str(GRAPH_HEIGHT),
                "--output",
                str(output),
                *(str(frame) for frame in frames),
            ),
        )
    )
    ffmpeg = find_optional_tool("ffmpeg")
    candidates.append(
        (
            "ffmpeg",
            ffmpeg,
            (
                "-y",
                "-framerate",
                str(GRAPH_FPS),
                "-i",
                str(work_dir / "frame-%04d.png"),
                "-filter_complex",
                "[0:v]split[a][b];[a]palettegen=max_colors=128[p];[b][p]paletteuse=dither=sierra2_4a",
                str(output),
            ),
        )
    )
    available = False
    failures: list[str] = []
    for name, executable, args in candidates:
        if executable is None:
            continue
        available = True
        try:
            output.unlink()
        except FileNotFoundError:
            pass
        result = runner(
            (str(executable), *args),
            work_dir,
            controlled_env(),
            300,
        )
        if output.is_file():
            data = output.read_bytes()
            try:
                validate_gif(data)
            except AssetError as exc:
                failures.append(f"{name}: {exc}")
            else:
                return data
        else:
            detail = result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}"
            failures.append(f"{name}: {detail}")
    if not available:
        raise AssetSkip("gifski or ffmpeg", "graph.gif")
    raise AssetError("graph GIF encoding failed: " + "; ".join(failures))


def render_graph_gif(
    html: str,
    work_dir: Path,
    browser: Path,
    runner: Runner = run_process,
) -> bytes:
    frames = _capture_graph_frames(html, work_dir, browser, runner)
    return _encoded_graph_gif(frames, work_dir, runner)


def _wait_prompt(fd: int, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    tail = b""
    quiet_since: float | None = None
    while time.monotonic() < deadline:
        readable, _, _ = select.select([fd], [], [], 0.15)
        if readable:
            chunk = os.read(fd, 65536)
            if not chunk:
                raise AssetError("recording shell ended before the prompt")
            tail = (tail + chunk)[-256:]
            quiet_since = None
        elif PROMPT in tail:
            if quiet_since is None:
                quiet_since = time.monotonic()
            elif time.monotonic() - quiet_since > 0.4:
                return
    raise AssetError("recording prompt was not seen before timeout")


def _type_line(fd: int, text: str, rng: random.Random) -> None:
    for char in text:
        os.write(fd, char.encode())
        time.sleep(rng.uniform(0.04, 0.08))
    time.sleep(0.35)
    os.write(fd, b"\r")


def record_cast(home: Path, cast: Path, asciinema: Path, rows: int) -> None:
    env = recording_env(home)
    pid, fd = pty.fork()
    if pid == 0:
        os.chdir(home)
        os.execvpe(
            str(asciinema),
            (
                str(asciinema), "rec", str(cast), "--cols", str(COLS),
                "--rows", str(rows), "-c", f"bash --rcfile {home / '.castrc'} -i",
            ),
            env,
        )
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, COLS, 0, 0))
    rng = random.Random(SEED)
    completed = False
    try:
        _wait_prompt(fd, 30)
        time.sleep(1.2)
        for index, args in enumerate(COMMANDS):
            _type_line(fd, "sigwood " + " ".join(args), rng)
            _wait_prompt(fd, 300)
            time.sleep(DIGEST_DWELL_SECONDS if index == 0 else HUNT_DWELL_SECONDS)
        time.sleep(0.6)
        _type_line(fd, "exit", rng)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            readable, _, _ = select.select([fd], [], [], 1.0)
            if readable:
                try:
                    if not os.read(fd, 65536):
                        completed = True
                        break
                except OSError:
                    completed = True
                    break
            done, _ = os.waitpid(pid, os.WNOHANG)
            if done:
                completed = True
                break
        if not completed:
            raise AssetError("asciinema recording did not exit")
    finally:
        if not completed:
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        try:
            os.waitpid(pid, 0)
        except ChildProcessError:
            pass
        try:
            os.close(fd)
        except OSError:
            pass
    if not cast.is_file():
        raise AssetError("asciinema did not create a cast")


def convert_and_trim_cast(
    cast: Path,
    cast_v2: Path,
    asciinema: Path,
    rows: int,
    runner: Runner = run_process,
) -> None:
    _run_checked(
        runner,
        (str(asciinema), "convert", "-f", "asciicast-v2", str(cast), str(cast_v2)),
        cast.parent,
        controlled_env(),
        60,
        "asciinema v3-to-v2 conversion",
    )
    lines = cast_v2.read_text(encoding="utf-8").splitlines()
    if len(lines) < 2:
        raise AssetError("converted cast is empty")
    meta = json.loads(lines[0])
    if not meta.get("width") or not meta.get("height"):
        meta["width"], meta["height"] = COLS, rows
    elif (meta["width"], meta["height"]) != (COLS, rows):
        raise AssetError(f"unexpected recorded size {meta['width']}x{meta['height']}")
    events = lines[1:]
    parsed: list[tuple[int, str]] = []
    for index, line in enumerate(events):
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if len(event) >= 3 and event[1] == "o":
            parsed.append((index, event[2]))
    big = [index for index, data in parsed if len(data) >= 200]
    if not big:
        raise AssetError("cast has no substantive output event")
    last = next((index for index, data in parsed if index > big[-1] and "›" in data), None)
    if last is None:
        raise AssetError("cast has no prompt after final report output")
    if len(events[last + 1:]) > 40:
        raise AssetError("refusing to trim more than 40 cast events")
    header = json.dumps(meta, separators=(",", ":"))
    _write_text(cast_v2, "\n".join([header, *events[:last + 1]]) + "\n")


_THEME_REQUIRED = (
    ('fill="#282D35"', 'fill="#000000"'),
    ("fill:#C0C0C0", "fill:#28fe14"),
    (
        "font-family:Monaco,Consolas,'Courier New',monospace",
        "font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace",
    ),
)
_PROMPT_COLORS = ("fill:#FF00FF", "fill:#800080", "fill:#008080")


def theme_demo_svg(svg: str) -> str:
    if "fill:#00FFFF" not in svg:
        raise AssetError("demo SVG has no bright-cyan method chrome")
    themed = svg
    for source, target in _THEME_REQUIRED:
        if source not in themed:
            raise AssetError(f"demo SVG theme source is missing: {source}")
        themed = themed.replace(source, target)
    prompt_colors = [color for color in _PROMPT_COLORS if color in themed]
    if not prompt_colors:
        raise AssetError("demo SVG has no recognized prompt color")
    for color in prompt_colors:
        themed = themed.replace(color, "fill:#ff9800")
    match = re.search(r"animation:k [0-9.]+s infinite steps\(1,end\)", themed)
    if match is None:
        raise AssetError("demo SVG main animation declaration is missing")
    replacement = match.group(0).replace(" infinite", "") + ";animation-fill-mode:forwards"
    themed = themed.replace(match.group(0), replacement, 1)
    if re.search(r"animation:k [0-9.]+s infinite", themed):
        raise AssetError("demo SVG still loops its main animation")
    return themed


def render_demo_svg(
    home: Path,
    work_dir: Path,
    asciinema: Path,
    termsvg: Path,
    rows: int,
    runner: Runner = run_process,
) -> bytes:
    work_dir.mkdir(parents=True, exist_ok=True)
    cast = work_dir / "demo.cast"
    cast_v2 = work_dir / "demo.v2.cast"
    svg = work_dir / "demo.svg"
    record_cast(home, cast, asciinema, rows)
    convert_and_trim_cast(cast, cast_v2, asciinema, rows, runner)
    _run_checked(
        runner,
        (str(termsvg), "export", str(cast_v2), "-o", str(svg)),
        work_dir,
        controlled_env(home),
        120,
        "termsvg export",
    )
    if not svg.is_file():
        raise AssetError("termsvg did not create an SVG")
    themed = theme_demo_svg(svg.read_text(encoding="utf-8"))
    return themed.encode("utf-8")


def load_stamps(path: Path | None = None) -> dict[str, object]:
    if path is None:
        path = STAMP_PATH
    if not path.exists():
        return {"schema_version": SCHEMA_VERSION, "tz": TZ}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AssetError(f"cannot read asset stamps: {exc}") from exc
    if not isinstance(data, dict) or data.get("schema_version") != SCHEMA_VERSION:
        raise AssetError("unknown assets.stamp.json schema_version")
    if data.get("tz") != TZ:
        raise AssetError("assets.stamp.json tz must be UTC")
    return data


def write_stamps(data: Mapping[str, object], path: Path | None = None) -> None:
    if path is None:
        path = STAMP_PATH
    atomic_write(path, (json.dumps(data, indent=2, sort_keys=True) + "\n").encode("utf-8"))


def _stamp_entry(oracle: str, digest: str) -> dict[str, str]:
    return {"oracle": oracle, "hash": digest}


def _selection(value: str | None) -> tuple[str, ...]:
    return (value,) if value else ("report", "demo")


def refresh_assets(
    selected: Sequence[str],
    *,
    browser_arg: str | None,
    graph_source: Path | None = None,
    graph_top_hosts: int = GRAPH_TOP_HOSTS,
    runner: Runner = run_process,
) -> tuple[list[str], list[AssetSkip]]:
    if "graph" in selected and tuple(selected) != ("graph",):
        raise AssetError("graph refresh must be selected alone")
    if "graph" in selected and graph_source is None:
        raise AssetError("graph refresh requires an explicit scrubbed source")
    stamps = load_stamps() if set(selected) & {"report", "demo"} else {}
    stamps_changed = False
    refreshed: list[str] = []
    skipped: list[AssetSkip] = []
    pending: list[tuple[Path, bytes]] = []
    with tempfile.TemporaryDirectory(prefix="sigwood-assets-") as raw_work:
        work = Path(raw_work)
        home: Path | None = None
        if "demo" in selected:
            home = build_sandbox(work, runner)
        if "report" in selected:
            html, digest = generate_report_html(work, runner)
            browser = find_browser(browser_arg)
            if browser is None:
                skipped.append(AssetSkip("browser", "report.png"))
            else:
                png = render_report_png(html, work / "report-render", browser, runner)
                pending.append((REPORT_ASSET, png))
                stamps["report_png"] = _stamp_entry(REPORT_ORACLE, digest)
                stamps_changed = True
                refreshed.append("report.png")
        if "demo" in selected:
            assert home is not None
            digest, rows = generate_demo_state(home, runner)
            asciinema = find_optional_tool("asciinema")
            termsvg = find_optional_tool("termsvg")
            if asciinema is None:
                skipped.append(AssetSkip("asciinema", "demo.svg"))
            elif termsvg is None:
                skipped.append(AssetSkip("termsvg", "demo.svg"))
            else:
                svg = render_demo_svg(
                    home, work / "demo-render", asciinema, termsvg, rows, runner
                )
                pending.append((DEMO_ASSET, svg))
                stamps["demo_svg"] = _stamp_entry(DEMO_ORACLE, digest)
                stamps_changed = True
                refreshed.append("demo.svg")
        if "graph" in selected:
            assert graph_source is not None
            browser = find_browser(browser_arg)
            if browser is None:
                skipped.append(AssetSkip("browser", "graph.gif"))
            elif find_optional_tool("gifski") is None and find_optional_tool("ffmpeg") is None:
                skipped.append(AssetSkip("gifski or ffmpeg", "graph.gif"))
            else:
                html = generate_graph_html(
                    graph_source,
                    work / "graph-source",
                    top_hosts=graph_top_hosts,
                    runner=runner,
                )
                gif = render_graph_gif(
                    html,
                    work / "graph-render",
                    browser,
                    runner,
                )
                pending.append((GRAPH_ASSET, gif))
                refreshed.append("graph.gif")
        if pending:
            for path, data in pending:
                atomic_write(path, data)
        if stamps_changed:
            write_stamps(stamps)
    return refreshed, skipped


def check_assets(selected: Sequence[str], runner: Runner = run_process) -> list[str]:
    if "graph" in selected:
        raise AssetError("graph is intentionally outside --check")
    stamps = load_stamps()
    stale: list[str] = []
    with tempfile.TemporaryDirectory(prefix="sigwood-assets-check-") as raw_work:
        work = Path(raw_work)
        if "report" in selected:
            _, digest = generate_report_html(work, runner)
            expected = _stamp_entry(REPORT_ORACLE, digest)
            if stamps.get("report_png") != expected or not REPORT_ASSET.is_file():
                stale.append("report")
        if "demo" in selected:
            home = build_sandbox(work, runner)
            digest = generate_demo_oracle(home, runner)
            expected = _stamp_entry(DEMO_ORACLE, digest)
            if stamps.get("demo_svg") != expected or not DEMO_ASSET.is_file():
                stale.append("demo")
    return stale


def refresh_command(selected: Sequence[str], browser_arg: str | None = None) -> str:
    command = "python tools/refresh_assets.py"
    if len(selected) == 1:
        command += f" --only={selected[0]}"
    if browser_arg is not None:
        command += f" --browser={browser_arg}"
    return command


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="compare semantic asset stamps")
    parser.add_argument(
        "--browser", metavar="PATH", help="authoritative Chrome/Chromium executable"
    )
    parser.add_argument(
        "--only", choices=("report", "demo", "graph"), help="operate on one asset"
    )
    parser.add_argument(
        "--from",
        dest="graph_source",
        type=Path,
        metavar="SCRUBBED_CONN",
        help="explicit private scrubbed source for --only=graph",
    )
    parser.add_argument(
        "--top-hosts",
        type=int,
        metavar="N",
        help="graph top-host ceiling; default 30 for --only=graph",
    )
    args = parser.parse_args(argv)
    if args.only == "graph":
        if args.check:
            parser.error("--only=graph is intentionally outside --check")
        if args.graph_source is None:
            parser.error("--only=graph requires --from=SCRUBBED_CONN")
        if args.top_hosts is None:
            args.top_hosts = GRAPH_TOP_HOSTS
        if args.top_hosts < 1:
            parser.error("--top-hosts must be positive")
    elif args.graph_source is not None or args.top_hosts is not None:
        parser.error("--from and --top-hosts are only valid with --only=graph")
    return args


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    selected = _selection(args.only)
    try:
        if args.check:
            stale = check_assets(selected)
            if stale:
                print(
                    f"stale assets: {', '.join(stale)}; refresh with: "
                    f"{refresh_command(selected, args.browser)}",
                    file=sys.stderr,
                )
                return 4
            print(f"assets fresh: {', '.join(selected)}")
            return 0
        refreshed, skipped = refresh_assets(
            selected,
            browser_arg=args.browser,
            graph_source=args.graph_source,
            graph_top_hosts=args.top_hosts or GRAPH_TOP_HOSTS,
        )
        for item in refreshed:
            print(f"refreshed {item}")
        for item in skipped:
            print(str(item), file=sys.stderr)
        return 3 if skipped else 0
    except AssetError as exc:
        print(f"refresh-assets: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
