"""Protect the release workflow's privileged publishing boundary."""

from __future__ import annotations

import re
from pathlib import Path


_ROOT = Path(__file__).resolve().parents[1]
_WORKFLOW = _ROOT / ".github" / "workflows" / "release.yml"
_LINK_CHECK_WORKFLOW = _ROOT / ".github" / "workflows" / "link-check.yml"
_JOB_HEADER = re.compile(r"^  (?P<name>[A-Za-z0-9_-]+):\s*$")
_USES = re.compile(
    r"^\s*(?:-\s+)?uses:\s+(?P<target>[^\s#]+)", re.MULTILINE
)
_PINNED_ACTION = re.compile(
    r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}$"
)


def _job_block(workflow: str, name: str) -> str:
    """Return one fixed top-level job block from the release workflow."""
    lines = workflow.splitlines()
    starts = [index for index, line in enumerate(lines) if line == f"  {name}:"]
    assert len(starts) == 1, f"expected one {name!r} job, found {len(starts)}"
    start = starts[0]
    end = next(
        (
            index
            for index in range(start + 1, len(lines))
            if _JOB_HEADER.fullmatch(lines[index])
        ),
        len(lines),
    )
    return "\n".join(lines[start:end])


def _action_targets(block: str) -> list[str]:
    """Return action references in their execution order."""
    return [match.group("target") for match in _USES.finditer(block)]


def _assert_actions_sha_pinned(workflow: str) -> None:
    """Require every action reference in a workflow fragment to use a full SHA."""
    targets = _action_targets(workflow)
    assert targets, "workflow must invoke actions"
    unpinned = [target for target in targets if not _PINNED_ACTION.fullmatch(target)]
    assert unpinned == [], f"workflow actions must use full SHA pins: {unpinned}"


def test_release_actions_are_sha_pinned() -> None:
    _assert_actions_sha_pinned(_WORKFLOW.read_text(encoding="utf-8"))


def test_link_check_actions_are_sha_pinned() -> None:
    # CI's existing tag pins remain a separate accepted policy; this guard owns
    # the privileged release and the informational external-link workflows.
    _assert_actions_sha_pinned(_LINK_CHECK_WORKFLOW.read_text(encoding="utf-8"))


def test_sha_pin_guard_covers_uses_after_step_metadata() -> None:
    workflow = """steps:
  - name: Upload dist
    if: success()
    uses: actions/upload-artifact@v7
"""
    assert _action_targets(workflow) == ["actions/upload-artifact@v7"]
    try:
        _assert_actions_sha_pinned(workflow)
    except AssertionError as exc:
        assert "actions/upload-artifact@v7" in str(exc)
    else:
        raise AssertionError("tag-pinned action after step metadata was not rejected")


def test_publish_job_keeps_the_privileged_boundary() -> None:
    workflow = _WORKFLOW.read_text(encoding="utf-8")
    preamble, separator, _ = workflow.partition("\njobs:\n")
    assert separator, "release workflow must declare jobs"
    build = _job_block(workflow, "build")
    publish = _job_block(workflow, "publish")

    assert re.search(r"^    needs:\s*build\s*$", publish, re.MULTILINE)
    assert re.search(r"^    environment:\s*$", publish, re.MULTILINE)
    assert re.search(
        r"^    permissions:\s*\n      id-token:\s*write\s*\n    steps:\s*$",
        publish,
        re.MULTILINE,
    )
    assert "id-token" not in preamble
    assert "id-token" not in build
    assert not re.search(r"^\s*(?:-\s+)?run\s*:", publish, re.MULTILINE)

    identities = [target.split("@", 1)[0] for target in _action_targets(publish)]
    assert identities == [
        "actions/download-artifact",
        "pypa/gh-action-pypi-publish",
    ]
