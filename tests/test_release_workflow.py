"""Guard workflow action pins and the release publishing boundary."""

from __future__ import annotations

import re
from pathlib import Path


_ROOT = Path(__file__).resolve().parents[1]
_WORKFLOW = _ROOT / ".github" / "workflows" / "release.yml"
_WORKFLOW_DIR = _ROOT / ".github" / "workflows"
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


def test_all_workflow_actions_are_sha_pinned() -> None:
    workflow_paths = sorted(
        [*_WORKFLOW_DIR.glob("*.yml"), *_WORKFLOW_DIR.glob("*.yaml")]
    )
    # Empty discovery must fail instead of passing while protecting no workflows.
    assert workflow_paths, "workflow discovery must find at least one workflow"

    failures = []
    for workflow_path in workflow_paths:
        workflow = workflow_path.read_text(encoding="utf-8")
        if not _action_targets(workflow):
            continue
        try:
            _assert_actions_sha_pinned(workflow)
        except AssertionError as exc:
            failures.append(
                f"{workflow_path.relative_to(_ROOT)}: {str(exc).splitlines()[0]}"
            )

    assert failures == [], "\n".join(failures)


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


def test_github_release_job_drafts_only_after_the_pypi_publish() -> None:
    """The draft-release job is downstream of the upload and can only ever draft.

    A Release that appears before (or without) a successful PyPI upload would let the
    Releases page advertise a version the index does not carry, and a job that could
    publish would remove the maintainer's read-the-rendered-notes step. Both are
    pinned structurally: the job needs ``publish``, runs on tag pushes only, holds
    ``contents: write`` and nothing privileged beyond it, and never passes
    ``--draft=false``.
    """
    workflow = _WORKFLOW.read_text(encoding="utf-8")
    preamble, _, _ = workflow.partition("\njobs:\n")
    build = _job_block(workflow, "build")
    publish = _job_block(workflow, "publish")
    release = _job_block(workflow, "github-release")

    assert re.search(r"^    needs:\s*publish\s*$", release, re.MULTILINE)
    assert re.search(r"^    if:\s*success\(\) && github\.event_name == 'push'\s*$", release, re.MULTILINE)
    assert re.search(r"^    permissions:\s*\n      contents:\s*write\s*$", release, re.MULTILINE)
    # The write grant is scoped to this one job; the workflow default stays read-only.
    assert re.search(r"^permissions:\s*\n  contents:\s*read\s*$", preamble, re.MULTILINE)
    assert "contents: write" not in build
    assert "contents: write" not in publish
    assert "id-token" not in release
    assert "environment:" not in release

    # gh, not a third-party release action: the only action is the pinned checkout.
    identities = [target.split("@", 1)[0] for target in _action_targets(release)]
    assert identities == ["actions/checkout"]

    # Draft only: creation carries --draft and nothing here can flip it to published.
    assert re.search(r"gh release create .*--draft\b", release, re.DOTALL)
    assert "--draft=false" not in release
    assert "gh release edit" not in release
    # Idempotent: an existing release is detected before creation is attempted.
    assert release.index("gh release view") < release.index("gh release create")
