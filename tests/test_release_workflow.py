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


def _job_permissions(block: str) -> dict[str, str]:
    """Return one job's explicit permissions as an order-independent map."""
    lines = block.splitlines()
    declarations = [
        (index, line)
        for index, line in enumerate(lines)
        if line.startswith("    permissions:")
    ]
    if not declarations:
        return {}
    assert len(declarations) == 1, (
        f"expected at most one permissions map, found {len(declarations)}"
    )
    start, declaration = declarations[0]
    assert declaration == "    permissions:", (
        "job permissions must use the supported block-map form"
    )

    permissions: dict[str, str] = {}
    for line in lines[start + 1 :]:
        if not line.startswith("      "):
            break
        match = re.fullmatch(r"      ([A-Za-z0-9-]+):\s*(\S+)\s*", line)
        assert match, f"unsupported permissions entry: {line!r}"
        name, value = match.groups()
        assert name not in permissions, f"duplicate permission: {name}"
        permissions[name] = value
    return permissions


def _job_names(workflow: str) -> list[str]:
    """Return top-level release job names in declaration order."""
    _, separator, jobs = workflow.partition("\njobs:\n")
    assert separator, "release workflow must declare jobs"
    return [
        match.group("name")
        for line in jobs.splitlines()
        if (match := _JOB_HEADER.fullmatch(line))
    ]


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


def test_main_history_gate_stays_unconditional_and_least_privilege() -> None:
    """Pin the gate's structure and direct shell decision inputs.

    The decision-input scan is deliberately line-local: an alias assigned from a ref
    variable on an earlier line can evade it. Indirect shell data flow remains a code
    review responsibility rather than a claim this readable structural test can prove.
    """
    workflow = _WORKFLOW.read_text(encoding="utf-8")
    gate = _job_block(workflow, "gate")
    package = _job_block(workflow, "package")

    assert re.search(r"^    needs:\s*gate\s*$", package, re.MULTILINE)
    assert not re.search(r"^    if:\s*", gate, re.MULTILINE)
    assert re.search(
        r"^    permissions:\s*\n      contents:\s*read\s*\n    steps:\s*$",
        gate,
        re.MULTILINE,
    )
    assert "environment:" not in gate
    assert "id-token:" not in gate
    assert "contents: write" not in gate

    targets = _action_targets(gate)
    assert targets == [
        "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
    ]
    assert re.search(
        r"uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
        r"[^\n]*\n        with:\n          fetch-depth: 0$",
        gate,
        re.MULTILINE,
    )
    assert (
        'git merge-base --is-ancestor "$GITHUB_SHA" origin/main' in gate
    )
    assert "github.event_name" not in gate

    decision_lines = [
        line.strip()
        for line in gate.splitlines()
        if line.strip().startswith(("if ", "elif ", "case ", "[ ", "[[ ", "test "))
    ]
    decision_text = "\n".join(decision_lines)
    assert "GITHUB_REF_NAME" not in decision_text
    assert "GITHUB_REF_TYPE" not in decision_text


def test_publish_job_keeps_the_privileged_boundary() -> None:
    """Pin narrow, observable job structure without claiming shell data flow.

    The package job necessarily gains OIDC for signing. Because it also has shell
    steps, these checks cannot prove that it is incapable of publication: shell code
    could mint a token and upload without naming the publisher action. The expected
    decisive control is the external PyPI Trusted Publisher environment binding, which
    is not verified by this repository test.
    """
    workflow = _WORKFLOW.read_text(encoding="utf-8")
    preamble, separator, _ = workflow.partition("\njobs:\n")
    assert separator, "release workflow must declare jobs"
    package = _job_block(workflow, "package")
    test = _job_block(workflow, "test")
    publish = _job_block(workflow, "publish")

    assert re.search(
        r"^    needs:\s*\[package, test\]\s*$", publish, re.MULTILINE
    )
    assert re.search(r"^    environment:\s*$", publish, re.MULTILINE)
    assert _job_permissions(package) == {
        "contents": "read",
        "id-token": "write",
        "attestations": "write",
    }
    assert _job_permissions(publish) == {"id-token": "write"}
    assert "id-token" not in preamble
    assert "id-token" not in test
    assert workflow.count("id-token:") == 2
    id_token_jobs = {
        name
        for name in _job_names(workflow)
        if _job_permissions(_job_block(workflow, name)).get("id-token") == "write"
    }
    assert id_token_jobs == {"package", "publish"}
    attestation_jobs = {
        name
        for name in _job_names(workflow)
        if _job_permissions(_job_block(workflow, name)).get("attestations")
        == "write"
    }
    assert attestation_jobs == {"package"}

    # The job census begins after ``jobs:``, and unsupported inline permission
    # maps fail closed instead of disappearing from the OIDC-holder set.
    assert "push" not in _job_names(workflow)
    inline = workflow.replace(
        "\n  test:\n",
        "\n  third:\n    permissions: {id-token: write}\n    steps: []\n\n  test:\n",
        1,
    )
    assert "third" in _job_names(inline)
    try:
        _job_permissions(_job_block(inline, "third"))
    except AssertionError as exc:
        assert "supported block-map form" in str(exc)
    else:
        raise AssertionError("inline permissions map was not rejected")

    assert "environment:" not in package
    package_lower = package.lower()
    assert "pypa/gh-action-pypi-publish" not in package_lower
    assert "twine upload" not in package_lower
    assert "/legacy/" not in package_lower
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
    package = _job_block(workflow, "package")
    test = _job_block(workflow, "test")
    publish = _job_block(workflow, "publish")
    release = _job_block(workflow, "github-release")

    assert re.search(r"^    needs:\s*publish\s*$", release, re.MULTILINE)
    assert re.search(r"^    if:\s*success\(\) && github\.event_name == 'push'\s*$", release, re.MULTILINE)
    assert re.search(r"^    permissions:\s*\n      contents:\s*write\s*$", release, re.MULTILINE)
    # The write grant is scoped to this one job; the workflow default stays read-only.
    assert re.search(r"^permissions:\s*\n  contents:\s*read\s*$", preamble, re.MULTILINE)
    assert "contents: write" not in package
    assert "contents: write" not in test
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


def test_release_packages_once_before_tests_and_publication() -> None:
    """Pin the readable package-first graph and its direct command markers.

    The negative checks are deliberately textual, not a YAML or shell data-flow
    proof. An indirect command assembled across variables could evade them, and
    artifact-name aliases could obscure the direct ``name: dist`` relationship.
    Those remain code-review responsibilities rather than claims made here. The
    POSIX ``test`` in the tag/version comparison is not test-suite execution.
    """
    workflow = _WORKFLOW.read_text(encoding="utf-8")
    package = _job_block(workflow, "package")
    test = _job_block(workflow, "test")
    publish = _job_block(workflow, "publish")

    assert re.search(r"^    needs:\s*gate\s*$", package, re.MULTILINE)
    assert re.search(r"^    needs:\s*package\s*$", test, re.MULTILINE)
    assert re.search(
        r"^    needs:\s*\[package, test\]\s*$", publish, re.MULTILINE
    )

    locked_install = "python -m pip install --require-hashes --force-reinstall"
    assert locked_install in package
    assert "-r .github/requirements/build-toolchain.txt" in package
    assert "python -m build --no-isolation" in package

    tag_check = package.index("Tag matches version (tag push only)")
    version_edit = package.index("Throwaway version for TestPyPI")
    build = package.index("python -m build --no-isolation")
    assert tag_check < version_edit < build

    validate = package.index("python tools/validate_distribution.py dist")
    digest = package.index("sha256sum dist/*", validate)
    attest_target = "actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6"
    attest = package.index(attest_target)
    upload = package.index(
        "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
    )
    assert build < validate < digest < attest < upload
    assert package.count(attest_target) == 1
    assert re.search(
        r"uses: actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6"
        r"[^\n]*\n        with:\n          subject-path: dist/\*$",
        package,
        re.MULTILINE,
    )

    for test_marker in ('python -m pytest', '.[dev]', 'Install dev extras'):
        assert test_marker not in package

    assert workflow.count("python -m build --no-isolation") == 1
    upload_target = "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
    download_target = "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c"
    assert workflow.count(upload_target) == 1
    assert upload_target in package
    assert download_target not in package
    assert download_target in test
    assert download_target in publish

    for block in (package, test, publish):
        assert re.search(r"^          name:\s*dist\s*$", block, re.MULTILINE)

    assert not re.search(r"^\s*(?:-\s+)?run\s*:", publish, re.MULTILINE)
