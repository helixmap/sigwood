# Releasing sigwood

This is the maintainer checklist for publishing sigwood to PyPI and GitHub. Run it from the
repository root in one Bash session, and confirm each step before continuing. The pushed tag
can still be replaced before PyPI approval; publishing a version to PyPI cannot be undone or
repeated.

sigwood publishes through **Trusted Publishing**. A tag-triggered GitHub Actions workflow
(`.github/workflows/release.yml`) builds the distributions and authenticates to PyPI with
OpenID Connect, so no long-lived API token is stored. Each upload also carries a **PEP 740
PyPI Publish Attestation**, a Sigstore-backed record of which Trusted Publisher uploaded the
distribution. That is publication provenance, not a claim that the code is safe.

Two human gates remain deliberate:

- Build and validate locally before creating a tag.
- Approve the `pypi` GitHub environment only after the tagged commit passes the complete CI
  matrix.

## One-time setup

No API token is involved in the normal release path.

### Trusted publishers

Register a trusted publisher for `sigwood` on both [PyPI](https://pypi.org) and
[TestPyPI](https://test.pypi.org). TestPyPI uses a separate account and publisher.

| Field | PyPI | TestPyPI |
|---|---|---|
| Owner | `helixmap` | `helixmap` |
| Repository | `sigwood` | `sigwood` |
| Workflow | `release.yml` | `release.yml` |
| Environment | `pypi` | `testpypi` |

### GitHub environments

In repository **Settings -> Environments**:

- `pypi`: add yourself as a required reviewer. Where available, restrict deployment branches
  and tags to `v*` and disable administrator bypass. Do not enable **Prevent self-review** for
  a single-maintainer project; that would make the release impossible to approve.
- `testpypi`: no reviewer is needed because this is the rehearsal path. Restrict deployments
  to the default branch.

Also authenticate `gh` as a maintainer of `helixmap/sigwood`:

```bash
gh auth status
```

The working clone needs a development venv at `.venv`. Packaging tools are installed into a
separate temporary venv during validation; `.[dev]` does not install `build` or `twine` by
itself.

## Versioning

The executable package version has one owner: `sigwood/__init__.py` (`__version__`).
`pyproject.toml` reads it dynamically and `sigwood --version` prints it. The README status
line deliberately repeats the version as rendered prose, so update it in the same commit.

Stable versions use `X.Y.Z`; tags use `vX.Y.Z`. The release workflow rejects a tag whose
version does not exactly match `__version__`.

## Release checklist

### 0 - Preflight the current branch

Do this *before* kicking off the release process. Start from an up-to-date, clean `main` in a fresh terminal and run the complete local suite:

```bash
git switch main &&
  test -z "$(git status --short)" &&
  git pull --ff-only &&
  test "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)" &&
  .venv/bin/python -m pytest
```

Anything pushed to the public repository may be cached permanently. Confirm that no private
or secret-bearing path is tracked:

```bash
if git ls-files | grep -iE 'privdocs|scratch|memory/|secret|token|\.env'; then
  printf 'review the tracked paths above before continuing\n' >&2
  false
else
  printf 'tracked-path scan: clean\n'
fi
```

### 1 - Prepare the release state

This section only edits files. Nothing in it commits, pushes, or tags, so its work stays
reversible: the result is an uncommitted diff that can be corrected or discarded before any
of it becomes public. That is the seam. Every step from section 2 onward is authoritative -
commits, tags, and uploads other people can see - so finish this section, and read its diff,
before running anything in the next one.

1. Set `__version__` in `sigwood/__init__.py` to the stable version being released.
2. Update the README status line to the same version.
3. Move every `[Unreleased]` changelog entry into a new dated `## [X.Y.Z]` section, leave
   `[Unreleased]` empty, and update the comparison links at the bottom of `CHANGELOG.md`.
4. Refresh the development venv's package metadata, which step 1 has just made stale:

   ```bash
   .venv/bin/pip install -e . -q
   ```

   An editable install records the version at install time, so until this runs
   `importlib.metadata.version("sigwood")` still reports the previous release and
   `tests/test_version.py::test_version_single_sourced` fails. It is a local environment
   refresh: no tracked file changes, and nothing about it belongs in the release commit.

5. Land every other file that belongs in the release, including new documentation.
6. Re-run the complete suite. It must be green before the state is offered for commit.

Two checks belong here as well, because no test covers either:

- **Prior release sections are intact.** Diff the changelog's released portion against the
  previous tag and confirm the only differences are the new section and the two expected link
  lines. A changelog rewritten from a stale base has silently erased a whole released section
  before, and no runbook gate reads a prior version's heading:

  ```bash
  PREV="$(git describe --tags --abbrev=0)" &&
    git show "$PREV:CHANGELOG.md" | sed -n "/^## \[${PREV#v}\]/,\$p" > /tmp/cl-prev.txt &&
    sed -n "/^## \[${PREV#v}\]/,\$p" CHANGELOG.md > /tmp/cl-now.txt &&
    diff /tmp/cl-prev.txt /tmp/cl-now.txt
  ```

- **Shipped images still match shipped output.** The README screenshots and terminal
  recording under `docs/img/` render on the project page *and* on PyPI. Any release that
  changed what a report looks like needs them recaptured, or the front page advertises older
  output than the release produces.

The section is done when the working tree holds the intended release state, the suite is
green, and both checks above have been made. It stays uncommitted.

### 2 - Commit the release state and capture the release identity

This is the first authoritative step, and the first one that is awkward to undo. Review the
diff yourself before running anything below: from here on, the work is visible to others and
the tagged commit *is* the released state - do not plan to add documentation or packaging
fixes after the tag.

Read the prepared diff:

```bash
git status --short && git diff
```

then commit exactly those files and push `main`:

```bash
VERSION=$(
  .venv/bin/python - <<'PY'
import pathlib
import re

text = pathlib.Path("sigwood/__init__.py").read_text()
versions = re.findall(r'^__version__ = "([^"]+)"$', text, re.M)
assert len(versions) == 1
print(versions[0])
PY
)

git add CHANGELOG.md README.md sigwood/__init__.py
git commit -m "sigwood $VERSION"
git push origin main
```

 and wait for [Release Workflow](https://github.com/helixmap/sigwood/actions) to show a green matrix before proceding.

The identity block below re-checks that the commit exists and that `main` matches the remote,
so a forgotten push fails here rather than at the tag. Every version-specific command after
this point uses these variables without editing. If the shell closes or `__version__` changes,
run the block again.

```bash
REPO=helixmap/sigwood

if [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  TAG="v${VERSION}"
  printf 'repository: %s\nversion:    %s\ntag:        %s\n' "$REPO" "$VERSION" "$TAG" &&
    grep -F "$VERSION" README.md &&
    grep -F "## [$VERSION] - " CHANGELOG.md &&
    test -z "$(git status --short)" &&
    test "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)"
else
  TAG=
  printf 'not a stable release version: %s\n' "$VERSION" >&2
  false
fi
```

All checks must succeed.

### 3 - Build and validate locally

GitHub Actions rebuilds the artifacts, but local validation is the go/no-go gate before any
tag exists. Build from a clean export of the tracked commit, never from the working tree; a
working-tree build can accidentally include untracked files.

The block runs fail-fast inside a subshell, leaves the caller in the repository root, removes
its temporary export on success, and retains it for inspection on failure.

It guards the working tree first. Everything here builds from `HEAD`, while `$VERSION` was
read from the working tree in step 2, so an uncommitted release state produces artifacts one
version behind and fails on the very last line - the smoke test - after a full test run, with
a version mismatch that looks like a packaging fault rather than a missing commit. The guard
turns that into an immediate, accurate message.

```bash
BUILD=$(mktemp -d "${TMPDIR:-/tmp}/sigwood-build.XXXXXX")
(
  set -euo pipefail

  if [[ -n "$(git status --short)" ]]; then
    printf 'uncommitted changes: this builds from HEAD, so land the release state first (step 1)\n' >&2
    exit 1
  fi

  git archive HEAD | tar -x -C "$BUILD"
  cd "$BUILD"

  python3 -m venv .venv-rel
  .venv-rel/bin/python -m pip install -q --upgrade pip
  .venv-rel/bin/python -m pip install -e ".[dev]" build twine
  .venv-rel/bin/python -m pytest -q

  .venv-rel/bin/python -m build
  .venv-rel/bin/python -m twine check dist/*
  .venv-rel/bin/python tools/validate_distribution.py dist

  # The suite checks commit-local doc links; the periodic link-check workflow watches external liveness.

  shopt -s nullglob
  WHEELS=(dist/*.whl)
  (( ${#WHEELS[@]} == 1 ))
  python3 -m venv .venv-smoke
  .venv-smoke/bin/python -m pip install -q "${WHEELS[0]}"
  .venv-smoke/bin/python -m pip check
  test "$(.venv-smoke/bin/sigwood --version)" = "sigwood $VERSION"
  .venv-smoke/bin/sigwood --help >/dev/null
  .venv-smoke/bin/python - <<'PY'
import importlib.resources as resources

assert (resources.files("sigwood") / "data" / "config_example.toml").is_file()
print("data OK")
PY
)
BUILD_STATUS=$?

if (( BUILD_STATUS == 0 )); then
  rm -rf "$BUILD"
  printf 'local release validation passed\n'
else
  printf 'local release validation failed; inspect %s\n' "$BUILD" >&2
  false
fi
```

Nothing above this point changes remote release state.

### 4 - Rehearse on TestPyPI when required

This step is non-negotiable before the first Trusted Publishing release and after any change
to `.github/workflows/release.yml`. It is still recommended for later releases when that workflow is
unchanged.

The manual dispatch builds and tests `main`, changes the artifact version to the
throwaway `X.Y.Z.dev<run-number>` form, and publishes through the ungated
`testpypi` environment. The commands derive that version from the run itself;
there is no placeholder to replace. Progress can be monitored on the 
[Actions tab](https://github.com/helixmap/sigwood/actions) of the GitHub Repository.

```bash
REHEARSAL_URL=$(gh workflow run release.yml --repo "$REPO" --ref main)
REHEARSAL_RUN_ID=${REHEARSAL_URL##*/}
if [[ "$REHEARSAL_RUN_ID" =~ ^[0-9]+$ ]] &&
  gh run watch "$REHEARSAL_RUN_ID" --repo "$REPO" --compact --exit-status &&
  test "$(gh run view "$REHEARSAL_RUN_ID" --repo "$REPO" --json headSha --jq .headSha)" = "$(git rev-parse HEAD)" &&
  REHEARSAL_RUN_NUMBER=$(gh run view "$REHEARSAL_RUN_ID" --repo "$REPO" --json number --jq .number) &&
  [[ "$REHEARSAL_RUN_NUMBER" =~ ^[0-9]+$ ]]; then
  DEV_VERSION="${VERSION}.dev${REHEARSAL_RUN_NUMBER}"
  printf 'TestPyPI version: %s\n' "$DEV_VERSION"

  TEST_VENV=$(mktemp -d "${TMPDIR:-/tmp}/sigwood-testpypi.XXXXXX")
  if python3 -m venv "$TEST_VENV" &&
    "$TEST_VENV/bin/python" -m pip --isolated install \
      --index-url https://test.pypi.org/simple/ \
      --extra-index-url https://pypi.org/simple/ \
      "sigwood==$DEV_VERSION" &&
    "$TEST_VENV/bin/python" -m pip check &&
    test "$("$TEST_VENV/bin/sigwood" --version)" = "sigwood $DEV_VERSION"; then
    rm -rf "$TEST_VENV"
  else
    printf 'TestPyPI install verification failed; inspect %s\n' "$TEST_VENV" >&2
    false
  fi
else
  printf 'TestPyPI rehearsal failed for %s\n' "${REHEARSAL_URL:-no run URL}" >&2
  false
fi
```

Both index flags are required. `--index-url` selects the sigwood package from TestPyPI;
`--extra-index-url` allows dependencies such as pandas to resolve from real PyPI.

On the [TestPyPI project page](https://test.pypi.org/project/sigwood/#history), confirm that the dev
release and its provenance/attestation panel are present. Rehearsing again creates a fresh
`.dev` version because package indexes never accept the same version twice.

### 5 - Push the tag

This starts the production release workflow against the exact tagged commit:

```bash
if test -z "$(git tag --list "$TAG")" &&
  test -z "$(git ls-remote --tags origin "refs/tags/$TAG")" &&
  git tag -a "$TAG" -m "sigwood $TAG" &&
  git show --no-patch --decorate "$TAG" &&
  git push origin "$TAG"; then
  printf 'pushed %s\n' "$TAG"
else
  printf 'tag creation or push failed for %s\n' "$TAG" >&2
  false
fi
```

Capture the workflow run belonging to the tagged commit. This lookup block is safe to rerun
if the shell closes after the tag push; initialize `REPO`, `VERSION`, and `TAG` again first.

```bash
if TAG_SHA=$(git rev-list -n 1 "$TAG") && [[ -n "$TAG_SHA" ]]; then
  RUN_ID=
  for _ in {1..30}; do
    RUN_ID=$(gh run list --repo "$REPO" --workflow release.yml --event push \
      --commit "$TAG_SHA" --limit 1 --json databaseId --jq '.[0].databaseId')
    [[ -n "$RUN_ID" ]] && break
    sleep 2
  done

  if [[ "$RUN_ID" =~ ^[0-9]+$ ]]; then
    gh run view "$RUN_ID" --repo "$REPO" --web
  else
    printf 'release workflow did not appear for %s\n' "$TAG" >&2
    false
  fi
else
  printf 'could not resolve tagged commit for %s\n' "$TAG" >&2
  false
fi
```

The workflow reruns the complete Python 3.11-3.14 matrix, validates a fresh sdist and wheel,
and waits at the `pypi` environment before upload. The browser command opens the exact run;
monitor that page until it reaches the approval trigger below.

### 6 - Approve the PyPI publish (irreversible)

Approve only when every `build + verify` job is green and `publish PyPI` is waiting for
review. In the run opened above:

1. Click **Review deployments**.
2. Select the `pypi` environment.
3. Click **Approve and deploy**.

Then confirm that the upload completes successfully:

```bash
[[ "$RUN_ID" =~ ^[0-9]+$ ]] &&
  gh run watch "$RUN_ID" --repo "$REPO" --compact --exit-status
```

If the matrix is red, the approval gate never opens. If the tag is wrong, do not approve;
follow the pre-publish recovery steps below.

Once the GitHub workflow completes, validate the new release appears in the
[PyPI project release history](https://pypi.org/project/sigwood/#history). PyPI
permanently reserves a published version. A bad `X.Y.Z` can be yanked, but it
cannot be deleted and uploaded again under the same version.

### 7 - Create, inspect, and publish the GitHub Release

Extract the matching changelog section into a temporary notes file. The section heading is
omitted because the release title already carries the version.

```bash
if NOTES_FILE=$(mktemp "${TMPDIR:-/tmp}/sigwood-${VERSION}-notes.XXXXXX") &&
  awk -v version="$VERSION" '
    index($0, "## [" version "] - ") == 1 { copying = 1; next }
    copying && /^## \[/ { exit }
    copying { print }
    END { if (!copying) exit 1 }
  ' CHANGELOG.md > "$NOTES_FILE" &&
  test -s "$NOTES_FILE"; then
  cat "$NOTES_FILE"
else
  printf 'could not extract release notes for %s\n' "$VERSION" >&2
  false
fi
```

Create a draft from the existing remote tag, then open it for rendered inspection:

```bash
if gh release create "$TAG" --repo "$REPO" --title "sigwood $TAG" \
  --verify-tag --fail-on-no-commits --draft --notes-file "$NOTES_FILE"; then
  gh release view "$TAG" --repo "$REPO" --web
else
  printf 'GitHub Release draft creation failed; notes remain at %s\n' "$NOTES_FILE" >&2
  false
fi
```

The draft appears on the repository's **Releases** page and remains editable. Confirm the
title, tag, and rendered notes. Publishing is a separate explicit action:

```bash
if gh release edit "$TAG" --repo "$REPO" --draft=false; then
  [[ -z "${NOTES_FILE:-}" ]] || rm -f "$NOTES_FILE"
else
  printf 'GitHub Release publication failed; notes remain at %s\n' "${NOTES_FILE:-unknown}" >&2
  false
fi
```

Attaching built artifacts is optional; PyPI remains the distribution source of truth.

### 8 - Verify the public release

Install the exact version from real PyPI into a clean venv *from the project
venv*. `--no-cache-dir` prevents a local wheel cache from satisfying the check.

```bash
if POST_VENV=$(mktemp -d "${TMPDIR:-/tmp}/sigwood-postpub.XXXXXX") &&
  python3 -m venv "$POST_VENV" &&
  "$POST_VENV/bin/python" -m pip --isolated install --no-cache-dir \
    --index-url https://pypi.org/simple/ "sigwood==$VERSION" &&
  "$POST_VENV/bin/python" -m pip check &&
  test "$("$POST_VENV/bin/sigwood" --version)" = "sigwood $VERSION" &&
  "$POST_VENV/bin/sigwood" --help >/dev/null; then
  rm -rf "$POST_VENV"
else
  printf 'public-release verification failed; inspect %s\n' "${POST_VENV:-no venv}" >&2
  false
fi
```

This exact-version install is the authoritative signal that the release is live. PyPI's JSON
endpoint is CDN-cached and can briefly lag the file index used by pip.

Then confirm:

- The PyPI project page renders the README and images correctly.
- The PyPI file page shows the provenance/attestation panel.
- The GitHub Release is published with the intended notes.
- On a PEP 668 system such as Debian 12 or Raspberry Pi OS, bare `pip install sigwood` is
  refused with `externally-managed-environment`, while `pipx install sigwood` succeeds and
  `sigwood --help` runs.

## If something goes wrong

### Before PyPI approval

No package has been published. If the run is active or waiting for approval, cancel it first:

```bash
[[ "$RUN_ID" =~ ^[0-9]+$ ]] && gh run cancel "$RUN_ID" --repo "$REPO"
```

Once GitHub shows the run as failed or cancelled and you have confirmed that PyPI has no such
version, remove the remote tag before the local tag:

```bash
git push origin ":refs/tags/$TAG" &&
  git tag -d "$TAG"
```

Fix and push the release state, rerun the identity and validation steps, and create a new tag.
If the workflow had already failed or been cancelled, the cancel command is unnecessary. If
the shell restarted, rerun the exact-run lookup in step 5 before cancelling an active run.

### After PyPI publication

Do not move or reuse the tag. Bump the patch version, fix the problem, and publish a new
release. Yank the bad version from **PyPI project -> Manage -> Release -> Yank** so normal
resolution avoids it while exact pins remain available.

### Trusted Publishing is unavailable

If PyPI OIDC or GitHub Actions is unavailable and a release is genuinely urgent, rerun local
build validation and use `twine upload` with a freshly generated, project-scoped token. Revoke
the token immediately afterward. This is an emergency path only; the normal path stores no
credential.

### Sensitive material reached the public repository

Assume it was seen and cached. Force-pushing or changing repository visibility does not
unpublish it. Rotate exposed credentials immediately; the preflight scan is preventive, not a
cleanup mechanism.
