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

Do this *before* kicking off the release process. Start from an up-to-date, clean `main` and run the complete local suite:

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

### 1 - Prepare and land the release state

Before tagging:

1. Set `__version__` in `sigwood/__init__.py` to the stable version being released.
2. Update the README status line to the same version.
3. Move every `[Unreleased]` changelog entry into a new dated `## [X.Y.Z]` section, leave
   `[Unreleased]` empty, and update the comparison links at the bottom of `CHANGELOG.md`.
4. Land every other file that belongs in the release, including new documentation.
5. Review the diff, commit only the intended release state, and push `main`.

The tagged commit is the released state. Do not plan to add documentation or packaging fixes
after the tag.

### 2 - Capture the release identity once

Run this block after the release-state commit is on `main`. Every version-specific command
below uses these variables without editing. If the shell closes or `__version__` changes, run
the block again.

```bash
REPO=helixmap/sigwood
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

```bash
BUILD=$(mktemp -d "${TMPDIR:-/tmp}/sigwood-build.XXXXXX")
(
  set -euo pipefail

  git archive HEAD | tar -x -C "$BUILD"
  cd "$BUILD"

  python3 -m venv .venv-rel
  .venv-rel/bin/python -m pip install -q --upgrade pip
  .venv-rel/bin/python -m pip install -q -e ".[dev]" build twine
  .venv-rel/bin/python -m pytest -q

  .venv-rel/bin/python -m build
  .venv-rel/bin/python -m twine check dist/*
  .venv-rel/bin/python tools/validate_distribution.py dist

  README_URLS=$(grep -oE 'https://[^\") ]+' README.md | sort -u)
  test -n "$README_URLS"
  while IFS= read -r url; do
    printf 'checking %s\n' "$url"
    curl --fail --silent --show-error --location --output /dev/null "$url"
  done <<< "$README_URLS"

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
to `.github/workflows/release.yml`. It is optional for later releases when that workflow is
unchanged.

The manual dispatch builds and tests `main`, changes the artifact version to the throwaway
`X.Y.Z.dev<run-number>` form, and publishes through the ungated `testpypi` environment. The
commands derive that version from the run itself; there is no placeholder to replace.

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

On the [TestPyPI project page](https://test.pypi.org/project/sigwood/), confirm that the dev
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

PyPI permanently reserves a published version. A bad `X.Y.Z` can be yanked, but it cannot be
deleted and uploaded again under the same version.

For the first production release only: if a `0.0.0` name-reservation release still exists,
delete that **release** from the PyPI project management page. Never delete the project,
because that releases the package name.

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

Install the exact version from real PyPI into a clean venv. `--no-cache-dir` prevents a local
wheel cache from satisfying the check.

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
