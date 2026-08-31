# Releasing sigwood

This is the maintainer checklist for publishing sigwood to PyPI and GitHub. Run it from the
repository root in one Bash session, and confirm each step before continuing. The pushed tag
can still be replaced before PyPI approval; publishing a version to PyPI cannot be undone or
repeated.

sigwood publishes through **Trusted Publishing**. A tag-triggered GitHub Actions workflow
(`.github/workflows/release.yml`) builds the distributions and authenticates to PyPI with
OpenID Connect, so no long-lived API token is stored. Each upload also carries a **PEP 740
PyPI Publish Attestation**, a Sigstore-backed record of which Trusted Publisher uploaded the
distribution. That is publication provenance, not a claim that the code is safe. After a
successful upload the same workflow **drafts** the matching GitHub Release from the tag's
`CHANGELOG.md` section; it never publishes one.

Two human gates remain deliberate:

- Build and validate locally before creating a tag.
- Approve the `pypi` GitHub environment only after the tagged commit passes the complete CI
  matrix.

And one human step remains deliberate: the GitHub Release is published by hand, after the
rendered notes have been read (step 7). The public record of a release is never written
without a maintainer looking at it - and because the draft is created by the workflow, a
release that reached PyPI can no longer be missing from GitHub merely because the checklist
was set down after the approval.

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

The in-fence `### §N` echo lines are deliberate: once a pasted section has scrolled out
of the terminal, they identify the last section the maintainer pasted.

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
if git ls-files | grep -iE 'private/|scratch|memory/|secret|token|(\.env$|\.env\.)'; then
  printf 'review the tracked paths above before continuing\n' >&2
  false
else
  printf 'tracked-path scan: clean\n'
fi
```

Audit the installed dependencies for known advisories. Dependabot proposes updates to the CI
action pins on a schedule, but it does not scan the Python packages sigwood installs, so a
published advisory against a runtime dependency would otherwise reach a cut unnoticed. Run
`pip-audit` ephemerally with `uvx` (nothing is installed into the venv) against the venv's
resolved third-party packages:

```bash
uvx pip-audit -r <(.venv/bin/pip freeze --exclude-editable)
```

`--exclude-editable` drops the editable `sigwood` line itself, so only the third-party
dependencies are audited. `pip-audit` exits non-zero when it finds a vulnerability. Resolve
anything it reports by bumping the affected version or consciously accepting it with a note before
tagging; a clean report is the pass, and an unreviewed one is not.

Finally, confirm that nothing is knowingly shipping in a defective state. A detector outside the
default hunt is still reachable by name and under `--detect=all`, so "not in the default hunt" is
not the same as "not reachable"; a detector known to produce wrong results still reaches anyone
who asks for it. Clear any open release blocker you are tracking, or consciously accept it, before
tagging.

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

- **Shipped images still match shipped output.** The report screenshot (`docs/img/report.png`)
  and the terminal recording (`docs/img/demo.svg`) render on the project page *and* on PyPI, so
  a release that changed what a report looks like otherwise ships a front page advertising older
  output than the release produces. Check it rather than judging it by eye:

  ```bash
  python tools/refresh_assets.py --check
  ```

  The check regenerates the report's finding rows and the terminal text from the demo corpus and
  compares their semantic hashes with `docs/img/assets.stamp.json`. Fresh exits 0; drift exits
  non-zero, names the stale asset, and prints the refresh command.

  Read that as what it is. It catches a change in sigwood's OUTPUT since the images were built.
  It does not inspect the image bytes, and the report oracle covers the finding rows rather than
  the header, so run the refresh and LOOK at the regenerated images before continuing rather
  than treating a green check as the whole answer.

  The check itself needs no external tools. Refreshing needs Chrome for `report.png`, and
  `asciinema` plus `termsvg` for `demo.svg`; a missing tool skips only the image that needs it.
  Skipping this step is possible and is a choice to advertise stale output.

  **This step covers two of the three shipped images. `docs/img/graph.gif` is NOT covered**, and
  a green check says nothing about it. Its source is a real capture that is address-scrubbed
  before rendering, so there is no reproducible input to hash and no stamp to compare
  against. Refresh it deliberately when the graph's rendering changes; `demo/README.md` carries
  the commands. Treating a green check as covering all three is the mistake this note exists to
  prevent.

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

then commit **everything section 1 landed** and push `main`. That is usually the three
version-bearing files, but step 5 of that section lands any other file the release needs - a
test the release state required, new documentation - so the commit is defined by the diff you
just read, never by a fixed list. A fixed list silently drops the rest: the commit looks
right, and the omission surfaces as a red matrix minutes later, or not at all when no test
covers the missing file.

`git add -u` stages every tracked file section 1 modified or deleted. A genuinely new file is
untracked, so `git add` it by path as well - and when you forget, the clean-tree test below
catches it.

The push is gated on that test rather than following it. The commit itself is still local at
that point, so a leftover file is fixed with `git add <path> && git commit --amend` while
nothing public has happened:

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

git add -u
# plus any new file section 1 added:  git add <path>

if git commit -m "sigwood $VERSION final" &&
  test -z "$(git status --short)"; then
  git push origin main
else
  printf 'release state is not fully committed - nothing pushed\n' >&2
  false
fi

### §2a
```

 and wait for [Release Workflow](https://github.com/helixmap/sigwood/actions) to show a green matrix before proceeding.

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

### §2b
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

### §3
```

Nothing above this point changes remote release state.

### 4 - Rehearse on TestPyPI when required

This step is non-negotiable before the first Trusted Publishing release and after any change
to `.github/workflows/release.yml`. It is still recommended for later releases when that workflow is
unchanged.

The manual dispatch builds and tests `main`, changes the artifact version to the
throwaway `X.Y.Z.dev<run-number>` form, and publishes through the ungated
`testpypi` environment. It does not exercise the `draft GitHub Release` job, which runs on
tag pushes only (a rehearsal has no tag and must create no Release); that job's failure
mode is covered by the by-hand fallback in step 7, not by this rehearsal. The commands derive that version from the run itself;
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

### §4
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
  git tag -a "$TAG" -m "sigwood $TAG tag" &&
  git show --no-patch --decorate "$TAG" &&
  git push origin "$TAG"; then
  printf 'pushed %s\n' "$TAG"
else
  printf 'tag creation or push failed for %s\n' "$TAG" >&2
  false
fi

### §5a
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

### §5b
```

The workflow reruns the complete Python 3.11-3.14 matrix, validates a fresh sdist and wheel,
waits at the `pypi` environment before upload, and after a successful upload drafts the
GitHub Release. The browser command opens the exact run;
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

The watch returns when the whole run finishes, including the `draft GitHub Release` job
that follows the upload. If that job fails, the upload is still complete and valid - the
draft is created by hand in step 7 instead.

If the matrix is red, the approval gate never opens. If the tag is wrong, do not approve;
follow the pre-publish recovery steps below.

Once the GitHub workflow completes, validate the new release appears in the
[PyPI project release history](https://pypi.org/project/sigwood/#history). PyPI
permanently reserves a published version. A bad `X.Y.Z` can be yanked, but it
cannot be deleted and uploaded again under the same version.

### 7 - Inspect and publish the GitHub Release

A successful `publish PyPI` job is followed by the workflow's `draft GitHub Release` job. It
creates a **draft** Release for the tag, titled `sigwood vX.Y.Z`, whose body is the tag's own
`## [X.Y.Z] - ...` section of `CHANGELOG.md` with the heading omitted (the title already
carries the version). Nothing is public yet: a draft is visible only to maintainers, and the
Releases page keeps advertising the previous version as latest until this step publishes it.

Confirm the draft exists and open it for rendered inspection:

```bash
case "$(gh release view "$TAG" --repo "$REPO" --json isDraft --jq .isDraft 2>/dev/null)" in
  true)  gh release view "$TAG" --repo "$REPO" --web ;;
  false) printf 'GitHub Release %s is already published - skip to step 8\n' "$TAG" ;;
  *)     printf 'no Release for %s - create the draft by hand (see the end of this step)\n' "$TAG" >&2
         false ;;
esac

### §7a
```

Confirm the title, tag, and rendered notes. Publishing is a separate explicit action:

```bash
gh release edit "$TAG" --repo "$REPO" --draft=false &&
  test "$(gh release view "$TAG" --repo "$REPO" --json isDraft --jq .isDraft)" = "false" &&
  printf 'published GitHub Release %s\n' "$TAG"

### §7b
```

Attaching built artifacts is optional; PyPI remains the distribution source of truth.

#### If the draft was not created

The draft job fails closed: a missing or misnamed changelog section, or a GitHub API failure,
leaves the tag with no Release rather than one with wrong notes, and the PyPI upload is
unaffected either way. Create the draft by hand with the same notes extraction the workflow
uses - reading `CHANGELOG.md` from the *tagged commit*, so the working tree cannot matter -
then return to §7a:

```bash
if NOTES_FILE=$(mktemp "${TMPDIR:-/tmp}/sigwood-${VERSION}-notes.XXXXXX") &&
  git show "$TAG:CHANGELOG.md" | awk -v version="$VERSION" '
    index($0, "## [" version "] - ") == 1 { copying = 1; next }
    copying && /^## \[/ { exit }
    copying { print }
    END { if (!copying) exit 1 }
  ' > "$NOTES_FILE" &&
  test -s "$NOTES_FILE" &&
  gh release create "$TAG" --repo "$REPO" --title "sigwood $TAG" \
    --verify-tag --draft --notes-file "$NOTES_FILE"; then
  rm -f "$NOTES_FILE"
else
  printf 'could not draft the GitHub Release for %s; notes remain at %s\n' \
    "$TAG" "${NOTES_FILE:-unknown}" >&2
  false
fi

### §7c
```

### 8 - Verify the public release

*Wait for the publish to settle.* Then install the exact version from real PyPI
into a clean venv. `--no-cache-dir` prevents a local wheel cache from satisfying
the check.

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

### §8a
```

This exact-version install is the authoritative signal that the release is live. PyPI's JSON
endpoint is CDN-cached and can briefly lag the file index used by pip.

Then confirm the GitHub side from the terminal. Without a tag argument, `gh release view`
resolves the repository's **latest published** Release, so the second test catches the one
failure the Releases page shows silently - a release that was drafted but never published,
leaving the previous version advertised as latest:

```bash
test "$(gh release view "$TAG" --repo "$REPO" --json isDraft --jq .isDraft)" = "false" &&
  test "$(gh release view --repo "$REPO" --json tagName --jq .tagName)" = "$TAG" &&
  printf 'GitHub Release %s is published and latest\n' "$TAG"

### §8b
```

Then confirm:

- The PyPI project page renders the README and images correctly.
- The PyPI file page shows the provenance/attestation panel.
- The GitHub Release is published with the intended notes.
- On a PEP 668 system such as Debian 12 or Raspberry Pi OS, bare `pip install sigwood` is
  refused with `externally-managed-environment`, while `pipx install sigwood` succeeds and
  `sigwood --help` runs.

## If something goes wrong

### Before PyPI approval

No package has been published, and no GitHub Release has been drafted - the draft job runs
only after a successful upload. If the run is active or waiting for approval, cancel it first:

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
resolution avoids it while exact pins remain available. The bad version's GitHub Release is
still a draft at this point: either delete it (`gh release delete "$TAG" --repo "$REPO"
--yes`) or publish it with a note pointing at the replacement - do not leave an unexplained
draft beside the tag.

### Trusted Publishing is unavailable

If PyPI OIDC or GitHub Actions is unavailable and a release is genuinely urgent, rerun local
build validation and use `twine upload` with a freshly generated, project-scoped token. Revoke
the token immediately afterward. This is an emergency path only; the normal path stores no
credential.

### Sensitive material reached the public repository

Assume it was seen and cached. Force-pushing or changing repository visibility does not
unpublish it. Rotate exposed credentials immediately; the preflight scan is preventive, not a
cleanup mechanism.
