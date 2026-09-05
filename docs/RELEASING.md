# Releasing sigwood

This is the maintainer checklist for publishing sigwood to PyPI and GitHub. Run it from the
repository root in one Bash session, and confirm each step before continuing. A pushed `v*` tag
cannot be deleted or replaced under the version-protection ruleset, and publishing a version to
PyPI cannot be undone or repeated.

sigwood publishes through **Trusted Publishing**. The GitHub Actions route builds and tests one
set of distributions, then authenticates to the selected package index with OpenID Connect, so
no long-lived API token is stored in the normal path. The complete route and the limits of its
two kinds of attestation are described once under **Release workflow route** below.

Three human gates remain deliberate:

- Build and validate locally before creating a tag.
- Sign the release commit and the tag with the hardware key; each signature is one physical
  touch, and so is each push (**One-time setup** below).
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

### Signing key

Commits on `main` and release tags are signed with an SSH key held on a FIDO2 hardware
token (an `sk-ssh-ed25519` key), registered on the maintainer's GitHub account as both an
authentication key and a signing key, and listed in `allowed_signers` at the repository
root. Configure the clone once. `user.signingkey` takes the private key handle's absolute
path, so signing talks to the token directly and never through an agent:

```bash
git config gpg.format ssh
git config user.signingkey /absolute/path/to/the/sk/key/handle
git config commit.gpgsign true
git config tag.gpgsign true
git config gpg.ssh.allowedSignersFile "$(pwd)/allowed_signers"
```

On macOS, Apple's `/usr/bin/ssh` and `/usr/bin/ssh-keygen` carry no FIDO provider and fail
with `No FIDO SecurityKeyProvider specified`. Point git at a build that has one, and let the
repository fetch over https so only pushes reach the token:

```bash
git config gpg.ssh.program /opt/homebrew/opt/openssh/bin/ssh-keygen
git config core.sshCommand /opt/homebrew/opt/openssh/bin/ssh
git remote set-url origin https://github.com/helixmap/sigwood.git
git remote set-url --push origin git@github.com:helixmap/sigwood.git
```

Every `git commit`, `git tag`, and `git push` then asks for one touch. A touch prompt you
did not cause is the signal to stop and look.

The keys are resident on their tokens, so a second machine needs no new key and no GitHub
change. With the token plugged in, download its handle, then run the same configuration
against that file:

```bash
ssh-keygen -K
```

It asks for the token's PIN and writes `id_ed25519_sk_rk_helixmap-github` and its `.pub`
into the current directory. The handle is useless without that token, and each of the
three tokens produces its own.

Also authenticate `gh` as a maintainer of `helixmap/sigwood`. The token wants read access
plus issues and pull requests, and nothing that can push, dispatch a workflow, approve a
deployment, publish or edit a release, or edit repository rules; each of those is a browser act.

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

## Release workflow route

The workflow has one ordered graph: `gate -> package -> test -> publish -> github-release`.
`github-release` runs only for a tag push; a TestPyPI dispatch ends after `publish`.

The `gate` job first requires the selected commit to be an ancestor of `origin/main` as fetched
when the job runs. This applies to both trigger paths. It neither proves that GitHub required a
passing check before the commit reached `main` nor replaces the `pypi` environment's human
review of the exact tagged SHA.

The `package` job constructs the wheel and source distribution once, before any development
dependency or project test runs. Its three direct build-tool roots are `build`, `twine`, and
`setuptools>=77`. Their resolved graph is recorded in
`.github/requirements/build-toolchain.txt`; installation requires every download to match a
recorded hash and force-reinstalls even a matching version already present on the runner. The
job builds without PEP 517 isolation, so the hash-checked backend is the backend that runs.

Regenerate the lock with uv 0.12.7 and the exact runner target:

```bash
uv pip compile .github/requirements/build-toolchain.in --generate-hashes \
  --python-version 3.12 --python-platform x86_64-unknown-linux-gnu \
  -o .github/requirements/build-toolchain.txt
```

Do not omit the Python or platform arguments. A lock resolved for the maintainer's macOS host is
not the Linux lock consumed by the GitHub-hosted runner. The hashes cover the Python build
toolchain, not the `ubuntu-latest` runner image, the Python installed by
`actions/setup-python`, that Python's bundled pip, or the package index serving the hashed
downloads; those layers remain trusted by assumption.

After validation, `package` creates a GitHub build provenance attestation for both distributions,
then uploads those same files as the `dist` workflow artifact. The attestation binds their
digests to the source commit and `release.yml` workflow that built them. It does not prove that
the code is safe or reviewed, that the inputs were reproducible, or that no packaging-layer
difference changes behavior.

The four `test` legs download that completed artifact before installing the checkout's broad
development dependencies. The suite tests the checkout at the build commit; pytest's import mode
can let that checkout shadow an installed wheel. The Python 3.12 clean-venv smoke is the wheel
check: it installs the downloaded wheel, checks its dependencies, imports its data, and runs its
command.

Only after all test legs pass does the environment-scoped, action-only `publish` job download
the same `dist` artifact and upload it. A dispatch selects the deliberately ungated `testpypi`
environment; a tag push selects `pypi`, whose required reviewer is the production human gate.
Each index upload carries a PEP 740 PyPI Publish Attestation recording the artifact digest and
Trusted Publisher identity. That is publication provenance, distinct from the GitHub build
provenance above, and it is not a claim that the code is safe or reviewed.

The package job needs OpenID Connect for build attestation, so repository structure alone cannot
prove that it is unable to publish. The expected decisive control is the external Trusted
Publisher binding to the matching environment: if configured as intended, a token from the
environment-free package job does not satisfy it. Confirm the publisher identity on each index
rather than inferring it from this workflow. After a successful production upload,
`github-release` drafts the matching GitHub Release from the tag's `CHANGELOG.md` section; it
never publishes the draft.

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
resolved third-party packages. `uvx` runs the audit under an interpreter of its own choosing, so
hand it the venv's version: a dependency pinned to a newer Python than the audit's interpreter
fails the audit before it starts, and the graph the venv actually runs is the one to audit:

```bash
uvx --python "$(.venv/bin/python -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')" \
  pip-audit -r <(.venv/bin/pip freeze --exclude-editable)
```

`--exclude-editable` drops the editable `sigwood` line itself, so only the third-party
dependencies are audited. `pip-audit` exits non-zero when it finds a vulnerability. Resolve
anything it reports by bumping the affected version or consciously accepting it with a note before
tagging; a clean report is the pass, and an unreviewed one is not.

The audited population is the development venv, which is wider than what a release ships: anything
installed for local work sits in it too. Before treating a report as a blocker, check whether the
affected package is in what users receive, which is `[project] dependencies` plus the shipped
extras in `pyproject.toml`; the `dev` extra is maintainer-only. A finding in tooling that reaches
no user is still worth fixing, and it is not a reason to hold the cut.

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
7. Write the commit message to a file and keep its path in `RELEASE_MESSAGE` for section 2.
   It is public text for a reader who knows nothing of how the work was organized: say what
   changed in the release and why, in the product's own terms, and stop. Hyphens only; the
   commit-msg hook refuses dash punctuation.

   ```bash
   RELEASE_MESSAGE=$(mktemp "${TMPDIR:-/tmp}/sigwood-release-message.XXXXXX")
   "${EDITOR:-vi}" "$RELEASE_MESSAGE"
   ```

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
  .venv/bin/python tools/refresh_assets.py --check
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

then commit **everything section 1 landed**, with the message section 1 wrote, and push `main`.
The commit and the push each ask for one touch on the signing key. That is usually the three
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

if test -s "${RELEASE_MESSAGE:-}" &&
  git commit -F "$RELEASE_MESSAGE" &&
  test -z "$(git status --short)"; then
  git push origin main
else
  printf 'release state is not fully committed - nothing pushed\n' >&2
  false
fi

### §2a
```

Wait for the [CI workflow](https://github.com/helixmap/sigwood/actions/workflows/ci.yml) run on
that push to go green before proceeding.

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
tag exists. Build from a fresh clone of the tracked commit, never from the working tree: a
working-tree build can include untracked files, and the clone is also a repository, which the
suite needs because several tests read the tracked file inventory through git.

The block runs fail-fast inside a subshell, leaves the caller in the repository root, removes
its temporary clone on success, and retains it for inspection on failure.

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

  git clone -q --no-local --no-hardlinks "$PWD" "$BUILD/src"
  git -C "$BUILD/src" checkout -q "$(git rev-parse HEAD)"
  cd "$BUILD/src"

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

This step is non-negotiable before the first Trusted Publishing release, after any change to
`.github/workflows/release.yml`, and after any change to the repository's allowed-actions policy.
It is still recommended for later releases when none of those changed.

An unchanged workflow is not the same as an unchanged release path. The publish job resolves
actions that no workflow file names: `pypa/gh-action-pypi-publish` pins its own
`actions/setup-python`, and an allowed-actions list assembled from the workflow files alone leaves
that one out. The refusal surfaces in the publish job's `Set up job` step, which runs only after
the `pypi` environment is approved, so the production failure is a tag pushed, a green matrix, an
approval given, nothing published, and a tag that cannot be reused. Bumping the publish action's
pin can change which `setup-python` it resolves, so treat that bump as a policy change too.

The manual dispatch builds and tests `main`, changes the artifact version to the
throwaway `X.Y.Z.dev<run-number>` form, and publishes through the ungated
`testpypi` environment. It does not exercise the `draft GitHub Release` job, which runs on
tag pushes only (a rehearsal has no tag and must create no Release); that job's failure
mode is covered by the by-hand fallback in step 7, not by this rehearsal. The commands derive that version from the run itself;
there is no placeholder to replace. The dispatch itself is a browser act: `gh workflow run`
needs the Actions write permission that the maintainer token from the one-time setup
deliberately does not carry, so the block below asks for the click and then finds the run by
the commit it ran on and the time it was created. Progress can be monitored on the
[Actions tab](https://github.com/helixmap/sigwood/actions) of the GitHub Repository.

```bash
REHEARSAL_SINCE=$(date -u +%Y-%m-%dT%H:%M:%SZ)
read -r -p "dispatch now (Actions tab -> release -> Run workflow -> branch main), then press Enter: "
REHEARSAL_RUN_ID=
for _ in {1..30}; do
  REHEARSAL_RUN_ID=$(gh run list --repo "$REPO" --workflow release.yml --event workflow_dispatch \
    --commit "$(git rev-parse HEAD)" --created ">=$REHEARSAL_SINCE" --limit 1 \
    --json databaseId --jq '.[0].databaseId')
  [[ -n "$REHEARSAL_RUN_ID" ]] && break
  sleep 2
done
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
  printf 'TestPyPI rehearsal failed for run %s\n' "${REHEARSAL_RUN_ID:-not found}" >&2
  false
fi

### §4
```

Both index flags are required. `--index-url` selects the sigwood package from TestPyPI;
`--extra-index-url` allows dependencies such as pandas to resolve from real PyPI.

On the [TestPyPI project page](https://test.pypi.org/project/sigwood/#history), confirm that the dev
release and its provenance/attestation panel are present. Rehearsing again creates a fresh
`.dev` version because package indexes never accept the same version twice.

Download the rehearsal's workflow artifact and verify both files against this repository and
the release workflow. Preserve the command and output with the release evidence:

```bash
ATTEST_DIR=$(mktemp -d "${TMPDIR:-/tmp}/sigwood-attestation.XXXXXX")
if gh run download "$REHEARSAL_RUN_ID" --repo "$REPO" --name dist --dir "$ATTEST_DIR" &&
  test "$(find "$ATTEST_DIR" -type f \( -name '*.whl' -o -name '*.tar.gz' \) | wc -l | tr -d ' ')" -eq 2 &&
  find "$ATTEST_DIR" -type f \( -name '*.whl' -o -name '*.tar.gz' \) \
    -exec gh attestation verify '{}' --repo "$REPO" \
      --signer-workflow "$REPO/.github/workflows/release.yml" \;; then
  rm -rf "$ATTEST_DIR"
else
  printf 'build provenance verification failed; inspect %s\n' "$ATTEST_DIR" >&2
  false
fi
```

This proves that GitHub accepted a signed statement binding those digests to the expected
repository and workflow. It does not prove that the source or resulting behavior is safe.

### 5 - Push the tag

This starts the production release workflow against the exact tagged commit. The tag is
signed and verified locally before it leaves the machine; expect one touch for the tag and
one for the push:

```bash
if test -z "$(git tag --list "$TAG")" &&
  test -z "$(git ls-remote --tags origin "refs/tags/$TAG")" &&
  git tag -s "$TAG" -m "sigwood $TAG tag" &&
  git verify-tag "$TAG" &&
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

Approve only when `require main history`, `package distributions` and every `test` job are
green and `publish PyPI` is waiting for review. In the run opened above:

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

The command-line token cannot see a draft, and it can neither publish nor create a release:
`gh release view` reports "release not found" for a draft that exists. Inspecting and publishing
are browser acts. The draft's address comes from the run's own log, where the draft job prints
it, and a release the token CAN see is one that is already public:

```bash
if test "$(gh release view "$TAG" --repo "$REPO" --json isDraft --jq .isDraft 2>/dev/null)" = "false"; then
  printf 'GitHub Release %s is already published - skip to step 8\n' "$TAG"
elif DRAFT_URL=$(gh run view "$RUN_ID" --repo "$REPO" --log 2>/dev/null |
    grep -oE 'drafted https://[^[:space:]]+' | head -1 | cut -d' ' -f2) && [[ -n "$DRAFT_URL" ]]; then
  printf 'read:    %s\npublish: %s\n' \
    "$DRAFT_URL" "${DRAFT_URL/\/releases\/tag\//\/releases\/edit\/}"
else
  printf 'no draft found in run %s - create it by hand (see the end of this step)\n' "${RUN_ID:-?}" >&2
  false
fi

### §7a
```

Open the first address and read the title, tag, and rendered notes. It is a read-only preview of
the draft and carries no publish control, so a draft cannot be published from it. The second
address is the same draft in the editor, where **Publish release** sits at the foot of the form
beside *Save draft*; the editor is also reachable from the preview's pencil button. Confirm the
tag field reads `vX.Y.Z` before publishing, because a draft carries its tag as a property, which
is why its preview address is an `untagged-` one. Then confirm from the terminal, which can see
the release once it is public:

```bash
test "$(gh release view "$TAG" --repo "$REPO" --json isDraft --jq .isDraft)" = "false" &&
  printf 'published GitHub Release %s\n' "$TAG"

### §7b
```

Attaching built artifacts is optional; PyPI remains the distribution source of truth.

#### If the draft was not created

The draft job fails closed: a missing or misnamed changelog section, or a GitHub API failure,
leaves the tag with no Release rather than one with wrong notes, and the PyPI upload is
unaffected either way. Extract the notes with the same rule the workflow uses, reading
`CHANGELOG.md` from the tagged commit so the working tree cannot matter:

```bash
if NOTES_FILE=$(mktemp "${TMPDIR:-/tmp}/sigwood-${VERSION}-notes.XXXXXX") &&
  git show "$TAG:CHANGELOG.md" | awk -v version="$VERSION" '
    index($0, "## [" version "] - ") == 1 { copying = 1; next }
    copying && /^## \[/ { exit }
    copying { print }
    END { if (!copying) exit 1 }
  ' > "$NOTES_FILE" &&
  test -s "$NOTES_FILE"; then
  printf 'notes for %s are at %s\n' "$TAG" "$NOTES_FILE"
else
  printf 'CHANGELOG.md at %s has no "## [%s] - " section\n' "$TAG" "$VERSION" >&2
  false
fi

### §7c
```

Then on the Releases page choose **Draft a new release**, pick the existing tag `vX.Y.Z`, title
it `sigwood vX.Y.Z`, paste the notes file's contents as the body, and **Save draft**. Return to
§7a.

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
```

Then confirm GitHub verified both signatures. The first call reads the tagged commit, the
second the annotated tag object itself:

```bash
test "$(gh api "repos/$REPO/commits/$(git rev-list -n 1 "$TAG")" --jq .commit.verification.verified)" = "true" &&
  test "$(gh api "repos/$REPO/git/tags/$(git rev-parse "$TAG")" --jq .verification.verified)" = "true" &&
  printf 'commit and tag for %s are Verified on GitHub\n' "$TAG"

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
only after a successful upload. If the run is active or waiting for approval, cancel it from
the run's page in the browser; the maintainer token cannot cancel runs.

Leave the tag where it is. A pushed `v*` tag is never deleted or moved, and nothing here needs
it to be: fix the problem on `main`, bump the patch version, rerun the identity and validation
steps, and cut a new signed tag. The tag that failed stays in the history as the record of what
was tried.

### After PyPI publication

Do not move or reuse the tag. Bump the patch version, fix the problem, and publish a new
release. Yank the bad version from **PyPI project -> Manage -> Release -> Yank** so normal
resolution avoids it while exact pins remain available. The bad version's GitHub Release is
still a draft at this point, and the maintainer token cannot see drafts, so open the Releases
page in the browser and either delete the draft or publish it with a note pointing at the
replacement - do not leave an unexplained draft beside the tag.

### Trusted Publishing is unavailable

If PyPI OIDC or GitHub Actions is unavailable and a release is genuinely urgent, rerun local
build validation and use `twine upload` with a freshly generated, project-scoped token. Revoke
the token immediately afterward. This is an emergency path only; the normal path stores no
credential.

### Sensitive material reached the public repository

Assume it was seen and cached. Force-pushing or changing repository visibility does not
unpublish it. Rotate exposed credentials immediately; the preflight scan is preventive, not a
cleanup mechanism.
