# Releasing sigwood

The maintainer runbook for cutting a release to PyPI and GitHub. It is a checklist, not a
script - read each step, run it, confirm the result before the next. The irreversible steps
(tagging, publishing to PyPI, publishing a GitHub Release) are called out; everything before
them is safe to redo.

sigwood publishes through **Trusted Publishing**: the release is built and uploaded by a
tag-triggered GitHub Actions workflow (`.github/workflows/release.yml`) that authenticates to
PyPI over OpenID Connect - **no long-lived API token is stored anywhere**. Each upload also
carries a **PEP 740 PyPI Publish Attestation**, a Sigstore-backed proof that the distribution
was published through this project's Trusted Publisher identity. That is *publication*
provenance - which pipeline uploaded it - not a claim about how the code was built, and not a
statement that the code is safe.

Two disciplines carry over from the older manual runbook and are not optional: you still
**build and validate locally** before you tag (the go/no-go gate), and a **human still
approves** the publish - the workflow pauses at a GitHub environment gate that a maintainer
must approve before anything reaches PyPI. CI adds the cryptographic receipt; it does not
replace your verification.

## One-time setup

Needed once, not per release. No API token is involved.

**Trusted publishers.** On each index, register a trusted publisher for `sigwood`:

| Field       | Value                                          |
|-------------|------------------------------------------------|
| Owner       | `helixmap`                                     |
| Repository  | `sigwood`                                      |
| Workflow    | `release.yml`                                  |
| Environment | `pypi` (on PyPI) / `testpypi` (on TestPyPI)    |

Do this on **both** [pypi.org](https://pypi.org) and [test.pypi.org](https://test.pypi.org)
(a separate account) - the TestPyPI publisher is what makes the rehearsal possible.

**GitHub environments** (repo Settings -> Environments):

- `pypi` - add yourself as a **required reviewer** (this is the approval gate) and, where
  available, restrict deployments to the tag pattern `v*` and disable admin bypass. Do **not**
  enable "prevent self-review": with a single maintainer it would deadlock, since no one else
  can approve. The gate is a deliberate manual confirmation before an irreversible publish, not
  a two-person control.
- `testpypi` - no reviewer needed (it is a dry run); restrict dispatch to the default branch.

**Also:** `gh` authenticated (`gh auth status`) against the account that owns `helixmap/sigwood`,
for the GitHub Release. For the local validate below, install the packaging tools into your
release venv (`pip install build twine`; `.[dev]` does not pull them).

## Versioning

The version lives in **one place**: `sigwood/__init__.py` (`__version__`). `pyproject.toml`
reads it dynamically, and `sigwood --version` prints it. To bump a release, edit that single
literal, and pair it with the README status line (rendered prose, not code) in the same commit.
Tags are `v<version>` (e.g. `v0.2.2`); the workflow asserts the tag matches the version literal
and refuses to publish a mismatch.

## Rehearse on TestPyPI first

**Non-negotiable before the first Trusted-Publishing cut, and again after any change to
`release.yml`.** Nothing about the published artifact should be verified for the first time on
real PyPI. The workflow's `workflow_dispatch` trigger publishes to **TestPyPI** under a
throwaway `X.Y.Z.dev<run>` version, so the whole chain runs harmlessly:

1. Actions -> **release** -> **Run workflow** (on `main`). It builds, runs the 3.11-3.14 test
   matrix, and stops at the `testpypi` environment.
2. Watch the matrix go green.
3. Confirm the three things only a live run can prove - it published, it installs, the
   attestation is attached:

   ```bash
   python3 -m venv /tmp/sw-test && /tmp/sw-test/bin/pip install \
     -i https://test.pypi.org/simple/ "sigwood==<the .dev version>"
   /tmp/sw-test/bin/sigwood --version
   rm -rf /tmp/sw-test
   ```

   Then open the file on the TestPyPI project page and confirm its provenance/attestation
   panel. Re-rehearse with a fresh dispatch (a new `.dev` number) if anything is off - TestPyPI
   will not accept the same version twice.

## The release checklist

### 0 - Preflight, all green before you touch anything

```bash
git switch main && git pull
git status --short                                    # clean tree
git rev-list --left-right --count origin/main...main  # 0  0 - nothing unpushed
python -m pytest -q                                   # full suite green locally
grep __version__ sigwood/__init__.py                  # the version you intend to ship
```

The repo is public and anything pushed is cached forever - confirm nothing sensitive is
tracked:

```bash
git ls-files | grep -iE 'privdocs|scratch|memory/|secret|token|\.env' || echo clean
```

### 1 - Bump the version, and 2 - land release docs

Edit `__version__` in `sigwood/__init__.py`; bump the README status line
(`> **Status: ... (`X.Y.Z`)**`) in the SAME commit (it is rendered prose and does not track the
literal automatically). Roll the changelog: move every `[Unreleased]` entry into a new
`## [X.Y.Z] - <today>` section, leave `[Unreleased]` empty, and repoint the compare links at
the bottom. Anything that ships (README, new docs) lands and is pushed **now** - the tagged
commit is the released state. Keep the new changelog section to paste as the GitHub Release
notes (step 6).

### 3 - Build and validate locally, the go/no-go gate

CI rebuilds the artifact, but you validate locally first: this is your confidence gate, and it
catches packaging bugs before you create an irreversible tag. Build from a **clean export of
the tracked tree**, never the working tree - a working-tree build can sweep untracked files
into the wheel:

```bash
BUILD=/tmp/sigwood-build; rm -rf "$BUILD" && mkdir "$BUILD"
git archive HEAD | tar -x -C "$BUILD" && cd "$BUILD"

# packaging tools live in a release venv (`.[dev]` does not pull build/twine):
python3 -m venv .venv-rel && ./.venv-rel/bin/pip install -q -e ".[dev]" build twine
./.venv-rel/bin/python -m pytest -q

./.venv-rel/bin/python -m build               # sdist + wheel into dist/
./.venv-rel/bin/python -m twine check dist/*  # metadata + README render must PASS
./.venv-rel/bin/python tools/validate_distribution.py dist

# README is baked into the release and PyPI never refetches it - every absolute image/badge
# URL must resolve NOW (a broken hero image is permanent):
grep -oE 'https://[^") ]+' README.md | sort -u | xargs -I{} curl -s -o /dev/null -w "%{http_code} {}\n" {}

# clean-venv smoke - catches packaging bugs a metadata check cannot:
python3 -m venv /tmp/sw-relcheck && /tmp/sw-relcheck/bin/pip install -q dist/*.whl
/tmp/sw-relcheck/bin/sigwood --version        # prints the release version
/tmp/sw-relcheck/bin/sigwood --help
/tmp/sw-relcheck/bin/python -c "import importlib.resources as r; \
  print((r.files('sigwood')/'data'/'config_example.toml').read_text()[:1] and 'data OK')"
rm -rf /tmp/sw-relcheck; cd -
```

Every check green is the go/no-go line. Nothing above this point is irreversible.

### 4 - Tag, which triggers the release workflow

```bash
git tag -a v0.2.2 -m "sigwood v0.2.2"
git push origin v0.2.2
```

The pushed tag starts `release.yml`. It reruns the full suite on the **3.11-3.14 matrix against
the exact tagged commit** - this is the automated "green on the release SHA" gate; the publish
job cannot run unless the whole matrix passes - rebuilds the sdist + wheel, and then **waits**
at the `pypi` environment gate. Nothing has reached PyPI yet. (A local suite can be green while
CI is red - a recursion-depth difference between macOS and Linux once shipped a broken tag - so
this matrix gate, not your laptop, is the release-SHA proof.)

### 5 - Approve the publish, **irreversible**

Watch the run (Actions -> release, or `gh run watch`). When the matrix is green and the
`publish` job is waiting for review, approve the `pypi` environment in the GitHub UI. The
workflow uploads to PyPI over OIDC and attaches the attestation. A version number is permanent:
you cannot re-upload `X.Y.Z`, only yank it and publish a new number - so approve only after the
matrix is green and you have rehearsed on TestPyPI.

If the matrix is red, the gate never opens. If the tag is wrong, do **not** approve - the gate
is your last stop before the irreversible step.

**First real Trusted-Publishing release only:** if a `0.0.0` name-reservation placeholder
release still exists, delete that RELEASE (Manage -> release 0.0.0 -> Delete) - never the
PROJECT, since deleting a project frees the name for anyone to claim.

### 6 - GitHub Release

```bash
gh release create v0.2.2 --repo helixmap/sigwood --title "sigwood v0.2.2" \
  --notes-file <(printf '%s\n' "...release notes, from the changelog section...")
```

Attaching the built artifacts is optional (PyPI is the source of truth).

### 7 - Post-publish verify

```bash
python3 -m venv /tmp/sw-postpub && /tmp/sw-postpub/bin/pip install sigwood
/tmp/sw-postpub/bin/sigwood --version    # matches the release
rm -rf /tmp/sw-postpub
```

A fresh `pip install` pulling the new version is the authoritative "it is live" signal. The
JSON endpoint (`https://pypi.org/pypi/sigwood/json`) is Fastly-cached and lags the file index
pip resolves against - it can still list the previous version for a minute or two after a
successful upload, so trust the install, not the JSON. On the PyPI file page, confirm the
**provenance/attestation panel** shows the publish attestation.

On a PEP 668 box (Debian 12+ / Raspberry Pi OS), confirm the documented path: a bare
`pip install sigwood` outside a venv is REFUSED (`externally-managed-environment`) and
`pipx install sigwood` succeeds with `sigwood --help` running - the README leads with pipx, so
that path must work.

Then eyeball the PyPI project page (README + image render) and the GitHub Release.

## If something goes wrong

- **Matrix red, or the publish job failed** - nothing was published (the gate never opened, or
  the build failed before upload). Fix the cause, delete the tag (below), and re-cut.
- **Tag points at the wrong commit, not yet approved** - do NOT approve the environment; delete
  and re-tag: `git push origin :refs/tags/v0.2.2 && git tag -d v0.2.2`.
- **Bad artifact already on PyPI** - you cannot overwrite or un-upload it. Bump the patch
  version, fix, publish the new number, and yank the bad one (Manage -> Release -> Yank) so pip
  stops resolving to it while leaving it installable by exact pin.
- **Trusted Publishing unavailable (break-glass)** - if PyPI's OIDC or the workflow is down and
  a release is genuinely urgent, a maintainer can fall back to a one-time manual upload with a
  **freshly generated, immediately revoked** project-scoped token (`twine upload` from the
  step-3 release venv). Emergency-only; it leaves no stored credential. The standing path is
  Trusted Publishing.
- **Something sensitive reached the public repo** - flipping visibility or force-pushing does
  not un-publish it; assume it was seen and cached. Rotate any exposed secret. Prevention (the
  preflight scan) is the only real control.
