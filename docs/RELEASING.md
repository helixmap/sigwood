# Releasing sigwood

The maintainer runbook for cutting a release to PyPI and GitHub. It is a checklist,
not a script - read each step, run it, confirm the result before the next. The
irreversible steps (tagging, uploading to PyPI, publishing a GitHub Release) are
called out; everything before them is safe to redo.

sigwood publishes **manually** from a maintainer's machine: build locally, verify a
clean install, then `twine upload`. There is no automated release pipeline - CI
(`.github/workflows/ci.yml`) only runs the test suite. Keeping the release manual keeps
the trust surface small.

## One-time setup

You need these once, not per release:

- **A PyPI account** with permission to publish `sigwood`, and an **API token**
  (Account settings → API tokens). Store it so `twine` can find it - either in
  `~/.pypirc`:

  ```ini
  [pypi]
    username = __token__
    password = pypi-AgEI…            # your token, kept out of version control
  ```

  or via your OS keyring / a `TWINE_USERNAME=__token__` + `TWINE_PASSWORD=…` pair in a
  secrets manager. **Never commit the token.** Scope it to the `sigwood` project -
  the name is already ours (a 0.0.0 placeholder release holds it), so a
  project-scoped token works from the first real upload.
- **`gh` authenticated** (`gh auth status`) against the account that owns
  `helixmap/sigwood`.
- The build/publish tools in your dev environment: `pip install -e '.[dev]'` gives you
  `pytest`; add `pip install build twine` for the packaging tools.

## Versioning

The version lives in **one place**: `sigwood/__init__.py` (`__version__`).
`pyproject.toml` reads it dynamically, and `sigwood --version` prints it. To bump a
release, edit that single literal - no other code changes (step 1 pairs it with the
README status line, which is rendered prose). Tags are `v<version>` (e.g.
`v0.1.0`).

## The release checklist

### 0 · Preflight gates - all green before you touch anything

```bash
git switch main && git pull            # on main, synced with origin
git status --short                     # clean tree (empty output)
git rev-list --left-right --count origin/main...main   # 0  0 - nothing unpushed
python -m pytest -q                    # full suite green locally
gh run list --branch main --limit 3    # CI green on the commit you're releasing
grep __version__ sigwood/__init__.py   # the version you intend to ship
```

For the **first real release**: the `sigwood` name is already registered to us -
a 0.0.0 name-reservation placeholder holds it, so availability checks are moot. Confirm you can manage the project (`https://pypi.org/manage/project/sigwood/`
lists you as owner) rather than testing the name for availability. After the first real
upload, delete the 0.0.0 placeholder RELEASE (step 5) - and never the PROJECT: deleting
a project releases the name for use by any other PyPI user.

```bash
curl -s https://pypi.org/pypi/sigwood/json | python3 -c "import json,sys; print(sorted(json.load(sys.stdin)['releases']))"
# expect: our own releases only
```

The repo is public - everything tracked ships, and anything ever pushed is cached
forever. Before any push that accompanies a release, confirm nothing sensitive is
tracked:

```bash
git ls-files | grep -iE 'privdocs|scratch|memory/|secret|token|\.env' || echo clean
```

### 1 · Bump the version (if not already done)

Edit `__version__` in `sigwood/__init__.py` - the single source. Bump the README
status line (`> **Status: … (`X.Y.Z`)**`) in the SAME commit; it is rendered prose, not
code, so it does not track the literal automatically. The `--version` and JSON-envelope
tests read `sigwood.__version__` dynamically, so they need no edit. Commit and push.
The tag in step 4 must point at a commit that already carries the new version.

### 2 · Land release docs

**Roll the changelog.** Move every entry under `[Unreleased]` in `CHANGELOG.md` into a
new `## [X.Y.Z] - <today>` section, leave an empty `[Unreleased]` behind, and repoint the
`[Unreleased]` link at the bottom of the file while adding a reference for the new
version. Land it in the same commit as the step-1 version bump, so the tagged commit
carries the released changelog - and paste that new section as the GitHub Release notes in
step 6 rather than re-deriving them from `git log`.

Anything that ships in the release (README status line, `CONTRIBUTING.md`, new docs)
lands and is pushed **now**, so the tagged commit is the released state. Write the
release notes for the GitHub Release (step 6) from the commits since the last tag:

```bash
git log --oneline "$(git describe --tags --abbrev=0)"..HEAD
# first release only: there is no prior tag (git describe fails) and a single
# squashed commit - write the notes from the README's feature list instead
```

### 3 · Build & validate

Build from a **clean export of the tracked tree**, never the working tree - a
working-tree build can sweep untracked files into the wheel:

```bash
BUILD=/tmp/sigwood-build
rm -rf "$BUILD" && mkdir "$BUILD"
git archive HEAD | tar -x -C "$BUILD" && cd "$BUILD"

# the export IS the public tree - prove the suite green in it, not just the checkout.
# Run every packaging tool through THIS release venv, never a bare `python`: on
# macOS/Homebrew the bare interpreter is usually a system python3 with no build/twine,
# and `python -m twine upload` then silently no-ops with `No module named twine`
# AFTER the tag is already pushed. `.[dev]` does not pull the packaging tools, so add
# build + twine to the same venv here and use it through step 5:
python3 -m venv .venv-rel && ./.venv-rel/bin/pip install -q -e ".[dev]" build twine
./.venv-rel/bin/python -m pytest -q

./.venv-rel/bin/python -m build              # sdist + wheel into dist/
./.venv-rel/bin/python -m twine check dist/* # metadata + README render must PASS
./.venv-rel/bin/python scripts/validate_distribution.py dist

# README is baked into the release and PyPI never refetches or rewrites it - every
# absolute image/badge URL must resolve NOW (a broken hero image is permanent):
grep -oE 'https://[^") ]+' README.md | sort -u | xargs -I{} curl -s -o /dev/null -w "%{http_code} {}\n" {}

# clean-venv smoke test - the gate that catches packaging bugs a metadata check can't:
python3 -m venv /tmp/sigwood-relcheck && /tmp/sigwood-relcheck/bin/pip install -q dist/*.whl
/tmp/sigwood-relcheck/bin/sigwood --version         # prints the release version
/tmp/sigwood-relcheck/bin/sigwood --help            # entry point + arg parser OK
/tmp/sigwood-relcheck/bin/python -c "import importlib.resources as r; \
  print((r.files('sigwood')/'data'/'config_example.toml').read_text()[:1] and 'data OK')"
rm -rf /tmp/sigwood-relcheck
cd -                                    # back to the repo - step 4 tags THERE, and
                                        # steps 5-6 upload/attach "$BUILD"/dist/*
```

Every check green is the go/no-go line. Nothing above this point is irreversible.

### 4 · Tag - *irreversible-ish* (a pushed tag should not be moved)

```bash
git tag -a v0.1.0 -m "sigwood v0.1.0"
git push origin v0.1.0
```

### 5 · Publish to PyPI - **irreversible**

A version number is permanent: you cannot re-upload `0.1.0`, only yank it and publish a
new number. Upload the exact artifacts you validated in step 3:

```bash
"$BUILD"/.venv-rel/bin/twine upload "$BUILD"/dist/*   # the venv that HAS twine (step 3)
```

Do NOT use a bare `python -m twine upload` - on macOS/Homebrew `python` is often a
system interpreter with no twine, which no-ops with `No module named twine` after the tag
is already pushed. Use the step-3 release venv (`"$BUILD"/.venv-rel/bin/twine`, or any venv
where `pip install twine` has run), and confirm the project page at
`https://pypi.org/project/sigwood/`.

**First real release only:** delete the 0.0.0 placeholder RELEASE (Manage → release
0.0.0 → Options → Delete) - the project survives on the new version. Do **not** delete
the project itself; that would free the name for anyone to claim.

### 6 · GitHub Release

```bash
gh release create v0.1.0 \
  --repo helixmap/sigwood \
  --title "sigwood v0.1.0" \
  --notes-file <(printf '%s\n' "…release notes…") \
  "$BUILD"/dist/sigwood-0.1.0*.tar.gz "$BUILD"/dist/sigwood-0.1.0*.whl
```

Attaching the built artifacts is optional (PyPI is the source of truth) but convenient.

### 7 · Repo visibility - nothing to do

`helixmap/sigwood` is created public with a single squashed initial commit; there is no
private-then-flip step. What guards each push is the step-0 secret scan and step 3's suite-plus-build run
against the clean export - the tree you build from is the tree the public sees.

### 8 · Post-publish verify

```bash
python3 -m venv /tmp/sigwood-postpub && /tmp/sigwood-postpub/bin/pip install sigwood
/tmp/sigwood-postpub/bin/sigwood --version    # matches the release
rm -rf /tmp/sigwood-postpub
```

A fresh `pip install` pulling the new version is the authoritative "it's live" signal. The
JSON metadata endpoint (`https://pypi.org/pypi/sigwood/json`) is Fastly-cached and lags the
file index pip resolves against - it can still list only the previous version for a minute or
two after a successful upload, so trust the install, not the JSON.

On a PEP 668 box (Debian 12+ / Raspberry Pi OS), also confirm the documented install
path end to end: a bare `pip install sigwood` outside a venv is REFUSED
(`externally-managed-environment`) and `pipx install sigwood` succeeds with
`sigwood --help` running - the README leads with pipx, so the pipx path is the one that
must work.

Then eyeball the PyPI project page (README + image render) and the GitHub Release.

## If something goes wrong

- **Bad artifact already on PyPI** - you cannot overwrite or un-upload it. Bump the
  patch version, fix, and publish the new number. Yank the bad one on PyPI (Manage →
  Release → Yank) so pip stops resolving to it while leaving it installable by exact pin.
- **Tag points at the wrong commit, not yet released** - delete and re-tag before any
  PyPI upload: `git push origin :refs/tags/v0.1.0 && git tag -d v0.1.0`.
- **Something sensitive reached the public repo** - flipping visibility or force-pushing
  does not un-publish it; assume anything that was public was seen and cached. Rotate any
  exposed secret. Prevention (the step-0 scan) is the only real control.
