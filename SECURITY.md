# Security Policy

## Reporting a vulnerability

If you believe you have found a security issue in sigwood, please report it
privately. **Do not open a public issue for security problems.**

- Email: **security@augros.org**
- Please include a description, reproduction steps, and the version or commit.

We aim to acknowledge a report within a few business days and to keep you updated
as we investigate. We will credit reporters who wish to be credited.

## Supported versions

sigwood is pre-1.0. Security fixes land on the latest release and `main`.

## Threat model - what sigwood does and does not trust

sigwood is a **local, offline, batch** analysis tool. It runs on your machine,
reads log files from disk, and writes reports and exports to directories you
choose.

**It trusts:**

- The machine and account it runs as.
- The configuration file and allowlist files you point it at. Allowlist `re:`
  patterns are compiled and executed, so review any allowlist you did not write
  yourself.

**It treats log *content* as untrusted data.** Log files may originate from
compromised hosts. sigwood is built so that hostile log content cannot execute
code or escape the tool:

- Every human-facing report surface - text, CSV, and HTML/PDF - strips terminal
  control bytes from log-derived values, so hostile log content cannot emit
  terminal control sequences when a report or worklist is printed or opened in a
  terminal.
- CSV worklist cells additionally carry a spreadsheet formula-injection guard
  (CWE-1236): a cell that would start with `=`, `+`, `-`, or `@` is quote-prefixed,
  so opening the file in Excel or LibreOffice cannot execute a formula planted in
  log content.
- HTML and PDF report output additionally escapes markup at a single enforced
  choke point, so a log line cannot inject markup or script into a report.
- No log field is ever passed to a shell, to `eval`, or to a code-executing
  deserializer - log content is parsed with `json.loads` and plain text parsers;
  there is no pickle, marshal, or YAML load anywhere on the data path.

**Two things to keep in mind when handling untrusted logs:**

- **Suggested commands contain values from your logs.** Findings include
  copy-pasteable triage commands (`whois …`, `grep …`) built from fields such as
  domains and IP addresses. Review a suggested command before you run it.
- **sigwood loads recognized log formats into memory and does not sandbox or
  hard-limit analysis input.** Analyzing an extremely large or maliciously
  crafted archive - for example, a decompression bomb - can exhaust memory.
  When you are scoping out logs of unknown origin, format, or size, start with
  `sigwood digest <file>`: unrecognized input is profiled from a bounded
  sample before you commit to a full analysis run. That bound covers the sample
  digest profiles - it is not a sandbox, and specific hostile shapes can still
  defeat it, including a single line of unbounded length and a timestamp span
  crafted to inflate the histogram (see `docs/KNOWN-ISSUES.md`). Recognized
  formats may still be loaded fully, so keep first-pass inputs narrow when you
  do not yet trust the archive.

## Design guarantees

- **No phone-home, no telemetry, no account, no cloud.** sigwood does not send
  your data anywhere. The only network activity is the optional exporters, which
  pull logs *toward* you - from Splunk or an S3 CloudTrail bucket into local
  files - and never push your data out.
- **No credential handling for AWS.** sigwood uses your ambient boto3
  credential chain and never reads, stores, or prompts for AWS credentials.
- **Splunk credentials** are read from environment variables
  (`SIGWOOD_SPLUNK_USER` / `SIGWOOD_SPLUNK_PASS`) - the recommended path - or
  from your config file. They are sent only to the Splunk host you configure.
  TLS certificate verification is on by default (`verify_tls = true`). Prefer
  the environment variables over storing a password in the config file.
- **No background process, no database, no daemon, no listening socket.**
- **No dynamic code execution.** sigwood uses no `eval`, `exec`, or shell
  invocation, and performs no code-executing deserialization of untrusted input.

## Dependencies

sigwood depends on widely-used scientific Python libraries (pandas, numpy,
scikit-learn) and log-analysis utilities (drain3, tldextract), plus an
arch-selected clustering backend: fast-hdbscan, which pulls numba and llvmlite, on
common 64-bit platforms (x86-64, aarch64/arm64); stock hdbscan elsewhere,
including 32-bit ARM. Optional features pull additional stacks (`[splunk]`,
`[cloudtrail]`, `[pdf]`). Keep your dependencies updated; we track advisories
against them as part of release hygiene.

## Repository and release integrity

sigwood is maintained by one person. This section states how the repository is
run so you can judge that directly rather than infer it.

**Branch model.** `main` is the development branch and the maintainer pushes to
it directly; there is no pull-request requirement, because there is no second
reviewer for one to route to. Force-pushes and branch deletion are blocked, so
history on `main` is append-only, and since 2026-09-01 the branch refuses unsigned
commits (next paragraph). What stands behind the absence of a review
gate: `main` is not a distribution channel - releases are tagged and published
to PyPI, and that is what an install gives you. Continuous integration runs on
every push to `main` across Python 3.11 through 3.14, and the release workflow
runs that same full matrix again at the tag, so a published release has passed
the suite on every supported interpreter.

**Commit and tag signing.** Every commit on `main` from 2026-09-01, and every release
tag from that date, is signed with an SSH key that lives on a FIDO2 hardware token and
cannot sign without a physical touch on the token. Pushing to GitHub authenticates with
the same keys. `main` and the `v*` tag namespace refuse unsigned pushes, and release
tags refuse deletion and replacement. The maintainer's command-line token holds no
permission to push, edit those rules, or approve a deployment; the `pypi` approval is
given by hand in the browser. History before 2026-09-01 is unsigned and stays that way.
The signing public keys are the signing-key list on the maintainer's GitHub account and
are mirrored in [`allowed_signers`](allowed_signers) at the repository root.

**Automated checks.** Code scanning analyzes both the Python source and the
workflow definitions, on change and weekly. Secret scanning is enabled with push
protection. Dependency alerts and automated security updates are enabled, so a
published advisory against a dependency raises an alert; because sigwood declares
dependency ranges rather than pinned versions, most fixed versions are already
permitted by the existing range, and an update is proposed where the declared
range itself has to move. Private vulnerability reporting is enabled, so a report
can also be raised confidentially through GitHub rather than by email.

**Release integrity.** Every GitHub Actions step is pinned to a full commit SHA
rather than a moving tag, and those pins are kept current by scheduled update
proposals. Workflows run read-only by default; the publish job is the single
exception and holds only the token-minting permission it needs. Releases are
published to PyPI with Trusted Publishing and carry signed provenance
attestations, so a release traces back to the workflow run and commit that
produced it.

**Verifying a checkout.** With any `ssh-keygen` from OpenSSH 8.2 or later on your
path, from the repository root:

```bash
git -c gpg.ssh.allowedSignersFile=allowed_signers verify-commit HEAD
```

```bash
git -c gpg.ssh.allowedSignersFile=allowed_signers verify-tag v1.0.0
```

Each prints `Good "git" signature for code@augros.org with ED25519-SK key ...`. GitHub
shows the same result as a **Verified** badge on the commit and on the tag. A published
wheel is checked against the attestation PyPI serves for it with the `pypi-attestations`
tool, which confirms the file was uploaded by this repository's `release.yml` workflow.
