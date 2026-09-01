# Field validation kit

## What the report collects - and what it leaves out

The field validation kit runs one small synthetic canary and one default sigwood
hunt, then writes a reviewable Markdown report. Its automated projection contains
no raw identifiers and no arbitrary or unbounded log-derived strings. It keeps
only closed allowlisted tokens, numeric aggregate distributions, and counts. It
contains no finding titles and no uncurated evidence values.

The three answers a collaborator may type at the end are the explicit free-text
exception. Do not paste log lines, hostnames, addresses, domains, user names, or
other system data into those answers. Finding titles appear only in the local
terminal during the optional triage pass.

The machine-data section contains:

- `kit`: kit version, kit-authored generation time, platform facts, validated
  sigwood version, report schema version, and a flag when version text could not
  be parsed
- `smoke`: whether the synthetic canary ran and passed
- `hunt`: the fixed `default_hunt` arm, exit code, and wall-clock seconds
- `peak_child_rss_mb`: maximum resident memory across the completed child
  processes
- `run_summary`: record counts, data-window span, requested span, data size,
  allowlisted source and detector tokens, classified status counts, and numeric
  suppression facts
- `findings`: detector-by-severity counts, numeric aggregate distributions, and
  closed allowlisted evidence histograms
- `triage`: token-only verdicts and untriaged counts
- `answers`: the three collaborator-authored answers

Log-derived data-window endpoints and per-finding dates are excluded. The report
keeps only the calculated window span. `kit.generated_at` and the filename date
describe the kit run, not the logs.

The script contains no network code and sends nothing. The report is created
with user-only permissions. Read the whole file before choosing whether to send
it.

## Run it cold

You need Python 3.9 or newer and a working `sigwood` command on `PATH`. The kit
is one standalone file: it does not import the sigwood package or require a
repository checkout.

If sigwood is not installed, install pipx through your platform first. On Debian
or Ubuntu:

```console
sudo apt install pipx
```

Then install sigwood in its own environment:

```console
pipx install sigwood
```

Configure the sources that the default hunt should use:

```console
sigwood init
```

Download
[`tools/fieldkit.py`](https://github.com/helixmap/sigwood/blob/main/tools/fieldkit.py)
from the canonical repository, save it as `fieldkit.py`, inspect it, and run it:

```console
python3 fieldkit.py
```

The report is written to the current directory. To select another existing
directory:

```console
python3 fieldkit.py --out=/path/to/review-directory
```

Two optional controls are available:

```console
python3 fieldkit.py --skip-smoke
python3 fieldkit.py --no-triage
```

`--skip-smoke` bypasses the synthetic installation canary. `--no-triage`
bypasses both finding triage and the three questions.

## Upgrade an existing pipx installation

A plain `pipx install sigwood==<version>` is not a clean reinstall when sigwood
is already installed. pipx can decline the request and still exit successfully.
Use the operation that matches what you mean:

```console
pipx upgrade sigwood
pipx install --force sigwood==<version>
```

For a genuine first-install test, remove the existing pipx environment before
installing the exact version:

```console
pipx uninstall sigwood
pipx install sigwood==<version>
```

Confirm the command that will be measured:

```console
sigwood --version
```

## Make the pipx command visible on PATH

pipx commonly installs commands under `~/.local/bin` and warns when that
directory is not on `PATH`. `pipx ensurepath` can update shell startup files,
but a new login session may be required before the change is visible.

An interactive login shell can find `sigwood` while a non-interactive command
such as `ssh host command` cannot, because the two shells may read different
startup files. Check in the same kind of shell that will run Fieldkit:

```console
command -v sigwood
```

If needed, set the path explicitly for that run:

```console
PATH="$HOME/.local/bin:$PATH" python3 fieldkit.py
```

## Let the run read the sources you selected

A stock Pi-hole installation can leave its logs owned by `pihole:pihole` with
mode `0640`. An ordinary account then cannot read them, even though the host has
DNS data. sigwood reports the resulting source gap; it cannot analyze bytes the
account cannot read.

If Pi-hole should contribute to the run, use the host's normal administration
policy to give the running account read access, start a new session so group
membership takes effect, and confirm the configured path before rerunning. Do
not make the logs world-readable for this test.

The report's `data sources` row may say `syslog_journal` instead of naming flat
syslog files. That means sigwood's provider arbitration selected the readable
system journal. It is expected behavior, not a Fieldkit fault.

## What to expect

The canary is small. The real hunt can take as long as an ordinary default hunt
over the configured default window. Progress bars, large-dataset prompts, and
diagnostics remain visible in the terminal.

When the report is available and the terminal is interactive, the kit shows up
to 20 finding titles locally. For each, enter:

- `k` for known benign
- `u` for unexplained but plausible
- `n` for nonsense
- `i` for interesting
- `s` to skip
- `q` to stop the triage pass

The kit then asks what the report missed, what was confusing, and whether you
would run it monthly. Empty answers are fine. A non-interactive run skips both
triage and the questions.

## Send a reviewed report

We read reports to find failures, confusing output, missing detections, and
patterns that do not transfer cleanly to another environment. We may quote
aggregate numbers with permission. We do not quote the three typed answers
without asking.

Read the whole Markdown file, then email it to
[fieldkit@augros.org](mailto:fieldkit@augros.org). Ask us to delete it at any
time and we will.
