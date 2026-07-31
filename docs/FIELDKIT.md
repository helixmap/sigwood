# Field validation kit

sigwood is approaching 1.0. Before that release, we want to see how its default
hunt behaves on logs that did not shape its development. The field validation
kit gives a collaborator one script to run and one reviewable Markdown file to
send back.

The script is not a sigwood command and it does not change sigwood. It drives
the installed command in the same way an operator would: a small synthetic
canary first, followed by one default hunt against the sources already selected
by `sigwood init`.

## The privacy boundary

The automated projection never copies a log-derived string into the field
report. It uses enumerated field and token lists, retains numeric measurements
and counts, and groups any unexpected identifier under `other`. Finding titles
are shown only in your terminal during the optional triage pass.

Your three typed answers are the sole free-text exception. Do not paste log
lines, hostnames, addresses, domains, user names, or other system data into
them. Read the whole Markdown file before sending it.

The machine-data section contains these top-level fields:

- `kit`: kit version, kit-authored generation time, platform facts, validated
  sigwood version, report schema version, and a flag when version text could not
  be parsed
- `smoke`: whether the synthetic canary ran and passed
- `hunt`: the fixed `default_hunt` arm, exit code, and wall-clock seconds
- `peak_child_rss_mb`: the maximum resident memory reported across all completed
  child processes—the version probe, canary when enabled, and hunt
- `run_summary`: record counts, data-window span in seconds, requested span,
  data size, source and detector tokens, classified skip/failure/note counts,
  and numeric allowlist-suppression facts
- `findings`: detector-by-severity counts plus numeric distributions and
  enumerated evidence histograms
- `triage`: token-only verdicts and untriaged counts
- `answers`: the three answers you typed

Log-derived data-window endpoints and per-finding dates are excluded. The
report keeps only the calculated data-window span. `kit.generated_at` and the
date in the filename describe when the kit ran; they are not dates taken from
your logs.

The script has no network code and sends nothing. You choose whether to email
the file.

## What we do with the file

We read the report to find failures, confusing output, missing detections, and
patterns that do not transfer cleanly to another environment. We may quote
aggregate numbers with your permission. We do not quote your typed answers
without asking.

Email the reviewed file to [fieldkit@augros.org](mailto:fieldkit@augros.org).
Ask us to delete it at any time and we will.

## Run the protocol

Many distributions do not ship pipx; install your platform’s pipx package first
(on Debian or Ubuntu):

```console
sudo apt install pipx
```

Install sigwood in its own environment:

```console
pipx install sigwood
```

Configure the log sources you want the default hunt to use:

```console
sigwood init
```

Download
[`tools/fieldkit.py`](https://github.com/helixmap/sigwood/blob/main/tools/fieldkit.py)
from the canonical repository and save it as `fieldkit.py`. Download the file
first, inspect it if you wish, then run it:

```console
python3 fieldkit.py
```

The report is written to the current directory. To choose another existing
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

## What to expect

The canary is small. The real hunt can take as long as an ordinary default
hunt over your configured default window. Progress bars, large-dataset prompts,
and diagnostics remain visible in the terminal.

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

The resulting file is created with private permissions. Its final instruction
is the important one: read the whole file, then email it to
[fieldkit@augros.org](mailto:fieldkit@augros.org).
