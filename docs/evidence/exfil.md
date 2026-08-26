# exfil — calibration record

exfil surfaces bulk outbound transfers to external endpoints over Zeek connection
logs. Both of its shipped constants were put to a sweep. Both ratified — and the sweep
found that the detector's real noise problem is not a threshold at all.

## what was measured

A two-axis sweep of the only two constants an operator sees: the outbound byte floor
and the originator-share gate. Plus four obligations fixed in advance — report the
excluded population by mass rather than row share, measure the rate of the one
asymmetric failure the share gate structurally cannot see, check the synthetic corpus
in the direction that would trip it, and record the default-hunt evidence without
spending it.

The harness calls the detector's **own** eligibility code, so the measured population
is the detector's rather than a reimplementation of it. Window figures are composed by
summing per-unit totals, and that composition was **verified rather than assumed**
against a direct whole-window load: identical pair count, zero byte delta, zero
connection delta.

## data

- **121 days** of real connection logs (≈56.5 M connections, ≈3,835 GiB of measured
  outbound mass).
- A frozen one-week capture and a frozen single day from the same source.
- The shipped synthetic demo corpus.

Measured **without allowlist suppression**, deliberately — see the hazard below.
All real windows come from one estate, so the sweep measures noise and stability there,
not transfer to another environment.

## the gates applied

- Sweep **both** knobs across a wide grid, at window lengths including the shipped
  default window, and report the distribution across rolling windows rather than one
  whole-archive number.
- Report the excluded population by **mass**, not just row count, because a row share
  says nothing about how much data went unmeasured.
- Record the default-hunt evidence and **do not spend it** — no recommendation on the
  seat from within the sweep.

## outcome

**Both constants ratify.**

- **The byte floor** shows smooth decay of roughly −15% per doubling across seven
  grid points, with **no cliff in either direction**. It is not perched on an edge, and
  it is not the lever that governs noise.
- **The share gate does real work at scale** — at the shipped floor it removes a handful
  of pairs carrying tens of gigabytes, correctly excluding genuine download-heavy
  transfers and near-symmetric ones, and it sits safely above the observed
  near-symmetric cluster. Honest bound on that verdict: the shipped value versus the
  next value down is worth exactly one pair in 121 days. It is defensible and on the
  safer side of an observed cluster; it is **not** finely calibrated, and no surface
  should imply that it is.

**The asymmetric failure class was empty at every scale measured** — zero occurrences
in 16.1 M rows reaching the byte gate. Scope discipline: that is strong evidence of low
incidence on these corpora, not proof of impossibility, and it is not restated as
"cannot happen."

**The dominant finding is the aggregation grain, not the thresholds.** A rotating
service pool answers on many addresses, so one activity becomes many findings, and the
count grows with window length while the activity count does not. Across rolling
windows at the shipped default the median is 9 findings, the 90th percentile is 125,
and the worst window carries **138 findings representing two activities**. No threshold
fixes it: at eight times the shipped floor the archive still yields 144, because every
pool member of a very large backup clears any plausible floor.

**Two interim conclusions drawn from the one-week corpus were reversed by 121 days**,
and both are recorded because the failure mode is instructive. The share gate looked
*inert* on the week — it removed nothing — when in fact the week simply did not contain
the population the gate exists for. And the byte floor looked like it sat mid-plateau;
at scale there is no plateau, only smooth decay. The defensible claim is the weaker one.

## what is frozen as a result

- **The outbound byte floor and the originator-share gate** at their shipped values,
  ratified rather than retuned.
- **The destination-pool fold** — surfaced pairs sharing one source and one canonical
  destination network fold into a single rollup. The fold count and the network prefix
  widths are frozen calibration, not operator tuning. The prefix was chosen *against*
  measurement: a tighter prefix still left double-digit rows for one backup, and two
  wider choices gave the identical result, so the tighter of the two equals was taken
  for less over-merge risk on unseen data.
- **The fold changes presentation, never measurement.** Every gate, every byte figure,
  and the surfaced-pair population are untouched by it.
- **Default-hunt membership**, seated on this sweep — and coupled to the fold. Seated
  without it, every default run would inherit the 138-finding weeks the fold removes,
  so the two ship together.
- **Both gates stay absolute.** No baseline, no learned per-pair normal, no
  cross-run persistence.

## limitations

- **Spray across many destinations defeats the per-pair grain**, and low-and-slow
  transfer below the floor is invisible to this detector.
- **The floor is window-relative** — a transfer split across two runs may clear it in
  neither.
- **A benign recurring pair surfaces every run until it is allowlisted**, and for a
  rotating pool that means allowlisting the network, not the address: 343 of 344
  observed destinations appeared on under 5% of days, so per-address rules cannot
  converge.
- **An unrecorded responder value can make a download present as an upload** — the one
  false-positive path the share gate structurally cannot see. Measured incidence on
  these corpora: zero.
- **Every mass, share, and count figure covers the measured population only.** Outbound
  mass cannot bound the error on the share, so no surface presents a measured share as
  an all-records share.
- **The synthetic demo corpus cannot exercise this detector at all** — it carries about
  7 MB of total outbound mass and seeds no bulk transfer. Recorded as a product gap.
- **Every finding surfaced across every corpus in 121 days was benign** — a pooled
  backup service and an API endpoint. Zero true-malicious transfers were present to
  find, so this evidence bounds noise, not recall.

## the hazard this sweep documents

A bare numeric allowlist rule added for one detector **silently recalibrates another**.
Flat numeric rules are scope-blind. On the frozen week, one such rule added for a
different detector took exfil from 9 findings to 1 — removing 89% of findings and two
thirds of the surfaced mass. A post-suppression measurement would have reported
"exfil yields about one finding a week on a real network — nicely quiet," wrong by 9×
for reasons having nothing to do with exfil's thresholds. Measuring unsuppressed was
deliberate and is the only reason the headline numbers are right.

## reproducibility

The corpora carry real network data and are not published; the per-day instrument
outputs are identity-bearing and were not retained as public artifacts. Reproducibility
rests on the detector-owned eligibility path and the verified composition check used to
derive the aggregate results above.
