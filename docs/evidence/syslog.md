# syslog calibration record

syslog templates log lines, scores templates for rarity, and folds the rare set into
review units. Its calibration is a sequence of small measured cycles rather than one
sweep: each shipped mask and each collapse threshold has its own before-and-after
measurement on real corpora.

## what was measured

Three separate questions, each with its own cycle:

1. **Do the shipped template masks earn their place?** Measured as a finding-multiset
   A/B, running the real detector end to end with one arm per candidate and an identical
   contract per corpus, not as a template-count delta, which understates the effect
   by construction (rows folded into a burst leave the pool before a template-level
   metric counts them).
2. **Where does a rollup start paying for itself?** The floor at which folding a cluster
   of rare lines into one row costs less ink than printing the lines.
3. **When is a recognized admin session not a session?** Measured as the distribution of
   event spans on real fleet corpora.

## data

- A frozen one-week real capture (≈2.26 M log rows, 22 days of archive span).
- A month of real exports (≈14.6 M rows, 54 days of span), the stress corpus and the
  one where the mask problem was visible at all.
- A held-back fleet host, used once as a transfer check rather than a tuning input.
- Aggregate-only; hosts pseudonymized in the records.

All three real populations come from one estate. The held-back host checks transfer
within that estate; it is not an independent-environment validation.

## the gates applied

Written before each implementation cycle and checked afterward against the shipped
tree, by hand:

- **Reproduce the candidate arm exactly.** The shipped detector had to hit the
  measured numbers for findings, bursts, templates, and per-tier counts.
- **No manufactured and no silently lost findings.** Every delta had to account to the
  class the change targets, with the more-severe count held constant.
- **A recall floor.** A seeded once-ever line of the masked shape must still surface.
  Masking may never quietly empty the detector.
- **Conservation.** For the session-bounding change, every finding previously claimed
  by a unit that no longer forms must reappear in its own underlying shape, with
  represented row counts conserved exactly.
- **Boundary exactness.** A span equal to the ceiling forms; one second over declines.
- **Drift pins.** The shipped mask and the diagnostic instrument's copy of it must stay
  byte-identical, so the measured instrument *is* the shipped mask.

## outcome

**Two masks ship; the six other candidate classes measured zero and did not.**

- The long-hex mask earned a measurable reduction in one-off rare lines.
- The hex-pair mask targets debug dumps that are space-separated pairs, a shape the
  first mask structurally cannot match. On the month corpus it took findings from 100
  to 87 and bursts from 25 to 14, eliminating a per-login dump burst, while the count
  of more-severe findings stayed constant and the week's finding multiset was
  byte-identical across every arm.
- The pair-run floor was set at four. Floors of three and four were **identical** on
  both corpora at finding and template level, so four was taken for the strictly larger
  safety margin against short benign prose at zero measured cost. A floor of eight was
  marginally worse.
- A letter-required clause was **rejected on measurement**: the letter-free dump lines
  come from the same programs, so requiring a letter would have leaked around 10% of
  the dumps back as residual rare lines.

**Admin sessions: the population is bimodal with an empty band between the modes.**
Genuine interactive sessions measured at most 1.6 hours; automation chains started at
22.6 hours and ran as long as 14 days. No event on either corpus fell in between, so
any ceiling inside a wide range yields identical separation. The report never again
claims a multi-day session.

Two alternative mechanisms were **measured and refuted**: a cadence-regularity gate
(the ranges overlap), and a density gate (genuine sessions are *denser* than automation
chains, so density points the wrong way). Splitting an over-long chain instead of
declining it was rejected as strictly worse: it mints dozens of meaningless units
instead of one.

The bounding change **releases content, and that is the honest cost**: the rows an
over-wide unit had absorbed reappear as their own findings. Some re-compress naturally.
A small increase in the more-severe count is an honesty improvement, not manufacture.
One capsule had been hiding privileged lines at their own severity.

## what is frozen as a result

- **Both mask patterns**, as literal strings with no configuration surface. These are
  measured calibration, not operator tuning.
- **The rollup breakeven at four rows**, shared by the burst fold and the family fold.
- **The burst and boot clustering windows**, and the deliberately narrower association
  tolerance used when labeling a burst as contemporaneous with a reboot.
- **The admin-session ceiling at eight hours.** It sits several times above the longest
  observed genuine session and well below the structural floor of the automation-chain
  class, and it carries the semantic story the refuted gates lack: a session longer than
  a working day is not one session.
- **Recognition-unit minimums**, and the boot-window suppression offsets that keep
  ordinary shutdown-and-boot chatter from forming a false update run.
- **The privileged-program roster** as a shipped list an operator replaces rather than
  merges.

## limitations

- **A genuinely once-ever debug dump stays rare and its excerpt still shows raw hex.**
  Correct: a once-ever kernel fault *should* surface, and the excerpt filter's scope
  is a settled boundary.
- **A genuine continuous session longer than the ceiling loses its label.** Its findings
  stay. Label lost, data kept.
- **Runs of two or three hex pairs never mask** (the floor). Measured cost at finding
  level: zero.
- **Rotation or midnight can split or decline a recognized unit**, and a foreign
  distribution whose log grammar differs degrades to scattered individual findings
  rather than units. Both degrade toward the pre-recognition behavior, never worse.
- **Rows whose host and program are both unidentifiable can merge across origins.**
- **Update runs are unmeasured for the chain pathology** that bounded admin sessions,
  because none was observed. Revisit only with a measured case.

## reproducibility

The corpora carry real log content and are not published. Reproducibility rests on the
drift-pinned mask patterns, focused product tests, and the recorded aggregate A/B tables
reported above.
