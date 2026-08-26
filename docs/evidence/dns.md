# dns — calibration record

dns clusters DNS queries on behavioral features and scores each name's labels with a
weighted lexical heuristic. This record covers the label score's operating point, the
dense-cluster scan gates, and the promotion channel — and it records a measured
refutation as prominently as it records a setting.

## what was measured

Whether the lexical label score can catch more of the shapes it is designed for — and
any of the letter-only shape it currently cannot catch at all — **at zero additional
benign cost**, with the surfacing gate held where it is.

The measurement replaced an earlier probe whose alphabet and random seed were never
recorded and whose script was never kept. That probe's numbers were circulating; they
could not be reproduced. Everything in this record was re-measured with the method
written down first and the harness content-hashed.

## data

- **Benign:** a frozen one-week real DNS capture (≈2.18 M queries, ≈11.2 K distinct
  names) plus a frozen single day (≈286 K queries, ≈5.7 K distinct). Scored **raw** —
  before allowlist suppression — which is stricter than what an operator sees and
  immune to "the allowlist was doing the work."
- **Generated:** 1,000 synthetic labels per cell across eleven lengths from 6 to 63
  characters, in six alphabet classes (alphanumeric, letters-only, consonant-only,
  low-vowel, hex, and concatenated dictionary words), mounted under a reserved
  documentation domain and scored through the same live code path.
- Aggregate-only throughout. No benign name appears in any record; a name that needed
  characterizing is described numerically — length, vowel share, label count.

All real captures in this record come from one estate. They measure that environment's
benign cost; they do not establish transfer to another environment.

## the gates applied

Fixed before any outcome number existed, and not moved afterward:

- **Zero new benign names may cross the surfacing bar** under a candidate rule, on both
  captures, raw. This was the binding one.
- **At least 80% catch** on the target classes at every length the rule fires at.
- **Admissibility:** additive-only (never lowers a score), keyed on length and vowel
  share or consonant-run length and nothing else, gate position unchanged, bonus
  capped. A minimum label length was fixed by an existing pinned score value, so no
  rule could fire below it.
- The harness had to reproduce the live per-query scoring path exactly, with zero
  tolerance, over every benign and generated name, before any rule was evaluated. A
  drifting mirror would have invalidated the run.

## outcome

**No headroom. 0 of 76 candidate rules passed.** The score is at its ceiling, and the
sweep shows why: the failure is a pincer, and each jaw alone is fatal.

- The strictest possible length-and-vowel cell still crossed 57 distinct benign names
  on the week. Real traffic is full of long, near-vowel-free, token-shaped
  infrastructure names.
- The letter-only class's score **plateaus with length** and never approaches the bar.
  At the realistic form even the maximum admissible bonus catches under half.
- One genuinely quiet key exists — a long consonant-run requirement produced zero
  benign crossings at every bonus — and it still could not lift the class.

The structural finding underneath: **there is no separation valley for any gate to sit
in.** The benign distribution decays smoothly through the whole gate region with no
elbow, and roughly 19% of raw distinct benign names already sit at or above the bar.
The gate is not mis-placed; there is no better placement. What keeps the operator's
report small is not the score — it is the allowlist, the clustering, the grouping, and
the severity ladder absorbing the mass.

Two figures were corrected by this measurement. The earlier "6–16%" band **reproduced**
almost exactly at its lengths, so the band was robust despite the lost method — but the
class it described was mislabeled, and the truly tuned-toward alphabet catches roughly
double. And a published point estimate that a 32-character hex label "scores about
1.78, just below the bar" was wrong: the measured mean is *above* the bar and the
distribution straddles it. That entry's conclusion survives for a better reason —
around half the members clearing is well short of the 80% member fraction the dense
scan requires — and the public wording was corrected rather than quietly kept.

## what is frozen as a result

- **The surfacing bar and the dense-scan member bar**, pinned equal to each other. Their
  position is out of scope for retuning: moving one couples the candidate gate, the
  dense-scan member fraction, and config compatibility.
- **The dense-cluster scan's three gates** — member fraction, cluster-size floor, and
  concentration under one registrable domain — set conservatively against real
  multi-week captures.
- **The below-gate promotion fraction**, the measured minimum yielding zero benign
  promotions on the reference week. The *count* side of that gate is an inverted lever
  and is never raised: benign parents carry the most distinct children, a real
  low-throughput family carries few.
- **The corroborator constants** for the resolution-outcome leg, and the distinct-child
  floor that decides whether a dense origin has earned tunnel language at all.
- **Severity is behavioral, never a score band.** No score maps to a tier. The top tier
  requires the lexical gate plus a corroborator from a different evidence category.
- **The refutation itself.** The length-and-vowel lift is recorded as measured and
  refuted; it is not re-litigated without new data.

## limitations

- **Letter-only high-entropy labels cannot reach the bar by construction.** The score's
  largest positive term is digit density, so a random all-alphabetic label forfeits
  enough that the all-unique-letter ceiling sits below the gate at every length. This
  class is covered only behaviorally — a family with enough distinct children and a
  high failed-resolution fraction promotes with no lexical requirement — which misses
  singletons, small families, and live-resolving families.
- **Dictionary-word DGAs score zero at every length.** Structurally excluded from the
  lexical lane; measured, not assumed.
- **The clustering vocabulary is batch-relative by design.** What counts as a common
  suffix is derived from the data in front of it, not from a shipped list.
- **The top tier is unreachable on a Pi-hole-only feed** — no resolution outcome is
  recorded there and the dense scan does not run on that path. Honest fidelity tiering,
  not a gap.
- **A tunnel spread thin across many registrable domains, or below the conservative
  volume floor, is unscanned.**

## reproducibility

The corpora carry real network data and are not published. The measurement harness was
content-hashed and its raw output preserved. The measured catch rates by alphabet class
and length, including the letter-only result, are also reflected in the public FAQ and
known-issues pages.
