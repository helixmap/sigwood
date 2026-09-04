# auth calibration record

auth reads authentication decisions out of the system-log lane. This record is
different from its siblings: it documents a measurement study that was **stopped
before it produced calibrated thresholds**, why stopping was the right call, and what
the detector ships as instead.

## what was measured

The study asked whether authentication-failure volume could be calibrated into
reliable thresholds, and how to reconcile the several independent observers that record
the same authentication event: an SSH daemon, the pluggable-authentication stack, and
the audit subsystem, each with its own dialect.

## data

One live estate, plus external corpora. The external corpora turned out not to carry
authentication logs at all: of the public capture sets acquired, the one that loads
natively supplies system logs without an authentication stream, and the honeypot
corpora sit at the unrecognized-format floor and serve as a reference for that, not as
auth data.

That is the whole finding about the data, and it is what ended the study.

## the outcome: a stop, recorded as a result

**The measurement program was stopped.** The rigor being applied was
sized for roughly ten times the data variety actually available: one live estate is not
a population you can calibrate absolute thresholds against, and no second environment
existed to transfer them to. Continuing would have produced numbers that looked
calibrated and were not.

Cancelled with it: a cross-producer overlap measurement, a live-fire calibration on a
second host, an oracle repair, and several further arbitration variants. The defects
the study had found were then cleared **by simplification rather than by cleverer
arbitration**, which is the part worth keeping.

## what shipped instead, and why each choice is conservative

- **Counting is the union of the observer streams. No observer may delete another's
  decisions.** Two winner-picking rules were tried and both failed in opposite
  directions: dropping by observer rank is outcome-blind (one benign grant deleted
  every audit denial on a host, and a brute-force attempt vanished), and picking by
  cardinality is coverage-blind (the smaller observer's exclusive decisions vanish).
  Those two failure directions are why no third winner rule is attempted.
- **Reconciliation survives only inside the audit observer**, where exact event
  identifiers make duplicate suppression safe. The identifier is scoped per host,
  because two machines reusing one identifier must not erase each other.
- **Magnitudes are decision-record counts, never inferred human attempts**, and the
  wording says so.
- **Severity caps at MEDIUM across the whole detector**, with a single-signal basis
  always. There is no HIGH rule to reach; the tier is held for corroboration between
  detectors, which is measured work this detector cannot do alone.
- **One lens never promotes or demotes another.** That invariant is what structurally
  closes an attacker-choosable severity subtraction, rather than repairing the timing
  mechanism it rode on.
- **Co-reported lenses disclose their shared identity rather than deduplicating.** Three
  lenses asking distinct questions all still print, each carrying an identity-free count
  of its siblings in that run.
- **Reader identities degrade deliberately.** A title uses an account only where safety
  rules make that sound; otherwise it falls back to source, service, or neutral wording.
- **`[heuristics]` chrome.** The run summary renders the method in brackets rather than
  as a named technique, because plain counting is what it is.
- **Opt-in, not in the default hunt.** Run `auth` directly or select it by name.

## what is frozen as a result

Nothing was frozen as a *calibrated* constant, and that is the point. The numeric
floors are unchanged from their pre-study values and were deliberately **not**
retuned for union-scale counting. Retuning them against one estate is precisely the
move the ruling rejected.

What is frozen is structural: the union-counting rule, the per-host scoping of the
audit identifier, the severity ceiling, and the requirement that every observer dialect
remain reachable through the stream builder. That last one is pinned by test, because
a dialect silently dropping out of the union is invisible in output.

## limitations

All named, none hidden:

- **A host observed by two sources counts each decision once per observer**, up to
  roughly double. A volume floor can therefore clear at half the true attempt count on
  such a host. Disclosed in the run's own notes on every run, not just here.
- **The audit-dialect reconciliation may undercount a genuine partial union.**
- **A conservative miss on landing episodes**, never a manufactured one: where a tie or
  a declination blocks the evidence, the standalone finding is absent entirely and the
  failures surface only if a counting floor is reached.
- **Allowlisting in this lane suppresses whole hosts**, not individual addresses
  extracted from message text. The run notes disclose that alongside the source count.
- **No calibrated thresholds and no measured precision.** The detector is built to be
  built on.

## reproducibility

No sweep was sealed because the measurement stopped before a confirmatory run. The
union-counting rule, per-host audit-identifier scope, severity ceiling, and observer
reachability are pinned by product tests. This record therefore publishes structural
decisions and limitations, not calibrated thresholds.
