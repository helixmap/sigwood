# Evidence and its limits

sigwood has nine detectors, but it does not have nine equally mature bodies of
evidence. This ledger says what has actually been measured, what each result can
support, and what is still owed. An empty row would hide the most useful fact, so every
detector has an explicit disposition.

Five detailed conclusions are published today. They report aggregate measurements and
the shipped decisions those measurements support; they are not claims of universal
precision, recall, or transfer across environments. If you can help test that transfer,
use the [field validation kit](FIELDKIT.md).

| Detector | Disposition | What was measured, and on what population | What it supports, and what it does not | What is owed |
|---|---|---|---|---|
| `auth` | published conclusion | One live estate plus external corpora that proved not to contain authentication logs; several observer-reconciliation rules were also tested. | [The measurement stopped before producing calibrated thresholds](evidence/auth.md). It supports conservative structural choices, not precision, recall, or an absolute volume calibration. | Authentication data from an independent environment before any threshold calibration. |
| `aws` | no calibration campaign found | No calibration population was found. | No efficacy or transfer claim is made. | A preregistered study on representative CloudTrail populations. |
| `beacon` | published conclusion | Seeded timing trains, the shipped 180-second demo flow, and output volume from one home network. | [The scorer and its reproducible anchor are measured](evidence/beacon.md). Precision, recall, labeled-corpus performance, and second-environment transfer are not. | Held-out public-corpus validation, a same-corpus RITA comparison, and a simple timing baseline. |
| `dns` | published conclusion | About 2.18 million real queries from one estate, a frozen day from the same source, and generated labels across six alphabet classes and eleven lengths. | [No tested additive lexical rule improved catch at zero added benign cost](evidence/dns.md). The result bounds that rule family on this estate; it is not a universal DGA recall rate. | Held-out public-corpus validation and a simple entropy baseline. |
| `dnsblock` | measured; conclusion not yet published | A one-estate threshold sweep plus an 11-day held-out transfer and burden check from that estate. | The held-out budgets passed and the shipped grid moved on that interval. This is real measurement, but it is not yet a reader-facing calibration record and is not cross-estate validation. | A record-shaped public conclusion, then validation on an independent environment. |
| `exfil` | published conclusion | 121 days of one estate's connection logs: about 56.5 million connections and 3,835 GiB of measured outbound mass, plus shorter windows and the synthetic demo. | [Both shipped gates ratified and destination-pool aggregation was the dominant noise issue](evidence/exfil.md). The corpus contained no malicious transfers, so the result bounds noise, not recall. | Held-out malicious-transfer coverage and independent-environment validation. |
| `scan` | no calibration campaign found | No calibration population was found. | No efficacy or transfer claim is made. | Held-out public-corpus validation with labeled scanning activity. |
| `ssl` | measured; conclusion not yet published | Both detection legs and their eligibility funnel were calibrated against one estate. | The evidence supports an opt-in, one-estate behavioral detector. It does not support default-hunt membership or transfer to a second estate. | Cross-estate validation and a record-shaped public conclusion. |
| `syslog` | published conclusion | A roughly 2.26-million-row capture, a roughly 14.6-million-row stress corpus, and one held-back fleet host, all from one estate. | [Masks and collapse thresholds passed measured before-and-after gates](evidence/syslog.md). The result covers that estate's log grammars, not every distribution or environment. | Independent-environment validation through the field kit. |

## What comes next

The next evidence work is held-out public-corpus validation, a RITA comparison on the
same corpus, and simple-baseline comparisons. Results should be published whether they
win, lose, or split. Field reports from other environments are equally important:
[the field validation kit](FIELDKIT.md) collects aggregate behavior without copying log
identifiers into its report.
