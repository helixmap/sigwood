# Prior work

Three of sigwood's nine detectors rest on a published technique. The rest do not, and this
page says which is which, because the difference matters more than the citations do.

What follows is a reading list, not a lineage claim. sigwood does not implement any of these
papers, does not reproduce their results, and inherits none of their measured performance. It
uses two of the algorithms through their maintained libraries and borrows the signal from a
third. Where a paper and sigwood agree on an idea but differ in what they do with it, the
entry says so. Measurements of sigwood itself are in [the evidence ledger](EVIDENCE.md), and
they are separate from everything here.

## The three named techniques

Every run's summary tags each detector with the method it used. A named published technique
prints in parentheses; a house method prints in brackets. Three detectors carry a name.

### beacon `(FFT)`

beacon bins connection arrivals onto a fixed grid, takes a real FFT of the counts, and scores
the result on spectral concentration, peak prominence, and timing jitter. The transform is the
Cooley-Tukey algorithm by way of NumPy.

- Cooley and Tukey, [*An Algorithm for the Machine Calculation of Complex Fourier
  Series*](https://doi.org/10.1090/S0025-5718-1965-0178586-1), Mathematics of Computation,
  1965.
- Hu et al., [*BAYWATCH: Robust Beaconing Detection to Identify Infected Hosts in Large-Scale
  Enterprise Networks*](https://doi.org/10.1109/DSN.2016.50), DSN 2016. The nearest published
  relative: it reads periodicity out of the frequency domain to find command-and-control
  check-ins, on 30 billion events from a 130,000-device network. It is a filtering pipeline
  that works toward a verdict. sigwood scores a flow and stops, and says a regular cadence
  looks automated rather than malicious, because [it has no second category of evidence to
  corroborate that with](ROADMAP.md#correlating-findings-across-detectors).

### dns `(fast-HDBSCAN)` or `(HDBSCAN)`

dns clusters queries on behavioral features, scores subdomain labels for how generated they
look, and raises severity only when an independent category of evidence agrees.

- Campello, Moulavi and Sander, [*Density-Based Clustering Based on Hierarchical Density
  Estimates*](https://doi.org/10.1007/978-3-642-37456-2_14), PAKDD 2013. The algorithm.
- McInnes, Healy and Astels, [*hdbscan: Hierarchical density based
  clustering*](https://doi.org/10.21105/joss.00205), JOSS 2017. The implementation sigwood
  installs, alongside its faster sibling `fast-hdbscan`. The run summary names whichever
  backend is present, so the label is a fact about your install.
- Yadav et al., [*Detecting Algorithmically Generated Malicious Domain
  Names*](https://doi.org/10.1145/1879141.1879148), IMC 2010. The origin of reading a domain's
  spelling for signs of generation. sigwood's scoring function is its own and is not one of
  theirs; it is a weighted composite, and despite the column heading it is not Shannon
  entropy. [The measurement](evidence/dns.md) found no additive lexical rule that improved
  catch at zero added cost on the estate tested, which is why spelling alone never earns the
  top severity here.
- Antonakakis et al., [*From Throw-Away Traffic to Bots: Detecting the Rise of DGA-Based
  Malware*](https://www.usenix.org/conference/usenixsecurity12/technical-sessions/presentation/antonakakis),
  USENIX Security 2012. Generated names mostly fail to resolve, and that failure is a signal
  in its own right. sigwood uses it exactly that way: a mostly-NXDOMAIN result is one of the
  two corroborators that can lift a finding to HIGH, and it is why a Pi-hole-only feed cannot
  reach that tier.

### syslog `(drain3)`

syslog groups log lines into templates before it asks which templates are rare.

- He, Zhu, Zheng and Lyu, [*Drain: An Online Log Parsing Approach with Fixed Depth
  Tree*](https://doi.org/10.1109/ICWS.2017.13), ICWS 2017. The parsing method.
- [`drain3`](https://github.com/logpai/Drain3), the maintained implementation sigwood
  installs. sigwood adds two masks of its own for hex identifiers and register dumps, chosen
  by [measurement on a real estate](evidence/syslog.md) rather than taken from the paper.

## The six with nothing to cite

`scan`, `exfil`, `aws`, `auth`, `ssl` and `dnsblock` print a house method in brackets:
`[pattern]`, `[heuristics]`, `[statistical]`. There is no paper behind any of them. They are
arithmetic and operational judgement: a byte total against a floor, a count of destination
ports in a window, a z-score across a population, a first-seen date. The bracket is there so
the report doesn't dress one of these as an algorithm.

That is not a statement about how well they work. Six of the nine detectors have
[published measurement records](EVIDENCE.md); the two with no calibration campaign at all are
`scan` and `aws`, and the ledger says so on its own rows.

## Specifications the parsers implement

Not research, but the documents a reader would need to check the parsing against.

- [Zeek](https://docs.zeek.org/) log formats, for `conn`, `dns`, `ssl`, `x509`, `weird` and
  Zeek's own `syslog.log`.
- [RFC 3164](https://www.rfc-editor.org/rfc/rfc3164) and
  [RFC 5424](https://www.rfc-editor.org/rfc/rfc5424) for syslog. RFC 3164 carries no year,
  which is why sigwood warns when a file's timestamps parse far newer than the file itself.
- The [Public Suffix List](https://publicsuffix.org/), through `tldextract`, for deciding
  where a registrable domain ends. A bundled snapshot keeps the scan offline and repeatable.
- [AWS CloudTrail](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference.html)
  event records.
- [RFC 5737](https://www.rfc-editor.org/rfc/rfc5737) and
  [RFC 3849](https://www.rfc-editor.org/rfc/rfc3849) documentation address space, which every
  example, fixture and test in this repository uses instead of a real address.

sigwood's findings are also mapped onto the [MITRE ATT&CK](https://attack.mitre.org/) matrix;
[the roadmap](ROADMAP.md) carries that table and the pinned framework version.
