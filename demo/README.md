# sigwood demo corpus

A tiny synthetic log corpus in which five detector views independently surface facets
of one compromised host - across Pi-hole, beacon, dns, exfil, and syslog. The analyst,
not sigwood, joins those facets into a single hunt. It drives the real
`loader → allowlist → detector → renderer` path - nothing is faked or
pre-baked. This is the corpus behind the animated demo in the top-level README.

The story: an internal host `192.168.1.37` is compromised and shows up in

- **Pi-hole** - a readable dnsmasq query log with one dominant client, blocked
  placeholder domains, and a modest DGA burst,
- **beacon** - periodic command-and-control call-outs to two external IPs,
- **dns** - a burst of high-entropy DGA-style lookups under one throwaway domain,
- **syslog** - a root SSH login from the C2 address, a UID-0 account added, and a
  root cron entry planted,
- **exfil** - a bulk transfer out to a drop host late that evening, hours after the
  intrusion, closing the arc from break-in to data leaving.

Every address is documentation space (RFC 5737 `198.51.100.x` / `203.0.113.x` /
`192.0.2.x`) or private space (RFC 1918 `192.168.x.x`); the readable domains come
from reserved space (`example.{com,net,org}`, `.invalid`, `.test`, `.arpa`, `.local`);
the malware apex is a random high-entropy label under `.xyz`. No real network data.

## Regenerate the corpus

The corpus is generated on demand and is not committed (see `.gitignore`). From
the repository root:

```
python3 demo/gen_corpus.py
```

This writes `demo/corpus/zeek/{conn.log,dns.log}`,
`demo/corpus/pihole/pihole.log`, and `demo/corpus/syslog/messages`.
It makes no network calls and is byte-for-byte deterministic for a given seed,
anchor, and timezone (defaults: seed `3759`, window anchored at
`2026-06-01T00:00:00` UTC), so it is safe to run offline or in CI. The syslog and
dnsmasq stamps render in the generating box's local time - the timezone those
daemons write in - so a corpus generated and hunted on the same box in the same year
keeps the flat-log timelines correlated with the conn/dns epochs. RFC 3164 carries no
year, so hunting after a year boundary re-dates those flat-log stamps while the
epoch-based conn and dns rows stay put; the loader's re-dating tripwire discloses that
shift when it happens. Pass a different `--seed` or `--anchor` to vary it.

## Run the hunt

From the repository root, after generating the corpus:

```
sigwood digest demo/corpus/pihole/pihole.log
sigwood dns demo/corpus/pihole --all
sigwood hunt --config=demo/sigwood.toml
```

The first orients you with a one-card summary of the Pi-hole log; the second runs
only the DNS detector on that slice and should surface the modest DGA burst. The
third runs the detector list configured for the demo. Add `-vv` to the hunt to see
the scoring evidence behind each finding (FFT beacon scores, DGA label scores,
drain3 templates).

> The demo config sets `root = ""` so the log paths resolve relative to the
> repository root. If you have `SIGWOOD_ROOT` set in your environment it
> overrides that, so run the commands with it unset - e.g.
> `env -u SIGWOOD_ROOT sigwood hunt --config=demo/sigwood.toml`.

## What you should see

At the default seed, these commands show:

- **Pi-hole digest:** one card for `pihole.log` with a dominant client,
  a top repeated domain, a long-query tail from the DGA source, qtype mix, and a
  small but visible block rate.
- **Pi-hole dns - 1 finding (MEDIUM):** one entropy-gated grouped finding covering
  16 high-entropy subdomains under the same random `.xyz` apex used by the Zeek DNS
  slice. This demo keeps the Pi-hole burst below HDBSCAN's `min_cluster_size` so it
  remains visible as noise. It lands MEDIUM rather than HIGH by design: a Pi-hole
  feed carries no resolution outcome, so the corroborating evidence that would raise
  it is not available on this source. The hunt below reaches HIGH on the Zeek side of
  the same burst, where that corroboration is available - though the two feeds carry
  different generated labels under the shared apex, so the two findings cover the same
  campaign rather than the same names.
- **beacon - 2 findings (both MEDIUM):**
  `192.168.1.37 → 198.51.100.20:443/tcp` at a 3-minute cadence, and
  `192.168.1.37 → 203.0.113.61:8443/tcp` at 10 minutes. Clean periodic beacons
  land in the MEDIUM band; the score is a transparent FFT composite you can read
  under `-vv`.
- **dns - 3 findings (1 HIGH + 1 MEDIUM + 1 INFO):** the HIGH is the DGA burst -
  high-entropy subdomains sharing a single random `.xyz` apex, all from
  `192.168.1.37`, most returning NXDOMAIN, max label score ~1.96. The MEDIUM covers
  six names under a private `.lan` namespace, and the INFO is a quieter family of
  eight subdomains under a second throwaway apex that sits below the surfacing gate
  on lexical score alone and is surfaced on its failure pattern instead. Only the
  first is the planted story; the other two are there so the demo shows the
  gradient rather than a single verdict.
- **exfil - 1 finding (MEDIUM):** `192.168.1.37 → 203.0.113.77`, about 1.9 GB out
  across 12 connections in 55 minutes, with 98% of the pair's bytes flowing outbound.
  It reports the fact and stops there - a large transfer left for that endpoint - and
  makes no claim that it was theft. It renders as one finding for the pair rather than
  one per connection, and because there is a single destination it is a plain pair
  finding, not the grouped form sigwood uses for a rotating cloud destination pool.
- **syslog - 10 findings (4 MEDIUM + 5 LOW + 1 INFO):** the intrusion on `webhost`
  surfaces as four MEDIUM privileged rows - a root SSH login from the C2 address, a
  `sudo … USER=root` shell, a `useradd … UID=0` account, and, about an hour later, an
  sshd listener on port 8443. Rare lines sharing one host and program fold into a
  single per-program review unit only from four lines up, so the two `sshd` lines stay
  separate rather than folding. Five LOW rare events sit around them - a root
  `crontab REPLACE` on `webhost`, and `db01` kernel, smartd, and named one-offs - and
  one INFO burst collapses a 13-line `gateway` reboot. Burst rows carry a first-seen
  timestamp; `-v` shows up to three sampled lines, and HTML reports offer a closed
  full-sample expansion. Rows stay chronological within each section, so the analyst
  still picks the `webhost` cluster out of the surrounding noise.

The banner also shows a non-zero `allowlist:` line: a minority of the DNS queries
are reverse-PTR / mDNS / DNS-SD lookups that the shipped allowlist suppresses
before analysis, so you can see suppression working too.

## The README images (how they are built)

The two images at the top of the project README are build products, not hand made assets.
`docs/img/report.png` is a screenshot of a real HTML report and `docs/img/demo.svg` is a
recorded terminal session, and both are regenerated by one tool from the deterministic corpus
described above:

```
python tools/refresh_assets.py
```

That refreshes both images. It needs Chrome for the screenshot and `asciinema` plus `termsvg`
for the recording; a missing tool skips only the image that needs it, says which one and why,
and leaves the other refreshed.

There is also a cheap freshness check that needs neither Chrome nor termsvg:

```
python tools/refresh_assets.py --check
```

It regenerates the report's finding rows and the terminal text from the corpus, compares their
semantic hashes against `docs/img/assets.stamp.json`, and exits non-zero with the refresh
command when either drifts. The release runbook runs it before a cut.

What it does and does not prove is worth being exact about. It detects that sigwood's OUTPUT
changed since the images were built, which is the usual way they go stale. It does not read the
PNG or SVG bytes, and the report oracle covers the finding rows rather than the report header,
so it is not a substitute for looking at the regenerated images.

## The third image, and why it is not checked

`docs/img/graph.gif` further down the project README is also a build product, but it is
generated differently and deliberately sits outside the freshness check above.

The other two render from the seeded demo corpus, which is what lets a semantic stamp mean
anything: the same inputs produce the same output, so a changed hash means the rendering changed.
The graph animation is captured from a real capture that has been address-scrubbed first, and a
real capture is not in this repository, not reproducible, and not the same twice. There is
nothing stable to hash.

So it is refreshed explicitly, with an operator-supplied source:

```
python tools/scrub_conn.py <raw-conn-log.gz> <private-output.log.gz>
python tools/refresh_assets.py --only=graph --from=<private-output.log.gz>
```

`tools/scrub_conn.py` maps addresses consistently while preserving structure, and states in its
own receipt what it does not mask. Neither the raw capture nor the scrubbed output belongs in
this repository, and the tool refuses to write one here.

**The consequence, stated rather than left to be discovered: `graph.gif` can go stale without
`--check` noticing.** It is the one shipped image whose freshness nobody verifies for you.

Three deliberate choices worth knowing. The terminal theme is applied at export time rather
than baked into the recording, so it can change without re-shooting. SVG rather than GIF is
deliberate for the terminal demo: it is crisp vector, small, and both renders and animates on
the GitHub README and the PyPI project page. And the recording's terminal is sized to the hunt
it captures, so the whole report is readable in the held final frame instead of scrolling away.
