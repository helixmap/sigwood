# sigwood demo corpus

A tiny synthetic log corpus that shows sigwood finding one compromised host
four different ways - across Pi-hole, beacon, dns, and syslog - in a single hunt. It drives the real
`loader → allowlist → detector → renderer` path - nothing is faked or
pre-baked. This is the corpus behind the animated demo in the top-level README.

The story: an internal host `192.168.1.37` is compromised and shows up in

- **Pi-hole** - a readable dnsmasq query log with one dominant client, blocked
  placeholder domains, and a modest DGA burst,
- **beacon** - periodic command-and-control call-outs to two external IPs,
- **dns** - a burst of high-entropy DGA-style lookups under one throwaway domain,
- **syslog** - a root SSH login from the C2 address, a UID-0 account added, and a
  root cron entry planted.

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
daemons write in - so a corpus generated and hunted on the same box keeps the
flat-log timelines correlated with the conn/dns epochs. Pass a different `--seed`
or `--anchor` to vary it.

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
- **Pi-hole dns - 1 finding (HIGH):** one entropy-gated grouped finding for a
  modest set of high-entropy subdomains under the same random `.xyz` apex used
  by the Zeek DNS slice. This demo keeps the Pi-hole burst below HDBSCAN's
  `min_cluster_size` so it remains visible as noise.
- **beacon - 2 findings (both MEDIUM):**
  `192.168.1.37 → 198.51.100.20:443/tcp` at a 3-minute cadence, and
  `192.168.1.37 → 203.0.113.61:8443/tcp` at 10 minutes. Clean periodic beacons
  land in the MEDIUM band; the score is a transparent FFT composite you can read
  under `-vv`.
- **dns - 1 finding (HIGH):** one grouped finding for ~13 high-entropy subdomains
  sharing a single random `.xyz` apex, all from `192.168.1.37`, most returning
  NXDOMAIN. Max label score ~1.96.
- **syslog - 8 findings (7 MEDIUM + 1 INFO):** the intrusion on `webhost` across two
  tight clusters - initial access + escalation (root SSH login from the C2 IP, a
  `sudo … USER=root` shell, a `useradd … UID=0` account) then, ~an hour later,
  persistence (a root `crontab REPLACE` and an sshd listener on port 8443). Rare
  lines sharing one host and program fold into a single per-program review unit,
  so the two `sshd` lines render as `webhost · sshd · 2 rare lines · 1h` (the
  sampled lines sit one verbosity level down); `db01`'s two kernel one-offs fold
  the same way, alongside its smartd SMART pre-fail and `named` lookup failure,
  and one INFO burst collapses a `gateway` reboot. The rare events are shown
  chronologically, so the analyst still picks the `webhost` cluster out of the
  surrounding noise.

The banner also shows a non-zero `allowlist:` line: a minority of the DNS queries
are reverse-PTR / mDNS / DNS-SD lookups that the shipped allowlist suppresses
before analysis, so you can see suppression working too.

## The README animation (how it is built)

The animated terminal demo at the top of the project README (`docs/img/demo.svg`) is
a build product, not a hand-made asset: it is rendered from a committed recording so
anyone can reproduce or re-shoot it. Two scripts and one cast file, all in this
directory:

- **`demo.cast`** - the recording itself, an
  [asciicast v2](https://docs.asciinema.org/manual/asciicast/v2/) file: a
  `sigwood digest` + `sigwood hunt` session against a sandbox built from this corpus.
  It carries only synthetic data (RFC 5737 / RFC 1918 addresses, reserved domains, and
  the random `.xyz` DGA stand-in) - the same corpus described above.
- **`render.sh`** - turns the cast into the shipped SVG, deterministically. `termsvg`
  exports the cast to an animated SVG, then a post-process applies the sigwood terminal
  theme (black background, lime text, orange prompt, cyan method chrome), fixes the
  font, and makes the animation play ONCE and hold the final frame so the report stays
  readable. Re-running it is byte-identical.
- **`record.sh`** - builds a throwaway sandbox HOME (this corpus + a config + a prompt)
  and prints the record / convert / trim / render steps for shooting a fresh cast. Your
  real `$HOME` is never touched.

Regenerate the SVG from the committed cast (needs `termsvg` - `brew install termsvg`):

```
bash demo/render.sh
```

Re-record from scratch (needs `asciinema` as well):

```
bash demo/record.sh        # then follow the printed steps
```

Two deliberate choices worth knowing. The theme is applied at render time rather than
baked into the recording, so it can change without re-shooting. And SVG, not GIF, is
deliberate: it is crisp vector, small, and both renders and animates on the GitHub
README and the PyPI project page. termsvg's own `-b`/`-t` theme flags are avoided on
purpose - they collapse the terminal colour palette to a single colour, which would
hide the coloured prompt and method chrome, so `render.sh` recolours the palette
classes in the SVG directly instead.
