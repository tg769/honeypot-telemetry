# Weekend findings

> Fill this in from `data/reports/report-*.md` (the latest auto-generated
> snapshot) plus your own read of the Splunk dashboard and any sessions you
> dug into by hand via `docs/runbooks/investigate-finding.md`. Write it like
> a lab notebook -- what you saw, what surprised you, what you'd do
> differently -- not like a resume bullet.

## Headline numbers
- Collection window: `<start>` -> `<end>` (~`<N>` hours)
- Total events: `<N>`
- Distinct source IPs: `<N>`
- Botnet clusters identified (2+ IPs): `<N>`
- Successful logins: `<N>`
- Sessions with post-exploit commands / payload downloads: `<N>`

## What actually hit the box
<!-- Top attacker IPs, what they're flagged as (Tor exit? known abuse?
     other open services per InternetDB), and what they tried. -->

## Credential patterns
<!-- Top attempted username/password pairs, Mirai match percentage, and
     whether the dominant traffic looks like generic IoT-botnet scanning
     vs. something more targeted. -->

## Successful logins and what happened next
<!-- For each SUCCESSFUL_LOGIN finding: what credentials worked, what
     commands ran, what was downloaded (URL + hash, never the file itself),
     and whether the observed behavior matches a known malware family. -->

## Botnet clustering results
<!-- How many distinct campaigns vs. how many raw IPs -- this is the
     "how many attackers are actually behind this" number, and the
     genuinely original analysis in this project. -->

## What surprised me
<!-- The honest, non-generic part. What didn't match expectations going in. -->

## What I'd do differently
<!-- E.g. clustering on a single common credential (admin/admin) produces
     low-value giant clusters -- a real limitation observed while building
     this; note how you'd fix it (minimum credential-set size, weighting
     rarer credentials higher in the similarity score). -->
