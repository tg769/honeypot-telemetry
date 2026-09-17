# Weekend findings

## Headline numbers
- Collection window: `<start>` to `<end>` (~`<N>` hours)
- Total events: `<N>`
- Distinct source IPs: `<N>`
- Botnet clusters identified (2+ IPs): `<N>`
- Successful logins: `<N>`
- Sessions with post-exploit commands or payload downloads: `<N>`

## What actually hit the box
<!-- Top attacker IPs, what they're flagged as (Tor exit, known abuse,
     other open services per InternetDB), and what they tried. -->

## Credential patterns
<!-- Top attempted username/password pairs, Mirai match percentage, and
     whether the dominant traffic looks like generic IoT-botnet scanning
     or something more targeted. -->

## Successful logins and what happened next
<!-- For each SUCCESSFUL_LOGIN finding: what credentials worked, what
     commands ran, what was downloaded (URL and hash only, never the
     actual file), and whether it matches a known malware family. -->

## Botnet clustering results
<!-- How many distinct campaigns versus how many raw IPs. This is the
     "how many attackers are actually behind this" number, and the
     original analysis piece in this project. -->

## What surprised me
<!-- The honest part. What didn't match expectations going in. -->

## What I'd do differently
<!-- Example: clustering on a single common credential (admin/admin)
     produces low-value giant clusters, a real limitation found while
     building this. Note the fix (minimum credential-set size, weighting
     rarer credentials higher in the similarity score). -->
