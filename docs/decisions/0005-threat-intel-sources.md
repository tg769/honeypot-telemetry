# ADR-0005: Shodan InternetDB + AbuseIPDB, GreyNoise evaluated and dropped

## Context
Enrichment needs some source of reputation/context data per IP, and it has
to be genuinely free since this is a personal project, not something with
a company card behind it.

## Decision
Ended up using two sources:
- Shodan's InternetDB (`internetdb.shodan.io`), no API key, no signup, and
  no rate limit that actually matters in practice. Returns open ports,
  CPEs, tags, known CVEs for an IP.
- AbuseIPDB's free tier, needs a key, budgeted at 900 checks a day (some
  headroom under their real 1000/day limit), with a 7-day disk cache so a
  re-run never burns budget on an IP it's already looked up.

GreyNoise got evaluated and dropped. Their v2 API is retired, and the
current v3 Community endpoint requires a business email to even get a free
key, consumer domains like gmail get rejected outright. Worth writing down
rather than just quietly not using it: "looked at a tool and it didn't fit"
is a normal outcome, not something to hide.

## Why this split matters for the actual analysis
InternetDB and AbuseIPDB answer different questions, and `respond.py`'s
scoring treats them that way instead of lumping them together. InternetDB
tells you what the IP looks like from the outside (known Tor exit? other
open services?), AbuseIPDB gives a community-sourced abuse score. Neither
one alone is enough signal on its own, which is why the responder only
weights AbuseIPDB's confidence at a fraction of its raw value (0.3x)
instead of trusting it outright. What this project actually observed
first-hand (a real successful login, real commands run afterward) counts
for more than someone else's reputation score.
