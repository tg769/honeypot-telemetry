# ADR-0005: Shodan InternetDB + AbuseIPDB; GreyNoise evaluated and dropped

## Context
Enrichment needs a source of reputation/context data per observed IP,
within a genuinely free tier (this is a personal project, not a company
card).

## Decision
Use two sources:
- **Shodan InternetDB** (`internetdb.shodan.io`) -- no API key, no signup,
  no rate limit in practice. Returns open ports, CPEs, tags, and known CVEs
  for an IP.
- **AbuseIPDB** free tier -- requires a key, budgeted at 900 checks/day
  (headroom under their 1000/day limit) with a 7-day disk cache so a re-run
  never re-spends budget on an IP already looked up.

**GreyNoise was evaluated and deliberately not used.** Their v2 API was
retired; the current v3 Community endpoint requires a business email
address to issue a free API key, and consumer domains (gmail, etc.) are
rejected. Rather than skip documenting this, it's recorded here: this is
what "evaluate a tool and it doesn't fit the constraints" looks like in
practice, which is itself a real part of the job.

## Why this matters for the analysis
InternetDB and AbuseIPDB answer different questions and are combined in
`respond.py`'s scoring, not treated as interchangeable: InternetDB describes
what else the IP looks like from the outside (is it a known Tor exit, does
it have other open services), while AbuseIPDB gives a community-sourced
abuse confidence score. Neither alone is sufficient reputation signal, which
is why the responder's scoring weights AbuseIPDB confidence at a fraction
(0.3x) of its raw value rather than trusting it outright -- this project's
own observed findings (successful login, post-exploit execution) are
weighted higher because they're first-hand evidence, not third-party
reputation.
