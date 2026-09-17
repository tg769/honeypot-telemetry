# Architecture

```
  INTERNET (background radiation)
        |  :22
        v
+---------------------------------------+
| AWS EC2 t4g.micro, dedicated VPC       |   No instance profile.
|  iptables 22 -> 2222                   |   IMDSv2 required, hop limit 1.
|  Cowrie 3.0 (Docker, arm64)            |   Egress: default-deny.
|  -> var/log/cowrie/cowrie.json         |   Admin SSH :52222, home IP only.
+---------------------------------------+
        |  rsync over SSH (pull, so Splunk is never exposed)
        v
+-------------------------------------------------------------+
| MacBook: Python pipeline                                      |
|                                                               |
|  collector.py -> ship.py         enrich.py -> detect.py       |
|       |               |              |            |          |
|  data/raw/       Splunk HEC     Shodan/AbuseIPDB   findings   |
|  cowrie.json      :8088                            (state/)   |
|       |               |                                 |     |
|       v               v                                 v     |
|  data/events.ndjson (canonical local store)      respond.py   |
|                                            (dry-run default)  |
+-------------------------------------------------------|-------+
                                                          | boto3 (scoped IAM, local creds only)
                                                          v
                                                 NACL deny entries
                                                 (capped, TTL'd, audited)
```

## How data moves through it

1. `collector.py` rsyncs `cowrie.json` down from the sensor into `data/raw/`, then parses only the lines that arrived since last time (tracked by a byte offset in `state/collector.json`) and appends them to `data/events.ndjson`. That file is the one thing every other script reads from.
2. `ship.py` pushes whatever's new in `events.ndjson` to Splunk over HEC. It keeps its own cursor so running it twice doesn't double-ship anything.
3. `enrich.py` looks up every distinct source IP against Shodan's InternetDB (no key needed) and AbuseIPDB (free tier, budgeted at 1000/day), caching each result for a week so it's not re-querying IPs it already knows about.
4. `detect.py` runs the actual detection rules: brute force, password spray, successful logins, commands run after a login succeeds, payload downloads. Plus two things that aren't standard rules: grouping IPs into probable botnet campaigns by shared credentials and client fingerprints, and checking what fraction of login attempts match Mirai's published credential list.
5. `respond.py` scores every IP using those findings plus AbuseIPDB's confidence score, ranks them, throws out anything allowlisted or private, and reconciles against a capped/TTL'd blocklist. It's dry-run unless you pass `--enforce`.
6. `report.py` writes a markdown snapshot of the current dataset. `docs/findings/weekend-report.md` is the actual hand-written writeup, not something auto-generated.
7. `healthcheck.py` checks whether the sensor's reachable, the log is growing, HEC is accepting data, and there's still AbuseIPDB quota left.

## Why pull instead of push for Splunk

Splunk never has a port open to the internet. The collector reaches out to the sensor on a schedule; the sensor never initiates anything toward the Mac. Reasoning in [ADR-0001](decisions/0001-pull-model.md).

## Why the sensor gets its own VPC

This AWS account already had other stuff in it before this project, so the sensor lives in its own VPC with no route to anything else, no IAM instance profile, and IMDSv2 with a hop limit of 1 so a compromised container can't reach instance metadata. Reasoning in [ADR-0002](decisions/0002-dedicated-vpc-isolation.md).
