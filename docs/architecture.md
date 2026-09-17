# Architecture

```
  INTERNET (background radiation)
        |  :22
        v
+---------------------------------------+
| AWS EC2 t4g.micro -- dedicated VPC     |   No instance profile.
|  iptables 22 -> 2222                   |   IMDSv2 required, hop limit 1.
|  Cowrie 3.0 (Docker, arm64)            |   Egress: default-deny.
|  -> var/log/cowrie/cowrie.json         |   Admin SSH :52222, home IP only.
+---------------------------------------+
        |  rsync over SSH (pull -- Splunk is never exposed)
        v
+-------------------------------------------------------------+
| MacBook -- Python pipeline                                    |
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

## Data flow

1. **collector.py** rsyncs `cowrie.json` from the sensor down to `data/raw/`, then parses only the newly-arrived complete lines (tracked by a byte offset in `state/collector.json`) and appends them to `data/events.ndjson` -- the single canonical local event store every other script reads from.
2. **ship.py** pushes new lines from `events.ndjson` to Splunk over HEC, tracking a separate line-count cursor so re-runs never double-ship.
3. **enrich.py** looks up every distinct source IP against Shodan InternetDB (no key needed) and AbuseIPDB (budgeted, 1000/day free tier), caching results by IP with a 7-day TTL.
4. **detect.py** runs rule-based detections (brute force, password spray, successful logins, post-exploit command execution, payload staging) plus two original analyses: botnet-family clustering (credential-set + client-version similarity) and Mirai credential-list provenance.
5. **respond.py** scores every source IP using findings + AbuseIPDB confidence, ranks candidates, filters anything allowlisted or private/loopback, and reconciles against a capped, TTL'd blocklist. Dry-run by default; `--enforce` is required to actually touch AWS.
6. **report.py** renders a markdown snapshot of the current dataset for quick review; `docs/findings/weekend-report.md` is the hand-curated final deliverable.
7. **healthcheck.py** checks sensor reachability, log growth, HEC acceptance, and AbuseIPDB quota remaining.

## Why pull, not push (Splunk side)

Splunk never has an open port to the internet. The collector reaches out to the sensor over SSH on a schedule; the sensor never initiates a connection to anything on the Mac. See [ADR-0001](decisions/0001-pull-model.md).

## Why a dedicated VPC

The AWS account predates this project and has unrelated resources in it. The honeypot sensor lives in its own VPC with no route to anything else, no IAM instance profile, and IMDSv2 with a hop limit of 1 so a compromised container cannot reach instance metadata. See [ADR-0002](decisions/0002-dedicated-vpc-isolation.md).
