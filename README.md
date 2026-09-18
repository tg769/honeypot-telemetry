# honeypot-telemetry

What actually hits a server the moment it's exposed to the internet?

I put an SSH honeypot on a real AWS box and built a pipeline around it to
find out - not guessing, actual source IPs, actual credentials people try,
actual commands run after a fake login succeeds.

Findings are in [`docs/findings/report.md`](docs/findings/report.md).

## What's actually in here

- Cowrie (SSH honeypot) running on a locked-down EC2 instance
- a Python pipeline that pulls the logs down, enriches every IP against
  Shodan's InternetDB and AbuseIPDB, runs some detection rules, and ships
  everything into a local Splunk instance
- an auto-blocker that can add attacker IPs to a NACL, dry-run by default
  because auto-blocking on the sensor itself would kill the data collection
- two things I added because a plain "here are the top attacker IPs" table
  felt thin: grouping IPs into probable botnet campaigns by shared
  credentials/client fingerprints, and checking what fraction of attempted
  logins match Mirai's actual published credential list

More on how it's wired together in [`docs/architecture.md`](docs/architecture.md).
The reasoning behind some of the less obvious calls (isolation setup,
pull vs push for logs, why the responder doesn't actually block anything by
default) is in [`docs/decisions/`](docs/decisions/) if you're curious why.

## Layout

```
infra/           EC2 provisioning + sensor bootstrap
src/secu/        the pipeline itself - collector, enrich, detect, respond, ship, report, healthcheck
splunk/          local Splunk stack, saved searches, dashboard
tests/           pytest, mostly detection rules + the allowlist safety check
docs/            architecture notes, decision records, runbooks, findings
```

## Running it yourself

1. Splunk (local, in Docker):
   ```
   cd splunk && cp .env.example .env   # set a real password + HEC token
   docker compose up -d
   # wait for `docker inspect --format='{{.State.Health.Status}}' secu-splunk` to say "healthy"
   ./init-index.sh
   ```
2. Sensor - this is the part that costs real money and puts a real port on
   the internet, so read [`docs/runbooks/deploy-sensor.md`](docs/runbooks/deploy-sensor.md)
   before running it:
   ```
   bash infra/provision-aws.sh
   ```
3. Pipeline:
   ```
   python3.12 -m venv .venv && source .venv/bin/activate
   pip install -r requirements.txt
   cp .env.example .env   # fill in sensor + Splunk + AbuseIPDB details
   PYTHONPATH=src python -m secu.collector
   PYTHONPATH=src python -m secu.ship
   PYTHONPATH=src python -m secu.enrich
   PYTHONPATH=src python -m secu.detect
   PYTHONPATH=src python -m secu.respond      # dry-run by default, won't touch AWS
   PYTHONPATH=src python -m secu.report
   ```
   Put `collector.py` on a cron/launchd schedule (every 15 min or so) so it
   keeps pulling on its own.
4. `pytest` runs the test suite - 12 tests, the one that actually matters is
   the allowlist check that makes sure the responder can never block your
   own IP or anything private/internal.

## Why the auto-blocker doesn't block anything by default

If it actually blocked attackers on the sensor, it would stop the data from
coming in - which defeats the point. So `respond.py` scores and logs what it
*would* block, and only touches AWS if you pass `--enforce`. Details on the
allowlist and TTL logic in
[`docs/decisions/0004-dry-run-default.md`](docs/decisions/0004-dry-run-default.md).
