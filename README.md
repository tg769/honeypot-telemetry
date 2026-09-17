# secu -- what actually hits an exposed server on the internet?

I wanted to see what really shows up within minutes of putting a server on
the open internet -- not in the abstract, but with real source IPs, real
credential attempts, and real post-login behavior. So I stood up an SSH
honeypot, built a pipeline to enrich and analyze what it caught, and let it
run for a weekend.

**Status: actively collecting.** The sensor went live 2026-09-17 and is
running the full pipeline (enrichment, detection, clustering) in real time.
Findings will land in
[`docs/findings/weekend-report.md`](docs/findings/weekend-report.md) as the
dataset grows -- headline numbers, credential patterns, how many distinct
botnet campaigns were actually behind the noise (not just how many IPs),
and what surprised me. Check back or watch the repo for updates.

## What this is

- A Cowrie SSH honeypot on a locked-down, isolated EC2 sensor
- A Python pipeline that pulls the logs, enriches every source IP against
  live threat intel (Shodan InternetDB + AbuseIPDB), runs detection rules,
  ships everything to a local Splunk instance, and can (very carefully)
  auto-block the worst offenders
- Two analyses that go past "here's a table of attacker IPs":
  **botnet-family clustering** (grouping IPs by shared credential sets and
  SSH client fingerprints, to estimate distinct campaigns rather than raw
  IP counts) and **Mirai credential-list provenance** (what fraction of
  observed attempts match Mirai's publicly documented hardcoded table)

See [`docs/architecture.md`](docs/architecture.md) for the full data flow
diagram, and [`docs/decisions/`](docs/decisions/) for the reasoning behind
the security-relevant calls (isolation posture, pull-vs-push, why the
auto-blocker is dry-run by default, why one threat-intel source was
evaluated and dropped).

## Repo layout

```
infra/           EC2 provisioning + sensor bootstrap (you run these, not an agent)
src/secu/        the pipeline: collector, enrich, detect, respond, ship, report, healthcheck
splunk/          local Splunk stack, saved searches, dashboard
tests/           pytest -- detection rules and the responder's allowlist safety logic
docs/            architecture, decision records, runbooks, findings
```

## Running it

1. **Splunk** (local, Docker):
   ```
   cd splunk && cp .env.example .env   # set a real password + HEC token
   docker compose up -d
   # wait for `docker inspect --format='{{.State.Health.Status}}' secu-splunk` to say "healthy"
   ./init-index.sh
   ```
2. **Sensor** (AWS, real cost, real internet exposure -- read
   [`docs/runbooks/deploy-sensor.md`](docs/runbooks/deploy-sensor.md) first):
   ```
   bash infra/provision-aws.sh
   ```
3. **Pipeline** (repo root):
   ```
   python3.12 -m venv .venv && source .venv/bin/activate
   pip install -r requirements.txt
   cp .env.example .env   # fill in sensor + Splunk + AbuseIPDB details
   PYTHONPATH=src python -m secu.collector
   PYTHONPATH=src python -m secu.ship
   PYTHONPATH=src python -m secu.enrich
   PYTHONPATH=src python -m secu.detect
   PYTHONPATH=src python -m secu.respond      # dry-run by default
   PYTHONPATH=src python -m secu.report
   ```
   Schedule `collector.py` every 15 minutes (cron/launchd) so data
   accumulates on its own.
4. **Tests**: `pytest` (12 tests -- detection rule fixtures, and the
   responder's allowlist logic, which is the one piece where a bug would
   actually matter).

## Why dry-run auto-response

Auto-blocking attackers on the sensor itself would cut off the data the
sensor exists to collect -- so `respond.py` computes and logs what it
*would* block by default, and only mutates AWS with an explicit `--enforce`.
Full reasoning, plus how the allowlist and TTL-based eviction work, in
[`docs/decisions/0004-dry-run-default.md`](docs/decisions/0004-dry-run-default.md).
