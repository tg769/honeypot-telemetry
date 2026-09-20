# honeypot-telemetry

What actually hits a server the moment it's exposed to the internet?

I put an SSH honeypot on a real AWS box and built a pipeline around it to
find out - actual source IPs, actual credentials people try,
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
default) is in [`docs/decisions.md`](docs/decisions.md) if you're curious why.

## Layout

```
infra/           EC2 provisioning + sensor bootstrap
src/secu/        the pipeline itself - collector, enrich, detect, respond, ship, report, healthcheck
splunk/          local Splunk stack, saved searches, dashboard
tests/           pytest, mostly detection rules + the allowlist safety check
docs/            architecture notes, decision records, findings
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
   the internet, so read this whole step first. You'll need an EC2 key
   pair (`aws ec2 create-key-pair --key-name secu-sensor --query 'KeyMaterial' --output text > ~/.ssh/secu-sensor.pem && chmod 400 ~/.ssh/secu-sensor.pem`)
   and your current public IP (`curl -s ifconfig.me`) for the admin-SSH
   allowlist, note that this can rotate on a home connection, and if it
   does, admin SSH will start timing out until the security group gets
   the new IP. Edit the top of `infra/provision-aws.sh` (key name, your IP,
   a budget alert email), then:
   ```
   bash infra/provision-aws.sh
   ```
   Once it's up, verify before doing anything else: `nc -vz <ip> 22`
   connects, admin SSH works on port 52222, `docker ps` on the box shows
   `cowrie` running, and `aws ec2 describe-instances ... --query
   'Reservations[0].Instances[0].[IamInstanceProfile,MetadataOptions.HttpPutResponseHopLimit]'`
   prints `null` and `1` (confirming the isolation actually landed).
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
4. `pytest` runs the test suite - 15 tests, the one that actually matters is
   the allowlist check that makes sure the responder can never block your
   own IP or anything private/internal.
5. When you're done collecting, `bash infra/teardown.sh` terminates the
   instance and deletes the VPC/subnet/security group, that's what
   actually stops the AWS bill. Do a final `collector.py` pull and write
   up `docs/findings/report.md` first, once the instance is gone there's
   no going back for anything you forgot to pull.
