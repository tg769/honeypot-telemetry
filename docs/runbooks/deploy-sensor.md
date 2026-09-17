# Runbook: Deploy the sensor

Every hour of delay here is an hour of lost attack data -- this is the
first thing to do, before touching any other part of the pipeline.

## Prerequisites
- AWS CLI installed and `aws configure` run against an account you're
  willing to spend ~$1-2 in over a weekend (this account's free tier has
  expired -- see `docs/decisions/` for cost context).
- An EC2 key pair created in your target region:
  `aws ec2 create-key-pair --key-name secu-sensor --query 'KeyMaterial' --output text > ~/.ssh/secu-sensor.pem && chmod 400 ~/.ssh/secu-sensor.pem`
- Your home/current public IP (`curl -s ifconfig.me`), for the admin-SSH
  allowlist.

## Steps
1. Edit the top of `infra/provision-aws.sh`: set `KEY_NAME`, `HOME_IP_CIDR`
   (as a `/32`), and `BUDGET_EMAIL`.
2. Run it: `bash infra/provision-aws.sh`. Note the printed instance ID.
3. Wait ~60s for boot + user-data, then get the public IP:
   `aws ec2 describe-instances --instance-ids <id> --query 'Reservations[0].Instances[0].PublicIpAddress' --output text`
4. **Verify before doing anything else** (see the plan's Phase 0
   verification steps):
   - `nc -vz <ip> 22` connects.
   - SSH to the *admin* port works: `ssh -i ~/.ssh/secu-sensor.pem -p 52222 ubuntu@<ip>`
   - `docker ps` on the box shows the `cowrie` container running.
   - Fail a login against `<ip>:22` from your own machine, then
     `tail -f ~/cowrie-data/cowrie.json` on the box and confirm the event
     appears within seconds.
   - Confirm unsolicited scans are arriving (unfamiliar `src_ip` values) --
     this is the real proof it's live and being found by the internet.
5. Fill in `.env` at the repo root: `SENSOR_HOST`, `SENSOR_SSH_KEY`, and
   `SENSOR_COWRIE_LOG_PATH=/home/ubuntu/cowrie-data/cowrie.json`.
6. Confirm the isolation posture actually landed:
   `aws ec2 describe-instances --instance-ids <id> --query 'Reservations[0].Instances[0].[IamInstanceProfile,MetadataOptions.HttpPutResponseHopLimit]'`
   should show `null` and `1`.
7. Set up a recurring `collector.py` run (cron or `launchd`, every 15 min)
   and walk away -- data now accumulates on its own.

## When you're done collecting
Run `infra/teardown.sh`. See `docs/runbooks/teardown.md`.
