# Runbook: Deploy the sensor

Do this first, before touching anything else in the pipeline. Every hour of
delay here is an hour of lost attack data.

## Prerequisites
- AWS CLI installed and `aws configure` run against an account you're
  willing to spend a couple dollars on over a weekend (this account's free
  tier had already expired, see `docs/decisions/` for the cost reasoning).
- An EC2 key pair created in your target region:
  `aws ec2 create-key-pair --key-name secu-sensor --query 'KeyMaterial' --output text > ~/.ssh/secu-sensor.pem && chmod 400 ~/.ssh/secu-sensor.pem`
- Your current public IP (`curl -s ifconfig.me`), for the admin-SSH
  allowlist. Note that this can rotate if you're on a home connection, and
  if it does, admin SSH will start timing out until the security group
  rule gets updated with the new IP.

## Steps
1. Edit the top of `infra/provision-aws.sh`: set `KEY_NAME`, `HOME_IP_CIDR`
   (as a `/32`), and `BUDGET_EMAIL`.
2. Run it: `bash infra/provision-aws.sh`. Note the instance ID it prints.
3. Wait about a minute for boot and user-data to run, then get the public
   IP: `aws ec2 describe-instances --instance-ids <id> --query 'Reservations[0].Instances[0].PublicIpAddress' --output text`
4. Verify before doing anything else:
   - `nc -vz <ip> 22` connects.
   - SSH to the admin port works: `ssh -i ~/.ssh/secu-sensor.pem -p 52222 ubuntu@<ip>`
   - `docker ps` on the box shows the `cowrie` container running.
   - Fail a login against `<ip>:22` from your own machine, then check
     `~/cowrie-data/cowrie.json` on the box and confirm the event shows up
     within seconds.
   - Check for scans you didn't trigger yourself (unfamiliar `src_ip`
     values). That's the real proof it's live and already being found.
5. Fill in `.env` at the repo root: `SENSOR_HOST`, `SENSOR_SSH_KEY`, and
   `SENSOR_COWRIE_LOG_PATH=/home/ubuntu/cowrie-data/cowrie.json`.
6. Double-check the isolation actually landed:
   `aws ec2 describe-instances --instance-ids <id> --query 'Reservations[0].Instances[0].[IamInstanceProfile,MetadataOptions.HttpPutResponseHopLimit]'`
   should print `null` and `1`.
7. Set up a recurring `collector.py` run (cron or launchd, every 15
   minutes) and leave it alone. Data accumulates on its own from here.

## When you're done collecting
Run `infra/teardown.sh`. See `docs/runbooks/teardown.md`.
