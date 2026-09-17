# Runbook: Teardown

Run this once the data collection window is over -- it's what stops the
AWS meter (~$10/mo if left running, since this account's free tier has
expired).

## Steps
1. Final collector pull to make sure nothing is left un-ingested:
   `python -m secu.collector`
2. Run the last `report.py` / write the final `docs/findings/weekend-report.md`
   *before* tearing anything down -- once the instance is gone you can't go
   back for anything you forgot to pull.
3. `bash infra/teardown.sh` -- terminates the instance and deletes the VPC,
   subnet, IGW, route table, and security group.
4. Confirm nothing billable is left:
   `aws ec2 describe-instances --filters Name=tag:Name,Values=secu-honeypot`
   should return nothing running.
5. Stop the local Splunk stack if you're done with it:
   `cd splunk && docker compose down` (add `-v` to also delete the indexed
   data, once you've exported/screenshotted what you need).
6. Revoke/delete the AbuseIPDB key and the EC2 key pair if you don't plan to
   redeploy:
   `aws ec2 delete-key-pair --key-name secu-sensor`
