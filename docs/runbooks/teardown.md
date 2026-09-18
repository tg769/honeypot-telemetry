# Runbook: Teardown

Run this once the collection window is over. It's what actually stops the
AWS meter (roughly $10/month if left running, since this account's free
tier had already expired).

## Steps
1. Do a final collector pull so nothing gets left un-ingested:
   `python -m secu.collector`
2. Run `report.py` and write the final `docs/findings/report.md`
   before tearing anything down. Once the instance is gone there's no
   going back for anything you forgot to pull.
3. `bash infra/teardown.sh` terminates the instance and deletes the VPC,
   subnet, internet gateway, route table, and security group.
4. Confirm nothing billable is left:
   `aws ec2 describe-instances --filters Name=tag:Name,Values=secu-honeypot`
   should come back empty.
5. Stop the local Splunk stack if you're done with it: `cd splunk && docker
   compose down` (add `-v` to also delete the indexed data, once you've
   exported or screenshotted whatever you need).
6. If you're not planning to redeploy, revoke the AbuseIPDB key and delete
   the EC2 key pair: `aws ec2 delete-key-pair --key-name secu-sensor`
