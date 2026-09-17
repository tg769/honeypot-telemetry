# Runbook: If the sensor itself looks compromised

The sensor is supposed to look compromised from Cowrie's point of view,
that part's simulated. This is for the other scenario: something outside
Cowrie looks wrong, on the actual host, not the fake shell.

## Signs worth taking seriously
- `docker ps` shows something running that isn't `cowrie`, or `cowrie`
  itself stuck in a crash loop.
- Outbound connections in `conntrack`/`ss` going somewhere that isn't DNS
  or HTTPS (the security group should already block this, but check).
- CPU or network usage that doesn't match honeypot traffic, sustained high
  outbound bandwidth in particular, which would suggest it's being used as
  a relay, exactly what the egress rules are there to prevent.
- Real sshd on `:52222` stops answering, or answers differently than
  expected.

## Immediate actions
1. Don't SSH in and start poking around if you actually suspect the
   underlying host is compromised, not just Cowrie. Treat it as
   unrecoverable rather than something to debug live.
2. From your Mac, pull whatever logs haven't been collected yet:
   `python -m secu.collector`. Best-effort, it might just fail if the box
   is already unreachable, that's fine, don't keep retrying it.
3. Revoke the security group's ingress rules so nothing new can reach it,
   without terminating the instance yet. Keeps the box around if you want
   to look at it later, while cutting off further exposure right away.
4. If you want to preserve evidence, snapshot the root volume with
   `aws ec2 create-snapshot`.
5. Terminate it: run `infra/teardown.sh`, or manually
   `aws ec2 terminate-instances --instance-ids <id>`.
6. If you want to keep collecting, provision a fresh box with
   `infra/provision-aws.sh`. Never reuse one you actually suspect was
   compromised.

## Why this is a fairly low-risk scenario by design
No IAM instance profile means there was never a real AWS credential on the
box to steal in the first place (see ADR-0002). Default-deny egress means
even a fully compromised host has a narrow path out. That's the actual
payoff of that isolation setup: "what's the worst case if this goes wrong"
has a short, concrete answer.
