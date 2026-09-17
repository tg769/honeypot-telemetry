# Runbook: If the sensor itself looks compromised

The sensor is *supposed* to look compromised from Cowrie's point of view --
that's simulated. This runbook is for the scenario where something outside
Cowrie's emulation looks wrong: the real host, not the honeypot's fake shell.

## Signs to take seriously
- `docker ps` shows a container other than `cowrie` running, or `cowrie`
  restarting in a crash loop.
- Outbound connections in `conntrack`/`ss` to destinations that aren't
  DNS/HTTPS (the security group should already block this, but verify).
- CPU/network usage inconsistent with honeypot traffic (e.g. sustained high
  outbound bandwidth -- possible sign of being used as a relay, which the
  egress security group rules exist specifically to prevent).
- Real sshd on :52222 no longer answering, or answering differently than
  expected.

## Immediate actions
1. **Don't SSH in and start investigating on the live box** if you suspect
   the underlying host (not just Cowrie) is compromised -- treat it as
   unrecoverable, not a debugging target.
2. From your Mac, pull whatever logs haven't been collected yet:
   `python -m secu.collector` (best-effort, may fail if the box is
   unreachable -- that's fine, don't retry aggressively).
3. Isolate: revoke the security group's ingress rules
   (`aws ec2 revoke-security-group-ingress ...`) so nothing new can reach it,
   without terminating yet -- this preserves the box for a look if you want
   one, while stopping further exposure.
4. Snapshot if you want to preserve evidence:
   `aws ec2 create-snapshot` on its root volume.
5. Terminate: run `infra/teardown.sh`, or manually
   `aws ec2 terminate-instances --instance-ids <id>`.
6. Re-provision fresh with `infra/provision-aws.sh` if you want to keep
   collecting -- never reuse a box you suspect was actually compromised.

## Why this is a low-risk scenario by design
No IAM instance profile means there was never an AWS credential on the box
to steal (ADR-0002). Egress default-deny means even a fully compromised
host has a narrow path out. This is the practical value of that isolation
decision: "what's the actual blast radius if this goes wrong" has a short,
concrete answer.
