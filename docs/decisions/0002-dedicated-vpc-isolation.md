# ADR-0002: Dedicated VPC, no instance profile, IMDSv2 hop-limit 1

## Context
This AWS account already had other stuff in it before this project started.
The sensor is meant to be exposed and, realistically, is going to get
compromised at the emulated-shell level pretty regularly.

## Decision
- The sensor gets its own VPC (`10.90.0.0/16`), own subnet, own route table.
  No peering, no shared security groups with anything else in the account.
- No IAM instance profile attached at all. If Cowrie's fake shell were ever
  actually escaped, there's just no AWS role sitting there to steal.
- IMDSv2 enforced (`HttpTokens=required`) with `HttpPutResponseHopLimit=1`.
  This one matters because the sensor runs Docker: a container is one
  network hop further from the instance than a normal process, and a hop
  limit of 2 (which is the default in some setups) would let a container
  reach the instance metadata service anyway. Hop limit of 1 blocks that
  even if something breaks out of the container.
- Egress is default-deny on the security group, with narrow holes for DNS
  and HTTPS so it can still install packages.

## Why this much and not more
A separate AWS sub-account would isolate things even further, but that felt
like overkill for a single micro instance running for a weekend. It adds
real account-management overhead for basically no extra protection, since
there's already no instance profile to steal in the first place. A
dedicated VPC plus no profile plus a locked-down IMDS matches the actual
risk here: the only thing worth anything if someone gets a shell on this
box is the box itself.

## Consequence
No AWS API calls can happen from the sensor, period. If a later version of
this wanted the sensor to report its own status back to AWS somehow, that'd
have to be a deliberate addition, and it would weaken this setup a bit, so
it's not something I'm planning to add.
