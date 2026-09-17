# ADR-0002: Dedicated VPC, no instance profile, IMDSv2 hop-limit 1

## Context
The AWS account this runs in predates the project and has unrelated
resources in it. The sensor is intentionally internet-exposed and intended
to be compromised.

## Decision
- The sensor lives in its own VPC (`10.90.0.0/16`), its own subnet, its own
  route table -- no peering, no shared security groups with anything else
  in the account.
- **No IAM instance profile is attached to the instance.** If Cowrie's
  emulated shell were ever escaped, there is no AWS role to steal.
- IMDSv2 is enforced (`HttpTokens=required`) with **`HttpPutResponseHopLimit=1`**.
  This matters specifically because the sensor runs Docker: a container
  is one network hop further from the instance than a plain process, and a
  hop limit of 2 (the AWS default in some paths) would let a container reach
  the instance metadata service. Hop limit 1 blocks that even if a container
  breaks out.
- Egress is default-deny at the security group, with narrow allowances for
  DNS and HTTPS (package installs only).

## Why this level, not more or less
A separate AWS **sub-account** would isolate further (blast radius capped
even if IAM itself were somehow compromised) but was disproportionate for a
single micro instance over a weekend -- it adds account-management overhead
with no meaningful additional protection given there's already no instance
profile to steal. A dedicated VPC with no profile and a locked-down IMDS is
the right amount of isolation for the actual risk: the only thing of value
reachable from a shell on this box is the box itself.

## Consequence
No AWS API calls can be made *from* the sensor. If a future version of this
project wanted the sensor to self-report status to AWS, that would need to
be added deliberately and would arguably weaken this posture -- so it isn't
planned.
