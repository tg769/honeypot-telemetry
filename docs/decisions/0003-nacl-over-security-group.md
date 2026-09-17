# ADR-0003: NACL deny entries, not Security Groups, for the responder

## Context
`respond.py` needs to block scored attacker IPs. AWS gives two ways to
filter traffic at the VPC layer.

## Decision
Use Network ACL deny entries, not Security Group rules.

## Why
Security Groups are **allow-only** -- there's no "deny" rule type, so you
can't use one to block a specific IP while still allowing everything else
in a broader allow rule (like the `0.0.0.0/0:22` bait rule). A NACL supports
explicit deny, evaluated in rule-number order before the default allow,
which is exactly the shape this problem needs: "let everyone hit :22 except
these specific IPs."

## The constraint this creates
A NACL has a practical limit of about 20 rules by default. Over a weekend
this sensor will see thousands of distinct source IPs. That gap -- thousands
of candidates, ~18 usable slots (leaving headroom below the ~20 cap) -- is
the actual engineering problem, and it's why `respond.py` isn't just "block
everything bad":

- **Scoring** ranks candidates so the 18 slots go to the IPs that did the
  most damage (successful login + post-exploit execution scores far above a
  single failed login), not just the highest-volume noise.
- **TTL + eviction** means the list stays current -- a block expires, and if
  a higher-scored new candidate shows up while the list is full, it evicts
  the lowest-scored active entry rather than being silently dropped.

## Consequence
This only ever blocks a small, high-value slice of observed attackers -- it
is a demonstration of triage logic under a hard resource constraint, not a
comprehensive blocklist. That's an honest characterization to give in an
interview, not a limitation to hide.
