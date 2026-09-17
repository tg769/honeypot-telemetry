# ADR-0003: NACL deny entries, not Security Groups, for the responder

## Context
`respond.py` needs to block scored attacker IPs. AWS gives two ways to
filter traffic at the VPC layer, and they behave pretty differently.

## Decision
Use Network ACL deny entries instead of Security Group rules.

## Why
Security Groups are allow-only, there's no deny rule at all, so there's no
way to block one specific IP while still allowing everyone else through a
broader rule (like the `0.0.0.0/0:22` bait rule that has to stay open). A
NACL actually supports deny, evaluated in rule-number order before the
default allow kicks in, which is exactly what this needs: let everyone hit
`:22` except these specific IPs.

## The constraint this creates
A NACL only supports around 20 rules by default. Over a weekend this sensor
will see thousands of distinct IPs. That gap, thousands of candidates
against maybe 18 usable slots (leaving some headroom under the cap), is
basically the whole engineering problem here, and it's why `respond.py`
doesn't just try to block everything bad:

- Scoring ranks candidates so the limited slots go to whoever actually did
  damage (a successful login plus running commands scores way above a
  single failed login attempt), not just whoever generated the most noise.
- TTL and eviction keep the list current: a block expires after a while,
  and if a higher-scored candidate shows up while the list is full, it
  bumps the lowest-scored entry instead of just getting dropped.

## Consequence
This only ever blocks a small, high-value slice of what's actually hitting
the sensor. It's not a real blocklist, it's more a demonstration of how you
triage under a hard resource constraint. Worth saying plainly rather than
pretending it's comprehensive.
