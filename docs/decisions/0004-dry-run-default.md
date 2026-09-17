# ADR-0004: `respond.py` is dry-run by default, `--enforce` is opt-in

## Context
The whole point of running this sensor is to collect real attacker
behavior. A response system that actually blocks attackers on the sensor
itself works directly against that. Every IP it blocks is data that stops
coming in.

## Decision
`respond.py` defaults to dry-run. It computes scores, ranks candidates,
reconciles against the active blocklist, and writes every decision to
`state/audit.jsonl`, but makes zero AWS API calls unless you explicitly
pass `--enforce`.

The one time I actually ran it live was a single controlled test: block one
IP I already understood well, confirm the NACL entry showed up via
`describe-network-acls`, then revert it. That proves the whole path works
without sacrificing the dataset.

## Why not just enforce it for real
Two reasons, and only one is really about the data:

1. It would be self-defeating, as above.
2. Blast radius. Something that mutates network ACLs based on a scoring
   heuristic can go wrong in ways that are hard to predict: a bug in the
   scoring, a bad allowlist entry, a false positive on a shared/CGNAT IP.
   Dry-run by default, an allowlist checked before anything else happens,
   and an append-only audit log are the normal ways you keep automation
   from doing something you can't explain or undo afterward. Treated that
   as a requirement here, not something to bolt on later.

## How it actually avoids blocking something it shouldn't
Allowlist gets checked first, before scoring even matters (home IP, the
sensor itself, anything RFC1918, see `_is_allowlisted` in `respond.py`).
Dry-run is the default. Every block has a TTL so nothing is permanent.
Every decision, real or simulated, goes into the audit log.
