# ADR-0004: `respond.py` is dry-run by default; `--enforce` is opt-in

## Context
The whole point of the sensor is to collect real attacker behavior. An
automated response system that blocks attackers *on the sensor itself*
directly works against that: every IP it successfully blocks stops
generating the data the project exists to gather.

## Decision
`respond.py` defaults to dry-run: it computes scores, ranks candidates,
reconciles against the active blocklist, and writes every decision to
`state/audit.jsonl` -- but makes zero AWS API calls unless invoked with
`--enforce`.

The one live exercise of the enforce path is a single controlled demo: block
one specific, already-well-understood IP, confirm the NACL entry exists via
`describe-network-acls`, then revert it. That proves the mechanism end to
end without sacrificing the dataset.

## Why not just enforce it for real
Two reasons, and only one of them is about protecting the data:

1. **It would be self-defeating** -- as above.
2. **Blast radius.** An automated system that mutates network ACLs based on
   a scoring heuristic can go wrong: a scoring bug, a compromised allowlist
   entry, or a false positive on a shared/CGNAT IP could block something it
   shouldn't. Dry-run-by-default, a hard-coded allowlist that's checked
   *before* anything else, and an append-only audit log are the standard
   mitigations for "don't let automation do something you can't explain or
   undo" -- this project treats that as a design requirement, not an
   afterthought.

## What this demonstrates in an interview
The prepared answer for "how do you avoid blocking something you shouldn't":
allowlist checked first (home IP, sensor, RFC1918 -- see `respond.py:_is_allowlisted`),
dry-run default, TTL on every block so nothing is permanent, and a full audit
trail of every decision, simulated or real.
