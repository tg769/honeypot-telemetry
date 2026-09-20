# Notes on a few decisions

Not everything in this project was an obvious choice. These are the ones worth explaining, in the order they came up.

## Pulling logs instead of pushing them

The sensor could just push its events straight to Splunk. Simpler to wire up. I didn't do that.

The sensor is deliberately sitting exposed to attackers, so I'm assuming it gets a shell popped on it fairly often (the fake one, at least). If it also had a live path to push data at Splunk, an HEC URL and token baked into its own config, someone who actually landed on the box could abuse that path: spam the collector, figure out where Splunk lives, maybe try to pivot through it. Instead, Splunk runs locally in Docker and never has a port open to the internet at all. A collector script reaches out to the sensor on a schedule and pulls the log down over SSH, using a key that doesn't even exist on the sensor. The sensor is a read-only source as far as the rest of the pipeline is concerned.

Considered pushing over a VPN tunnel instead, still rejected it, since that's just another persistent process running on a box that's supposed to look like easy prey.

## Isolating the sensor: VPC, no IAM role, IMDSv2

This account already had other stuff in it before this project, so the sensor got its own VPC, own subnet, own route table, no peering, no shared security groups with anything else.

More importantly: no IAM instance profile attached at all. If the fake shell were ever actually escaped, there's just no AWS role sitting there to steal. IMDSv2 is enforced with the hop limit set to 1, which matters specifically because the sensor runs Docker, a container is one extra network hop from the instance itself, and a hop limit of 2 (the default in some setups) would let a container reach the instance metadata service anyway. Hop limit 1 blocks that even if something breaks out of the container. Egress is default-deny too, narrow holes for DNS and HTTPS so it can still install packages.

A separate AWS sub-account would isolate things even further, but I skipped that, it felt like overkill for one micro instance running for a few days, real account-management overhead for basically no extra protection given there's already no instance profile to steal.

## NACL, not Security Group, for the auto-blocker

Security Groups are allow-only. There's no deny rule at all, so there's no way to block one specific IP while still keeping a broad allow rule open (the `0.0.0.0/0:22` bait has to stay open). A Network ACL actually supports deny, evaluated in rule order before the default allow.

This creates a real constraint worth mentioning on its own: a NACL only supports around 20 rules by default. Thousands of IPs will show up, and there are maybe 18 usable slots left after AWS's own defaults. That gap is basically the whole engineering problem behind the responder, which is why it scores every candidate instead of trying to block everyone bad, keeps only the highest scorers, expires blocks after a while, and evicts the lowest-scored entry if a new one outranks it while the list is full.

## Dry-run by default

Blocking attackers on the sensor itself would stop the exact data the project exists to collect, so that alone would justify defaulting to dry-run. But there's a second reason, and it's the one I actually care about more: something that mutates network rules based on a scoring heuristic can go wrong in ways that are hard to predict ahead of time. A scoring bug, a bad allowlist entry, a false positive on a shared IP.

So the responder always computes and logs what it *would* block. Only a real `--enforce` flag lets it call AWS, and before that, an allowlist gets checked first (home IP, the sensor itself, anything private), unconditionally, before scoring even matters. Every block also gets a TTL so nothing is permanent, and every decision, real or simulated, lands in an audit log. If asked "how do you avoid blocking something you shouldn't," that's the actual answer: allowlist first, dry-run by default, TTL on everything, full audit trail.

## Threat intel sources, and the one that got dropped

Ended up using two: Shodan's InternetDB, since it needs no key and no signup and just tells you what else an IP has exposed, and AbuseIPDB, which needs a free key and gives a community-sourced abuse confidence score, budgeted under its real daily limit and cached for a week so the same IP never burns budget twice.

GreyNoise got evaluated and dropped. Their v2 API was retired, and the current v3 free tier requires a business email to even get a key, gmail gets rejected outright. Worth writing down rather than quietly not using it, "looked at a tool and it didn't fit the constraints" is a normal, honest outcome, not something to hide.
