# Weekend findings

## Headline numbers
- Collection window: 2026-09-17 21:56 UTC to 2026-09-18 21:44 UTC (about 24 hours)
- Total events: 241
- Distinct source IPs: 54
- Botnet clusters identified (2+ IPs): 1
- Successful logins: 7
- Sessions with post-exploit commands or payload downloads: 8

## What actually hit the box
Most traffic was single-shot credential probes: one or two login attempts,
then gone. A handful of IPs stood out.

`92.118.39.50` and `92.118.39.71` (34 and 18 events) both come from the
same hosting provider in Romania (DMZHOST) and are both flagged as
`scanner` by Shodan's InternetDB, with a 100% AbuseIPDB confidence score.
`163.53.201.45` is different: it's tagged `eol-product` and has eight
open ports (22, 80, 82, 111, 443, 3001, 8080, 9000), which reads like an
already-compromised device (router, DVR, that kind of thing) being used
as an attack node rather than a dedicated scanning box. `35.95.103.254` is
worth a mention too: it's an Amazon-owned IP with no InternetDB tags but a
100% abuse score, likely a compromised or abused EC2 instance rather than
a home device.

## Credential patterns
Every successful login used `root`. Passwords were short, numeric, and
low-effort: `111111`, `123`, `123123`, `123321`, `000000`, plus one attempt
with `ubuntu` as the password. None of these matched Mirai's published
credential table (0/7), so whatever's driving this traffic is using its
own list, not Mirai's, or a much broader one that just happens to overlap
on `root` as the username.

## Successful logins and what happened next
Two very different behaviors showed up after login.

`92.118.39.50` and `92.118.39.71` (the DMZHOST pair) both ran the same
lengthy fingerprinting script after logging in: OS and architecture
detection with layered fallbacks (`uname`, `/proc/version`,
`/etc/os-release`, `busybox` variants), CPU model and core count, and
notably a GPU check (`lspci | grep -i nvidia`). Checking specifically for
an NVIDIA GPU before deciding what to do next is a pattern associated with
cryptomining campaigns that pick a GPU miner over a CPU miner depending on
what they find. Neither session downloaded a payload in this window, they
just fingerprinted and disconnected.

`163.53.201.45` did something more direct: it dropped a file into a hidden,
randomly-named directory (`.4911703562822964066/sshd`), made it
executable, and launched it with `nohup` and roughly 50 hardcoded IP
addresses as arguments. Naming a payload `sshd` is a straightforward way to
blend into a process list. The long IP list handed to it on launch is
consistent with a self-propagating SSH scanner being told what to hit
next, rather than a one-off download. The file itself wasn't retrievable
from this session, only its execution was observed.

## Verifying the auto-blocker actually works
Ran `respond.py --enforce` against the real top-scored IP (`92.118.39.50`,
the highest score in the dataset from its successful login plus
post-exploit activity). Confirmed a live deny entry landed in the NACL,
then reverted it manually since the goal was proving the mechanism, not
leaving the sensor's egress permanently altered. This also caught two bugs
that only showed up under a real AWS call: the rule numbering started at
100, which collides with AWS's own default NACL rule at that same number,
and dry-run mode was writing its simulated state to the same file real
blocks use, so a later `--enforce` run believed blocks already existed and
never called AWS at all. Both are fixed now, with tests covering each one.

## Botnet clustering results
One real cluster came out of this: `163.53.201.45`, `92.118.39.50`, and
`92.118.39.71`, grouped because they share the same SSH client fingerprint
(`SSH-2.0-Go`, meaning whatever's connecting was built with Go's SSH
library rather than OpenSSH). Two of the three are also on the same
hosting provider. Three raw IPs collapsing into what looks like one
campaign, using shared tooling, is the actual point of doing this analysis
instead of just counting source IPs.

## What surprised me
No brute-force or password-spray detections fired at all, despite having
detection rules for both. Every source IP that got in did it in one or two
tries with a weak default credential, not by grinding through a list. That
changes what "defend against this" would mean in practice: rate-limiting
repeated attempts from one IP wouldn't have stopped any of what actually
got in here, since nobody tried hard enough to trigger it.

## What I'd do differently
The botnet clustering groups IPs by Jaccard similarity over credential
sets, and with `92.118.39.50` and `92.118.39.71` both trying near-identical
short credential lists, the similarity score was high enough to combine
them correctly. But with a larger dataset, IPs that only share one generic
credential (`root`/`111111` alone, say) would cluster into large,
low-value groups that don't actually represent one campaign. A fix would
be requiring a minimum shared credential-set size, or weighting rarer
credentials higher in the similarity score, before two IPs get merged.
