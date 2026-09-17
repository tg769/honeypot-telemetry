# Runbook: Investigate a finding

Applies to anything in `state/findings.json` (or the equivalent Splunk
search results) -- most usefully a `SUCCESSFUL_LOGIN` or `POST_EXPLOIT_EXEC`
finding, since those represent a session that actually got somewhere.

## Steps

1. **Get the session ID.** Every finding from `detect.py` that isn't
   IP-level carries a `session` in its evidence string, or look it up:
   ```
   python -c "
   from secu import events
   for e in events.read_all():
       if e.get('src_ip') == '<ip>':
           print(e['eventid'], e.get('timestamp'), e.get('session'), e.get('input',''))
   "
   ```
2. **Reconstruct the session timeline** -- filter to that `session` value
   and read events in order: connect, login attempts, login success,
   commands, downloads, disconnect. This tells you what the attacker
   actually tried to do, not just that they got in.
3. **Check enrichment context**: `state/enrich_cache.json[<ip>]` -- is this
   a known Tor exit, a flagged abuse IP, does InternetDB show it running
   other exposed services? This tells you whether it's opportunistic
   scanning infrastructure or something more targeted.
4. **Check the cluster**: does this IP appear in `state/findings.json`'s
   `botnet_clusters`? If so, the same credential set / client version has
   been seen from other IPs -- worth checking if they showed the same
   post-login behavior (same downloaded payload, same commands), which
   would confirm it's the same automated campaign rather than a human.
5. **If a payload was downloaded**: do NOT execute or open it. Record the
   URL and `shasum` from the `cowrie.session.file_download` event only.
   Optionally look the hash up on a public malware-hash lookup (VirusTotal
   web UI, manually, not automated in this pipeline) to identify the
   family -- record the finding, not the file.
6. **Write it up** -- a line or two in `docs/findings/weekend-report.md`
   under whatever section it belongs in (successful logins / payloads /
   botnet campaigns). Include the session ID and what specifically made it
   interesting, not just "there was a hit."

## What NOT to do
- Don't `--enforce` a block based on a single finding investigation --
  that's a separate, scored decision made by `respond.py` across all
  findings, not a manual one-off.
- Don't download and run anything you retrieve from `cowrie.session.file_download`.
