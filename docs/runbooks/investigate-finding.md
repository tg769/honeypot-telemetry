# Runbook: Investigate a finding

Applies to anything in `state/findings.json` or the equivalent Splunk
search results. Most useful for a `SUCCESSFUL_LOGIN` or
`POST_EXPLOIT_EXEC` finding since those mean the session actually got
somewhere.

## Steps

1. Get the session ID. Most findings from `detect.py` carry a `session` in
   their evidence string already, or look it up directly:
   ```
   python -c "
   from secu import events
   for e in events.read_all():
       if e.get('src_ip') == '<ip>':
           print(e['eventid'], e.get('timestamp'), e.get('session'), e.get('input',''))
   "
   ```
2. Reconstruct the session timeline. Filter to that `session` value and
   read events in order: connect, login attempts, login success, commands,
   downloads, disconnect. Shows what the attacker actually tried to do,
   not just that they got in.
3. Check the enrichment context in `state/enrich_cache.json[<ip>]`. Known
   Tor exit? Flagged for abuse? Does InternetDB show other exposed
   services on it? Tells you whether this is opportunistic scanning
   infrastructure or something more deliberate.
4. Check whether the IP shows up in `state/findings.json`'s
   `botnet_clusters`. If it does, the same credential set or client
   version has shown up from other IPs too, worth checking whether they
   did the same thing afterward (same payload, same commands), which
   would confirm it's one automated campaign rather than a person.
5. If a payload got downloaded, don't run it or open it. Just record the
   URL and the `shasum` from the `cowrie.session.file_download` event. You
   can look the hash up manually on something like VirusTotal's web UI if
   you want to identify the malware family, just don't automate that and
   don't touch the actual file.
6. Write it up, a line or two in `docs/findings/weekend-report.md` under
   whatever section fits (successful logins, payloads, botnet campaigns).
   Include the session ID and whatever specifically made it worth noting,
   not just "there was a hit."

## What not to do
- Don't `--enforce` a block off a single investigation. That's a separate
  decision `respond.py` makes by scoring across everything, not something
  to do manually for one finding.
- Don't download or run anything pulled from `cowrie.session.file_download`.
