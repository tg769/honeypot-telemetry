# ADR-0001: Pull model for log ingestion, not push

## Context
The sensor needs to get Cowrie's logs to Splunk somehow. Obvious approach:
have the sensor push events straight to Splunk's HTTP Event Collector.

## Decision
Went the other way. Splunk runs locally in Docker, and a Python collector
(`collector.py`) reaches out to the sensor over SSH on a schedule and rsyncs
the log down. Splunk never has an open port reachable from the internet.

## Why
The sensor is deliberately sitting exposed to attackers, so I'm assuming
it's a target. If it also had a live path to push data at Splunk (an HEC
URL and token baked into its own config), someone who actually got a shell
on it could abuse that path: spam the collector, figure out where Splunk
lives, maybe try to pivot through it. Pull avoids all of that. The sensor
is just a read-only source as far as the rest of the pipeline cares, and
the only thing that ever connects to it is the collector, using an SSH key
that doesn't even exist on the sensor.

## Alternatives considered
- Push over a VPN tunnel (Tailscale/WireGuard) - more real-time, but that
  means another persistent process running on a box that's supposed to
  look like easy prey, and one more thing that could get attacked itself.
- HEC push directly from the sensor - simplest to wire up, but same problem
  as above, just without the tunnel.

## Consequence
Ingestion isn't real-time, it lags by however often `collector.py` runs
(15 minutes by default). Fine for this - it's forensic/batch analysis, not
live incident response.
