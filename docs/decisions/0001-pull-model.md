# ADR-0001: Pull model for log ingestion, not push

## Context
The sensor needs to get Cowrie's logs to Splunk somehow. The obvious approach
is to have the sensor push events to Splunk's HTTP Event Collector directly.

## Decision
Instead, Splunk runs locally in Docker and a Python collector (`collector.py`)
reaches out to the sensor over SSH on a schedule to `rsync` the log down.
Splunk never has an open port reachable from the internet.

## Why
The sensor is deliberately exposed to attackers and assumed to be a target.
If it also held a live path to push data at Splunk (an HEC URL/token baked
into its config), a sufficiently capable attacker who got a shell could
potentially abuse that path -- spam the collector, discover the Splunk
instance's location, or attempt to use it as a pivot. Pull removes that: the
sensor is a read-only source as far as the rest of the pipeline is concerned,
and the only thing that ever initiates a connection to it is the collector,
authenticating with an SSH key the sensor doesn't have.

## Alternatives considered
- **Push over a VPN tunnel (Tailscale/WireGuard):** more real-time, but adds
  a persistent tunnel daemon on the sensor -- another thing running on a box
  that's supposed to look like an easy target, and another thing that could
  be attacked.
- **HEC push directly from the sensor:** simplest to wire up, rejected for
  the reason above.

## Consequence
Ingestion has latency (however often `collector.py` is scheduled -- 15 min
by default) instead of being real-time. Acceptable: this is forensic/batch
analysis, not live incident response.
