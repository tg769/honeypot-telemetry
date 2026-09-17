#!/usr/bin/env bash
# Run once after `docker compose up -d` and Splunk has finished its first boot
# (check with: docker logs -f secu-splunk, wait for "Ansible playbook complete").
set -euo pipefail
cd "$(dirname "$0")"
set -a; source .env; set +a

docker exec -u splunk secu-splunk /opt/splunk/bin/splunk add index honeypot \
  -auth "admin:${SPLUNK_PASSWORD}"

echo "index 'honeypot' created. Web UI: http://localhost:8000 (admin / your SPLUNK_PASSWORD)"
