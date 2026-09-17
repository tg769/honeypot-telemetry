#!/usr/bin/env bash
# EC2 user-data for the honeypot sensor. Runs once, as root, on first boot.
# Target: Ubuntu 24.04 LTS (arm64 / t4g.micro).
#
# Fail-safe by design: the iptables redirect that sends public :22 traffic to
# Cowrie (and away from real sshd) only happens AFTER we've verified sshd is
# actually listening on the admin port. If that verification fails, :22 is
# left as real, unredirected sshd -- locked out of the bait, not locked out
# of the box. (Learned the hard way: sshd_config can be edited and `systemctl
# restart ssh` can succeed with zero errors while sshd still isn't bound to
# the new port -- e.g. if ssh is socket-activated via ssh.socket, which reads
# its ListenStream from the systemd unit, not from sshd_config's Port line.)
set -euo pipefail
exec > >(tee -a /var/log/secu-bootstrap.log) 2>&1
set -x

REAL_SSH_PORT="52222"
COWRIE_LOG_DIR="/home/ubuntu/cowrie-data"

# --- Move real admin SSH off :22 ---
sed -i "s/^#\?Port .*/Port ${REAL_SSH_PORT}/" /etc/ssh/sshd_config
if ! grep -q "^Port ${REAL_SSH_PORT}" /etc/ssh/sshd_config; then
  echo "Port ${REAL_SSH_PORT}" >> /etc/ssh/sshd_config
fi

# If ssh is socket-activated, the socket unit's ListenStream (not sshd_config)
# controls the actual port -- override it there too, then reload systemd.
if systemctl list-unit-files ssh.socket >/dev/null 2>&1 && systemctl is-enabled ssh.socket >/dev/null 2>&1; then
  mkdir -p /etc/systemd/system/ssh.socket.d
  # A bare `ListenStream=<port>` defaults to an IPv6-only socket on this
  # systemd/Ubuntu combination, which silently refuses IPv4 connections
  # (real connections come in as IPv4 -- EC2 public IPs are IPv4). Bind
  # both families explicitly.
  printf '[Socket]\nListenStream=\nListenStream=0.0.0.0:%s\nListenStream=[::]:%s\n' \
    "${REAL_SSH_PORT}" "${REAL_SSH_PORT}" \
    > /etc/systemd/system/ssh.socket.d/override.conf
  systemctl daemon-reload
  systemctl restart ssh.socket
fi

systemctl restart ssh.service || systemctl restart ssh

# --- Verify sshd is ACTUALLY listening on the admin port before doing
#     anything that could cut off :22 access. Retry briefly; a restart can
#     take a moment to bind. ---
ADMIN_PORT_LIVE="false"
for _ in $(seq 1 10); do
  # A real functional IPv4 connect test, not a textual parse of `ss` --
  # 127.0.0.1 is pure IPv4, so this fails the exact same way a real
  # external IPv4 connection would against an IPv6-only listener. That's
  # precisely the bug that bit this script once already: `ss` showed a
  # listener on the right port and the old (textual) check passed, while
  # the socket was actually IPv6-only and refused every real connection.
  if (exec 3<>"/dev/tcp/127.0.0.1/${REAL_SSH_PORT}") 2>/dev/null; then
    ADMIN_PORT_LIVE="true"
    break
  fi
  sleep 1
done

echo "=== diagnostic: listening sockets ==="
ss -ltnp || true
echo "=== diagnostic: sshd effective port ==="
sshd -T 2>&1 | grep -i '^port' || true
echo "=== diagnostic: ssh.socket status (if present) ==="
systemctl status ssh.socket --no-pager 2>&1 || true
echo "=== admin port live: ${ADMIN_PORT_LIVE} ==="

if [ "${ADMIN_PORT_LIVE}" != "true" ]; then
  echo "ABORT: sshd is not listening on ${REAL_SSH_PORT} -- refusing to add the" \
       ":22 redirect, which would lock out admin access entirely. :22 remains" \
       "real, unredirected sshd. See diagnostics above."
  exit 1
fi

# --- Docker ---
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y docker.io iptables-persistent
systemctl enable --now docker

# --- Cowrie ---
mkdir -p "${COWRIE_LOG_DIR}"
chown -R 999:999 "${COWRIE_LOG_DIR}"  # cowrie/cowrie:3.0 runs as uid 999, not 1000

docker rm -f cowrie 2>/dev/null || true
docker run -d \
  --name cowrie \
  --restart unless-stopped \
  --network host \
  -v "${COWRIE_LOG_DIR}:/cowrie/cowrie-git/var/log/cowrie" \
  -e COWRIE_HONEYPOT_HOSTNAME=srv04 \
  cowrie/cowrie:3.0
# --network host (not -p 2222:2222) is deliberate: Docker's default bridge
# networking relays published ports through docker-proxy, a userspace TCP
# relay that always re-sources connections from the bridge gateway
# (172.17.0.1) -- silently destroying every attacker's real source IP,
# which every downstream stage of this project (enrichment, detection,
# scoring, reporting) depends on. Host networking removes the bridge/proxy
# entirely, so Cowrie binds straight to the host's real interface.

# --- Only now: redirect public :22 -> Cowrie's :2222 ---
# (admin access already proven safe on REAL_SSH_PORT above)
PRIMARY_IP="$(hostname -I | awk '{print $1}')"
iptables -t nat -A PREROUTING -p tcp --dport 22 -j DNAT --to-destination "${PRIMARY_IP}:2222"
netfilter-persistent save

echo "bootstrap complete: real ssh on ${REAL_SSH_PORT}, cowrie bait on :22 -> :2222"
