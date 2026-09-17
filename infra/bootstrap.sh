#!/usr/bin/env bash
# EC2 user-data for the honeypot sensor. Runs once, as root, on first boot.
# Target: Ubuntu 24.04 LTS (arm64 / t4g.micro).
set -euxo pipefail

REAL_SSH_PORT="52222"
COWRIE_LOG_DIR="/home/ubuntu/cowrie-data"

# --- Move real admin SSH off :22 before anything else touches the network ---
sed -i "s/^#\?Port .*/Port ${REAL_SSH_PORT}/" /etc/ssh/sshd_config
if ! grep -q "^Port ${REAL_SSH_PORT}" /etc/ssh/sshd_config; then
  echo "Port ${REAL_SSH_PORT}" >> /etc/ssh/sshd_config
fi
systemctl restart ssh

# --- Docker ---
apt-get update -y
apt-get install -y docker.io iptables-persistent
systemctl enable --now docker

# --- Cowrie ---
mkdir -p "${COWRIE_LOG_DIR}"
chown -R 1000:1000 "${COWRIE_LOG_DIR}"

docker rm -f cowrie 2>/dev/null || true
docker run -d \
  --name cowrie \
  --restart unless-stopped \
  -p 2222:2222 \
  -v "${COWRIE_LOG_DIR}:/cowrie/cowrie-git/var/log/cowrie" \
  -e COWRIE_HONEYPOT_HOSTNAME=srv04 \
  -e COWRIE_SHELL_FILESYSTEM=share/cowrie/fs.pickle \
  cowrie/cowrie:3.0

# --- Redirect public :22 -> Cowrie's :2222 (real sshd now lives on 52222) ---
iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
netfilter-persistent save

echo "bootstrap complete: real ssh on ${REAL_SSH_PORT}, cowrie bait on :22 -> :2222" \
  > /var/log/secu-bootstrap.log
