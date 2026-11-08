#!/usr/bin/env bash
# One-command provisioning script for Ubuntu 24.04 on Vultr Cloud Compute VM.
# Usage:
#   export VULTR_INFERENCE_API_KEY="your_key"
#   export PUBLIC_DOMAIN="$(curl -s ifconfig.me).nip.io"
#   bash deploy_vultr.sh

set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

echo "[1/4] Updating apt packages and installing Docker + Docker Compose..."
if ! command -v docker >/dev/null 2>&1; then
  apt-get update -y
  apt-get install -y ca-certificates curl gnupg
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  chmod a+r /etc/apt/keyrings/docker.gpg
  echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
    $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
    tee /etc/apt/sources.list.d/docker.list > /dev/null
  apt-get update -y
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
fi

PUBLIC_IP=$(curl -s https://api.ipify.org || hostname -I | awk '{print $1}')
export PUBLIC_DOMAIN="${PUBLIC_DOMAIN:-${PUBLIC_IP}.nip.io}"
export VULTR_HOST_LABEL="vultr-vc2-${PUBLIC_IP}"

echo "[2/4] Configuring .env for Vultr Serverless Inference + HTTPS domain (${PUBLIC_DOMAIN})..."
cat > .env <<EOF
PUBLIC_DOMAIN=${PUBLIC_DOMAIN}
VULTR_HOST_LABEL=${VULTR_HOST_LABEL}
VULTR_INFERENCE_API_KEY=${VULTR_INFERENCE_API_KEY:-}
VULTR_INFERENCE_MODEL=${VULTR_INFERENCE_MODEL:-llama-3.3-70b-instruct}
EOF

echo "[3/4] Building and starting Honeypot Hunter + Caddy HTTPS stack..."
docker compose up -d --build

echo "[4/4] Verifying live health endpoint..."
sleep 5
curl -s http://127.0.0.1:8000/api/health | head -c 400
echo ""
echo "=================================================================="
echo "HONEYPOT HUNTER LIVE ON VULTR CLOUD COMPUTE:"
echo "  HTTPS URL: https://${PUBLIC_DOMAIN}"
echo "  HTTP URL : http://${PUBLIC_IP}:8000"
echo "=================================================================="
