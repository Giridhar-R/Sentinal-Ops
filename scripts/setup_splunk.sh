#!/bin/bash
# ============================================================
# SentinelOps — Splunk Enterprise + BOTS v3 Setup Script
# Sets up a Docker-based Splunk instance with the MCP Server
# and BOTS v3 dataset pre-loaded.
#
# Prerequisites: Docker and Docker Compose
#
# Usage:
#   chmod +x scripts/setup_splunk.sh
#   ./scripts/setup_splunk.sh
# ============================================================

set -e

echo "============================================================"
echo "  SentinelOps — Splunk Enterprise Setup"
echo "============================================================"

SPLUNK_PASSWORD="${SPLUNK_PASSWORD:-SentinelOps2026!}"
SPLUNK_PORT="${SPLUNK_PORT:-8089}"
SPLUNK_WEB_PORT="${SPLUNK_WEB_PORT:-8000}"
BOTS_VERSION="v3"

# Step 1: Pull Splunk Enterprise Docker Image
echo ""
echo "[1/4] Pulling Splunk Enterprise Docker image..."
docker pull splunk/splunk:latest

# Step 2: Start Splunk Container
echo ""
echo "[2/4] Starting Splunk Enterprise container..."
docker run -d \
  --name sentinelops-splunk \
  -p ${SPLUNK_WEB_PORT}:8000 \
  -p ${SPLUNK_PORT}:8089 \
  -e SPLUNK_START_ARGS="--accept-license" \
  -e SPLUNK_PASSWORD="${SPLUNK_PASSWORD}" \
  -e SPLUNK_APPS_URL="https://splunkbase.splunk.com/app/7931/release/latest/download" \
  splunk/splunk:latest

echo "  Waiting for Splunk to start (this may take 2-3 minutes)..."
sleep 30

# Wait for Splunk to be ready
MAX_WAIT=180
WAITED=0
while ! docker exec sentinelops-splunk /opt/splunk/bin/splunk status 2>/dev/null | grep -q "is running"; do
  sleep 10
  WAITED=$((WAITED + 10))
  if [ $WAITED -ge $MAX_WAIT ]; then
    echo "  ERROR: Splunk did not start within ${MAX_WAIT}s"
    exit 1
  fi
  echo "  Still waiting... (${WAITED}s)"
done

echo "  Splunk is running!"

# Step 3: Download and Install BOTS v3 Dataset
echo ""
echo "[3/4] Downloading BOTS v3 dataset (this may take a while)..."
docker exec sentinelops-splunk bash -c "
  cd /opt/splunk/etc/apps &&
  curl -L -o botsv3.tgz https://botsdataset.s3.amazonaws.com/botsv3/botsv3_data_set.tgz &&
  tar xzf botsv3.tgz &&
  rm botsv3.tgz
"

# Step 4: Restart Splunk to load the data
echo ""
echo "[4/4] Restarting Splunk to load BOTS v3 data..."
docker exec sentinelops-splunk /opt/splunk/bin/splunk restart

sleep 30

echo ""
echo "============================================================"
echo "  Splunk Enterprise is ready!"
echo ""
echo "  Web UI:  http://localhost:${SPLUNK_WEB_PORT}"
echo "  API:     https://localhost:${SPLUNK_PORT}"
echo "  User:    admin"
echo "  Pass:    ${SPLUNK_PASSWORD}"
echo ""
echo "  Next steps:"
echo "  1. Log in to Splunk Web and install the MCP Server app"
echo "  2. Generate an MCP token in the MCP Server app settings"
echo "  3. Update your .env file with the token"
echo "  4. Verify data: search index=botsv3 earliest=0 | head 10"
echo "============================================================"
