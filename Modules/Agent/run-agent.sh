#!/usr/bin/env bash
# ── PrivaCore Agent quick start (Linux / macOS) ──
# Edit the values below, then: chmod +x run-agent.sh && ./run-agent.sh

HOST=192.168.1.50
PORT=9720
USER=admin
PASS=changeme
PAIRING=ABCD-EFGH-JKLM
NAME=$(hostname)

# Comma-separated log files to ship (leave empty for heartbeat only).
TAIL=/var/log/auth.log,/var/log/syslog

./privacore-agent --host "$HOST" --port "$PORT" --user "$USER" --pass "$PASS" \
                  --pairing "$PAIRING" --name "$NAME" --tail "$TAIL"
