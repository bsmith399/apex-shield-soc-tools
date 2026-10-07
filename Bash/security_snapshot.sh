#!/bin/bash
# security_snapshot.sh
# Apex Shield SOC Tools -- Linux Security Snapshot
# Module 7 Project
#
# Collects: Login history, service status, network connections,
#           recently modified shell scripts
# Output: Timestamped .txt file in ~/security_reports/
#
# Usage: chmod +x security_snapshot.sh && ./security_snapshot.sh

# --- Configuration ---
REPORT_DIR="$HOME/security_reports"
TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")
REPORT_FILE="$REPORT_DIR/snapshot_$TIMESTAMP.txt"
HOSTNAME=$(hostname)
CURRENT_USER=$(whoami)

# Create the report directory if needed
mkdir -p "$REPORT_DIR"

# --- Report Header ---
{
    echo "======================================================="
    echo "  APEX SHIELD SOC -- LINUX SECURITY SNAPSHOT"
    echo "======================================================="
    echo "  Generated : $(date '+%Y-%m-%d %H:%M:%S')"
    echo "  Host      : $HOSTNAME"
    echo "  User      : $CURRENT_USER"
    echo "  Kernel    : $(uname -r)"
    echo "======================================================="
    echo ""
} > "$REPORT_FILE"     # '>' creates/overwrites the file with the block output

echo "[*] Starting security snapshot..."
echo "[*] Report: $REPORT_FILE"

# --- Section 1: Recent Login History ---
{
    echo ""
    echo "======================================================="
    echo "  RECENT LOGIN HISTORY (last 10)"
    echo "======================================================="
    echo ""
    last -n 10 --time-format iso 2>/dev/null
    echo ""
    echo "--- Failed login attempts (last 5) ---"
    lastb -n 5 2>/dev/null || echo "  (lastb requires root or cannot be read)"
    echo ""
} >> "$REPORT_FILE"

echo "[+] Login history collected."