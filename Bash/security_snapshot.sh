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


# --- Section 2: Critical Service Status ---
{
    echo "======================================================="
    echo "  CRITICAL SERVICE STATUS"
    echo "======================================================="
    echo ""

    # List of services to check
    SERVICES=("ssh" "cron" "wazuh-agent" "ufw")

    for service in "${SERVICES[@]}"; do
        if systemctl is-active --quiet "$service"; then
            STATUS="RUNNING "
        else
            STATUS="STOPPED "
        fi
        echo "  [$STATUS] $service"
    done
    echo ""
} >> "$REPORT_FILE"

echo "[+] Service status collected."

# --- Section 3: Active Network Connections ---
{
    echo "======================================================="
    echo "  ACTIVE NETWORK CONNECTIONS"
    echo "======================================================="
    echo ""
    echo "--- Listening ports ---"
    ss -tlnp 2>/dev/null
    echo ""
    echo "--- Established connections ---"
    ss -tunp 2>/dev/null | grep "ESTAB"
    echo ""
} >> "$REPORT_FILE"

echo "[+] Network connections collected."

# --- Section 4: Recently Modified Shell Scripts (last 7 days) ---
{
    echo "======================================================="
    echo "  RECENTLY MODIFIED SHELL SCRIPTS (past 7 days)"
    echo "======================================================="
    echo ""
    RECENT_SCRIPTS=$(find /home /root /tmp -name "*.sh" -newer /etc/passwd \
        -type f 2>/dev/null)

    if [ -z "$RECENT_SCRIPTS" ]; then
        echo "  None found."
    else
        echo "  *** Shell scripts modified recently: ***"
        echo "$RECENT_SCRIPTS" | while read -r filepath; do
            MODIFIED=$(stat -c "%y" "$filepath" 2>/dev/null | cut -d'.' -f1)
            echo "  $filepath  (modified: $MODIFIED)"
        done
    fi
    echo ""
} >> "$REPORT_FILE"

echo "[+] Shell script check complete."

# --- Report Complete ---
{
    echo "======================================================="
    echo "  Snapshot complete: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "======================================================="
} >> "$REPORT_FILE"

echo ""
echo "[+] Security snapshot complete."
echo "[+] Report saved to: $REPORT_FILE"
echo ""
