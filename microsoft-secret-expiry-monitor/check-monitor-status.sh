#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="$SCRIPT_DIR/logs/secret-monitor.log"

echo "=== Microsoft Secret Monitor Status ==="
echo ""

# Check if config exists and is properly set up
if [[ -f "$SCRIPT_DIR/secret-monitor-config.env" ]]; then
    if grep -q "your-tenant-id-here" "$SCRIPT_DIR/secret-monitor-config.env"; then
        echo "❌ Configuration file needs to be updated with real values"
    else
        echo "✓ Configuration file exists and appears configured"
    fi
else
    echo "❌ Configuration file missing"
fi

# Check recent log entries
if [[ -f "$LOG_FILE" ]]; then
    echo ""
    echo "Recent log entries:"
    tail -10 "$LOG_FILE"
else
    echo "❌ No log file found at $LOG_FILE"
fi

# Check cron job
echo ""
echo "Cron job status:"
if crontab -l 2>/dev/null | grep -q "microsoft-secret-expiry-monitor.sh"; then
    echo "✓ Cron job is configured"
    echo "Active cron jobs for this script:"
    crontab -l | grep "microsoft-secret-expiry-monitor.sh"
else
    echo "⚠️  No cron job found. Run setup script to configure automated monitoring."
fi
