#!/bin/bash

# Setup script for Microsoft Secret Key Expiration Monitor
# This script helps set up the monitoring system with proper permissions and cron jobs

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MONITOR_SCRIPT="$SCRIPT_DIR/microsoft-secret-expiry-monitor.sh"
CONFIG_TEMPLATE="$SCRIPT_DIR/secret-monitor-config.env.template"
CONFIG_FILE="$SCRIPT_DIR/secret-monitor-config.env"
LOG_DIR="$SCRIPT_DIR/logs"

echo "=== Microsoft Secret Key Expiration Monitor Setup ==="
echo ""

# Check if running as root for cron setup
if [[ $EUID -eq 0 ]]; then
    echo "Warning: Running as root. Consider running as a regular user for security."
fi

# Create necessary directories
echo "Creating directory structure..."
mkdir -p "$LOG_DIR"
echo "✓ Created log directory: $LOG_DIR"

# Check dependencies
echo ""
echo "Checking dependencies..."
missing_deps=()

for cmd in curl jq date; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        missing_deps+=("$cmd")
    else
        echo "✓ $cmd is installed"
    fi
done

if [[ ${#missing_deps[@]} -gt 0 ]]; then
    echo ""
    echo "❌ Missing dependencies: ${missing_deps[*]}"
    echo ""
    echo "Please install the missing dependencies:"
    echo "  Ubuntu/Debian: sudo apt-get install curl jq"
    echo "  CentOS/RHEL: sudo yum install curl jq"
    echo "  macOS: brew install curl jq"
    exit 1
fi

# Copy configuration template if config doesn't exist
if [[ ! -f "$CONFIG_FILE" ]]; then
    echo ""
    echo "Creating configuration file..."
    cp "$CONFIG_TEMPLATE" "$CONFIG_FILE"
    echo "✓ Created config file: $CONFIG_FILE"
    echo ""
    echo "⚠️  IMPORTANT: Please edit $CONFIG_FILE and fill in your Azure AD and email settings"
else
    echo "✓ Configuration file already exists: $CONFIG_FILE"
fi

# Set proper permissions
echo ""
echo "Setting file permissions..."
chmod +x "$MONITOR_SCRIPT"
chmod 600 "$CONFIG_FILE"  # Restrict access to config file containing secrets
echo "✓ Script is executable"
echo "✓ Config file permissions restricted"

# Test configuration (dry run)
echo ""
echo "Testing configuration..."
if [[ -f "$CONFIG_FILE" ]]; then
    # Check if config file has been customized
    if grep -q "your-tenant-id-here" "$CONFIG_FILE"; then
        echo "⚠️  Configuration file contains template values. Please update with real values."
    else
        echo "Running dry-run test..."
        if DRY_RUN=true "$MONITOR_SCRIPT" --config "$CONFIG_FILE"; then
            echo "✓ Dry run completed successfully"
        else
            echo "❌ Dry run failed. Please check your configuration."
        fi
    fi
fi

# Set up cron job with environment-based schedule
echo ""
echo "Setting up cron job..."

# Get schedule from environment variable or use default
CRON_SCHEDULE="${CRON_SCHEDULE:-0 9 * * *}"  # Default: Daily at 9:00 AM
ENABLE_CRON="${ENABLE_CRON:-true}"  # Default: Enable cron job

if [[ "$ENABLE_CRON" == "true" ]]; then
    echo "Using cron schedule: $CRON_SCHEDULE"

    # Add cron job
    cron_command="$CRON_SCHEDULE $MONITOR_SCRIPT --config $CONFIG_FILE >> $LOG_DIR/cron.log 2>&1"

    # Check if cron job already exists
    if crontab -l 2>/dev/null | grep -q "$MONITOR_SCRIPT"; then
        echo "⚠️  Cron job for this script already exists. Please check with 'crontab -l'"
    else
        # Add new cron job
        (crontab -l 2>/dev/null; echo "$cron_command") | crontab -
        echo "✓ Cron job added successfully"
        echo "  Schedule: $CRON_SCHEDULE"
        echo "  Command: $cron_command"
    fi
else
    echo "Cron job setup skipped (ENABLE_CRON=false)"
fi

# Create a simple status check script
echo ""
echo "Creating status check script..."
cat > "$SCRIPT_DIR/check-monitor-status.sh" << 'EOF'
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
EOF

chmod +x "$SCRIPT_DIR/check-monitor-status.sh"
echo "✓ Created status check script: $SCRIPT_DIR/check-monitor-status.sh"

echo ""
echo "=== Setup Complete ==="
echo ""
echo "Next steps:"
echo "1. Edit the configuration file: $CONFIG_FILE"
echo "2. Test the script manually: $MONITOR_SCRIPT --dry-run"
echo "3. Check status anytime: $SCRIPT_DIR/check-monitor-status.sh"
echo ""
echo "Files created:"
echo "  - Monitor script: $MONITOR_SCRIPT"
echo "  - Configuration: $CONFIG_FILE"
echo "  - Status checker: $SCRIPT_DIR/check-monitor-status.sh"
echo "  - Log directory: $LOG_DIR"
echo ""

if [[ ! -f "$CONFIG_FILE" ]] || grep -q "your-tenant-id-here" "$CONFIG_FILE"; then
    echo "⚠️  Remember to configure your Azure AD credentials and email settings!"
fi