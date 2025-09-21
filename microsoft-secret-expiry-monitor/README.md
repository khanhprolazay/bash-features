# Microsoft Secret Key Expiration Monitor

A bash-based monitoring tool that automatically checks Microsoft Azure AD app registrations for expiring client secrets and sends email notifications. Alerts are sent at configurable thresholds (default: 30, 7, and 3 days before expiration).

## Quick Start

1. **Run Setup**:
   ```bash
   ./setup-secret-monitor.sh
   ```

2. **Configure**:
   ```bash
   cp secret-monitor-config.env.template secret-monitor-config.env
   nano secret-monitor-config.env
   ```

3. **Test**:
   ```bash
   ./microsoft-secret-expiry-monitor.sh --dry-run
   ```

## Prerequisites

### Azure AD Setup
1. Create an Azure AD app registration
2. Grant `Application.Read.All` permission
3. Generate a client secret
4. Note down: Tenant ID, Client ID, and Client Secret

### System Requirements
- bash
- curl
- jq
- SMTP server access for email notifications

### Compatibility
- ✅ Linux (GNU date)
- ✅ macOS (BSD date)
- ✅ Cross-platform date handling

## Usage

### Interactive Setup
```bash
# Basic setup with default daily monitoring at 9 AM
./setup-secret-monitor.sh

# Custom schedule - twice daily
CRON_SCHEDULE="0 9,18 * * *" ./setup-secret-monitor.sh

# Skip cron setup (manual execution only)
ENABLE_CRON="false" ./setup-secret-monitor.sh
```

### Manual Execution
```bash
# Test run (no emails sent)
./microsoft-secret-expiry-monitor.sh --dry-run

# Force check all secrets regardless of thresholds
./microsoft-secret-expiry-monitor.sh --force

# Run with custom config file
CONFIG_FILE="/path/to/config.env" ./microsoft-secret-expiry-monitor.sh

# Run with custom log file
LOGFILE="/path/to/custom.log" ./microsoft-secret-expiry-monitor.sh
```

### Check Monitor Status
```bash
# Check if monitor is running and view recent logs
./check-monitor-status.sh
```

## Configuration

### Required Settings (secret-monitor-config.env)
```bash
# Azure AD Configuration
TENANT_ID="your-tenant-id-here"
CLIENT_ID="your-client-id-here"
CLIENT_SECRET="your-client-secret-here"

# Email Configuration
SMTP_SERVER="smtp.gmail.com"
SMTP_PORT="587"
SMTP_USERNAME="your-smtp-username@domain.com"
SMTP_PASSWORD="your-smtp-password-or-app-password"
NOTIFICATION_EMAIL="admin@yourdomain.com"
FROM_EMAIL="noreply@yourdomain.com"
```

### Optional Settings
```bash
# Custom alert thresholds (days before expiration)
ALERT_THRESHOLDS="30 14 7 3 1"

# Cron configuration
ENABLE_CRON="true"
CRON_SCHEDULE="0 9 * * *"
```

### Schedule Examples
```bash
# Daily at 9:00 AM
CRON_SCHEDULE="0 9 * * *"

# Twice daily (9:00 AM and 6:00 PM)
CRON_SCHEDULE="0 9,18 * * *"

# Weekdays only at 9:00 AM
CRON_SCHEDULE="0 9 * * 1-5"

# Every 6 hours
CRON_SCHEDULE="0 */6 * * *"
```

## Files

- `microsoft-secret-expiry-monitor.sh` - Main monitoring script
- `secret-monitor-config.env.template` - Configuration template
- `setup-secret-monitor.sh` - Automated setup script
- `check-monitor-status.sh` - Status checking utility
- `README.md` - This documentation
- `logs/` - Log directory (created automatically)

## Logging

Logs are written to `./logs/secret-monitor.log` by default. Each log entry includes:
- Timestamp
- Script execution status
- Secrets checked and their expiration dates
- Email notifications sent
- Errors encountered

## Troubleshooting

### Common Issues

1. **Authentication Failed**
   - Verify Tenant ID, Client ID, and Client Secret
   - Ensure the app has `Application.Read.All` permission
   - Check if admin consent has been granted

2. **Email Not Sending**
   - Verify SMTP settings
   - For Gmail, use App Password instead of regular password
   - Check firewall/network restrictions

3. **Script Not Running Automatically**
   - Check cron job installation: `crontab -l`
   - Verify script permissions: `chmod +x *.sh`
   - Check system logs for cron errors

### Debug Mode
```bash
# Enable verbose logging
set -x
./microsoft-secret-expiry-monitor.sh --dry-run
```

## Security Considerations

- Store the configuration file securely with restricted permissions
- Use app passwords for email authentication when possible
- Regularly rotate Azure AD client secrets
- Monitor log files for unauthorized access attempts
- Consider using Azure Key Vault for sensitive configuration

## Documentation

For complete documentation, see the Notion page: [Microsoft Secret Key Expiration Monitor](https://www.notion.so/275228989294812eb800ca48357180a2)