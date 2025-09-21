#!/usr/bin/env bash

# Microsoft Secret Key Expiration Monitor
# This script monitors Microsoft app registrations for expiring secrets and sends email notifications
# Alerts are sent at 30 days, 7 days, and 3 days before expiration

set -euo pipefail

# Configuration
CONFIG_FILE="${CONFIG_FILE:-./secret-monitor-config.env}"
LOGFILE="${LOGFILE:-./logs/secret-monitor.log}"
DRY_RUN="${DRY_RUN:-false}"

# Default thresholds (in days)
ALERT_THRESHOLDS=(30 7 3)

# Ensure log directory exists
mkdir -p "$(dirname "$LOGFILE")"

# Logging function
log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOGFILE"
}

# Error handling
error_exit() {
    log "ERROR: $1"
    exit 1
}

# Load configuration
load_config() {
    if [[ ! -f "$CONFIG_FILE" ]]; then
        error_exit "Configuration file not found: $CONFIG_FILE"
    fi

    source "$CONFIG_FILE"

    # Validate required environment variables
    local required_vars=(
        "TENANT_ID"
        "CLIENT_ID"
        "CLIENT_SECRET"
        "SMTP_SERVER"
        "SMTP_PORT"
        "SMTP_USERNAME"
        "SMTP_PASSWORD"
        "NOTIFICATION_EMAIL"
        "FROM_EMAIL"
    )

    for var in "${required_vars[@]}"; do
        if [[ -z "${!var:-}" ]]; then
            error_exit "Required environment variable $var is not set"
        fi
    done

    log "Configuration loaded successfully"
}

# Get Microsoft Graph access token
get_access_token() {
    local token_response
    token_response=$(curl -s -X POST \
        "https://login.microsoftonline.com/$TENANT_ID/oauth2/v2.0/token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "client_id=$CLIENT_ID" \
        -d "scope=https://graph.microsoft.com/.default" \
        -d "client_secret=$CLIENT_SECRET" \
        -d "grant_type=client_credentials") || error_exit "Failed to get access token"

    local access_token
    access_token=$(echo "$token_response" | jq -r '.access_token')

    if [[ "$access_token" == "null" ]] || [[ -z "$access_token" ]]; then
        error_exit "Failed to extract access token from response"
    fi

    echo "$access_token"
}

# Get all app registrations
get_app_registrations() {
    local access_token="$1"
    local apps_response

    apps_response=$(curl -s -X GET \
        "https://graph.microsoft.com/v1.0/applications" \
        -H "Authorization: Bearer $access_token" \
        -H "Content-Type: application/json") || error_exit "Failed to get app registrations"

    echo "$apps_response"
}

# Cross-platform date conversion function
date_to_epoch() {
    local date_str="$1"

    # Try GNU date first (Linux)
    if date -d "$date_str" +%s 2>/dev/null; then
        return 0
    fi

    # Try BSD date (macOS)
    if date -j -f "%Y-%m-%d" "$date_str" +%s 2>/dev/null; then
        return 0
    fi

    # If both fail, try parsing ISO format for BSD date
    if [[ "$date_str" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2} ]]; then
        # Extract date part from ISO format
        local date_part="${date_str:0:10}"
        if date -j -f "%Y-%m-%d" "$date_part" +%s 2>/dev/null; then
            return 0
        fi
    fi

    echo "0"
}

# Calculate days until expiration
days_until_expiry() {
    local expiry_date="$1"
    local current_epoch
    local expiry_epoch

    current_epoch=$(date +%s)
    expiry_epoch=$(date_to_epoch "$expiry_date")

    if [[ "$expiry_epoch" -eq 0 ]]; then
        echo "-1"
        return
    fi

    echo $(( (expiry_epoch - current_epoch) / 86400 ))
}

# Format expiry date from ISO format
format_expiry_date() {
    local iso_date="$1"

    # Extract date part from ISO format (YYYY-MM-DDTHH:MM:SS.sssZ)
    local date_part="${iso_date:0:10}"

    # Validate the date format
    if [[ "$date_part" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
        echo "$date_part"
    else
        echo "Invalid Date"
    fi
}

# Check for expiring secrets
check_expiring_secrets() {
    local access_token="$1"
    local apps_json="$2"
    local expiring_secrets=()

    log "Checking for expiring secrets..." >&2

    # Parse applications and check each secret
    while IFS= read -r app; do
        local app_id app_name
        app_id=$(echo "$app" | jq -r '.id')
        app_name=$(echo "$app" | jq -r '.displayName')

        log "Checking app: $app_name ($app_id)" >&2

        # Get password credentials (secrets) for this app
        while IFS= read -r credential; do
            local key_id display_name end_date_time
            key_id=$(echo "$credential" | jq -r '.keyId')
            display_name=$(echo "$credential" | jq -r '.displayName // "Unnamed Secret"')
            end_date_time=$(echo "$credential" | jq -r '.endDateTime')

            if [[ "$end_date_time" != "null" ]] && [[ -n "$end_date_time" ]]; then
                local formatted_date days_left
                formatted_date=$(format_expiry_date "$end_date_time")
                days_left=$(days_until_expiry "$formatted_date")

                log "  Secret: $display_name, expires: $formatted_date, days left: $days_left" >&2

                # Check if secret falls within alert thresholds
                for threshold in "${ALERT_THRESHOLDS[@]}"; do
                    if [[ "$days_left" -eq "$threshold" ]] || [[ "$days_left" -lt 0 ]]; then
                        local status="EXPIRING"
                        if [[ "$days_left" -lt 0 ]]; then
                            status="EXPIRED"
                        fi

                        expiring_secrets+=("$app_name|$display_name|$formatted_date|$days_left|$status|$app_id")
                        log "  *** ALERT: Secret '$display_name' in app '$app_name' $status ($days_left days)" >&2
                        break
                    fi
                done
            fi
        done < <(echo "$app" | jq -c '.passwordCredentials[]?')

    done < <(echo "$apps_json" | jq -c '.value[]')

    # Output only the expiring secrets data to stdout
    printf '%s\n' "${expiring_secrets[@]}"
}

# Generate email content
generate_email_content() {
    local expiring_secrets=("$@")
    local email_subject email_body

    if [[ ${#expiring_secrets[@]} -eq 0 ]]; then
        return 0
    fi

    email_subject="[ALERT] Microsoft App Secret Keys Expiring Soon"

    cat << EOF
Subject: $email_subject
From: $FROM_EMAIL
To: $NOTIFICATION_EMAIL
Content-Type: text/html; charset=UTF-8

<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #d73527; color: white; padding: 15px; border-radius: 5px; }
        .content { margin: 20px 0; }
        .secret-item {
            border: 1px solid #ddd;
            margin: 10px 0;
            padding: 15px;
            border-radius: 5px;
            background-color: #f9f9f9;
        }
        .expired { border-left: 5px solid #d73527; background-color: #ffeaa7; }
        .expiring { border-left: 5px solid #fdcb6e; background-color: #fff3cd; }
        .details { font-size: 14px; color: #666; margin-top: 10px; }
        .footer { margin-top: 30px; padding: 15px; background-color: #f8f9fa; border-radius: 5px; }
    </style>
</head>
<body>
    <div class="header">
        <h2>🚨 Microsoft App Secret Key Expiration Alert</h2>
        <p>Generated on: $(date +'%Y-%m-%d %H:%M:%S')</p>
    </div>

    <div class="content">
        <p>The following Microsoft app secret keys require immediate attention:</p>
EOF

    for secret_info in "${expiring_secrets[@]}"; do
        IFS='|' read -r app_name secret_name expiry_date days_left status app_id <<< "$secret_info"

        local css_class="expiring"
        local icon="⚠️"
        if [[ "$status" == "EXPIRED" ]]; then
            css_class="expired"
            icon="🚨"
        fi

        cat << EOF
        <div class="secret-item $css_class">
            <h3>$icon $app_name</h3>
            <p><strong>Secret Name:</strong> $secret_name</p>
            <p><strong>Expiry Date:</strong> $expiry_date</p>
            <p><strong>Days Remaining:</strong> $days_left</p>
            <p><strong>Status:</strong> $status</p>
            <div class="details">
                <p><strong>App ID:</strong> $app_id</p>
                <p><strong>Action Required:</strong>
EOF

        if [[ "$status" == "EXPIRED" ]]; then
            echo "Generate new secret immediately - this secret has already expired!"
        else
            echo "Generate new secret within $days_left days to avoid service disruption."
        fi

        cat << EOF
                </p>
            </div>
        </div>
EOF
    done

    cat << EOF
    </div>

    <div class="footer">
        <h3>📋 Next Steps:</h3>
        <ol>
            <li>Log into Azure Portal</li>
            <li>Navigate to Azure Active Directory > App registrations</li>
            <li>Select the affected application</li>
            <li>Go to "Certificates & secrets"</li>
            <li>Create a new client secret</li>
            <li>Update your application configuration with the new secret</li>
            <li>Remove the old secret after confirming the new one works</li>
        </ol>

        <p><strong>Important:</strong> Plan this update during maintenance windows to avoid service disruption.</p>

        <hr>
        <p style="font-size: 12px; color: #666;">
            This alert was generated by the OHBI Microsoft Secret Expiry Monitor.<br>
            Script location: obis-be/microsoft-secret-expiry-monitor.sh
        </p>
    </div>
</body>
</html>
EOF
}

# Send email notification
send_email() {
    local email_content="$1"

    if [[ "$DRY_RUN" == "true" ]]; then
        log "DRY RUN: Would send email notification"
        echo "=== EMAIL CONTENT ==="
        echo "$email_content"
        echo "===================="
        return 0
    fi

    # Use SMTP with curl
    local temp_file
    temp_file=$(mktemp)
    echo "$email_content" > "$temp_file"

    # Determine the correct URL scheme and options based on port
    local smtp_url
    local curl_opts=()

    if [[ "$SMTP_PORT" == "465" ]]; then
        # SMTPS (SSL/TLS on port 465)
        smtp_url="smtps://$SMTP_SERVER:$SMTP_PORT"
        curl_opts+=(--ssl-reqd)
    elif [[ "$SMTP_PORT" == "587" ]]; then
        # SMTP with STARTTLS (port 587)
        smtp_url="smtp://$SMTP_SERVER:$SMTP_PORT"
        curl_opts+=(--ssl-reqd)
    else
        # Plain SMTP (fallback)
        smtp_url="smtp://$SMTP_SERVER:$SMTP_PORT"
    fi

    log "Sending email via SMTP to $NOTIFICATION_EMAIL..."

    curl -s --url "$smtp_url" \
            "${curl_opts[@]}" \
            --mail-from "$FROM_EMAIL" \
            --mail-rcpt "$NOTIFICATION_EMAIL" \
            --user "$SMTP_USERNAME:$SMTP_PASSWORD" \
            --upload-file "$temp_file" || error_exit "Failed to send email via SMTP"

    log "Email sent successfully via SMTP"

    rm -f "$temp_file"
}

# Main execution
main() {
    log "Starting Microsoft Secret Expiry Monitor"

    # Load configuration
    load_config

    # Get access token
    log "Authenticating with Microsoft Graph API..."
    local access_token
    access_token=$(get_access_token)

    # Get app registrations
    log "Fetching app registrations..."
    local apps_json
    apps_json=$(get_app_registrations "$access_token")

    # Check for expiring secrets
    local expiring_secrets_array
    readarray -t expiring_secrets_array < <(check_expiring_secrets "$access_token" "$apps_json")

    # Send notifications if there are expiring secrets
    if [[ ${#expiring_secrets_array[@]} -gt 0 ]]; then
        log "Found ${#expiring_secrets_array[@]} expiring secret(s), sending notification..."
        local email_content
        email_content=$(generate_email_content "${expiring_secrets_array[@]}")
        send_email "$email_content"
    else
        log "No expiring secrets found"
    fi

    log "Microsoft Secret Expiry Monitor completed successfully"
}

# Show usage information
usage() {
    cat << EOF
Microsoft Secret Key Expiration Monitor

Usage: $0 [OPTIONS]

Options:
    -c, --config FILE       Configuration file path (default: ./secret-monitor-config.env)
    -l, --log FILE         Log file path (default: ./logs/secret-monitor.log)
    -d, --dry-run          Dry run mode - don't send emails, just show what would be sent
    -h, --help             Show this help message

Environment Variables (can be set in config file):
    TENANT_ID              Azure AD tenant ID
    CLIENT_ID              Azure AD application (client) ID
    CLIENT_SECRET          Azure AD application client secret
    SMTP_SERVER            SMTP server hostname
    SMTP_PORT              SMTP server port (usually 587 or 465)
    SMTP_USERNAME          SMTP username
    SMTP_PASSWORD          SMTP password
    NOTIFICATION_EMAIL     Email address to send alerts to
    FROM_EMAIL             Email address to send alerts from

Example:
    $0 --config ./config/prod.env --log ./logs/monitor.log
    CONFIG_FILE=./config/dev.env DRY_RUN=true $0
EOF
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -c|--config)
            CONFIG_FILE="$2"
            shift 2
            ;;
        -l|--log)
            LOGFILE="$2"
            shift 2
            ;;
        -d|--dry-run)
            DRY_RUN="true"
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

# Check dependencies
for cmd in curl jq date; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        error_exit "Required command not found: $cmd"
    fi
done

# Run main function
main "$@"