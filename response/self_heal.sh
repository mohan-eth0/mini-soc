#!/bin/bash

SERVICE="openvpn"          # change to php7.4-fpm, nginx, your-app, etc.
LOGFILE="/var/log/self_heal.log"
DATE="$(date '+%Y-%m-%d %H:%M:%S')"

# Check service status
systemctl is-active --quiet $SERVICE
STATUS=$?

if [ $STATUS -ne 0 ]; then
    echo "[$DATE] ALERT: $SERVICE was DOWN. Attempting restart..." >> $LOGFILE

    systemctl restart $SERVICE

    # Re-check
    systemctl is-active --quiet $SERVICE
    if [ $? -eq 0 ]; then
        echo "[$DATE] SUCCESS: $SERVICE restarted successfully." >> $LOGFILE
        echo "[HEALED] $SERVICE was down and is now running."
    else
        echo "[$DATE] FAILURE: $SERVICE restart failed." >> $LOGFILE
        echo "[FAILED] $SERVICE could NOT be restarted."
    fi
else
    echo "[$DATE] OK: $SERVICE is running." >> $LOGFILE
fi
