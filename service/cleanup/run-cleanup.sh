#!/bin/sh
set -eu

if [ -f /app/cleanup.env ]; then
    . /app/cleanup.env
    export SIGNMEMAYBE_DB_PATH
    export SIGNMEMAYBE_PDF_ROOT
    export SIGNMEMAYBE_EXPORT_ROOT
    export SIGNMEMAYBE_PACKET_ROOT
    export SIGNMEMAYBE_MAX_UPLOAD_BYTES
    export SIGNMEMAYBE_CLEANUP_RETENTION_SECONDS
    export SIGNMEMAYBE_CLEANUP_SWEEP_FILES
    export SIGNMEMAYBE_PCAP_ROOT
    export SIGNMEMAYBE_PCAP_RETENTION_MINUTES
fi

dotnet /app/SignMeMaybe.dll --cleanup-once

pcap_retention_minutes="${SIGNMEMAYBE_PCAP_RETENTION_MINUTES:-30}"
case "$pcap_retention_minutes" in
    ''|*[!0-9]*)
        pcap_retention_minutes=30
        ;;
esac

if [ "$pcap_retention_minutes" -le 0 ]; then
    pcap_retention_minutes=30
fi

if [ -n "${SIGNMEMAYBE_PCAP_ROOT:-}" ] && [ -d "$SIGNMEMAYBE_PCAP_ROOT" ]; then
    find "$SIGNMEMAYBE_PCAP_ROOT" -type f \( -name '*.pcap' -o -name '*.pcapng' -o -name '*.pcap.gz' \) -mmin +"$pcap_retention_minutes" -delete
fi
