#!/bin/sh
set -eu

if [ -f /app/cleanup.env ]; then
    . /app/cleanup.env
    export SIGNMEMAYBE_DB_PATH
    export SIGNMEMAYBE_PDF_ROOT
    export SIGNMEMAYBE_EXPORT_ROOT
    export SIGNMEMAYBE_MAX_UPLOAD_BYTES
    export SIGNMEMAYBE_CLEANUP_RETENTION_SECONDS
fi

dotnet /app/SignMeMaybe.dll --cleanup-once
