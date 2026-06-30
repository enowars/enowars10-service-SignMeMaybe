#!/bin/sh
set -e

mkdir -p /data/pdfs /data/exports /data/notary-vault
chown -R service:service /data

exec su -s /bin/sh -c 'dotnet /app/SignMeMaybe.dll' service
