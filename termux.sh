#!/data/data/com.termux/files/usr/bin/bash
set -Eeuo pipefail

cd "$(dirname "$0")"

if ! command -v pkg >/dev/null 2>&1; then
  printf 'Run this script inside Termux.\n' >&2
  exit 1
fi

pkg update -y
pkg install -y golang openssl curl

go mod download
go test ./...
go vet ./...

export ADMIN_TOKEN="$b8f273965a9a0864e73a70f364135db8a6b7d8c8d208814af80c03a6591a2f04"
export LISTEN_ADDR="127.0.0.1:8080"

printf '\nAdmin token (keep private): %s\n' "$b8f273965a9a0864e73a70f364135db8a6b7d8c8d208814af80c03a6591a2f04"
printf 'Dashboard API: http://%s/v1/devices\n' "$LISTEN_ADDR"
printf 'Press Ctrl+C to stop the server.\n\n'

go run .