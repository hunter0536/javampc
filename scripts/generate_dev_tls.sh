#!/usr/bin/env bash
set -euo pipefail

OUT_DIR=${OUT_DIR:-config}
mkdir -p "$OUT_DIR"

CERT="$OUT_DIR/node.crt"
KEY="$OUT_DIR/node.key"
CA="$OUT_DIR/ca.crt"

if command -v openssl >/dev/null 2>&1; then
  openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
    -keyout "$KEY" -out "$CERT" -subj "/CN=mpc-node" >/dev/null 2>&1
  cp "$CERT" "$CA"
  echo "Generated dev cert/key at $CERT and $KEY"
  exit 0
fi

echo "openssl not found. Install openssl or provide your own cert/key."
exit 1
