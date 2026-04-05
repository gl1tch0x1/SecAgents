#!/bin/sh
# One-shot HTTP(S) capture via mitmdump when available; else verbose curl fallback.
set -e
URL="${1:?usage: mitm_sniff.sh <url>}"
if command -v mitmdump >/dev/null 2>&1; then
  OUT="/tmp/mitmflows.$$"
  mitmdump --listen-host 127.0.0.1 --listen-port 8899 -w "$OUT" >/tmp/mitm.log 2>&1 &
  PID=$!
  sleep 2
  echo "=== curl via mitmproxy ==="
  curl -x http://127.0.0.1:8899 -sk "$URL" -D - -o /tmp/mitmbody.$$ 2>&1 | head -c 12000 || true
  echo ""
  kill "$PID" 2>/dev/null || true
  wait "$PID" 2>/dev/null || true
  echo "=== flow file (first 3k, printable filter) ==="
  if test -f "$OUT"; then
    strings "$OUT" 2>/dev/null | head -c 3000 || head -c 3000 "$OUT" | od -A x -t x1z -v | head -40
  fi
  rm -f "$OUT" /tmp/mitmbody.$$ /tmp/mitm.log
else
  echo "mitmdump not available; verbose curl trace:"
  curl -vk "$URL" 2>&1 | head -c 14000 || true
fi
