#!/usr/bin/env bash
# cron-injection.sh
# Check HEARTBEAT.md and any cron job configuration files for suspicious patterns
# like external URLs in payloads, eval, base64 -d, curl | sh, wget | sh patterns.
# These patterns indicate potential cron/heartbeat injection.
# Outputs a single JSON object to stdout.

set -euo pipefail

WORKSPACE="${OPENCLAW_WORKSPACE:-/home/claw/.openclaw/workspace}"
DATA_DIR="${OPENCLAW_DATA_DIR:-/home/claw/openclaw/data}"

PASSED=true
EVIDENCE_PARTS=()
REMEDIATION_PARTS=()

# Suspicious patterns that should NOT appear in HEARTBEAT.md or cron config files
INJECTION_PATTERNS=(
  'curl\s+[^|]*\|\s*(ba)?sh'
  'wget\s+[^|]*\|\s*(ba)?sh'
  'curl\s+[^|]*\|\s*bash'
  'wget\s+-O-\s+[^|]*\|\s*(ba)?sh'
  'eval\s*\$\('
  'eval\s*`'
  'base64\s+-d\s+.*\|\s*(ba)?sh'
  'base64\s+--decode.*\|\s*(ba)?sh'
  '\|\s*xargs\s+.*bash'
  'python\s+-c\s+.*exec\s*\('
  'python3\s+-c\s+.*exec\s*\('
  'nc\s+.*\s+-e\s+/bin/(ba)?sh'
  'bash\s+-i\s+>&'
  '/dev/tcp/'
  'rm\s+-rf\s+[/~]'
  'chmod\s+777\s+/'
)

# Files to check for injection patterns
FILES_TO_CHECK=()

# HEARTBEAT.md
if [ -f "${WORKSPACE}/HEARTBEAT.md" ]; then
  FILES_TO_CHECK+=("${WORKSPACE}/HEARTBEAT.md")
fi

# Only check user crontab, NOT system cron dirs
# System cron files (apt-compat, logrotate, etc.) legitimately use eval/shell patterns
# and would produce persistent false positives.

# Check user crontab (if readable)
USER_CRON=$(crontab -l 2>/dev/null || true)
if [ -n "$USER_CRON" ]; then
  # Write to temp file for scanning
  TMPFILE=$(mktemp)
  trap 'rm -f "$TMPFILE"' EXIT
  echo "$USER_CRON" > "$TMPFILE"
  FILES_TO_CHECK+=("$TMPFILE")
fi

# Check any .openclaw config files that might have cron definitions
if [ -d "/home/claw/.openclaw" ]; then
  while IFS= read -r -d '' CONF; do
    FILES_TO_CHECK+=("$CONF")
  done < <(find "/home/claw/.openclaw" -name "cron*.json" -o -name "schedules*.json" -print0 2>/dev/null)
fi

# Scan each file for injection patterns
for FPATH in "${FILES_TO_CHECK[@]}"; do
  [ -f "$FPATH" ] || continue
  BNAME=$(basename "$FPATH")
  
  for PATTERN in "${INJECTION_PATTERNS[@]}"; do
    if grep -qiE "$PATTERN" "$FPATH" 2>/dev/null; then
      MATCH=$(grep -iEm1 "$PATTERN" "$FPATH" 2>/dev/null | head -c 150 | tr '\n' ' ' || true)
      EVIDENCE_PARTS+=("Suspicious pattern in ${BNAME}: ${MATCH}")
      REMEDIATION_PARTS+=("Review ${BNAME} for injected commands. Remove suspicious patterns before they execute.")
      PASSED=false
    fi
  done
  
  # Also check for external URL fetching in HEARTBEAT.md
  if [[ "$BNAME" == "HEARTBEAT.md" ]]; then
    # Look for external HTTP calls to non-standard domains
    while IFS= read -r LINE; do
      if echo "$LINE" | grep -qE 'https?://(?!curious-wolverine-246|convex\.dev|github\.com|api\.anthropic\.com|api\.openai\.com)[a-zA-Z0-9.-]+\.[a-z]{2,}' 2>/dev/null; then
        URL=$(echo "$LINE" | grep -oE 'https?://[a-zA-Z0-9./-]+' | head -1)
        EVIDENCE_PARTS+=("External URL in HEARTBEAT.md: ${URL:0:80}")
        REMEDIATION_PARTS+=("Review external URL in HEARTBEAT.md: ${URL:0:80}. Ensure it's a trusted endpoint.")
        # This is a warning, not necessarily a fail — external URLs can be legitimate
        # Only fail if it's combined with | sh patterns (already caught above)
      fi
    done < "$FPATH"
  fi
done

# Build output
if [ "$PASSED" = "true" ]; then
  EVIDENCE="No injection patterns found in HEARTBEAT.md or cron configuration"
  REMEDIATION=""
else
  EVIDENCE=$(printf '%s; ' "${EVIDENCE_PARTS[@]}")
  EVIDENCE="${EVIDENCE%; }"
  EVIDENCE="${EVIDENCE:0:400}"
  REMEDIATION=$(printf '%s; ' "${REMEDIATION_PARTS[@]}")
  REMEDIATION="${REMEDIATION%; }"
fi

cat <<EOF
{
  "checkId": "custom.cron-injection",
  "checkName": "Cron and heartbeat injection check",
  "category": "cron_injection",
  "owaspCategory": "ASI01",
  "passed": ${PASSED},
  "severity": "critical",
  "evidence": $(printf '%s' "$EVIDENCE" | python3 -c "import sys,json; print(json.dumps(sys.stdin.read()))"),
  "remediation": $(printf '%s' "$REMEDIATION" | python3 -c "import sys,json; print(json.dumps(sys.stdin.read()))")
}
EOF
