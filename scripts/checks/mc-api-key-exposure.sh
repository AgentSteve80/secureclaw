#!/usr/bin/env bash
# mc-api-key-exposure.sh
# Check that CLAW_API_KEY value is not hardcoded in any workspace file.
# The actual key value to check for is in CLAW_API_KEY env var;
# if unset, check for common patterns.
# Outputs a single JSON object to stdout.

set -euo pipefail

WORKSPACE="${OPENCLAW_WORKSPACE:-/home/claw/.openclaw/workspace}"
DATA_DIR="${OPENCLAW_DATA_DIR:-/home/claw/openclaw/data}"

PASSED=true
EVIDENCE_PARTS=()
REMEDIATION_PARTS=()

# Get actual API key from environment (if set)
ACTUAL_KEY="${CLAW_API_KEY:-}"

scan_for_key() {
  local PATTERN="$1"
  local DESCRIPTION="$2"
  local DIR="$3"
  local MAX_DEPTH="${4:-3}"
  
  if [ ! -d "$DIR" ]; then
    return
  fi
  
  while IFS= read -r MATCH_LINE; do
    [ -z "$MATCH_LINE" ] && continue
    FPATH="${MATCH_LINE%%:*}"
    BNAME=$(basename "$FPATH")
    
    # Skip allowed files
    case "$FPATH" in
      */.git/*|*/node_modules/*|*/.env.example|*/secureclaw/*|*/package-lock.json)
        continue
        ;;
    esac
    case "$BNAME" in
      .env.example|*.min.js|*.map)
        continue
        ;;
    esac
    
    MATCH=$(echo "$MATCH_LINE" | sed 's/^[^:]*://' | head -c 120 | tr '\n' ' ')
    # Redact the actual key value in evidence
    if [ -n "$ACTUAL_KEY" ]; then
      MATCH="${MATCH//${ACTUAL_KEY}/[REDACTED]}"
    fi
    EVIDENCE_PARTS+=("${DESCRIPTION} in ${BNAME}: ${MATCH}")
    REMEDIATION_PARTS+=("Remove hardcoded API key from ${BNAME}. Use environment variables instead.")
    PASSED=false
  done < <(grep -rEH "$PATTERN" "$DIR" \
    --include="*.md" --include="*.txt" --include="*.ts" --include="*.js" \
    --include="*.json" --include="*.sh" --include="*.yaml" --include="*.yml" \
    --include="*.env" \
    --exclude-dir=".git" --exclude-dir="node_modules" \
    -m 3 2>/dev/null || true)
}

# If we have the actual key value, scan for it literally
if [ -n "$ACTUAL_KEY" ] && [ "${#ACTUAL_KEY}" -gt 10 ]; then
  # Search for the actual key value in files
  while IFS= read -r FPATH; do
    [ -z "$FPATH" ] && continue
    BNAME=$(basename "$FPATH")
    case "$FPATH" in
      */.git/*|*/node_modules/*|*/secureclaw/*|*/package-lock.json)
        continue
        ;;
    esac
    EVIDENCE_PARTS+=("Actual CLAW_API_KEY value hardcoded in ${BNAME}")
    REMEDIATION_PARTS+=("Remove hardcoded CLAW_API_KEY from ${BNAME} — use CLAW_API_KEY env var")
    PASSED=false
  done < <(grep -rlF "$ACTUAL_KEY" "$WORKSPACE" "$DATA_DIR" \
    --exclude-dir=".git" --exclude-dir="node_modules" \
    --include="*.md" --include="*.ts" --include="*.js" --include="*.json" \
    --include="*.sh" --include="*.yaml" --include="*.yml" \
    2>/dev/null || true)
fi

# Also scan for common key patterns (whether or not we have actual key)
# Pattern: k[0-9A-Za-z]{27}= (Convex key format — base64url 32 bytes)
scan_for_key 'k[0-9A-Za-z+/]{27}=' "Convex API key pattern (k...=)" "$WORKSPACE" 2
scan_for_key 'k[0-9A-Za-z+/]{27}=' "Convex API key pattern (k...=)" "$DATA_DIR" 2

# Pattern: CLAW_API_KEY assignment with actual value
scan_for_key 'CLAW_API_KEY\s*[=:]\s*[k][A-Za-z0-9+/=]{10,}' "CLAW_API_KEY assignment" "$WORKSPACE" 2
scan_for_key 'CLAW_API_KEY\s*[=:]\s*[k][A-Za-z0-9+/=]{10,}' "CLAW_API_KEY assignment" "$DATA_DIR" 2

# Build output
if [ "$PASSED" = "true" ]; then
  EVIDENCE="CLAW_API_KEY not found hardcoded in workspace files"
  REMEDIATION=""
else
  # Deduplicate evidence parts
  EVIDENCE=$(printf '%s\n' "${EVIDENCE_PARTS[@]}" | sort -u | head -5 | tr '\n' '; ')
  EVIDENCE="${EVIDENCE%; }"
  EVIDENCE="${EVIDENCE:0:400}"
  REMEDIATION="Remove all hardcoded API key values from workspace files. Always use CLAW_API_KEY environment variable."
fi

cat <<EOF
{
  "checkId": "custom.mc-api-key-exposure",
  "checkName": "Mission Control API key exposure check",
  "category": "api_key_exposure",
  "owaspCategory": "ASI03",
  "passed": ${PASSED},
  "severity": "critical",
  "evidence": $(printf '%s' "$EVIDENCE" | python3 -c "import sys,json; print(json.dumps(sys.stdin.read()))"),
  "remediation": $(printf '%s' "$REMEDIATION" | python3 -c "import sys,json; print(json.dumps(sys.stdin.read()))")
}
EOF
