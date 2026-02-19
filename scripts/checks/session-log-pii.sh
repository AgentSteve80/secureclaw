#!/usr/bin/env bash
# session-log-pii.sh
# Scan ~/openclaw/data/ for patterns indicating PII or credentials in session logs.
# Patterns: sk-[A-Za-z0-9]{20,}, key-[A-Za-z0-9]{20,}, ghp_[A-Za-z0-9]+,
#           "api_key", "password", "secret" in plaintext
# Severity=critical if found.
# Outputs a single JSON object to stdout.

set -euo pipefail

DATA_DIR="${OPENCLAW_DATA_DIR:-/home/claw/openclaw/data}"
WORKSPACE="${OPENCLAW_WORKSPACE:-/home/claw/.openclaw/workspace}"

PASSED=true
EVIDENCE_PARTS=()
REMEDIATION_PARTS=()

# Regex patterns to search for (grep -E compatible)
# We use grep --include to limit to text files only
CREDENTIAL_PATTERNS=(
  'sk-[A-Za-z0-9]{20,}'
  'ghp_[A-Za-z0-9]{10,}'
  'ghs_[A-Za-z0-9]{10,}'
  'ghr_[A-Za-z0-9]{10,}'
  'xoxb-[0-9]+-[A-Za-z0-9]+'
  'ANTHROPIC_API_KEY\s*=\s*[A-Za-z0-9+/=-]{20,}'
  'OPENAI_API_KEY\s*=\s*[A-Za-z0-9+/=-]{20,}'
  'CLAW_API_KEY\s*=\s*[A-Za-z0-9+/=]{20,}'
)

# Plaintext keyword patterns (less severe — look for assignment/disclosure)
KEYWORD_PATTERNS=(
  '"api_key"\s*:\s*"[^"]{8,}"'
  '"password"\s*:\s*"[^"]{4,}"'
  '"secret"\s*:\s*"[^"]{8,}"'
  '"token"\s*:\s*"[^"]{20,}"'
  'api_key\s*=\s*[A-Za-z0-9+/=]{8,}'
  'password\s*=\s*[^\s]{4,}'
)

scan_directory() {
  local DIR="$1"
  local MAX_DEPTH="${2:-3}"
  
  if [ ! -d "$DIR" ]; then
    return
  fi
  
  # Scan for credential patterns (high severity)
  for PATTERN in "${CREDENTIAL_PATTERNS[@]}"; do
    while IFS= read -r LINE; do
      if [ -z "$LINE" ]; then continue; fi
      # Extract filename (before the colon)
      FNAME="${LINE%%:*}"
      BNAME=$(basename "$FNAME")
      # Skip git objects and binary files
      case "$FNAME" in
        */.git/*|*/node_modules/*|*.png|*.jpg|*.gif|*.bin|*.lock)
          continue
          ;;
      esac
      MATCH=$(echo "$LINE" | sed 's/^[^:]*://; s/^[0-9]*://; s/^\s*//' | head -c 100)
      EVIDENCE_PARTS+=("Credential pattern in ${BNAME}: ${MATCH}")
      REMEDIATION_PARTS+=("Remove credential from ${BNAME} and rotate the key if exposed")
      PASSED=false
    done < <(grep -rEil "$PATTERN" "$DIR" --include="*.md" --include="*.txt" --include="*.log" --include="*.json" -m 1 2>/dev/null | while read -r f; do grep -EH "$PATTERN" "$f" -m 1 2>/dev/null; done || true)
  done
}

scan_keywords() {
  local DIR="$1"
  
  if [ ! -d "$DIR" ]; then
    return
  fi
  
  for PATTERN in "${KEYWORD_PATTERNS[@]}"; do
    while IFS= read -r LINE; do
      if [ -z "$LINE" ]; then continue; fi
      FNAME="${LINE%%:*}"
      BNAME=$(basename "$FNAME")
      case "$FNAME" in
        */.git/*|*/node_modules/*|*.png|*.jpg|*.gif|*.bin)
          continue
          ;;
      esac
      # Only flag if in log or session files (not architecture docs)
      case "$BNAME" in
        architecture-*|research-*|build-report-*)
          continue
          ;;
      esac
      MATCH=$(echo "$LINE" | sed 's/^[^:]*://; s/^[0-9]*://; s/^\s*//' | head -c 100)
      EVIDENCE_PARTS+=("Keyword pattern '${PATTERN:0:20}' in ${BNAME}: ${MATCH}")
      REMEDIATION_PARTS+=("Review ${BNAME} for plaintext credentials")
      PASSED=false
    done < <(grep -rEil "$PATTERN" "$DIR" --include="*.md" --include="*.log" --include="*.json" -m 1 2>/dev/null | while read -r f; do grep -EH "$PATTERN" "$f" -m 1 2>/dev/null; done || true)
  done
}

# Scan data directory
scan_directory "$DATA_DIR" 2
scan_keywords "$DATA_DIR"

# Scan workspace root (not subdirectories — too noisy)
if [ -d "$WORKSPACE" ]; then
  for WFILE in "$WORKSPACE"/*.md "$WORKSPACE"/*.txt "$WORKSPACE"/*.log; do
    [ -f "$WFILE" ] || continue
    BNAME=$(basename "$WFILE")
    for PATTERN in "${CREDENTIAL_PATTERNS[@]}"; do
      if grep -qE "$PATTERN" "$WFILE" 2>/dev/null; then
        MATCH=$(grep -Em1 "$PATTERN" "$WFILE" 2>/dev/null | head -c 100 || true)
        EVIDENCE_PARTS+=("Workspace credential in ${BNAME}: ${MATCH}")
        REMEDIATION_PARTS+=("Remove credential from ${BNAME}")
        PASSED=false
      fi
    done
  done
fi

# Build output
if [ "$PASSED" = "true" ]; then
  EVIDENCE="No credential or PII patterns found in session logs"
  REMEDIATION=""
else
  EVIDENCE=$(printf '%s; ' "${EVIDENCE_PARTS[@]}")
  EVIDENCE="${EVIDENCE%; }"
  # Limit evidence to 400 chars
  EVIDENCE="${EVIDENCE:0:400}"
  REMEDIATION=$(printf '%s; ' "${REMEDIATION_PARTS[@]}")
  REMEDIATION="${REMEDIATION%; }"
fi

cat <<EOF
{
  "checkId": "custom.session-log-pii",
  "checkName": "Session log PII and credential scan",
  "category": "credential_exposure",
  "owaspCategory": "ASI03",
  "passed": ${PASSED},
  "severity": "critical",
  "evidence": $(printf '%s' "$EVIDENCE" | python3 -c "import sys,json; print(json.dumps(sys.stdin.read()))"),
  "remediation": $(printf '%s' "$REMEDIATION" | python3 -c "import sys,json; print(json.dumps(sys.stdin.read()))")
}
EOF
