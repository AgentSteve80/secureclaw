#!/usr/bin/env bash
# cognitive-file-trust.sh
# Check that cognitive files (SOUL.md, AGENTS.md) contain trust level metadata markers.
# Pass if trust level markers present, fail with severity=medium if absent.
# Outputs a single JSON object to stdout.

set -euo pipefail

WORKSPACE="${OPENCLAW_WORKSPACE:-/home/claw/.openclaw/workspace}"

PASSED=true
EVIDENCE_PARTS=()
MISSING_FILES=()

# Files to check for trust level metadata
TRUST_FILES=(
  "SOUL.md"
  "AGENTS.md"
)

# Patterns that indicate trust level metadata is present
TRUST_PATTERNS=(
  "## Trust Level"
  "Trust Level:"
  "trust_level"
  "TRUSTED"
  "trust level"
  "Source Trust"
  "## Trust"
)

check_file_for_trust_markers() {
  local fpath="$1"
  local fname="$2"
  
  if [ ! -f "$fpath" ]; then
    EVIDENCE_PARTS+=("${fname} not found (cannot verify trust metadata)")
    return
  fi
  
  local found=false
  for PATTERN in "${TRUST_PATTERNS[@]}"; do
    if grep -qi "$PATTERN" "$fpath" 2>/dev/null; then
      found=true
      break
    fi
  done
  
  if [ "$found" = "false" ]; then
    MISSING_FILES+=("$fname")
    EVIDENCE_PARTS+=("${fname} missing trust level metadata markers")
    PASSED=false
  fi
}

for FILE in "${TRUST_FILES[@]}"; do
  check_file_for_trust_markers "${WORKSPACE}/${FILE}" "$FILE"
done

# Build evidence and remediation strings
if [ "$PASSED" = "true" ]; then
  EVIDENCE="Trust level metadata found in all cognitive files"
  REMEDIATION=""
else
  EVIDENCE=$(printf '%s; ' "${EVIDENCE_PARTS[@]}")
  EVIDENCE="${EVIDENCE%; }"
  
  # Build remediation
  MISSING_LIST=$(printf '%s, ' "${MISSING_FILES[@]}")
  MISSING_LIST="${MISSING_LIST%, }"
  REMEDIATION="Add '## Trust Level:' section to ${MISSING_LIST}. See skill/rules/source-trust-levels.md for the standard format."
fi

# Output JSON
cat <<EOF
{
  "checkId": "custom.cognitive-file-trust",
  "checkName": "Cognitive file trust level metadata",
  "category": "cognitive_file",
  "owaspCategory": "ASI06",
  "passed": ${PASSED},
  "severity": "medium",
  "evidence": $(printf '%s' "$EVIDENCE" | python3 -c "import sys,json; print(json.dumps(sys.stdin.read()))"),
  "remediation": $(printf '%s' "$REMEDIATION" | python3 -c "import sys,json; print(json.dumps(sys.stdin.read()))")
}
EOF
