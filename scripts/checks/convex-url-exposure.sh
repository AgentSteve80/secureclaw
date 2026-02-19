#!/usr/bin/env bash
# convex-url-exposure.sh
# Scan ~/openclaw/data/*.md, *.json, *.log for the Convex deployment URL
# appearing outside of architecture/research documents (where it legitimately belongs).
# Fail if found in session logs or task-log.md outside of legitimate contexts.
# Outputs a single JSON object to stdout.

set -euo pipefail

DATA_DIR="${OPENCLAW_DATA_DIR:-/home/claw/openclaw/data}"
CONVEX_SLUG="curious-wolverine-246"

PASSED=true
EVIDENCE_PARTS=()
REMEDIATION_PARTS=()

# Files where the Convex URL legitimately appears (architecture docs, research)
ALLOWED_PATTERNS=(
  "architecture-*.md"
  "architecture-*.json"
  "research-*.md"
  "build-report-*.md"
  "daily-report.md"
  "README.md"
  "test-report-*.md"
  "task-log.md"
)

is_allowed_file() {
  local fname="$1"
  local basename_f
  basename_f=$(basename "$fname")
  
  for PATTERN in "${ALLOWED_PATTERNS[@]}"; do
    # shellcheck disable=SC2254
    case "$basename_f" in
      $PATTERN)
        return 0  # allowed
        ;;
    esac
  done
  return 1  # not allowed
}

# Scan files for the Convex slug
if [ -d "$DATA_DIR" ]; then
  # Check .md files
  while IFS= read -r -d '' FILE; do
    if is_allowed_file "$FILE"; then
      continue
    fi
    
    if grep -q "$CONVEX_SLUG" "$FILE" 2>/dev/null; then
      FNAME=$(basename "$FILE")
      # Get the line content (first match, truncated)
      MATCH=$(grep -m1 "$CONVEX_SLUG" "$FILE" 2>/dev/null | head -c 150 | tr '\n' ' ')
      EVIDENCE_PARTS+=("${FNAME} contains Convex deployment URL: ${MATCH}")
      REMEDIATION_PARTS+=("Review and redact Convex URL from ${FNAME}")
      PASSED=false
    fi
  done < <(find "$DATA_DIR" -maxdepth 2 \( -name "*.md" -o -name "*.json" -o -name "*.log" \) -not -name "architecture-*" -not -name "research-*" -not -name "build-report-*" -print0 2>/dev/null)
  
  # Also check task-log.md specifically (it can grow large and accumulate URLs)
  TASKLOG="${DATA_DIR}/task-log.md"
  if [ -f "$TASKLOG" ]; then
    # task-log.md is allowed to reference it in build context, but warn if excessive
    COUNT=$(grep -c "$CONVEX_SLUG" "$TASKLOG" 2>/dev/null || echo "0")
    if [ "$COUNT" -gt 10 ]; then
      EVIDENCE_PARTS+=("task-log.md has ${COUNT} occurrences of Convex URL — may indicate URL leakage in logged content")
      REMEDIATION_PARTS+=("Review task-log.md and remove any raw Convex URLs from log entries")
      PASSED=false
    fi
  fi
fi

# Also check workspace files (not just data dir)
WORKSPACE="${OPENCLAW_WORKSPACE:-/home/claw/.openclaw/workspace}"
WORKSPACE_EXCLUDE_PATTERNS=("*.git/*" "node_modules/*")

# Quick scan of workspace root files (not subdirectories to avoid false positives in code)
while IFS= read -r -d '' FILE; do
  if grep -q "$CONVEX_SLUG" "$FILE" 2>/dev/null; then
    FNAME=$(basename "$FILE")
    MATCH=$(grep -m1 "$CONVEX_SLUG" "$FILE" 2>/dev/null | head -c 150 | tr '\n' ' ')
    EVIDENCE_PARTS+=("workspace/${FNAME} contains Convex deployment URL: ${MATCH}")
    REMEDIATION_PARTS+=("Review workspace/${FNAME} for inadvertent URL exposure")
    PASSED=false
  fi
done < <(find "$WORKSPACE" -maxdepth 1 \( -name "*.md" -o -name "*.txt" \) -print0 2>/dev/null)

# Build output
if [ "$PASSED" = "true" ]; then
  EVIDENCE="Convex deployment URL not found in unexpected files"
  REMEDIATION=""
else
  EVIDENCE=$(printf '%s; ' "${EVIDENCE_PARTS[@]}")
  EVIDENCE="${EVIDENCE%; }"
  REMEDIATION=$(printf '%s; ' "${REMEDIATION_PARTS[@]}")
  REMEDIATION="${REMEDIATION%; }"
fi

cat <<EOF
{
  "checkId": "custom.convex-url-exposure",
  "checkName": "Convex deployment URL exposure check",
  "category": "config_exposure",
  "owaspCategory": "ASI03",
  "passed": ${PASSED},
  "severity": "medium",
  "evidence": $(printf '%s' "$EVIDENCE" | python3 -c "import sys,json; print(json.dumps(sys.stdin.read()))"),
  "remediation": $(printf '%s' "$REMEDIATION" | python3 -c "import sys,json; print(json.dumps(sys.stdin.read()))")
}
EOF
