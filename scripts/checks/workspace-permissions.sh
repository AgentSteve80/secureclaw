#!/usr/bin/env bash
# workspace-permissions.sh
# Check that cognitive workspace files have restrictive permissions (600 or 640)
# and the workspace directory is 700 or 750.
# Outputs a single JSON object to stdout.

set -euo pipefail

WORKSPACE="${OPENCLAW_WORKSPACE:-/home/claw/.openclaw/workspace}"

# Files that should be permission-restricted
COGNITIVE_FILES=(
  "SOUL.md"
  "MEMORY.md"
  "AGENTS.md"
  "USER.md"
  "IDENTITY.md"
  "HEARTBEAT.md"
  "TOOLS.md"
)

PASSED=true
EVIDENCE_PARTS=()
REMEDIATION_PARTS=()

# Check workspace directory permission
if [ -d "$WORKSPACE" ]; then
  DIR_PERM=$(stat -c "%a" "$WORKSPACE" 2>/dev/null || echo "000")
  # Allow 700 or 750 or 755 (755 is warn, not fail)
  if [ "$DIR_PERM" != "700" ] && [ "$DIR_PERM" != "750" ]; then
    if [ "$DIR_PERM" = "755" ] || [ "$DIR_PERM" = "775" ]; then
      EVIDENCE_PARTS+=("workspace dir has permissions ${DIR_PERM} (world-readable dir)")
      REMEDIATION_PARTS+=("chmod 750 ${WORKSPACE}")
      PASSED=false
    elif [ "$DIR_PERM" = "777" ]; then
      EVIDENCE_PARTS+=("workspace dir has DANGEROUS permissions ${DIR_PERM}")
      REMEDIATION_PARTS+=("chmod 700 ${WORKSPACE}")
      PASSED=false
    fi
  fi
fi

# Check each cognitive file
for FILE in "${COGNITIVE_FILES[@]}"; do
  FPATH="${WORKSPACE}/${FILE}"
  if [ ! -f "$FPATH" ]; then
    continue
  fi
  
  PERM=$(stat -c "%a" "$FPATH" 2>/dev/null || echo "000")
  
  # Acceptable: 600, 640
  # Warning/fail: 644, 664, 666, 777
  case "$PERM" in
    600|640)
      # OK
      ;;
    644|664)
      EVIDENCE_PARTS+=("${FILE} has permissions ${PERM} (world-readable)")
      REMEDIATION_PARTS+=("chmod 600 ${FPATH}")
      PASSED=false
      ;;
    666|777)
      EVIDENCE_PARTS+=("${FILE} has DANGEROUS permissions ${PERM}")
      REMEDIATION_PARTS+=("chmod 600 ${FPATH}")
      PASSED=false
      ;;
    *)
      EVIDENCE_PARTS+=("${FILE} has unexpected permissions ${PERM}")
      REMEDIATION_PARTS+=("chmod 600 ${FPATH}")
      PASSED=false
      ;;
  esac
done

# Check memory/ directory and files
MEMORY_DIR="${WORKSPACE}/memory"
if [ -d "$MEMORY_DIR" ]; then
  while IFS= read -r -d '' MFILE; do
    MPERM=$(stat -c "%a" "$MFILE" 2>/dev/null || echo "000")
    MNAME=$(basename "$MFILE")
    case "$MPERM" in
      600|640|644)
        # 644 is acceptable for memory files (less sensitive than cognitive files)
        ;;
      666|777)
        EVIDENCE_PARTS+=("memory/${MNAME} has DANGEROUS permissions ${MPERM}")
        REMEDIATION_PARTS+=("chmod 640 ${MFILE}")
        PASSED=false
        ;;
    esac
  done < <(find "$MEMORY_DIR" -name "*.md" -print0 2>/dev/null)
fi

# Build evidence string
if [ ${#EVIDENCE_PARTS[@]} -eq 0 ]; then
  EVIDENCE="All cognitive files have appropriate permissions (600/640)"
  REMEDIATION=""
else
  EVIDENCE=$(printf '%s; ' "${EVIDENCE_PARTS[@]}")
  EVIDENCE="${EVIDENCE%; }"
  REMEDIATION=$(printf '%s; ' "${REMEDIATION_PARTS[@]}")
  REMEDIATION="${REMEDIATION%; }"
fi

# Output JSON
cat <<EOF
{
  "checkId": "custom.workspace-permissions",
  "checkName": "Workspace cognitive file permissions",
  "category": "file_permissions",
  "owaspCategory": "ASI06",
  "passed": ${PASSED},
  "severity": "high",
  "evidence": $(printf '%s' "$EVIDENCE" | python3 -c "import sys,json; print(json.dumps(sys.stdin.read()))"),
  "remediation": $(printf '%s' "$REMEDIATION" | python3 -c "import sys,json; print(json.dumps(sys.stdin.read()))")
}
EOF
