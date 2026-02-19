#!/usr/bin/env bash
# git-secret-scan.sh
# Check the workspace git repository (if it is one) for committed secrets
# by scanning recent git log patches with grep for credential patterns.
# Outputs a single JSON object to stdout.

set -euo pipefail

WORKSPACE="${OPENCLAW_WORKSPACE:-/home/claw/.openclaw/workspace}"

PASSED=true
EVIDENCE_PARTS=()
REMEDIATION_PARTS=()
IS_GIT_REPO=false

# Check if workspace is a git repository
if git -C "$WORKSPACE" rev-parse --git-dir >/dev/null 2>&1; then
  IS_GIT_REPO=true
else
  # Not a git repo — this is fine, report as passed with info
  cat <<EOF
{
  "checkId": "custom.git-secret-scan",
  "checkName": "Git history secret scan",
  "category": "credential_exposure",
  "owaspCategory": "ASI03",
  "passed": true,
  "severity": "high",
  "evidence": "Workspace is not a git repository — no git history to scan",
  "remediation": ""
}
EOF
  exit 0
fi

# Credential patterns to search for in git diffs
SECRET_PATTERNS=(
  'sk-[A-Za-z0-9]{20,}'
  'ghp_[A-Za-z0-9]{10,}'
  'ghs_[A-Za-z0-9]{10,}'
  'ANTHROPIC_API_KEY\s*=\s*[A-Za-z0-9+/=-]{10,}'
  'OPENAI_API_KEY\s*=\s*[A-Za-z0-9+/=-]{10,}'
  'CLAW_API_KEY\s*=\s*[A-Za-z0-9+/=]{10,}'
  'k[A-Za-z0-9+/]{27}='
)

# Get number of commits (scan last 50 or all if fewer)
COMMIT_COUNT=$(git -C "$WORKSPACE" rev-list --count HEAD 2>/dev/null || echo "0")
SCAN_COUNT=$(( COMMIT_COUNT < 50 ? COMMIT_COUNT : 50 ))

if [ "$SCAN_COUNT" -eq 0 ]; then
  cat <<EOF
{
  "checkId": "custom.git-secret-scan",
  "checkName": "Git history secret scan",
  "category": "credential_exposure",
  "owaspCategory": "ASI03",
  "passed": true,
  "severity": "high",
  "evidence": "Git repository has no commits to scan",
  "remediation": ""
}
EOF
  exit 0
fi

# Scan git log patches for secret patterns
# Use a temp file to avoid pipe/subshell issues with PASSED variable
TMPFILE=$(mktemp)
trap 'rm -f "$TMPFILE"' EXIT

# Write the git diff output to temp file for pattern matching
git -C "$WORKSPACE" log --all --oneline -"$SCAN_COUNT" --format="%H %s" 2>/dev/null | \
while IFS= read -r COMMIT_LINE; do
  HASH="${COMMIT_LINE%% *}"
  SUBJECT="${COMMIT_LINE#* }"
  
  for PATTERN in "${SECRET_PATTERNS[@]}"; do
    if git -C "$WORKSPACE" show "$HASH" 2>/dev/null | grep -qE "^\\+.*${PATTERN}" 2>/dev/null; then
      MATCH=$(git -C "$WORKSPACE" show "$HASH" 2>/dev/null | \
              grep -Em1 "^\\+.*${PATTERN}" 2>/dev/null | \
              head -c 120 | tr '\n' ' ' || true)
      echo "FINDING: Commit ${HASH:0:8} ('${SUBJECT:0:40}'): ${MATCH:0:100}" >> "$TMPFILE"
    fi
  done
done

# Read findings from temp file
if [ -s "$TMPFILE" ]; then
  PASSED=false
  while IFS= read -r LINE; do
    EVIDENCE_PARTS+=("$LINE")
    REMEDIATION_PARTS+=("Use 'git filter-branch' or BFG Repo Cleaner to purge secrets from git history. Rotate any exposed credentials immediately.")
  done < "$TMPFILE"
fi

# Build output
if [ "$PASSED" = "true" ]; then
  EVIDENCE="No secret patterns found in last ${SCAN_COUNT} commits of workspace git history"
  REMEDIATION=""
else
  EVIDENCE=$(printf '%s; ' "${EVIDENCE_PARTS[@]}")
  EVIDENCE="${EVIDENCE%; }"
  EVIDENCE="${EVIDENCE:0:400}"
  REMEDIATION="Remove secrets from git history using BFG Repo Cleaner or git filter-repo. Rotate all exposed credentials immediately. See: https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository"
fi

cat <<EOF
{
  "checkId": "custom.git-secret-scan",
  "checkName": "Git history secret scan",
  "category": "credential_exposure",
  "owaspCategory": "ASI03",
  "passed": ${PASSED},
  "severity": "high",
  "evidence": $(printf '%s' "$EVIDENCE" | python3 -c "import sys,json; print(json.dumps(sys.stdin.read()))"),
  "remediation": $(printf '%s' "$REMEDIATION" | python3 -c "import sys,json; print(json.dumps(sys.stdin.read()))")
}
EOF
