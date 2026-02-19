#!/usr/bin/env bash
# run-audit.sh
# One-shot full audit entrypoint.
# Runs SecureClaw + all custom checks and pushes results to Convex.
# Usage: ./scripts/run-audit.sh [full|quick|supply-chain] [--dry-run] [--verbose]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "${SCRIPT_DIR}")"
RUNNER_DIR="${REPO_ROOT}/packages/audit-runner"

# Parse arguments
AUDIT_TYPE="${1:-full}"
DRY_RUN_FLAG=""
VERBOSE_FLAG=""

for ARG in "${@:2}"; do
  case "$ARG" in
    --dry-run) DRY_RUN_FLAG="--dry-run" ;;
    --verbose|-v) VERBOSE_FLAG="--verbose" ;;
    *) echo "Unknown argument: $ARG" >&2 ;;
  esac
done

# Validate audit type
case "$AUDIT_TYPE" in
  full|quick|supply-chain|custom) ;;
  *)
    echo "ERROR: Invalid audit type '${AUDIT_TYPE}'"
    echo "       Valid types: full, quick, supply-chain, custom"
    exit 1
    ;;
esac

echo "=== SecureClaw Audit Runner ==="
echo "Type:     ${AUDIT_TYPE}"
echo "Dry run:  ${DRY_RUN_FLAG:-no}"
echo "Verbose:  ${VERBOSE_FLAG:-no}"
echo ""

# Check environment variables (unless dry-run)
if [ -z "$DRY_RUN_FLAG" ]; then
  if [ -z "${CONVEX_URL:-}" ] && [ -z "${CONVEX_SITE_URL:-}" ]; then
    echo "ERROR: CONVEX_URL or CONVEX_SITE_URL not set"
    echo "       Use --dry-run to run without pushing to Convex"
    exit 1
  fi
  if [ -z "${CLAW_API_KEY:-}" ]; then
    echo "ERROR: CLAW_API_KEY not set"
    echo "       Use --dry-run to run without pushing to Convex"
    exit 1
  fi
fi

# Install dependencies if needed
if [ ! -d "${RUNNER_DIR}/node_modules" ]; then
  echo "Installing audit runner dependencies..."
  cd "${RUNNER_DIR}" && npm ci
fi

# Run the audit
cd "${RUNNER_DIR}"
echo "Starting audit..."
echo ""

# Export CHECKS_DIR so the runner finds our custom scripts
export CHECKS_DIR="${REPO_ROOT}/scripts/checks"

npx tsx bin/audit.ts \
  --type "${AUDIT_TYPE}" \
  --triggered-by manual \
  ${DRY_RUN_FLAG} \
  ${VERBOSE_FLAG} \
  2>&1

EXIT_CODE=$?

echo ""
if [ $EXIT_CODE -eq 0 ]; then
  echo "=== Audit completed successfully ==="
elif [ $EXIT_CODE -eq 2 ]; then
  echo "=== Audit completed with new CRITICAL findings ==="
  echo "    Check Mission Control /security for details"
else
  echo "=== Audit failed (exit code: ${EXIT_CODE}) ==="
  exit $EXIT_CODE
fi
