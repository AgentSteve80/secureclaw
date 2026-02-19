# SecureClaw — Makefile
# Targets: install, audit, audit-quick, audit-supply-chain, typecheck, help

SHELL := /bin/bash
RUNNER := packages/audit-runner
CHECKS := scripts/checks

.PHONY: help install typecheck audit audit-quick audit-supply-chain audit-dry-run \
        install-secureclaw verify-scripts clean

## Show this help message
help:
	@echo ""
	@echo "SecureClaw Integration — Available Targets"
	@echo "==========================================="
	@echo ""
	@echo "  make install              Install audit runner dependencies"
	@echo "  make install-secureclaw   Install SecureClaw plugin from verified source"
	@echo "  make typecheck            Type-check TypeScript without building"
	@echo ""
	@echo "  make audit                Run full audit (SecureClaw + all custom checks)"
	@echo "  make audit-quick          Run quick audit (config + gateway checks only)"
	@echo "  make audit-supply-chain   Run supply-chain audit (skills only)"
	@echo "  make audit-dry-run        Dry run — no Convex writes, verbose output"
	@echo ""
	@echo "  make verify-scripts       Verify all bash scripts output valid JSON"
	@echo "  make clean                Remove build artifacts"
	@echo ""
	@echo "Environment variables:"
	@echo "  CONVEX_URL or CONVEX_SITE_URL   Convex site URL"
	@echo "  CLAW_API_KEY                     API key for Convex auth"
	@echo "  OPENCLAW_BIN                     Path to openclaw binary (default: openclaw)"
	@echo ""

## Install audit runner Node.js dependencies
install:
	@echo "Installing audit runner dependencies..."
	cd $(RUNNER) && npm ci
	@echo "✓ Dependencies installed"

## Install SecureClaw plugin from verified GitHub source
install-secureclaw:
	@bash scripts/install-secureclaw.sh

## Type-check TypeScript files without compiling
typecheck:
	cd $(RUNNER) && npx tsc --noEmit
	@echo "✓ TypeScript OK"

## Run full audit (55 SecureClaw + 7 custom checks)
audit: install
	@echo "Starting full SecureClaw audit..."
	@export CHECKS_DIR="$(PWD)/$(CHECKS)"; \
	 cd $(RUNNER) && npx tsx bin/audit.ts --type full --triggered-by manual

## Run quick audit (config + gateway checks only, ~30 seconds)
audit-quick: install
	@echo "Starting quick audit..."
	@export CHECKS_DIR="$(PWD)/$(CHECKS)"; \
	 cd $(RUNNER) && npx tsx bin/audit.ts --type quick --triggered-by manual

## Run supply-chain audit (skill inventory + ClawHavoc scan)
audit-supply-chain: install
	@echo "Starting supply-chain audit..."
	@export CHECKS_DIR="$(PWD)/$(CHECKS)"; \
	 cd $(RUNNER) && npx tsx bin/audit.ts --type supply-chain --triggered-by manual

## Dry run with verbose output — no Convex writes
audit-dry-run: install
	@echo "Starting dry-run audit (no Convex writes)..."
	@export CHECKS_DIR="$(PWD)/$(CHECKS)"; \
	 cd $(RUNNER) && npx tsx bin/audit.ts --type full --dry-run --verbose

## Verify all bash scripts in scripts/checks/ output valid JSON
verify-scripts:
	@echo "Verifying custom check scripts..."
	@PASS=0; FAIL=0; \
	for script in $(CHECKS)/*.sh; do \
	  name=$$(basename $$script); \
	  output=$$(bash $$script 2>/dev/null); \
	  if echo "$$output" | python3 -m json.tool >/dev/null 2>&1; then \
	    echo "  ✓ $$name"; \
	    PASS=$$((PASS + 1)); \
	  else \
	    echo "  ✗ $$name — invalid JSON output"; \
	    FAIL=$$((FAIL + 1)); \
	  fi; \
	done; \
	echo ""; \
	echo "Results: $$PASS passed, $$FAIL failed"; \
	if [ $$FAIL -gt 0 ]; then exit 1; fi

## Remove build artifacts
clean:
	rm -rf $(RUNNER)/dist
	rm -rf $(RUNNER)/node_modules/.cache
	@echo "✓ Cleaned"
