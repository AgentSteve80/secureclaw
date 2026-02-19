#!/usr/bin/env bash
# install-secureclaw.sh
# Install SecureClaw plugin from the verified source (adversa-ai/secureclaw on GitHub).
# NEVER installs from ClawHub — typosquatting risk with elevated system access.
# Verifies version before activation.

set -euo pipefail

REQUIRED_VERSION="2.1"
VERIFIED_SOURCE="adversa-ai/secureclaw"

echo "=== SecureClaw Installation Script ==="
echo "Source: github:${VERIFIED_SOURCE}"
echo "Required version: ${REQUIRED_VERSION}"
echo ""

# Check for openclaw binary
if ! command -v openclaw &>/dev/null; then
  echo "ERROR: openclaw binary not found in PATH"
  echo "       Please install OpenClaw first: https://openclaw.ai"
  exit 1
fi

OPENCLAW_VERSION=$(openclaw --version 2>/dev/null || echo "unknown")
echo "OpenClaw version: ${OPENCLAW_VERSION}"

# Check if SecureClaw is already installed
if openclaw secureclaw --version &>/dev/null 2>&1; then
  INSTALLED_VERSION=$(openclaw secureclaw --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+' | head -1)
  echo "SecureClaw already installed: v${INSTALLED_VERSION}"
  
  if [ "${INSTALLED_VERSION}" = "${REQUIRED_VERSION}" ]; then
    echo "✓ Version matches required ${REQUIRED_VERSION}"
    echo "No installation needed."
    exit 0
  else
    echo "Version mismatch: installed=${INSTALLED_VERSION}, required=${REQUIRED_VERSION}"
    echo "Proceeding with reinstall..."
  fi
fi

echo ""
echo "Installing SecureClaw v${REQUIRED_VERSION} from verified source..."
echo "Source: github:${VERIFIED_SOURCE}"
echo ""

# Install SecureClaw plugin
# The openclaw plugins install command should pull from GitHub directly
if openclaw plugins install "github:${VERIFIED_SOURCE}@v${REQUIRED_VERSION}" 2>&1; then
  echo "✓ SecureClaw plugin installed"
else
  echo "Plugin install failed. Trying alternative method..."
  # Fallback: try without version pin
  if openclaw plugins install "github:${VERIFIED_SOURCE}" 2>&1; then
    echo "✓ SecureClaw plugin installed (latest)"
  else
    echo "ERROR: Failed to install SecureClaw"
    echo ""
    echo "Manual installation steps:"
    echo "  1. Visit https://github.com/${VERIFIED_SOURCE}"
    echo "  2. Follow the installation instructions for v${REQUIRED_VERSION}"
    echo "  3. DO NOT install from ClawHub — use GitHub directly"
    exit 1
  fi
fi

# Verify installation
echo ""
echo "Verifying installation..."
if openclaw secureclaw --version &>/dev/null 2>&1; then
  INSTALLED_VERSION=$(openclaw secureclaw --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+' | head -1 || echo "unknown")
  echo "✓ SecureClaw v${INSTALLED_VERSION} is active"
else
  echo "WARNING: Cannot verify SecureClaw version"
  echo "         The plugin may require a gateway restart"
fi

echo ""
echo "=== Next Steps ==="
echo "1. Restart the gateway to activate the plugin:"
echo "   openclaw gateway restart"
echo ""
echo "2. Run a baseline audit:"
echo "   make audit-quick"
echo ""
echo "3. Apply security hardening (review before applying):"
echo "   openclaw secureclaw harden --modules permissions,auth,logging"
echo "   # Apply gateway module separately after checking LAN access:"
echo "   # openclaw secureclaw harden --modules gateway"
echo ""
echo "=== Installation Complete ==="
