// packages/audit-runner/src/parser.ts
// Normalizes SecureClaw JSON + custom check JSON → NormalizedFinding[]
// Includes OWASP category mapping table (ASI01–ASI10), severity scoring,
// and evidence truncation at 500 chars.

import {
  CustomCheckResult,
  FindingSeverity,
  NormalizedFinding,
  OWASP_NAMES,
  OWASPCategory,
  RawAuditOutput,
  SecureClawFinding,
  SecureClawOutput,
} from "./types.js";

// ── OWASP ASI Category Mapping ─────────────────────────────────────────────
// Maps SecureClaw check IDs (SC-XXX) and category strings to OWASP ASI categories

const SECURECLAW_OWASP_MAP: Record<string, OWASPCategory> = {
  // SC-001 range: Goal Hijack / Prompt Injection
  "SC-001": "ASI01",
  "SC-002": "ASI01",
  "SC-003": "ASI01",
  "SC-004": "ASI01",
  "SC-005": "ASI01",

  // SC-010 range: Sensitive Information Disclosure
  "SC-010": "ASI02",
  "SC-011": "ASI02",
  "SC-012": "ASI02",
  "SC-013": "ASI02",

  // SC-020 range: Misconfigured Secrets & PII Leakage
  "SC-020": "ASI03",
  "SC-021": "ASI03",
  "SC-022": "ASI03",
  "SC-023": "ASI03",
  "SC-024": "ASI03",
  "SC-025": "ASI03",

  // SC-030 range: Insecure Code Execution
  "SC-030": "ASI04",
  "SC-031": "ASI04",
  "SC-032": "ASI04",

  // SC-035 range: Model Denial of Service
  "SC-035": "ASI05",
  "SC-036": "ASI05",

  // SC-040 range: Cognitive File & Identity Tampering
  "SC-040": "ASI06",
  "SC-041": "ASI06",
  "SC-042": "ASI06",
  "SC-043": "ASI06",
  "SC-044": "ASI06",
  "SC-045": "ASI06",

  // SC-050 range: Supply Chain Compromise
  "SC-050": "ASI07",
  "SC-051": "ASI07",
  "SC-052": "ASI07",
  "SC-053": "ASI07",
  "SC-054": "ASI07",

  // SC-060 range: Insecure Tool Use
  "SC-060": "ASI08",
  "SC-061": "ASI08",
  "SC-062": "ASI08",

  // SC-070 range: Unsafe Output Handling
  "SC-070": "ASI09",
  "SC-071": "ASI09",

  // SC-080 range: Excessive Agency / Privilege Escalation
  "SC-080": "ASI10",
  "SC-081": "ASI10",
  "SC-082": "ASI10",
};

// Category string → OWASP mapping (for checks that don't have an ID match)
const CATEGORY_OWASP_MAP: Record<string, OWASPCategory> = {
  "prompt_injection": "ASI01",
  "goal_hijack": "ASI01",
  "injection": "ASI01",
  "information_disclosure": "ASI02",
  "data_leakage": "ASI02",
  "pii_exposure": "ASI02",
  "secrets_exposure": "ASI03",
  "credential_exposure": "ASI03",
  "file_permissions": "ASI06",
  "config_exposure": "ASI03",
  "api_key_exposure": "ASI03",
  "pii_leakage": "ASI03",
  "code_execution": "ASI04",
  "rce": "ASI04",
  "shell_injection": "ASI04",
  "dos": "ASI05",
  "resource_exhaustion": "ASI05",
  "cognitive_file": "ASI06",
  "identity_tampering": "ASI06",
  "soul_file": "ASI06",
  "memory_file": "ASI06",
  "supply_chain": "ASI07",
  "clawhavoc": "ASI07",
  "skill_validation": "ASI07",
  "tool_use": "ASI08",
  "tool_abuse": "ASI08",
  "unsafe_output": "ASI09",
  "xss": "ASI09",
  "privilege_escalation": "ASI10",
  "excessive_agency": "ASI10",
  "gateway_config": "ASI03",
  "gateway_exposure": "ASI03",
  "auth": "ASI10",
  "cron_injection": "ASI01",
};

const EVIDENCE_MAX_CHARS = 500;

function truncateEvidence(evidence: string | undefined): string | undefined {
  if (!evidence) return undefined;
  if (evidence.length <= EVIDENCE_MAX_CHARS) return evidence;
  return evidence.slice(0, EVIDENCE_MAX_CHARS) + "…[truncated]";
}

function inferOWASPFromSecureClawFinding(finding: SecureClawFinding): OWASPCategory {
  // Try ID-based lookup first
  const fromId = SECURECLAW_OWASP_MAP[finding.id];
  if (fromId) {
    return fromId;
  }

  // Try explicit owaspMapping field
  if (finding.owaspMapping) {
    const normalized = finding.owaspMapping.toUpperCase().replace(/\s/g, "");
    if (normalized.startsWith("ASI") && normalized.length <= 5) {
      return normalized as OWASPCategory;
    }
  }

  // Try category-based lookup
  const categoryKey = (finding.category ?? "").toLowerCase().replace(/[- ]/g, "_");
  if (CATEGORY_OWASP_MAP[categoryKey]) {
    return CATEGORY_OWASP_MAP[categoryKey];
  }

  // Default: ASI03 (most common catch-all for misconfiguration)
  return "ASI03";
}

function normalizeSecureClawFinding(finding: SecureClawFinding): NormalizedFinding {
  const owaspCategory = inferOWASPFromSecureClawFinding(finding);
  return {
    checkId: finding.id,
    checkName: finding.name,
    source: "secureclaw",
    owaspCategory,
    owaspName: OWASP_NAMES[owaspCategory],
    category: finding.category ?? "general",
    severity: finding.severity,
    passed: finding.passed,
    evidence: truncateEvidence(finding.evidence),
    remediation: finding.remediation,
  };
}

function normalizeCustomCheckResult(result: CustomCheckResult): NormalizedFinding {
  const owaspCategory = result.owaspCategory;
  return {
    checkId: result.checkId,
    checkName: result.checkName,
    source: "custom",
    owaspCategory,
    owaspName: OWASP_NAMES[owaspCategory],
    category: result.category,
    severity: result.severity,
    passed: result.passed,
    evidence: truncateEvidence(result.evidence),
    remediation: result.remediation,
  };
}

export function computeRiskScore(findings: NormalizedFinding[]): number {
  const failed = findings.filter((f) => !f.passed);
  const score =
    failed.filter((f) => f.severity === "critical").length * 25 +
    failed.filter((f) => f.severity === "high").length * 10 +
    failed.filter((f) => f.severity === "medium").length * 3 +
    failed.filter((f) => f.severity === "low").length * 1;
  return Math.min(100, score);
}

export function countBySeverity(
  findings: NormalizedFinding[]
): Record<FindingSeverity, number> {
  const failed = findings.filter((f) => !f.passed);
  return {
    critical: failed.filter((f) => f.severity === "critical").length,
    high: failed.filter((f) => f.severity === "high").length,
    medium: failed.filter((f) => f.severity === "medium").length,
    low: failed.filter((f) => f.severity === "low").length,
    info: failed.filter((f) => f.severity === "info").length,
  };
}

export class ResultParser {
  parse(raw: RawAuditOutput): NormalizedFinding[] {
    const findings: NormalizedFinding[] = [];

    // Parse SecureClaw findings
    if (raw.secureclaw) {
      for (const finding of raw.secureclaw.findings) {
        findings.push(normalizeSecureClawFinding(finding));
      }
    }

    // Parse custom check results (all custom checks are included, passed or not)
    for (const result of raw.customChecks) {
      findings.push(normalizeCustomCheckResult(result));
    }

    return findings;
  }

  getSecureClawVersion(raw: RawAuditOutput): string {
    return raw.secureclaw?.version ?? "unknown";
  }

  getTotalChecksRun(raw: RawAuditOutput): number {
    const scChecks = raw.secureclaw?.checksRun ?? 0;
    const customChecks = raw.customChecks.length;
    return scChecks + customChecks;
  }

  getTotalChecksPassed(raw: RawAuditOutput): number {
    const scPassed = raw.secureclaw?.checksPassed ?? 0;
    const customPassed = raw.customChecks.filter((c) => c.passed).length;
    return scPassed + customPassed;
  }
}

// Group findings by OWASP category
export function groupByOWASP(
  findings: NormalizedFinding[]
): Record<OWASPCategory, NormalizedFinding[]> {
  const groups: Record<OWASPCategory, NormalizedFinding[]> = {
    ASI01: [], ASI02: [], ASI03: [], ASI04: [], ASI05: [],
    ASI06: [], ASI07: [], ASI08: [], ASI09: [], ASI10: [],
  };

  for (const finding of findings) {
    groups[finding.owaspCategory].push(finding);
  }

  return groups;
}

// Extract failed findings only
export function failedFindings(findings: NormalizedFinding[]): NormalizedFinding[] {
  return findings.filter((f) => !f.passed);
}

export { truncateEvidence, normalizeSecureClawFinding, normalizeCustomCheckResult };
export type { SecureClawOutput };
