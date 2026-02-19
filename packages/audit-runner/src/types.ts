// packages/audit-runner/src/types.ts
// Shared type definitions for the SecureClaw audit runner

export type AuditType = "full" | "supply-chain" | "quick" | "custom";
export type FindingSeverity = "critical" | "high" | "medium" | "low" | "info";
export type ScanResult = "clean" | "suspicious" | "malicious" | "unscanned";
export type FindingStatus = "open" | "acknowledged" | "remediated" | "accepted";
export type AuditStatus = "running" | "complete" | "failed";
export type TriggerSource = "cron" | "manual" | "post-install" | "ci";

export type OWASPCategory =
  | "ASI01"
  | "ASI02"
  | "ASI03"
  | "ASI04"
  | "ASI05"
  | "ASI06"
  | "ASI07"
  | "ASI08"
  | "ASI09"
  | "ASI10";

export const OWASP_NAMES: Record<OWASPCategory, string> = {
  ASI01: "Goal Hijack / Prompt Injection",
  ASI02: "Sensitive Information Disclosure",
  ASI03: "Misconfigured Secrets & PII Leakage",
  ASI04: "Insecure Code Execution",
  ASI05: "Model Denial of Service",
  ASI06: "Cognitive File & Identity Tampering",
  ASI07: "Supply Chain Compromise",
  ASI08: "Insecure Tool Use",
  ASI09: "Unsafe Output Handling",
  ASI10: "Excessive Agency / Privilege Escalation",
};

// SecureClaw's native JSON output format (from `openclaw secureclaw audit --output json`)
export interface SecureClawFinding {
  id: string;          // "SC-001"
  name: string;
  category: string;
  severity: FindingSeverity;
  passed: boolean;
  evidence?: string;
  remediation?: string;
  owaspMapping?: string; // may be absent in some checks
  module?: string;       // "gateway" | "permissions" | "supply-chain" | etc.
}

export interface SecureClawOutput {
  version: string;       // "2.1"
  timestamp: string;
  hostname: string;
  checksRun: number;
  checksPassed: number;
  checksFailed: number;
  findings: SecureClawFinding[];
  riskScore: number;     // 0–100
}

// Our normalized finding format (unified across SecureClaw + custom checks)
export interface NormalizedFinding {
  checkId: string;
  checkName: string;
  source: "secureclaw" | "custom";
  owaspCategory: OWASPCategory;
  owaspName: string;
  category: string;
  severity: FindingSeverity;
  passed: boolean;
  evidence?: string;     // truncated to 500 chars
  remediation?: string;
}

// Custom check script output schema (each .sh script outputs this JSON)
export interface CustomCheckResult {
  checkId: string;           // "custom.workspace-permissions"
  checkName: string;
  category: string;
  owaspCategory: OWASPCategory;
  passed: boolean;
  severity: FindingSeverity;
  evidence?: string;
  remediation?: string;
}

// Configuration for running an audit
export interface AuditConfig {
  type: AuditType;
  modules?: string[];
  triggeredBy: TriggerSource;
  secureclawBin?: string;    // path to openclaw binary, defaults to "openclaw"
  checksDir?: string;        // path to scripts/checks/, auto-detected if not set
  dryRun?: boolean;
  verbose?: boolean;
}

// Raw merged output before normalization
export interface RawAuditOutput {
  secureclaw: SecureClawOutput | null;
  customChecks: CustomCheckResult[];
  errors: string[];
}

// Diff between current audit and previous
export interface AuditDiff {
  auditId: string;
  previousAuditId: string | null;
  newFindings: NormalizedFinding[];
  resolvedFindings: NormalizedFinding[];
  persistingFindings: NormalizedFinding[];
  riskScoreDelta: number;        // + = worse, - = better
  newCriticals: NormalizedFinding[];
}

// Audit run summary
export interface AuditSummary {
  type: AuditType;
  triggeredBy: TriggerSource;
  secureclawVersion: string;
  checksRun: number;
  checksPassed: number;
  checksFailed: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  infoCount: number;
  hostRiskScore: number;         // 0–100
  newFindingsCount: number;
  resolvedFindingsCount: number;
  riskScoreDelta: number;
  startedAt: number;
  finishedAt: number;
  durationMs: number;
}

// Composite security posture (SecureClaw + Augustus combined)
export interface SecurityPosture {
  hostRiskScore: number;         // SecureClaw (0–100)
  llmRiskScore: number;          // Augustus (0–100)
  compositeScore: number;        // weighted: host 60%, llm 40%
  trend: "improving" | "degrading" | "stable";
  lastAuditAt: number;
  lastScanAt: number;
  openCriticals: number;         // total across both sources
  openHighs: number;
}

// Skill inventory entry
export interface SkillInventoryEntry {
  name: string;
  source: string;
  version?: string;
  installedAt: number;
  lastScannedAt?: number;
  scanResult: ScanResult;
  clawhavocMatch: boolean;
  suspicionReasons: string[];
  quarantined: boolean;
}

// Security event
export interface SecurityEventPayload {
  eventType:
    | "new_critical_finding"
    | "clawhavoc_match"
    | "cognitive_file_tampered"
    | "credential_exposure_detected"
    | "gateway_exposure_detected"
    | "new_critical_vuln";
  severity: FindingSeverity;
  source: "secureclaw" | "augustus";
  sourceId?: string;
  message: string;
}

// Convex API record types (IDs as strings since we use HTTP API)
export interface ConvexAuditRecord {
  id: string;
  status: AuditStatus;
  hostRiskScore: number;
}

export interface ConvexFindingRecord {
  id: string;
  checkId: string;
  auditId: string;
  firstSeenAt: number;
}
