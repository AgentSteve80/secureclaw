// convex/schema-additions.ts
// SecureClaw additions to the Mission Control Convex schema.
// These 4 new tables should be merged into the existing convex/schema.ts.
// DO NOT destructively replace the existing schema — add these table definitions.

import { defineTable } from "convex/server";
import { v } from "convex/values";

// ── Audit Runs ────────────────────────────────────────────────────────────────
// Records of SecureClaw + custom check audit runs.
// Analogous to `scans` table in Augustus but for host-level audits.
export const auditsTable = defineTable({
  // Scope
  type: v.union(
    v.literal("full"),           // all 55 SecureClaw + 7 custom checks
    v.literal("supply-chain"),   // skills only
    v.literal("quick"),          // config + gateway only
    v.literal("custom"),         // specific modules
  ),
  modules: v.optional(v.array(v.string())),

  // Trigger
  triggeredBy: v.union(
    v.literal("cron"),
    v.literal("manual"),
    v.literal("post-install"),   // auto-triggered after skill install
    v.literal("ci"),
  ),

  // Execution
  status: v.union(
    v.literal("running"),
    v.literal("complete"),
    v.literal("failed"),
  ),
  secureclawVersion: v.string(),  // "2.1"

  // Results (denormalized for fast queries)
  checksRun: v.number(),
  checksPassed: v.number(),
  checksFailed: v.number(),
  criticalCount: v.number(),
  highCount: v.number(),
  mediumCount: v.number(),
  lowCount: v.number(),
  hostRiskScore: v.number(),      // 0–100

  // Diff vs previous
  newFindingsCount: v.number(),
  resolvedFindingsCount: v.number(),
  riskScoreDelta: v.number(),     // + = worse, - = better

  // Timing
  startedAt: v.number(),
  finishedAt: v.optional(v.number()),
  durationMs: v.optional(v.number()),
})
  .index("by_type", ["type"])
  .index("by_started", ["startedAt"])
  .index("by_status", ["status"]);


// ── Audit Findings ────────────────────────────────────────────────────────────
// Individual check results from audit runs.
// Analogous to `vulnerabilities` table in Augustus but for host checks.
export const auditFindingsTable = defineTable({
  auditId: v.id("audits"),

  // Identity
  checkId: v.string(),            // "SC-001" | "custom.workspace-permissions"
  checkName: v.string(),
  source: v.union(
    v.literal("secureclaw"),      // upstream Adversa AI check
    v.literal("custom"),          // our custom check scripts
  ),

  // Classification
  owaspCategory: v.string(),      // "ASI01" through "ASI10"
  owaspName: v.string(),          // "Goal Hijack / Prompt Injection"
  category: v.string(),           // "gateway_config" | "file_permissions" | etc.
  severity: v.union(
    v.literal("critical"),
    v.literal("high"),
    v.literal("medium"),
    v.literal("low"),
    v.literal("info"),
  ),

  // State
  passed: v.boolean(),
  status: v.union(
    v.literal("open"),
    v.literal("acknowledged"),
    v.literal("remediated"),
    v.literal("accepted"),
  ),
  isNew: v.boolean(),             // true = not present in previous audit

  // Evidence (truncated at 500 chars — no full credentials in DB)
  evidence: v.optional(v.string()),
  remediation: v.optional(v.string()),
  remediationNote: v.optional(v.string()),

  // Tracking
  firstSeenAt: v.number(),
  lastSeenAt: v.number(),
  remediatedAt: v.optional(v.number()),
})
  .index("by_audit", ["auditId"])
  .index("by_owasp", ["owaspCategory"])
  .index("by_severity", ["severity"])
  .index("by_status_severity", ["status", "severity"])
  .index("by_check", ["checkId"]);


// ── Skill Inventory ───────────────────────────────────────────────────────────
// Tracks all installed OpenClaw skills with ClawHavoc scan results.
// Updated on each supply-chain audit run.
export const skillInventoryTable = defineTable({
  name: v.string(),               // "secureclaw" | "gh-issues" | etc.
  source: v.string(),             // "clawhub" | "github:adversa-ai/secureclaw" | "local"
  version: v.optional(v.string()),
  installedAt: v.number(),
  lastScannedAt: v.optional(v.number()),
  scanResult: v.union(
    v.literal("clean"),
    v.literal("suspicious"),
    v.literal("malicious"),
    v.literal("unscanned"),
  ),
  clawhavocMatch: v.boolean(),    // matched against ClawHavoc signature DB
  suspicionReasons: v.array(v.string()),
  quarantined: v.boolean(),
})
  .index("by_scan_result", ["scanResult"])
  .index("by_name", ["name"]);


// ── Security Events ───────────────────────────────────────────────────────────
// Real-time alert event stream (both SecureClaw + Augustus findings).
// Unacknowledged events surface in Mission Control security overview.
export const securityEventsTable = defineTable({
  eventType: v.union(
    v.literal("new_critical_finding"),
    v.literal("clawhavoc_match"),
    v.literal("cognitive_file_tampered"),
    v.literal("credential_exposure_detected"),
    v.literal("gateway_exposure_detected"),
    v.literal("new_critical_vuln"),   // from Augustus
  ),
  severity: v.string(),
  source: v.union(v.literal("secureclaw"), v.literal("augustus")),
  sourceId: v.optional(v.string()),   // auditId or scanId
  message: v.string(),
  acknowledged: v.boolean(),
  createdAt: v.number(),
  acknowledgedAt: v.optional(v.number()),
})
  .index("by_acknowledged", ["acknowledged"])
  .index("by_type", ["eventType"])
  .index("by_created", ["createdAt"]);


// ── Schema merge instructions ────────────────────────────────────────────────
// To deploy these tables, add the following to your convex/schema.ts:
//
// import { auditsTable, auditFindingsTable, skillInventoryTable, securityEventsTable }
//   from "./schema-additions";
//
// export default defineSchema({
//   // ... existing tables ...
//   audits: auditsTable,
//   auditFindings: auditFindingsTable,
//   skillInventory: skillInventoryTable,
//   securityEvents: securityEventsTable,
// });
