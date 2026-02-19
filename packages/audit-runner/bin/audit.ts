#!/usr/bin/env tsx
// bin/audit.ts
// CLI entrypoint for the SecureClaw audit runner
// Usage: tsx bin/audit.ts [--type full|quick|supply-chain] [--dry-run] [--verbose]

import { parseArgs } from "util";
import { runAudit } from "../src/index.js";
import { AuditType, TriggerSource } from "../src/types.js";

const VALID_AUDIT_TYPES: AuditType[] = ["full", "quick", "supply-chain", "custom"];
const VALID_TRIGGER_SOURCES: TriggerSource[] = ["cron", "manual", "post-install", "ci"];

function printUsage(): void {
  console.log(`
SecureClaw Audit Runner

Usage:
  tsx bin/audit.ts [options]

Options:
  --type <type>         Audit type: full|quick|supply-chain|custom (default: full)
  --triggered-by <by>  Trigger source: cron|manual|post-install|ci (default: manual)
  --modules <list>      Comma-separated modules for custom audits
  --dry-run             Simulate audit without running actual checks or pushing to Convex
  --verbose, -v         Print detailed progress to stderr
  --help, -h            Show this help

Environment variables:
  CONVEX_URL            Convex site URL (required unless --dry-run)
  CLAW_API_KEY          API key for Convex auth (required unless --dry-run)
  OPENCLAW_BIN          Path to openclaw binary (default: "openclaw")
  CHECKS_DIR            Path to custom checks directory

Examples:
  tsx bin/audit.ts --type quick --dry-run --verbose
  tsx bin/audit.ts --type full --triggered-by cron
  tsx bin/audit.ts --type supply-chain --triggered-by post-install
  tsx bin/audit.ts --type custom --modules gateway,permissions --verbose
`);
}

async function main(): Promise<void> {
  const { values } = parseArgs({
    options: {
      type:          { type: "string", short: "t", default: "full" },
      "triggered-by": { type: "string", default: "manual" },
      modules:       { type: "string" },
      "dry-run":     { type: "boolean", default: false },
      verbose:       { type: "boolean", short: "v", default: false },
      help:          { type: "boolean", short: "h", default: false },
    },
    allowPositionals: true,
    strict: false,
  });

  if (values.help) {
    printUsage();
    process.exit(0);
  }

  // Validate --type
  const rawType = (values.type as string | undefined) ?? "full";
  if (!VALID_AUDIT_TYPES.includes(rawType as AuditType)) {
    console.error(`Error: Invalid --type "${rawType}". Must be one of: ${VALID_AUDIT_TYPES.join(", ")}`);
    process.exit(1);
  }
  const auditType = rawType as AuditType;

  // Validate --triggered-by
  const rawTriggeredBy = (values["triggered-by"] as string | undefined) ?? "manual";
  if (!VALID_TRIGGER_SOURCES.includes(rawTriggeredBy as TriggerSource)) {
    console.error(`Error: Invalid --triggered-by "${rawTriggeredBy}". Must be one of: ${VALID_TRIGGER_SOURCES.join(", ")}`);
    process.exit(1);
  }
  const triggeredBy = rawTriggeredBy as TriggerSource;

  // Parse modules
  const modulesRaw = values.modules as string | undefined;
  const modules = modulesRaw ? modulesRaw.split(",").map((m) => m.trim()).filter(Boolean) : undefined;

  const dryRun = (values["dry-run"] as boolean | undefined) ?? false;
  const verbose = (values.verbose as boolean | undefined) ?? false;

  // Get Convex config from environment
  const convexUrl = process.env.CONVEX_URL ?? process.env.CONVEX_SITE_URL ?? "";
  const apiKey = process.env.CLAW_API_KEY ?? "";

  if (!dryRun) {
    if (!convexUrl) {
      console.error("Error: CONVEX_URL or CONVEX_SITE_URL environment variable is required");
      console.error("       Use --dry-run to run without pushing to Convex");
      process.exit(1);
    }
    if (!apiKey) {
      console.error("Error: CLAW_API_KEY environment variable is required");
      console.error("       Use --dry-run to run without pushing to Convex");
      process.exit(1);
    }
  }

  console.error(`[Audit] Starting ${auditType} audit (dryRun=${dryRun}, triggeredBy=${triggeredBy})`);

  try {
    const result = await runAudit({
      type: auditType,
      triggeredBy,
      modules,
      dryRun,
      verbose,
      convexUrl: convexUrl || "http://localhost:3000",
      apiKey: apiKey || "dry-run-key",
    });

    // Print summary to stdout (JSON for machine consumption)
    const output = {
      auditId: result.auditId,
      type: auditType,
      triggeredBy,
      checksRun: result.summary.checksRun,
      checksPassed: result.summary.checksPassed,
      checksFailed: result.summary.checksFailed,
      findings: {
        critical: result.summary.criticalCount,
        high: result.summary.highCount,
        medium: result.summary.mediumCount,
        low: result.summary.lowCount,
        info: result.summary.infoCount,
      },
      hostRiskScore: result.summary.hostRiskScore,
      diff: {
        newFindings: result.diff.newFindings.length,
        resolvedFindings: result.diff.resolvedFindings.length,
        persistingFindings: result.diff.persistingFindings.length,
        newCriticals: result.diff.newCriticals.length,
        riskScoreDelta: result.diff.riskScoreDelta,
      },
      durationMs: result.summary.durationMs,
      errors: result.errors,
    };

    console.log(JSON.stringify(output, null, 2));

    // Exit non-zero if there are new critical findings (for CI gate)
    if (result.diff.newCriticals.length > 0 && !dryRun) {
      console.error(`[Audit] ⚠️  ${result.diff.newCriticals.length} new CRITICAL finding(s) — exiting with code 2`);
      process.exit(2);
    }

    // Exit non-zero if there are errors
    if (result.errors.length > 0) {
      console.error(`[Audit] ${result.errors.length} error(s) during audit:`);
      result.errors.forEach((e) => console.error(`  - ${e}`));
    }

  } catch (err) {
    console.error(`[Audit] Fatal error: ${String(err)}`);
    process.exit(1);
  }
}

main().catch((err) => {
  console.error(`[Audit] Unhandled error: ${String(err)}`);
  process.exit(1);
});
