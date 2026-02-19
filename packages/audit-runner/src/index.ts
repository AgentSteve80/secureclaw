// packages/audit-runner/src/index.ts
// Main orchestrator: wires AuditRunner → ResultParser → AuditDiffer → ConvexReporter → Alerter

import { alertOnCriticals } from "./alerter.js";
import { AuditDiffer } from "./differ.js";
import { ResultParser, computeRiskScore, countBySeverity, failedFindings } from "./parser.js";
import { ConvexReporter } from "./reporter.js";
import { AuditRunner } from "./runner.js";
import {
  AuditConfig,
  AuditDiff,
  AuditSummary,
  NormalizedFinding,
} from "./types.js";

interface OrchestratorConfig extends AuditConfig {
  convexUrl: string;
  apiKey: string;
}

interface OrchestratorResult {
  auditId: string;
  summary: AuditSummary;
  findings: NormalizedFinding[];
  diff: AuditDiff;
  errors: string[];
}

export async function runAudit(config: OrchestratorConfig): Promise<OrchestratorResult> {
  const startedAt = Date.now();
  const errors: string[] = [];

  // Initialize components
  const runner = new AuditRunner({
    secureclawBin: process.env.OPENCLAW_BIN ?? "openclaw",
    checksDir: process.env.CHECKS_DIR,
    verbose: config.verbose ?? false,
  });

  const parser = new ResultParser();
  const differ = new AuditDiffer();
  const reporter = new ConvexReporter({
    convexUrl: config.convexUrl,
    apiKey: config.apiKey,
    verbose: config.verbose ?? false,
  });

  if (config.verbose) {
    console.error(`[Orchestrator] Starting ${config.type} audit triggered by ${config.triggeredBy}`);
  }

  // Step 1: Check SecureClaw availability
  const scVersion = await runner.getSecureClawVersion();
  const scAvailable = await runner.isSecureClawAvailable();

  if (!scAvailable && !config.dryRun) {
    console.error("[Orchestrator] WARNING: SecureClaw not available — custom checks only");
  }

  // Step 2: Get previous audit findings for diff
  let previousAudit = null;
  if (!config.dryRun) {
    try {
      previousAudit = await reporter.getPreviousAuditFindings();
      if (config.verbose && previousAudit) {
        console.error(`[Orchestrator] Previous audit: ${previousAudit.auditId} (score: ${previousAudit.hostRiskScore})`);
      }
    } catch (err) {
      errors.push(`Failed to fetch previous audit: ${String(err)}`);
    }
  }

  // Step 3: Run the audit
  const rawOutput = await runner.run(config);
  errors.push(...rawOutput.errors);

  // Step 4: Normalize findings
  const findings = parser.parse(rawOutput);
  const failed = failedFindings(findings);
  const bySeverity = countBySeverity(findings);
  const hostRiskScore = computeRiskScore(findings);

  if (config.verbose) {
    console.error(`[Orchestrator] Findings: ${findings.length} total, ${failed.length} failed`);
    console.error(`[Orchestrator] Risk score: ${hostRiskScore}`);
  }

  // Step 5: Compute diff
  const diff = differ.compute(
    "pending", // will be replaced with actual ID after creation
    findings,
    hostRiskScore,
    previousAudit
  );

  const finishedAt = Date.now();
  const durationMs = finishedAt - startedAt;

  const summary: AuditSummary = {
    type: config.type,
    triggeredBy: config.triggeredBy,
    secureclawVersion: scVersion,
    checksRun: parser.getTotalChecksRun(rawOutput),
    checksPassed: parser.getTotalChecksPassed(rawOutput),
    checksFailed: parser.getTotalChecksRun(rawOutput) - parser.getTotalChecksPassed(rawOutput),
    criticalCount: bySeverity.critical,
    highCount: bySeverity.high,
    mediumCount: bySeverity.medium,
    lowCount: bySeverity.low,
    infoCount: bySeverity.info,
    hostRiskScore,
    newFindingsCount: diff.newFindings.length,
    resolvedFindingsCount: diff.resolvedFindings.length,
    riskScoreDelta: diff.riskScoreDelta,
    startedAt,
    finishedAt,
    durationMs,
  };

  // Step 6: Push to Convex (skip in dry-run)
  let auditId = "dry-run";
  let findingIds: string[] = [];

  if (!config.dryRun) {
    try {
      // Create audit record
      auditId = await reporter.createAudit(summary);
      if (config.verbose) console.error(`[Orchestrator] Created audit record: ${auditId}`);

      // Fix the diff audit ID now that we have it
      diff.auditId = auditId;

      // Upsert findings
      findingIds = await reporter.upsertFindings(auditId, findings, diff);
      if (config.verbose) console.error(`[Orchestrator] Upserted ${findingIds.length} findings`);

      // Complete the audit record
      await reporter.completeAudit(auditId, summary);
      if (config.verbose) console.error(`[Orchestrator] Audit completed`);

      // Step 7: Send alerts for new criticals
      await alertOnCriticals(diff, {
        convexUrl: config.convexUrl,
        apiKey: config.apiKey,
        verbose: config.verbose,
      });

    } catch (err) {
      errors.push(`Failed to push results to Convex: ${String(err)}`);
      console.error(`[Orchestrator] Convex error: ${String(err)}`);
    }
  }

  if (config.verbose) {
    const d = differ.summarize(diff);
    console.error(`[Orchestrator]\n${d}`);
  }

  return {
    auditId,
    summary,
    findings,
    diff,
    errors,
  };
}

export { AuditRunner, ResultParser, AuditDiffer, ConvexReporter };
export * from "./types.js";
