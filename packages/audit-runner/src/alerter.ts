// packages/audit-runner/src/alerter.ts
// Alerter: checks for new CRITICAL findings, posts to securityEvents table

import { AuditDiff, FindingSeverity, NormalizedFinding, SecurityEventPayload } from "./types.js";

interface AlertConfig {
  convexUrl: string;
  apiKey: string;
  verbose?: boolean;
}

async function postSecurityEvent(
  config: AlertConfig,
  event: SecurityEventPayload & { acknowledged: boolean; createdAt: number }
): Promise<{ id: string }> {
  const url = `${config.convexUrl.replace(/\/$/, "")}/api/security-events`;

  const res = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-claw-api-key": config.apiKey,
    },
    body: JSON.stringify(event),
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Failed to post security event: HTTP ${res.status}: ${text.slice(0, 200)}`);
  }

  return res.json() as Promise<{ id: string }>;
}

function buildAlertMessage(criticals: NormalizedFinding[], auditId: string): string {
  const categories = [...new Set(criticals.map((f) => f.owaspCategory))].join(", ");
  const checkNames = criticals.map((f) => f.checkName).join(", ");
  return (
    `🚨 ${criticals.length} new CRITICAL finding${criticals.length !== 1 ? "s" : ""} ` +
    `in audit ${auditId} — ` +
    `Categories: ${categories} — ` +
    `Checks: ${checkNames.slice(0, 200)}`
  );
}

export async function alertOnCriticals(
  diff: AuditDiff,
  config: AlertConfig
): Promise<void> {
  if (diff.newCriticals.length === 0) {
    if (config.verbose) {
      console.error("[Alerter] No new critical findings — no alert needed");
    }
    return;
  }

  const message = buildAlertMessage(diff.newCriticals, diff.auditId);

  if (config.verbose) {
    console.error(`[Alerter] Posting security event: ${message}`);
  }

  const event: SecurityEventPayload & { acknowledged: boolean; createdAt: number } = {
    eventType: "new_critical_finding",
    severity: "critical" as FindingSeverity,
    source: "secureclaw",
    sourceId: diff.auditId,
    message,
    acknowledged: false,
    createdAt: Date.now(),
  };

  try {
    const { id } = await postSecurityEvent(config, event);
    if (config.verbose) {
      console.error(`[Alerter] Security event created: ${id}`);
    }
  } catch (err) {
    console.error(`[Alerter] Failed to post security event: ${String(err)}`);
    // Non-fatal — don't throw, the audit should still complete
  }
}

export async function alertOnClawHavocMatch(
  skillName: string,
  source: string,
  config: AlertConfig
): Promise<void> {
  const event: SecurityEventPayload & { acknowledged: boolean; createdAt: number } = {
    eventType: "clawhavoc_match",
    severity: "critical" as FindingSeverity,
    source: "secureclaw",
    message: `🚨 ClawHavoc signature match: skill "${skillName}" from "${source}" flagged as malicious`,
    acknowledged: false,
    createdAt: Date.now(),
  };

  try {
    await postSecurityEvent(config, event);
  } catch (err) {
    console.error(`[Alerter] Failed to post ClawHavoc alert: ${String(err)}`);
  }
}

export async function alertOnCognitiveFileTamper(
  filePath: string,
  config: AlertConfig
): Promise<void> {
  const event: SecurityEventPayload & { acknowledged: boolean; createdAt: number } = {
    eventType: "cognitive_file_tampered",
    severity: "critical" as FindingSeverity,
    source: "secureclaw",
    message: `🚨 Cognitive file integrity check failed: ${filePath}`,
    acknowledged: false,
    createdAt: Date.now(),
  };

  try {
    await postSecurityEvent(config, event);
  } catch (err) {
    console.error(`[Alerter] Failed to post cognitive file tamper alert: ${String(err)}`);
  }
}
