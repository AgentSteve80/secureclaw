// convex/http-security-audit.ts
// HTTP actions for the SecureClaw audit API.
// All endpoints use x-claw-api-key auth (same pattern as Augustus http-security.ts).
// Add these routes to your existing convex/http.ts using http.route(...)

import { httpAction } from "./_generated/server";
import { api } from "./_generated/api";
import { Id } from "./_generated/dataModel";

// ── Auth helper ────────────────────────────────────────────────────────────────

function checkApiKey(request: Request): boolean {
  const key = request.headers.get("x-claw-api-key");
  // CLAW_API_KEY is set in Convex environment variables
  const expected = process.env.CLAW_API_KEY;
  if (!expected || !key) return false;
  return key === expected;
}

function unauthorized(): Response {
  return new Response(JSON.stringify({ error: "Unauthorized" }), {
    status: 401,
    headers: { "Content-Type": "application/json" },
  });
}

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function badRequest(message: string): Response {
  return new Response(JSON.stringify({ error: message }), {
    status: 400,
    headers: { "Content-Type": "application/json" },
  });
}

// ── Route handlers ────────────────────────────────────────────────────────────

// POST /api/audits — create a new audit record (called by audit runner on start)
export const handleCreateAudit = httpAction(async (ctx, request) => {
  if (!checkApiKey(request)) return unauthorized();

  let body: {
    type: "full" | "supply-chain" | "quick" | "custom";
    modules?: string[];
    triggeredBy: "cron" | "manual" | "post-install" | "ci";
    secureclawVersion?: string;
    startedAt?: number;
    checksRun?: number;
    checksPassed?: number;
    checksFailed?: number;
    criticalCount?: number;
    highCount?: number;
    mediumCount?: number;
    lowCount?: number;
    hostRiskScore?: number;
    newFindingsCount?: number;
    resolvedFindingsCount?: number;
    riskScoreDelta?: number;
  };

  try {
    body = await request.json() as typeof body;
  } catch {
    return badRequest("Invalid JSON body");
  }

  if (!body.type || !body.triggeredBy) {
    return badRequest("Missing required fields: type, triggeredBy");
  }

  const id = await ctx.runMutation(api.audits.create, {
    type: body.type,
    modules: body.modules,
    triggeredBy: body.triggeredBy,
    secureclawVersion: body.secureclawVersion ?? "unknown",
    startedAt: body.startedAt ?? Date.now(),
    checksRun: body.checksRun ?? 0,
    checksPassed: body.checksPassed ?? 0,
    checksFailed: body.checksFailed ?? 0,
    criticalCount: body.criticalCount ?? 0,
    highCount: body.highCount ?? 0,
    mediumCount: body.mediumCount ?? 0,
    lowCount: body.lowCount ?? 0,
    hostRiskScore: body.hostRiskScore ?? 0,
    newFindingsCount: body.newFindingsCount ?? 0,
    resolvedFindingsCount: body.resolvedFindingsCount ?? 0,
    riskScoreDelta: body.riskScoreDelta ?? 0,
  });

  return json({ id });
});

// POST /api/audit-results — receive findings from runner, complete audit
export const handleAuditResults = httpAction(async (ctx, request) => {
  if (!checkApiKey(request)) return unauthorized();

  let body: {
    auditId: string;
    action?: string;
    findings?: Array<{
      checkId: string;
      checkName: string;
      source: "secureclaw" | "custom";
      owaspCategory: string;
      owaspName: string;
      category: string;
      severity: "critical" | "high" | "medium" | "low" | "info";
      passed: boolean;
      isNew: boolean;
      status: "open" | "acknowledged" | "remediated" | "accepted";
      evidence?: string;
      remediation?: string;
      firstSeenAt: number;
      lastSeenAt: number;
    }>;
    // For "complete" action
    finishedAt?: number;
    durationMs?: number;
    checksRun?: number;
    checksPassed?: number;
    checksFailed?: number;
    criticalCount?: number;
    highCount?: number;
    mediumCount?: number;
    lowCount?: number;
    hostRiskScore?: number;
    newFindingsCount?: number;
    resolvedFindingsCount?: number;
    riskScoreDelta?: number;
    status?: string;
  };

  try {
    body = await request.json() as typeof body;
  } catch {
    return badRequest("Invalid JSON body");
  }

  const auditId = body.auditId as Id<"audits">;

  // Handle completion
  if (body.action === "complete" || body.status === "complete") {
    await ctx.runMutation(api.audits.complete, {
      id: auditId,
      finishedAt: body.finishedAt ?? Date.now(),
      durationMs: body.durationMs ?? 0,
      checksRun: body.checksRun ?? 0,
      checksPassed: body.checksPassed ?? 0,
      checksFailed: body.checksFailed ?? 0,
      criticalCount: body.criticalCount ?? 0,
      highCount: body.highCount ?? 0,
      mediumCount: body.mediumCount ?? 0,
      lowCount: body.lowCount ?? 0,
      hostRiskScore: body.hostRiskScore ?? 0,
      newFindingsCount: body.newFindingsCount ?? 0,
      resolvedFindingsCount: body.resolvedFindingsCount ?? 0,
      riskScoreDelta: body.riskScoreDelta ?? 0,
    });
    return json({ ok: true });
  }

  // Handle findings upsert
  if (!body.findings || !Array.isArray(body.findings)) {
    return badRequest("Missing findings array");
  }

  const findingIds = await Promise.all(
    body.findings.map((f) =>
      ctx.runMutation(api.auditFindings.upsert, {
        auditId,
        checkId: f.checkId,
        checkName: f.checkName,
        source: f.source,
        owaspCategory: f.owaspCategory,
        owaspName: f.owaspName,
        category: f.category,
        severity: f.severity,
        passed: f.passed,
        isNew: f.isNew,
        status: f.status,
        evidence: f.evidence,
        remediation: f.remediation,
        firstSeenAt: f.firstSeenAt,
        lastSeenAt: f.lastSeenAt,
      })
    )
  );

  return json({ findingIds });
});

// PATCH /api/audit-findings — update finding status
export const handleUpdateFinding = httpAction(async (ctx, request) => {
  if (!checkApiKey(request)) return unauthorized();

  let body: {
    id?: string;
    auditId?: string;
    action?: string;
    status?: "open" | "acknowledged" | "remediated" | "accepted";
    remediationNote?: string;
  };

  try {
    body = await request.json() as typeof body;
  } catch {
    return badRequest("Invalid JSON body");
  }

  if (body.id) {
    // Update a specific finding
    if (!body.status) return badRequest("Missing status");
    await ctx.runMutation(api.auditFindings.updateStatus, {
      id: body.id as Id<"auditFindings">,
      status: body.status,
      remediationNote: body.remediationNote,
    });
  } else if (body.auditId && body.action === "update-status") {
    // Update audit status
    if (!body.status) return badRequest("Missing status");
    await ctx.runMutation(api.audits.updateStatus, {
      id: body.auditId as Id<"audits">,
      status: body.status as "running" | "complete" | "failed",
    });
  } else {
    return badRequest("Missing id or auditId+action");
  }

  return json({ ok: true });
});

// POST /api/skill-inventory/sync — sync installed skills list
export const handleSkillSync = httpAction(async (ctx, request) => {
  if (!checkApiKey(request)) return unauthorized();

  let body: {
    skills: Array<{
      name: string;
      source: string;
      version?: string;
      installedAt: number;
      lastScannedAt?: number;
      scanResult: "clean" | "suspicious" | "malicious" | "unscanned";
      clawhavocMatch: boolean;
      suspicionReasons: string[];
      quarantined: boolean;
    }>;
  };

  try {
    body = await request.json() as typeof body;
  } catch {
    return badRequest("Invalid JSON body");
  }

  if (!body.skills || !Array.isArray(body.skills)) {
    return badRequest("Missing skills array");
  }

  const result = await ctx.runMutation(api.skillInventory.sync, { skills: body.skills });
  return json(result);
});

// GET /api/security/posture — composite SecurityPosture
export const handleSecurityPosture = httpAction(async (ctx, request) => {
  if (!checkApiKey(request)) return unauthorized();

  // Get latest audit stats
  const auditStats = await ctx.runQuery(api.audits.stats);

  // Try to get Augustus scan data (may not exist)
  let llmRiskScore = 0;
  let lastScanAt = 0;
  try {
    // Augustus scans are in the same Convex deployment
    // These queries may not exist if Augustus isn't deployed yet
    const scans = await ctx.runQuery(api.scans.list as never, { limit: 1 } as never) as Array<{
      riskScore?: number;
      startedAt?: number;
    }>;
    if (scans && scans.length > 0 && scans[0]) {
      llmRiskScore = scans[0].riskScore ?? 0;
      lastScanAt = scans[0].startedAt ?? 0;
    }
  } catch {
    // Augustus tables not deployed yet — use defaults
  }

  const hostRiskScore = auditStats.currentRiskScore;
  const compositeScore = Math.round(hostRiskScore * 0.6 + llmRiskScore * 0.4);

  // Determine trend (need previous scores)
  let trend: "improving" | "degrading" | "stable" = "stable";
  if (auditStats.riskScoreDelta > 5) trend = "degrading";
  else if (auditStats.riskScoreDelta < -5) trend = "improving";

  const posture = {
    hostRiskScore,
    llmRiskScore,
    compositeScore,
    trend,
    lastAuditAt: auditStats.lastAuditAt ?? 0,
    lastScanAt,
    openCriticals: auditStats.openCriticals,
    openHighs: 0, // TODO: compute from auditFindings
  };

  return json(posture);
});

// POST /api/security-events — create a security event alert
export const handleCreateSecurityEvent = httpAction(async (ctx, request) => {
  if (!checkApiKey(request)) return unauthorized();

  let body: {
    eventType: "new_critical_finding" | "clawhavoc_match" | "cognitive_file_tampered" |
               "credential_exposure_detected" | "gateway_exposure_detected" | "new_critical_vuln";
    severity: string;
    source: "secureclaw" | "augustus";
    sourceId?: string;
    message: string;
    acknowledged?: boolean;
    createdAt?: number;
  };

  try {
    body = await request.json() as typeof body;
  } catch {
    return badRequest("Invalid JSON body");
  }

  if (!body.eventType || !body.severity || !body.source || !body.message) {
    return badRequest("Missing required fields: eventType, severity, source, message");
  }

  const id = await ctx.runMutation(api.securityEvents.create, {
    eventType: body.eventType,
    severity: body.severity,
    source: body.source,
    sourceId: body.sourceId,
    message: body.message,
  });

  return json({ id });
});

// PATCH /api/security-events/:id/acknowledge — acknowledge an event
export const handleAcknowledgeEvent = httpAction(async (ctx, request) => {
  if (!checkApiKey(request)) return unauthorized();

  // Extract ID from URL path
  const url = new URL(request.url);
  const pathParts = url.pathname.split("/");
  const idIndex = pathParts.indexOf("security-events") + 1;
  const eventId = pathParts[idIndex] as Id<"securityEvents"> | undefined;

  if (!eventId) {
    return badRequest("Missing event ID in path: /api/security-events/:id/acknowledge");
  }

  await ctx.runMutation(api.securityEvents.acknowledge, {
    id: eventId,
  });

  return json({ ok: true });
});

// GET /api/audits/latest — get latest audit + findings (for diff computation by runner)
export const handleLatestAudit = httpAction(async (ctx, request) => {
  if (!checkApiKey(request)) return unauthorized();

  const latest = await ctx.runQuery(api.audits.latest);
  if (!latest) return json({ audit: null, findings: null });

  const findings = await ctx.runQuery(api.auditFindings.byScan, {
    auditId: latest._id,
    includeAll: false,
  });

  return json({
    audit: {
      id: latest._id,
      status: latest.status,
      hostRiskScore: latest.hostRiskScore,
      startedAt: latest.startedAt,
    },
    findings: findings.map((f) => ({
      id: f._id,
      checkId: f.checkId,
      auditId: f.auditId,
      source: f.source,
      owaspCategory: f.owaspCategory,
      owaspName: f.owaspName,
      category: f.category,
      severity: f.severity,
      passed: f.passed,
      evidence: f.evidence,
      remediation: f.remediation,
      firstSeenAt: f.firstSeenAt,
    })),
  });
});

// ── Route registration map ────────────────────────────────────────────────────
// Add to your convex/http.ts:
//
// import * as securityAudit from "./http-security-audit";
//
// http.route({ path: "/api/audits", method: "POST", handler: securityAudit.handleCreateAudit });
// http.route({ path: "/api/audits/latest", method: "GET", handler: securityAudit.handleLatestAudit });
// http.route({ path: "/api/audit-results", method: "POST", handler: securityAudit.handleAuditResults });
// http.route({ path: "/api/audit-findings", method: "PATCH", handler: securityAudit.handleUpdateFinding });
// http.route({ path: "/api/skill-inventory/sync", method: "POST", handler: securityAudit.handleSkillSync });
// http.route({ path: "/api/security/posture", method: "GET", handler: securityAudit.handleSecurityPosture });
// http.route({ path: "/api/security-events", method: "POST", handler: securityAudit.handleCreateSecurityEvent });
// http.route({ pathPrefix: "/api/security-events/", method: "PATCH", handler: securityAudit.handleAcknowledgeEvent });
