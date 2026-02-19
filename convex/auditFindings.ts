// convex/auditFindings.ts
// Queries and mutations for the auditFindings table

import { mutation, query } from "./_generated/server";
import { v } from "convex/values";

// ── Queries ────────────────────────────────────────────────────────────────────

export const open = query({
  args: {
    severity: v.optional(v.string()),
    limit: v.optional(v.number()),
  },
  handler: async (ctx, { severity, limit = 50 }) => {
    if (severity) {
      return ctx.db
        .query("auditFindings")
        .withIndex("by_status_severity", (q) =>
          q.eq("status", "open").eq(
            "severity",
            severity as "critical" | "high" | "medium" | "low" | "info"
          )
        )
        .order("desc")
        .take(limit);
    }
    return ctx.db
      .query("auditFindings")
      .withIndex("by_status_severity", (q) => q.eq("status", "open"))
      .order("desc")
      .take(limit);
  },
});

export const byOWASP = query({
  args: {
    owaspCategory: v.string(),
    statusFilter: v.optional(v.string()),
    limit: v.optional(v.number()),
  },
  handler: async (ctx, { owaspCategory, statusFilter, limit = 50 }) => {
    const findings = await ctx.db
      .query("auditFindings")
      .withIndex("by_owasp", (q) => q.eq("owaspCategory", owaspCategory))
      .order("desc")
      .take(200);

    if (statusFilter) {
      return findings.filter((f) => f.status === statusFilter).slice(0, limit);
    }
    return findings.slice(0, limit);
  },
});

export const bySeverity = query({
  args: {
    severity: v.string(),
    limit: v.optional(v.number()),
  },
  handler: async (ctx, { severity, limit = 50 }) => {
    return ctx.db
      .query("auditFindings")
      .withIndex("by_severity", (q) =>
        q.eq("severity", severity as "critical" | "high" | "medium" | "low" | "info")
      )
      .order("desc")
      .take(limit);
  },
});

export const byScan = query({
  args: {
    auditId: v.id("audits"),
    includeAll: v.optional(v.boolean()),
  },
  handler: async (ctx, { auditId, includeAll = false }) => {
    const findings = await ctx.db
      .query("auditFindings")
      .withIndex("by_audit", (q) => q.eq("auditId", auditId))
      .collect();

    if (includeAll) return findings;
    // By default, only return failed checks
    return findings.filter((f) => !f.passed);
  },
});

// Get all finding counts grouped by OWASP category for the coverage map
export const owaspSummary = query({
  args: { auditId: v.optional(v.id("audits")) },
  handler: async (ctx, { auditId }) => {
    const categories = ["ASI01", "ASI02", "ASI03", "ASI04", "ASI05",
                        "ASI06", "ASI07", "ASI08", "ASI09", "ASI10"];

    const summary: Record<string, {
      total: number;
      open: number;
      critical: number;
      high: number;
      medium: number;
      low: number;
    }> = {};

    for (const cat of categories) {
      let findings;
      if (auditId) {
        const auditFindings = await ctx.db
          .query("auditFindings")
          .withIndex("by_audit", (q) => q.eq("auditId", auditId))
          .collect();
        findings = auditFindings.filter(
          (f) => f.owaspCategory === cat && !f.passed
        );
      } else {
        findings = await ctx.db
          .query("auditFindings")
          .withIndex("by_owasp", (q) => q.eq("owaspCategory", cat))
          .collect();
        findings = findings.filter((f) => !f.passed && f.status === "open");
      }

      summary[cat] = {
        total: findings.length,
        open: findings.filter((f) => f.status === "open").length,
        critical: findings.filter((f) => f.severity === "critical").length,
        high: findings.filter((f) => f.severity === "high").length,
        medium: findings.filter((f) => f.severity === "medium").length,
        low: findings.filter((f) => f.severity === "low").length,
      };
    }

    return summary;
  },
});

// Get findings for diff view (current vs previous audit)
export const forDiff = query({
  args: {
    currentAuditId: v.id("audits"),
    previousAuditId: v.optional(v.id("audits")),
  },
  handler: async (ctx, { currentAuditId, previousAuditId }) => {
    const currentFindings = await ctx.db
      .query("auditFindings")
      .withIndex("by_audit", (q) => q.eq("auditId", currentAuditId))
      .collect();

    const previousFindings = previousAuditId
      ? await ctx.db
          .query("auditFindings")
          .withIndex("by_audit", (q) => q.eq("auditId", previousAuditId))
          .collect()
      : [];

    const currentCheckIds = new Set(
      currentFindings.filter((f) => !f.passed).map((f) => f.checkId)
    );
    const previousCheckIds = new Set(
      previousFindings.filter((f) => !f.passed).map((f) => f.checkId)
    );

    return {
      newFindings: currentFindings.filter(
        (f) => !f.passed && !previousCheckIds.has(f.checkId)
      ),
      resolvedFindings: previousFindings.filter(
        (f) => !f.passed && !currentCheckIds.has(f.checkId)
      ),
      persistingFindings: currentFindings.filter(
        (f) => !f.passed && previousCheckIds.has(f.checkId)
      ),
    };
  },
});

// ── Mutations ────────────────────────────────────────────────────────────────

export const upsert = mutation({
  args: {
    auditId: v.id("audits"),
    checkId: v.string(),
    checkName: v.string(),
    source: v.union(v.literal("secureclaw"), v.literal("custom")),
    owaspCategory: v.string(),
    owaspName: v.string(),
    category: v.string(),
    severity: v.union(
      v.literal("critical"),
      v.literal("high"),
      v.literal("medium"),
      v.literal("low"),
      v.literal("info"),
    ),
    passed: v.boolean(),
    isNew: v.boolean(),
    status: v.union(
      v.literal("open"),
      v.literal("acknowledged"),
      v.literal("remediated"),
      v.literal("accepted"),
    ),
    evidence: v.optional(v.string()),
    remediation: v.optional(v.string()),
    firstSeenAt: v.number(),
    lastSeenAt: v.number(),
  },
  handler: async (ctx, args) => {
    // Check if finding for this check already exists in this audit
    const existing = await ctx.db
      .query("auditFindings")
      .withIndex("by_audit", (q) => q.eq("auditId", args.auditId))
      .filter((q) => q.eq(q.field("checkId"), args.checkId))
      .first();

    if (existing) {
      await ctx.db.patch(existing._id, {
        ...args,
        lastSeenAt: args.lastSeenAt,
      });
      return existing._id;
    }

    return ctx.db.insert("auditFindings", args);
  },
});

export const updateStatus = mutation({
  args: {
    id: v.id("auditFindings"),
    status: v.union(
      v.literal("open"),
      v.literal("acknowledged"),
      v.literal("remediated"),
      v.literal("accepted"),
    ),
    remediationNote: v.optional(v.string()),
  },
  handler: async (ctx, { id, status, remediationNote }) => {
    const patch: Record<string, unknown> = { status };
    if (remediationNote !== undefined) patch.remediationNote = remediationNote;
    if (status === "remediated") patch.remediatedAt = Date.now();
    await ctx.db.patch(id, patch);
  },
});
