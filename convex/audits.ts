// convex/audits.ts
// Queries and mutations for the audits table (SecureClaw audit runs)

import { mutation, query } from "./_generated/server";
import { v } from "convex/values";

// ── Queries ────────────────────────────────────────────────────────────────────

export const list = query({
  args: {
    limit: v.optional(v.number()),
    status: v.optional(v.string()),
  },
  handler: async (ctx, { limit = 20, status }) => {
    let q = ctx.db.query("audits").order("desc");
    const all = await q.take(100);
    const filtered = status ? all.filter((a) => a.status === status) : all;
    return filtered.slice(0, limit);
  },
});

export const latest = query({
  args: {},
  handler: async (ctx) => {
    const audits = await ctx.db
      .query("audits")
      .withIndex("by_status", (q) => q.eq("status", "complete"))
      .order("desc")
      .take(1);
    return audits[0] ?? null;
  },
});

export const getById = query({
  args: { id: v.id("audits") },
  handler: async (ctx, { id }) => {
    return ctx.db.get(id);
  },
});

export const byType = query({
  args: { type: v.string(), limit: v.optional(v.number()) },
  handler: async (ctx, { type, limit = 20 }) => {
    return ctx.db
      .query("audits")
      .withIndex("by_type", (q) => q.eq("type", type as "full" | "supply-chain" | "quick" | "custom"))
      .order("desc")
      .take(limit);
  },
});

// Returns the two most recent completed audits for computing diffs
export const diff = query({
  args: {},
  handler: async (ctx) => {
    const recent = await ctx.db
      .query("audits")
      .withIndex("by_status", (q) => q.eq("status", "complete"))
      .order("desc")
      .take(2);

    if (recent.length < 2) {
      return { current: recent[0] ?? null, previous: null };
    }
    return { current: recent[0], previous: recent[1] };
  },
});

// Get audit with all findings
export const getWithFindings = query({
  args: { id: v.id("audits") },
  handler: async (ctx, { id }) => {
    const audit = await ctx.db.get(id);
    if (!audit) return null;
    const findings = await ctx.db
      .query("auditFindings")
      .withIndex("by_audit", (q) => q.eq("auditId", id))
      .collect();
    return { audit, findings };
  },
});

// Aggregate stats for the security posture card
export const stats = query({
  args: {},
  handler: async (ctx) => {
    const recent = await ctx.db
      .query("audits")
      .order("desc")
      .take(30);

    const latest = recent.find((a) => a.status === "complete") ?? null;
    const previous = recent.filter((a) => a.status === "complete").slice(1, 2)[0] ?? null;

    // Count open findings across all audits
    const openFindings = await ctx.db
      .query("auditFindings")
      .withIndex("by_status_severity", (q) => q.eq("status", "open").eq("severity", "critical"))
      .take(100);

    return {
      totalAudits: recent.length,
      lastAuditAt: latest?.startedAt ?? null,
      currentRiskScore: latest?.hostRiskScore ?? 0,
      riskScoreDelta: latest && previous ? latest.hostRiskScore - previous.hostRiskScore : 0,
      openCriticals: openFindings.length,
    };
  },
});

// ── Mutations ────────────────────────────────────────────────────────────────

export const create = mutation({
  args: {
    type: v.union(
      v.literal("full"),
      v.literal("supply-chain"),
      v.literal("quick"),
      v.literal("custom"),
    ),
    modules: v.optional(v.array(v.string())),
    triggeredBy: v.union(
      v.literal("cron"),
      v.literal("manual"),
      v.literal("post-install"),
      v.literal("ci"),
    ),
    secureclawVersion: v.string(),
    startedAt: v.number(),
    checksRun: v.optional(v.number()),
    checksPassed: v.optional(v.number()),
    checksFailed: v.optional(v.number()),
    criticalCount: v.optional(v.number()),
    highCount: v.optional(v.number()),
    mediumCount: v.optional(v.number()),
    lowCount: v.optional(v.number()),
    hostRiskScore: v.optional(v.number()),
    newFindingsCount: v.optional(v.number()),
    resolvedFindingsCount: v.optional(v.number()),
    riskScoreDelta: v.optional(v.number()),
  },
  handler: async (ctx, args) => {
    return ctx.db.insert("audits", {
      ...args,
      status: "running",
      checksRun: args.checksRun ?? 0,
      checksPassed: args.checksPassed ?? 0,
      checksFailed: args.checksFailed ?? 0,
      criticalCount: args.criticalCount ?? 0,
      highCount: args.highCount ?? 0,
      mediumCount: args.mediumCount ?? 0,
      lowCount: args.lowCount ?? 0,
      hostRiskScore: args.hostRiskScore ?? 0,
      newFindingsCount: args.newFindingsCount ?? 0,
      resolvedFindingsCount: args.resolvedFindingsCount ?? 0,
      riskScoreDelta: args.riskScoreDelta ?? 0,
    });
  },
});

export const updateStatus = mutation({
  args: {
    id: v.id("audits"),
    status: v.union(v.literal("running"), v.literal("complete"), v.literal("failed")),
  },
  handler: async (ctx, { id, status }) => {
    await ctx.db.patch(id, { status });
  },
});

export const complete = mutation({
  args: {
    id: v.id("audits"),
    finishedAt: v.number(),
    durationMs: v.number(),
    checksRun: v.number(),
    checksPassed: v.number(),
    checksFailed: v.number(),
    criticalCount: v.number(),
    highCount: v.number(),
    mediumCount: v.number(),
    lowCount: v.number(),
    hostRiskScore: v.number(),
    newFindingsCount: v.number(),
    resolvedFindingsCount: v.number(),
    riskScoreDelta: v.number(),
  },
  handler: async (ctx, { id, ...fields }) => {
    await ctx.db.patch(id, {
      status: "complete",
      ...fields,
    });
  },
});

export const fail = mutation({
  args: { id: v.id("audits"), error: v.optional(v.string()) },
  handler: async (ctx, { id }) => {
    await ctx.db.patch(id, {
      status: "failed",
      finishedAt: Date.now(),
    });
  },
});
