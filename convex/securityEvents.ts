// convex/securityEvents.ts
// Queries and mutations for the securityEvents table
// Shared between SecureClaw (host audit) and Augustus (LLM scan) alert pipelines.

import { mutation, query } from "./_generated/server";
import { v } from "convex/values";

// ── Queries ────────────────────────────────────────────────────────────────────

export const unacknowledged = query({
  args: { limit: v.optional(v.number()) },
  handler: async (ctx, { limit = 50 }) => {
    return ctx.db
      .query("securityEvents")
      .withIndex("by_acknowledged", (q) => q.eq("acknowledged", false))
      .order("desc")
      .take(limit);
  },
});

export const recent = query({
  args: {
    limit: v.optional(v.number()),
    includeAcknowledged: v.optional(v.boolean()),
  },
  handler: async (ctx, { limit = 20, includeAcknowledged = false }) => {
    const events = await ctx.db
      .query("securityEvents")
      .withIndex("by_created")
      .order("desc")
      .take(100);

    if (includeAcknowledged) {
      return events.slice(0, limit);
    }
    return events.filter((e) => !e.acknowledged).slice(0, limit);
  },
});

export const byType = query({
  args: {
    eventType: v.string(),
    limit: v.optional(v.number()),
  },
  handler: async (ctx, { eventType, limit = 20 }) => {
    return ctx.db
      .query("securityEvents")
      .withIndex("by_type", (q) => q.eq("eventType", eventType as
        "new_critical_finding" | "clawhavoc_match" | "cognitive_file_tampered" |
        "credential_exposure_detected" | "gateway_exposure_detected" | "new_critical_vuln"
      ))
      .order("desc")
      .take(limit);
  },
});

export const unacknowledgedCount = query({
  args: {},
  handler: async (ctx) => {
    const events = await ctx.db
      .query("securityEvents")
      .withIndex("by_acknowledged", (q) => q.eq("acknowledged", false))
      .collect();
    return events.length;
  },
});

// ── Mutations ────────────────────────────────────────────────────────────────

export const create = mutation({
  args: {
    eventType: v.union(
      v.literal("new_critical_finding"),
      v.literal("clawhavoc_match"),
      v.literal("cognitive_file_tampered"),
      v.literal("credential_exposure_detected"),
      v.literal("gateway_exposure_detected"),
      v.literal("new_critical_vuln"),
    ),
    severity: v.string(),
    source: v.union(v.literal("secureclaw"), v.literal("augustus")),
    sourceId: v.optional(v.string()),
    message: v.string(),
  },
  handler: async (ctx, args) => {
    return ctx.db.insert("securityEvents", {
      ...args,
      acknowledged: false,
      createdAt: Date.now(),
    });
  },
});

export const acknowledge = mutation({
  args: { id: v.id("securityEvents") },
  handler: async (ctx, { id }) => {
    await ctx.db.patch(id, {
      acknowledged: true,
      acknowledgedAt: Date.now(),
    });
    return { ok: true };
  },
});

export const acknowledgeAll = mutation({
  args: { source: v.optional(v.string()) },
  handler: async (ctx, { source }) => {
    const unacked = await ctx.db
      .query("securityEvents")
      .withIndex("by_acknowledged", (q) => q.eq("acknowledged", false))
      .collect();

    const toAck = source ? unacked.filter((e) => e.source === source) : unacked;
    const now = Date.now();

    await Promise.all(
      toAck.map((e) => ctx.db.patch(e._id, { acknowledged: true, acknowledgedAt: now }))
    );

    return { acknowledged: toAck.length };
  },
});

// Purge acknowledged events older than 90 days
export const purgeOld = mutation({
  args: {},
  handler: async (ctx) => {
    const cutoff = Date.now() - 90 * 24 * 60 * 60 * 1000;
    const old = await ctx.db
      .query("securityEvents")
      .withIndex("by_acknowledged", (q) => q.eq("acknowledged", true))
      .filter((q) => q.lt(q.field("acknowledgedAt"), cutoff))
      .collect();

    await Promise.all(old.map((e) => ctx.db.delete(e._id)));
    return { deleted: old.length };
  },
});
