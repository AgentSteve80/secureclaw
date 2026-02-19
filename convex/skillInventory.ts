// convex/skillInventory.ts
// Queries and mutations for the skillInventory table

import { mutation, query } from "./_generated/server";
import { v } from "convex/values";

// ── Queries ────────────────────────────────────────────────────────────────────

export const all = query({
  args: {},
  handler: async (ctx) => {
    return ctx.db.query("skillInventory").order("desc").collect();
  },
});

export const flagged = query({
  args: {},
  handler: async (ctx) => {
    const suspicious = await ctx.db
      .query("skillInventory")
      .withIndex("by_scan_result", (q) => q.eq("scanResult", "suspicious"))
      .collect();

    const malicious = await ctx.db
      .query("skillInventory")
      .withIndex("by_scan_result", (q) => q.eq("scanResult", "malicious"))
      .collect();

    return [...malicious, ...suspicious].sort((a, b) => {
      if (a.scanResult === "malicious" && b.scanResult !== "malicious") return -1;
      if (b.scanResult === "malicious" && a.scanResult !== "malicious") return 1;
      return 0;
    });
  },
});

export const byName = query({
  args: { name: v.string() },
  handler: async (ctx, { name }) => {
    return ctx.db
      .query("skillInventory")
      .withIndex("by_name", (q) => q.eq("name", name))
      .first();
  },
});

export const unscanned = query({
  args: {},
  handler: async (ctx) => {
    return ctx.db
      .query("skillInventory")
      .withIndex("by_scan_result", (q) => q.eq("scanResult", "unscanned"))
      .collect();
  },
});

// ── Mutations ────────────────────────────────────────────────────────────────

export const sync = mutation({
  args: {
    skills: v.array(v.object({
      name: v.string(),
      source: v.string(),
      version: v.optional(v.string()),
      installedAt: v.number(),
      lastScannedAt: v.optional(v.number()),
      scanResult: v.union(
        v.literal("clean"),
        v.literal("suspicious"),
        v.literal("malicious"),
        v.literal("unscanned"),
      ),
      clawhavocMatch: v.boolean(),
      suspicionReasons: v.array(v.string()),
      quarantined: v.boolean(),
    })),
  },
  handler: async (ctx, { skills }) => {
    let updated = 0;

    for (const skill of skills) {
      const existing = await ctx.db
        .query("skillInventory")
        .withIndex("by_name", (q) => q.eq("name", skill.name))
        .first();

      if (existing) {
        await ctx.db.patch(existing._id, skill);
      } else {
        await ctx.db.insert("skillInventory", skill);
      }
      updated++;
    }

    return { updated };
  },
});

export const quarantine = mutation({
  args: {
    name: v.string(),
    reason: v.optional(v.string()),
  },
  handler: async (ctx, { name, reason }) => {
    const skill = await ctx.db
      .query("skillInventory")
      .withIndex("by_name", (q) => q.eq("name", name))
      .first();

    if (!skill) throw new Error(`Skill "${name}" not found in inventory`);

    await ctx.db.patch(skill._id, {
      quarantined: true,
      scanResult: "suspicious",
      suspicionReasons: reason
        ? [...skill.suspicionReasons, reason]
        : skill.suspicionReasons,
    });

    return { ok: true };
  },
});

export const updateScanResult = mutation({
  args: {
    name: v.string(),
    scanResult: v.union(
      v.literal("clean"),
      v.literal("suspicious"),
      v.literal("malicious"),
      v.literal("unscanned"),
    ),
    clawhavocMatch: v.boolean(),
    suspicionReasons: v.array(v.string()),
    lastScannedAt: v.number(),
  },
  handler: async (ctx, { name, ...fields }) => {
    const skill = await ctx.db
      .query("skillInventory")
      .withIndex("by_name", (q) => q.eq("name", name))
      .first();

    if (!skill) {
      throw new Error(`Skill "${name}" not found`);
    }

    await ctx.db.patch(skill._id, fields);
    return { ok: true };
  },
});
