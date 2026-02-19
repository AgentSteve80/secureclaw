"use client";

// OWASPCoverageMap.tsx
// 2x5 grid showing ASI01–ASI10 coverage.
// Each cell: category name + status emoji + finding count.
// Click to jump to that category in FindingsBoard.

import { useQuery } from "convex/react";
import { api } from "../../../convex/_generated/api";
import { Id } from "../../../convex/_generated/dataModel";
import { cn } from "@/lib/utils";

const OWASP_CATEGORIES = [
  { id: "ASI01", name: "Goal Hijack", shortName: "Prompt Injection" },
  { id: "ASI02", name: "Info Disclosure", shortName: "Data Leakage" },
  { id: "ASI03", name: "Secrets & PII", shortName: "Misconfigured Secrets" },
  { id: "ASI04", name: "Code Execution", shortName: "Insecure Exec" },
  { id: "ASI05", name: "Denial of Service", shortName: "DoS" },
  { id: "ASI06", name: "Cognitive Files", shortName: "Identity Tamper" },
  { id: "ASI07", name: "Supply Chain", shortName: "Skill Compromise" },
  { id: "ASI08", name: "Tool Use", shortName: "Insecure Tools" },
  { id: "ASI09", name: "Output Safety", shortName: "Unsafe Output" },
  { id: "ASI10", name: "Privilege", shortName: "Excessive Agency" },
];

type CellStatus = "clean" | "findings" | "critical" | "uncovered";

function getCellStatus(summary: {
  total: number;
  open: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
} | undefined): CellStatus {
  if (!summary) return "uncovered";
  if (summary.total === 0) return "clean";
  if (summary.critical > 0) return "critical";
  return "findings";
}

const CELL_STYLES: Record<CellStatus, {
  bg: string;
  border: string;
  text: string;
  emoji: string;
}> = {
  clean: {
    bg: "bg-emerald-500/10 hover:bg-emerald-500/15",
    border: "border-emerald-500/30",
    text: "text-emerald-400",
    emoji: "🟢",
  },
  findings: {
    bg: "bg-yellow-500/10 hover:bg-yellow-500/15",
    border: "border-yellow-500/30",
    text: "text-yellow-400",
    emoji: "🟡",
  },
  critical: {
    bg: "bg-red-500/10 hover:bg-red-500/15",
    border: "border-red-500/30",
    text: "text-red-400",
    emoji: "🔴",
  },
  uncovered: {
    bg: "bg-[hsl(222,47%,11%)] hover:bg-[hsl(222,47%,13%)]",
    border: "border-[hsl(222,47%,18%)]",
    text: "text-[hsl(215,20%,40%)]",
    emoji: "⬜",
  },
};

interface OWASPCoverageMapProps {
  auditId?: Id<"audits"> | null;
  onCategoryClick?: (categoryId: string) => void;
}

export function OWASPCoverageMap({ auditId, onCategoryClick }: OWASPCoverageMapProps) {
  const summary = useQuery(api.auditFindings.owaspSummary, {
    auditId: auditId ?? undefined,
  });

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <h3 className="text-xs font-medium text-[hsl(215,20%,45%)] uppercase tracking-wider">
          OWASP ASI Coverage
        </h3>
        <div className="flex items-center gap-3 text-[9px] text-[hsl(215,20%,35%)]">
          <span>🟢 Clean</span>
          <span>🟡 Findings</span>
          <span>🔴 Critical</span>
          <span>⬜ Uncovered</span>
        </div>
      </div>

      {/* 2x5 grid */}
      <div className="grid grid-cols-5 gap-2">
        {OWASP_CATEGORIES.map((cat) => {
          const catSummary = summary?.[cat.id];
          const status = getCellStatus(catSummary);
          const styles = CELL_STYLES[status];

          return (
            <button
              key={cat.id}
              className={cn(
                "rounded-lg border p-3 text-left transition-colors cursor-pointer",
                styles.bg,
                styles.border,
              )}
              onClick={() => onCategoryClick?.(cat.id)}
              title={`${cat.id}: ${cat.name}${catSummary?.total ? ` — ${catSummary.total} findings` : ""}`}
            >
              <div className="flex items-start justify-between mb-1.5">
                <span className="text-[10px] font-mono font-bold text-[hsl(215,20%,50%)]">
                  {cat.id}
                </span>
                <span className="text-sm">{styles.emoji}</span>
              </div>
              <div className="text-[10px] font-medium text-[hsl(213,31%,85%)] leading-tight mb-1">
                {cat.shortName}
              </div>
              {catSummary && catSummary.total > 0 ? (
                <div className={cn("text-[9px] font-medium tabular-nums", styles.text)}>
                  {catSummary.total} finding{catSummary.total !== 1 ? "s" : ""}
                </div>
              ) : (
                <div className="text-[9px] text-[hsl(215,20%,30%)]">
                  {summary ? "Clean" : "Not audited"}
                </div>
              )}
            </button>
          );
        })}
      </div>

      {/* Summary row */}
      {summary && (
        <div className="flex items-center gap-4 pt-1 text-xs text-[hsl(215,20%,40%)]">
          {(() => {
            const totalFindings = Object.values(summary).reduce(
              (sum, s) => sum + (s?.total ?? 0),
              0
            );
            const cleanCategories = OWASP_CATEGORIES.filter(
              (cat) => (summary[cat.id]?.total ?? 0) === 0
            ).length;
            return (
              <>
                <span>
                  <span className="text-[hsl(213,31%,91%)] font-medium">{cleanCategories}/10</span>{" "}
                  categories clean
                </span>
                <span>·</span>
                <span>
                  <span className="text-[hsl(213,31%,91%)] font-medium">{totalFindings}</span>{" "}
                  total open findings
                </span>
              </>
            );
          })()}
        </div>
      )}
    </div>
  );
}
