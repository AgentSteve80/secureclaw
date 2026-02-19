"use client";

// AuditDiff.tsx
// Side-by-side diff of current vs previous audit.
// Three columns: New Findings (red), Resolved (green), Persisting (grey).
// The primary weekly review surface.

import { useQuery } from "convex/react";
import { api } from "../../../convex/_generated/api";
import { Id } from "../../../convex/_generated/dataModel";
import { cn } from "@/lib/utils";
import { ArrowDown, ArrowUp, Minus } from "lucide-react";

type FindingSeverity = "critical" | "high" | "medium" | "low" | "info";

interface Finding {
  _id: Id<"auditFindings">;
  checkId: string;
  checkName: string;
  source: "secureclaw" | "custom";
  owaspCategory: string;
  severity: FindingSeverity;
  passed: boolean;
  evidence?: string | null;
  remediation?: string | null;
}

function SeverityDot({ severity }: { severity: FindingSeverity }) {
  const colors: Record<FindingSeverity, string> = {
    critical: "bg-red-500",
    high: "bg-orange-500",
    medium: "bg-yellow-500",
    low: "bg-blue-500",
    info: "bg-slate-500",
  };
  return (
    <span className={cn("inline-block w-2 h-2 rounded-full shrink-0", colors[severity])} />
  );
}

function FindingItem({ finding, variant }: {
  finding: Finding;
  variant: "new" | "resolved" | "persisting";
}) {
  const textColors = {
    new: "text-[hsl(213,31%,91%)]",
    resolved: "text-[hsl(215,20%,55%)]",
    persisting: "text-[hsl(215,20%,65%)]",
  };

  return (
    <div className={cn(
      "rounded-lg p-3 space-y-1",
      variant === "new" && "bg-red-500/5 border border-red-500/20",
      variant === "resolved" && "bg-emerald-500/5 border border-emerald-500/20",
      variant === "persisting" && "bg-[hsl(222,47%,12%)] border border-[hsl(222,47%,18%)]",
    )}>
      <div className="flex items-start gap-2">
        <SeverityDot severity={finding.severity} />
        <div className="flex-1 min-w-0">
          <div className={cn("text-xs font-medium leading-tight", textColors[variant])}>
            {finding.checkName}
          </div>
          <div className="text-[9px] text-[hsl(215,20%,40%)] mt-0.5 flex items-center gap-1">
            <span>{finding.owaspCategory}</span>
            <span>·</span>
            <span className="capitalize">{finding.source}</span>
          </div>
        </div>
      </div>
      {finding.evidence && (
        <p className="text-[10px] text-[hsl(215,20%,40%)] line-clamp-2 pl-4">
          {finding.evidence}
        </p>
      )}
    </div>
  );
}

function CountBadge({ count, variant }: {
  count: number;
  variant: "new" | "resolved" | "persisting";
}) {
  const styles = {
    new: "bg-red-500/20 text-red-400 border-red-500/30",
    resolved: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30",
    persisting: "bg-[hsl(222,47%,16%)] text-[hsl(215,20%,55%)] border-[hsl(222,47%,22%)]",
  };
  return (
    <span className={cn(
      "text-xs font-bold border px-2 py-0.5 rounded-full tabular-nums",
      styles[variant]
    )}>
      {count}
    </span>
  );
}

interface AuditDiffProps {
  currentAuditId: Id<"audits"> | null;
  previousAuditId: Id<"audits"> | null;
}

export function AuditDiff({ currentAuditId, previousAuditId }: AuditDiffProps) {
  const diffData = useQuery(
    api.auditFindings.forDiff,
    currentAuditId
      ? {
          currentAuditId,
          previousAuditId: previousAuditId ?? undefined,
        }
      : "skip"
  );

  if (!currentAuditId) {
    return (
      <div className="rounded-lg border border-[hsl(222,47%,16%)] bg-[hsl(222,47%,8%)] p-8 text-center">
        <div className="text-2xl mb-2">📊</div>
        <div className="text-sm text-[hsl(213,31%,91%)]">No audit data yet</div>
        <div className="text-xs text-[hsl(215,20%,40%)] mt-1">Run an audit to see the diff view</div>
      </div>
    );
  }

  if (!diffData) {
    return (
      <div className="rounded-lg border border-[hsl(222,47%,16%)] bg-[hsl(222,47%,8%)] p-6 text-center">
        <div className="text-sm text-[hsl(215,20%,40%)]">Loading diff…</div>
      </div>
    );
  }

  const { newFindings, resolvedFindings, persistingFindings } = diffData;

  return (
    <div className="space-y-4">
      {/* Summary bar */}
      <div className="flex items-center gap-3 p-3 rounded-lg bg-[hsl(222,47%,9%)] border border-[hsl(222,47%,15%)]">
        <div className="flex items-center gap-1.5">
          <ArrowUp size={14} className="text-red-400" />
          <span className="text-xs text-[hsl(215,20%,50%)]">
            <span className="text-red-400 font-bold">{newFindings.length}</span> new
          </span>
        </div>
        <div className="w-px h-4 bg-[hsl(222,47%,20%)]" />
        <div className="flex items-center gap-1.5">
          <ArrowDown size={14} className="text-emerald-400" />
          <span className="text-xs text-[hsl(215,20%,50%)]">
            <span className="text-emerald-400 font-bold">{resolvedFindings.length}</span> resolved
          </span>
        </div>
        <div className="w-px h-4 bg-[hsl(222,47%,20%)]" />
        <div className="flex items-center gap-1.5">
          <Minus size={14} className="text-slate-400" />
          <span className="text-xs text-[hsl(215,20%,50%)]">
            <span className="text-slate-400 font-bold">{persistingFindings.length}</span> persisting
          </span>
        </div>
        {!previousAuditId && (
          <span className="ml-auto text-[10px] text-[hsl(215,20%,35%)]">
            No previous audit — showing baseline
          </span>
        )}
      </div>

      {/* Three-column diff */}
      <div className="grid grid-cols-3 gap-4">
        {/* New findings column */}
        <div className="space-y-2">
          <div className="flex items-center gap-2 pb-2 border-b border-[hsl(222,47%,16%)]">
            <h4 className="text-xs font-semibold text-red-400 uppercase tracking-wider flex-1">
              New Findings
            </h4>
            <CountBadge count={newFindings.length} variant="new" />
          </div>
          {newFindings.length === 0 ? (
            <div className="text-xs text-[hsl(215,20%,35%)] py-4 text-center">
              No new findings
            </div>
          ) : (
            <div className="space-y-2">
              {(newFindings as Finding[]).map((f) => (
                <FindingItem key={f._id} finding={f} variant="new" />
              ))}
            </div>
          )}
        </div>

        {/* Resolved column */}
        <div className="space-y-2">
          <div className="flex items-center gap-2 pb-2 border-b border-[hsl(222,47%,16%)]">
            <h4 className="text-xs font-semibold text-emerald-400 uppercase tracking-wider flex-1">
              Resolved
            </h4>
            <CountBadge count={resolvedFindings.length} variant="resolved" />
          </div>
          {resolvedFindings.length === 0 ? (
            <div className="text-xs text-[hsl(215,20%,35%)] py-4 text-center">
              Nothing resolved
            </div>
          ) : (
            <div className="space-y-2">
              {(resolvedFindings as Finding[]).map((f) => (
                <FindingItem key={f._id} finding={f} variant="resolved" />
              ))}
            </div>
          )}
        </div>

        {/* Persisting column */}
        <div className="space-y-2">
          <div className="flex items-center gap-2 pb-2 border-b border-[hsl(222,47%,16%)]">
            <h4 className="text-xs font-semibold text-[hsl(215,20%,55%)] uppercase tracking-wider flex-1">
              Persisting
            </h4>
            <CountBadge count={persistingFindings.length} variant="persisting" />
          </div>
          {persistingFindings.length === 0 ? (
            <div className="text-xs text-[hsl(215,20%,35%)] py-4 text-center">
              None persisting
            </div>
          ) : (
            <div className="space-y-2">
              {(persistingFindings as Finding[]).map((f) => (
                <FindingItem key={f._id} finding={f} variant="persisting" />
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
