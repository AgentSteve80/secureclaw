"use client";

// AuditHistory.tsx
// Table of past SecureClaw audit runs with expandable findings.

import { useState } from "react";
import { useQuery, useMutation } from "convex/react";
import { api } from "../../../convex/_generated/api";
import { Id } from "../../../convex/_generated/dataModel";
import { cn } from "@/lib/utils";
import { ChevronDown, ChevronRight, RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/button";

type AuditStatus = "running" | "complete" | "failed";

interface AuditRow {
  _id: Id<"audits">;
  type: string;
  triggeredBy: string;
  status: AuditStatus;
  startedAt: number;
  durationMs?: number | null;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  hostRiskScore: number;
  newFindingsCount: number;
  resolvedFindingsCount: number;
  riskScoreDelta: number;
  secureclawVersion: string;
}

function formatDate(ts: number): string {
  return new Date(ts).toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function formatDuration(ms: number | null | undefined): string {
  if (!ms) return "—";
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
  return `${Math.floor(ms / 60000)}m ${Math.floor((ms % 60000) / 1000)}s`;
}

function StatusBadge({ status }: { status: AuditStatus }) {
  const styles: Record<AuditStatus, string> = {
    complete: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30",
    running: "bg-blue-500/20 text-blue-400 border-blue-500/30 animate-pulse",
    failed: "bg-red-500/20 text-red-400 border-red-500/30",
  };
  const labels: Record<AuditStatus, string> = {
    complete: "Complete",
    running: "Running",
    failed: "Failed",
  };
  return (
    <span className={cn(
      "text-[10px] font-medium border px-2 py-0.5 rounded-full",
      styles[status]
    )}>
      {labels[status]}
    </span>
  );
}

function DeltaBadge({ delta }: { delta: number }) {
  if (delta === 0) return <span className="text-[hsl(215,20%,40%)] text-xs">—</span>;
  const color = delta > 0 ? "text-red-400" : "text-emerald-400";
  const sign = delta > 0 ? "+" : "";
  return <span className={cn("text-xs font-medium tabular-nums", color)}>{sign}{delta}</span>;
}

function SeverityCounts({ c, h, m, l }: { c: number; h: number; m: number; l: number }) {
  return (
    <div className="flex items-center gap-1.5 text-[10px] font-medium tabular-nums">
      {c > 0 && <span className="text-red-400">{c}C</span>}
      {h > 0 && <span className="text-orange-400">{h}H</span>}
      {m > 0 && <span className="text-yellow-400">{m}M</span>}
      {l > 0 && <span className="text-blue-400">{l}L</span>}
      {c === 0 && h === 0 && m === 0 && l === 0 && (
        <span className="text-emerald-400">Clean</span>
      )}
    </div>
  );
}

function AuditFindingsExpanded({ auditId }: { auditId: Id<"audits"> }) {
  const data = useQuery(api.auditFindings.byScan, { auditId, includeAll: false });

  if (!data) {
    return (
      <div className="px-4 py-3 text-xs text-[hsl(215,20%,40%)]">Loading findings…</div>
    );
  }

  if (data.length === 0) {
    return (
      <div className="px-4 py-3 text-xs text-emerald-400">✓ No findings — audit passed</div>
    );
  }

  return (
    <div className="px-4 py-3 space-y-2 border-t border-[hsl(222,47%,13%)]">
      {data.slice(0, 10).map((f) => (
        <div key={f._id} className="flex items-start gap-2 text-xs">
          <span className={cn("font-medium shrink-0 pt-0.5", {
            "text-red-400": f.severity === "critical",
            "text-orange-400": f.severity === "high",
            "text-yellow-400": f.severity === "medium",
            "text-blue-400": f.severity === "low",
            "text-slate-400": f.severity === "info",
          })}>
            [{f.severity.toUpperCase()}]
          </span>
          <div className="flex-1 min-w-0">
            <div className="text-[hsl(213,31%,91%)] font-medium">{f.checkName}</div>
            {f.evidence && (
              <div className="text-[hsl(215,20%,40%)] mt-0.5 truncate">{f.evidence}</div>
            )}
          </div>
          <span className="shrink-0 text-[9px] text-[hsl(215,20%,35%)] bg-[hsl(222,47%,14%)] px-1.5 py-0.5 rounded">
            {f.owaspCategory}
          </span>
        </div>
      ))}
      {data.length > 10 && (
        <div className="text-xs text-[hsl(215,20%,40%)]">+{data.length - 10} more findings</div>
      )}
    </div>
  );
}

interface AuditHistoryProps {
  limit?: number;
  onRerun?: (type: string) => void;
}

export function AuditHistory({ limit = 20, onRerun }: AuditHistoryProps) {
  const audits = useQuery(api.audits.list, { limit });
  const [expanded, setExpanded] = useState<string | null>(null);

  if (!audits) {
    return (
      <div className="rounded-lg border border-[hsl(222,47%,16%)] bg-[hsl(222,47%,8%)] p-6 text-center">
        <div className="text-sm text-[hsl(215,20%,40%)]">Loading audit history…</div>
      </div>
    );
  }

  if (audits.length === 0) {
    return (
      <div className="rounded-lg border border-[hsl(222,47%,16%)] bg-[hsl(222,47%,8%)] p-8 text-center">
        <div className="text-2xl mb-2">🔍</div>
        <div className="text-sm text-[hsl(213,31%,91%)] font-medium">No audits yet</div>
        <div className="text-xs text-[hsl(215,20%,40%)] mt-1">
          Run your first SecureClaw audit to see results here
        </div>
      </div>
    );
  }

  return (
    <div className="rounded-lg border border-[hsl(222,47%,16%)] bg-[hsl(222,47%,8%)] overflow-hidden">
      {/* Table header */}
      <div className="grid grid-cols-[24px_1fr_80px_80px_100px_60px_60px_80px] gap-2 px-4 py-2 border-b border-[hsl(222,47%,13%)] bg-[hsl(222,47%,10%)]">
        <div />
        <div className="text-[10px] font-medium text-[hsl(215,20%,40%)] uppercase tracking-wider">Date / Type</div>
        <div className="text-[10px] font-medium text-[hsl(215,20%,40%)] uppercase tracking-wider">Duration</div>
        <div className="text-[10px] font-medium text-[hsl(215,20%,40%)] uppercase tracking-wider">Findings</div>
        <div className="text-[10px] font-medium text-[hsl(215,20%,40%)] uppercase tracking-wider">Risk Score</div>
        <div className="text-[10px] font-medium text-[hsl(215,20%,40%)] uppercase tracking-wider">Delta</div>
        <div className="text-[10px] font-medium text-[hsl(215,20%,40%)] uppercase tracking-wider">Status</div>
        <div />
      </div>

      {/* Rows */}
      <div className="divide-y divide-[hsl(222,47%,12%)]">
        {(audits as AuditRow[]).map((audit) => {
          const isExpanded = expanded === audit._id;
          return (
            <div key={audit._id}>
              <button
                className="w-full grid grid-cols-[24px_1fr_80px_80px_100px_60px_60px_80px] gap-2 px-4 py-3 hover:bg-[hsl(222,47%,10%)] transition-colors text-left items-center"
                onClick={() => setExpanded(isExpanded ? null : audit._id)}
              >
                <div className="text-[hsl(215,20%,40%)]">
                  {isExpanded
                    ? <ChevronDown size={14} />
                    : <ChevronRight size={14} />
                  }
                </div>
                <div>
                  <div className="text-xs text-[hsl(213,31%,91%)] font-medium">
                    {formatDate(audit.startedAt)}
                  </div>
                  <div className="text-[10px] text-[hsl(215,20%,45%)] capitalize mt-0.5">
                    {audit.type} audit · {audit.triggeredBy}
                  </div>
                </div>
                <div className="text-xs text-[hsl(215,20%,45%)] tabular-nums">
                  {formatDuration(audit.durationMs)}
                </div>
                <SeverityCounts
                  c={audit.criticalCount}
                  h={audit.highCount}
                  m={audit.mediumCount}
                  l={audit.lowCount}
                />
                <div className="flex items-center gap-1.5">
                  <div className={cn("text-sm font-bold tabular-nums", {
                    "text-emerald-400": audit.hostRiskScore <= 25,
                    "text-yellow-400": audit.hostRiskScore > 25 && audit.hostRiskScore <= 50,
                    "text-orange-400": audit.hostRiskScore > 50 && audit.hostRiskScore <= 75,
                    "text-red-400": audit.hostRiskScore > 75,
                  })}>
                    {audit.hostRiskScore}
                  </div>
                  <div className="flex-1 h-1 rounded-full bg-[hsl(222,47%,14%)] overflow-hidden max-w-[40px]">
                    <div
                      className={cn("h-full rounded-full", {
                        "bg-emerald-500": audit.hostRiskScore <= 25,
                        "bg-yellow-500": audit.hostRiskScore > 25 && audit.hostRiskScore <= 50,
                        "bg-orange-500": audit.hostRiskScore > 50 && audit.hostRiskScore <= 75,
                        "bg-red-500": audit.hostRiskScore > 75,
                      })}
                      style={{ width: `${audit.hostRiskScore}%` }}
                    />
                  </div>
                </div>
                <DeltaBadge delta={audit.riskScoreDelta} />
                <StatusBadge status={audit.status} />
                {onRerun && audit.status !== "running" && (
                  <Button
                    size="sm"
                    variant="ghost"
                    className="h-6 px-2 text-[10px] text-[hsl(215,20%,45%)] hover:text-[hsl(213,31%,91%)]"
                    onClick={(e) => {
                      e.stopPropagation();
                      onRerun(audit.type);
                    }}
                  >
                    <RefreshCw size={11} className="mr-1" />
                    Re-run
                  </Button>
                )}
              </button>

              {isExpanded && (
                <AuditFindingsExpanded auditId={audit._id} />
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
