"use client";

// FindingsBoard.tsx
// Findings grouped by OWASP ASI category (ASI01–ASI10).
// Each category is a collapsible section with severity counts and individual FindingCards.

import { useState } from "react";
import { useQuery, useMutation } from "convex/react";
import { api } from "../../../convex/_generated/api";
import { Id } from "../../../convex/_generated/dataModel";
import { cn } from "@/lib/utils";
import { ChevronDown, ChevronRight } from "lucide-react";

type FindingSeverity = "critical" | "high" | "medium" | "low" | "info";
type FindingStatus = "open" | "acknowledged" | "remediated" | "accepted";

const OWASP_CATEGORIES: { id: string; name: string }[] = [
  { id: "ASI01", name: "Goal Hijack / Prompt Injection" },
  { id: "ASI02", name: "Sensitive Information Disclosure" },
  { id: "ASI03", name: "Misconfigured Secrets & PII Leakage" },
  { id: "ASI04", name: "Insecure Code Execution" },
  { id: "ASI05", name: "Model Denial of Service" },
  { id: "ASI06", name: "Cognitive File & Identity Tampering" },
  { id: "ASI07", name: "Supply Chain Compromise" },
  { id: "ASI08", name: "Insecure Tool Use" },
  { id: "ASI09", name: "Unsafe Output Handling" },
  { id: "ASI10", name: "Excessive Agency / Privilege Escalation" },
];

const SEVERITY_COLORS: Record<FindingSeverity, { bg: string; text: string; border: string }> = {
  critical: { bg: "bg-red-500/10", text: "text-red-400", border: "border-red-500/30" },
  high: { bg: "bg-orange-500/10", text: "text-orange-400", border: "border-orange-500/30" },
  medium: { bg: "bg-yellow-500/10", text: "text-yellow-400", border: "border-yellow-500/30" },
  low: { bg: "bg-blue-500/10", text: "text-blue-400", border: "border-blue-500/30" },
  info: { bg: "bg-slate-500/10", text: "text-slate-400", border: "border-slate-500/30" },
};

interface AuditFinding {
  _id: Id<"auditFindings">;
  checkId: string;
  checkName: string;
  source: "secureclaw" | "custom";
  owaspCategory: string;
  owaspName: string;
  severity: FindingSeverity;
  status: FindingStatus;
  passed: boolean;
  isNew: boolean;
  evidence?: string | null;
  remediation?: string | null;
  remediationNote?: string | null;
  firstSeenAt: number;
  lastSeenAt: number;
}

function FindingCard({ finding, onStatusChange }: {
  finding: AuditFinding;
  onStatusChange: (id: Id<"auditFindings">, status: FindingStatus) => void;
}) {
  const [expanded, setExpanded] = useState(false);
  const { bg, text, border } = SEVERITY_COLORS[finding.severity];

  return (
    <div className={cn(
      "rounded-lg border transition-colors",
      finding.status === "open" ? `${bg} ${border}` : "bg-[hsl(222,47%,10%)] border-[hsl(222,47%,16%)]",
    )}>
      <button
        className="w-full flex items-start gap-3 p-3 text-left"
        onClick={() => setExpanded(!expanded)}
      >
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className={cn("text-[10px] font-bold uppercase", text)}>
              {finding.severity}
            </span>
            {finding.isNew && (
              <span className="text-[9px] bg-blue-500/20 text-blue-400 border border-blue-500/30 px-1.5 py-0.5 rounded-full font-medium">
                NEW
              </span>
            )}
            {finding.source === "custom" && (
              <span className="text-[9px] bg-purple-500/20 text-purple-400 border border-purple-500/30 px-1.5 py-0.5 rounded-full">
                custom
              </span>
            )}
            <span className={cn("text-[9px] ml-auto", {
              "text-[hsl(215,20%,40%)]": finding.status === "open",
              "text-[hsl(215,20%,35%)]": finding.status !== "open",
            })}>
              {finding.status}
            </span>
          </div>
          <div className="text-xs text-[hsl(213,31%,91%)] font-medium mt-1">
            {finding.checkName}
          </div>
          {!expanded && finding.evidence && (
            <p className="text-[10px] text-[hsl(215,20%,40%)] mt-1 line-clamp-1">
              {finding.evidence}
            </p>
          )}
        </div>
        <div className="text-[hsl(215,20%,40%)] shrink-0 pt-0.5">
          {expanded ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
        </div>
      </button>

      {expanded && (
        <div className="px-3 pb-3 space-y-3 border-t border-[hsl(222,47%,15%)] pt-3">
          {finding.evidence && (
            <div>
              <div className="text-[9px] font-medium text-[hsl(215,20%,40%)] uppercase tracking-wider mb-1">
                Evidence
              </div>
              <p className="text-xs text-[hsl(215,20%,60%)] font-mono bg-[hsl(222,47%,12%)] rounded p-2 break-all">
                {finding.evidence}
              </p>
            </div>
          )}
          {finding.remediation && (
            <div>
              <div className="text-[9px] font-medium text-[hsl(215,20%,40%)] uppercase tracking-wider mb-1">
                Remediation
              </div>
              <p className="text-xs text-[hsl(215,20%,60%)]">{finding.remediation}</p>
            </div>
          )}
          <div className="flex items-center gap-2 pt-1">
            <span className="text-[9px] text-[hsl(215,20%,35%)]">
              First seen: {new Date(finding.firstSeenAt).toLocaleDateString()}
            </span>
            <div className="flex gap-1.5 ml-auto">
              {finding.status === "open" && (
                <button
                  className="text-[10px] bg-yellow-500/10 hover:bg-yellow-500/20 text-yellow-400 border border-yellow-500/30 px-2 py-1 rounded transition-colors"
                  onClick={() => onStatusChange(finding._id, "acknowledged")}
                >
                  Acknowledge
                </button>
              )}
              {(finding.status === "open" || finding.status === "acknowledged") && (
                <button
                  className="text-[10px] bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 px-2 py-1 rounded transition-colors"
                  onClick={() => onStatusChange(finding._id, "remediated")}
                >
                  Mark Remediated
                </button>
              )}
              {finding.status !== "accepted" && finding.status !== "remediated" && (
                <button
                  className="text-[10px] bg-slate-500/10 hover:bg-slate-500/20 text-slate-400 border border-slate-500/30 px-2 py-1 rounded transition-colors"
                  onClick={() => onStatusChange(finding._id, "accepted")}
                >
                  Accept Risk
                </button>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function OWASPSection({
  category,
  onStatusChange,
  defaultExpanded = false,
}: {
  category: { id: string; name: string };
  onStatusChange: (id: Id<"auditFindings">, status: FindingStatus) => void;
  defaultExpanded?: boolean;
}) {
  const findings = useQuery(api.auditFindings.byOWASP, {
    owaspCategory: category.id,
    statusFilter: "open",
    limit: 30,
  });
  const [expanded, setExpanded] = useState(defaultExpanded);

  const failedFindings = (findings ?? []).filter((f: AuditFinding) => !f.passed);
  const critCount = failedFindings.filter((f: AuditFinding) => f.severity === "critical").length;
  const highCount = failedFindings.filter((f: AuditFinding) => f.severity === "high").length;
  const hasFindings = failedFindings.length > 0;

  return (
    <div className={cn(
      "rounded-lg border overflow-hidden",
      hasFindings ? "border-[hsl(222,47%,22%)]" : "border-[hsl(222,47%,14%)]",
      "bg-[hsl(222,47%,8%)]"
    )}>
      <button
        className="w-full flex items-center gap-3 px-4 py-3 hover:bg-[hsl(222,47%,10%)] transition-colors text-left"
        onClick={() => setExpanded(!expanded)}
      >
        <span className="text-[10px] font-mono font-bold text-[hsl(215,20%,45%)] w-10 shrink-0">
          {category.id}
        </span>
        <span className="flex-1 text-xs font-medium text-[hsl(213,31%,91%)]">
          {category.name}
        </span>
        <div className="flex items-center gap-2 shrink-0">
          {critCount > 0 && (
            <span className="text-[10px] font-bold text-red-400 bg-red-500/10 border border-red-500/20 px-1.5 py-0.5 rounded">
              {critCount}C
            </span>
          )}
          {highCount > 0 && (
            <span className="text-[10px] font-bold text-orange-400 bg-orange-500/10 border border-orange-500/20 px-1.5 py-0.5 rounded">
              {highCount}H
            </span>
          )}
          {failedFindings.length === 0 && (
            <span className="text-[10px] text-emerald-400">✓ Clean</span>
          )}
          {failedFindings.length > 0 && critCount === 0 && highCount === 0 && (
            <span className="text-[10px] text-yellow-400">{failedFindings.length} finding{failedFindings.length !== 1 ? "s" : ""}</span>
          )}
          {expanded
            ? <ChevronDown size={14} className="text-[hsl(215,20%,40%)]" />
            : <ChevronRight size={14} className="text-[hsl(215,20%,40%)]" />
          }
        </div>
      </button>

      {expanded && (
        <div className="px-4 pb-4 space-y-2 border-t border-[hsl(222,47%,13%)] pt-3">
          {failedFindings.length === 0 ? (
            <div className="text-xs text-[hsl(215,20%,35%)] py-2 text-center">
              No open findings in this category
            </div>
          ) : (
            (failedFindings as AuditFinding[]).map((finding) => (
              <FindingCard
                key={finding._id}
                finding={finding}
                onStatusChange={onStatusChange}
              />
            ))
          )}
        </div>
      )}
    </div>
  );
}

interface FindingsBoardProps {
  defaultExpandCritical?: boolean;
}

export function FindingsBoard({ defaultExpandCritical = true }: FindingsBoardProps) {
  const updateStatus = useMutation(api.auditFindings.updateStatus);

  const handleStatusChange = async (
    id: Id<"auditFindings">,
    status: FindingStatus
  ) => {
    await updateStatus({ id, status });
  };

  return (
    <div className="space-y-2">
      {OWASP_CATEGORIES.map((cat) => (
        <OWASPSection
          key={cat.id}
          category={cat}
          onStatusChange={handleStatusChange}
          defaultExpanded={false}
        />
      ))}
    </div>
  );
}

// Also export the FindingCard for use in AuditHistory expanded view
export { FindingCard };
