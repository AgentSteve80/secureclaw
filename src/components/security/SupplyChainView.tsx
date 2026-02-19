"use client";

// SupplyChainView.tsx
// Table of installed OpenClaw skills with ClawHavoc scan status.
// Shows: Name, Source, Install Date, Last Scanned, ClawHavoc Status.
// Quick-remove button for flagged skills. "Scan All" button.

import { useState } from "react";
import { useQuery, useMutation } from "convex/react";
import { api } from "../../../convex/_generated/api";
import { cn } from "@/lib/utils";
import { RefreshCw, AlertTriangle, Shield, ShieldAlert, HelpCircle } from "lucide-react";
import { Button } from "@/components/ui/button";

type ScanResult = "clean" | "suspicious" | "malicious" | "unscanned";

interface SkillRecord {
  _id: string;
  name: string;
  source: string;
  version?: string | null;
  installedAt: number;
  lastScannedAt?: number | null;
  scanResult: ScanResult;
  clawhavocMatch: boolean;
  suspicionReasons: string[];
  quarantined: boolean;
}

const SCAN_RESULT_CONFIG: Record<ScanResult, {
  icon: string;
  label: string;
  color: string;
  bg: string;
  border: string;
}> = {
  clean: {
    icon: "🟢",
    label: "Clean",
    color: "text-emerald-400",
    bg: "bg-emerald-500/10",
    border: "border-emerald-500/20",
  },
  suspicious: {
    icon: "🟡",
    label: "Suspicious",
    color: "text-yellow-400",
    bg: "bg-yellow-500/10",
    border: "border-yellow-500/20",
  },
  malicious: {
    icon: "🔴",
    label: "Malicious",
    color: "text-red-400",
    bg: "bg-red-500/10",
    border: "border-red-500/20",
  },
  unscanned: {
    icon: "⬜",
    label: "Unscanned",
    color: "text-[hsl(215,20%,45%)]",
    bg: "bg-[hsl(222,47%,12%)]",
    border: "border-[hsl(222,47%,18%)]",
  },
};

function formatDate(ts: number | null | undefined): string {
  if (!ts) return "Never";
  return new Date(ts).toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
  });
}

function ScanStatusBadge({ result, clawhavocMatch }: { result: ScanResult; clawhavocMatch: boolean }) {
  const config = SCAN_RESULT_CONFIG[result];
  return (
    <div className="flex items-center gap-1.5">
      <span className={cn(
        "text-[10px] font-medium border px-2 py-0.5 rounded-full flex items-center gap-1",
        config.bg,
        config.border,
        config.color,
      )}>
        {config.icon} {config.label}
      </span>
      {clawhavocMatch && (
        <AlertTriangle size={12} className="text-red-400" title="ClawHavoc signature match" />
      )}
    </div>
  );
}

function SkillRow({ skill, onQuarantine }: {
  skill: SkillRecord;
  onQuarantine: (name: string) => void;
}) {
  const [showReasons, setShowReasons] = useState(false);
  const isHighRisk = skill.scanResult === "malicious" || skill.clawhavocMatch;
  const isFlagged = skill.scanResult === "suspicious" || isHighRisk;

  return (
    <>
      <tr className={cn(
        "border-b border-[hsl(222,47%,12%)] hover:bg-[hsl(222,47%,10%)] transition-colors",
        skill.quarantined && "opacity-50",
        isHighRisk && "bg-red-500/5",
      )}>
        <td className="px-4 py-3">
          <div className="flex items-center gap-2">
            <div>
              <div className="text-xs font-medium text-[hsl(213,31%,91%)] flex items-center gap-1.5">
                {skill.name}
                {skill.quarantined && (
                  <span className="text-[9px] text-red-400 border border-red-500/30 bg-red-500/10 px-1 py-0.5 rounded">
                    QUARANTINED
                  </span>
                )}
              </div>
              {skill.version && (
                <div className="text-[10px] text-[hsl(215,20%,40%)]">v{skill.version}</div>
              )}
            </div>
          </div>
        </td>
        <td className="px-4 py-3">
          <div className="text-[10px] text-[hsl(215,20%,50%)] font-mono max-w-[180px] truncate" title={skill.source}>
            {skill.source}
          </div>
        </td>
        <td className="px-4 py-3">
          <div className="text-xs text-[hsl(215,20%,50%)]">{formatDate(skill.installedAt)}</div>
        </td>
        <td className="px-4 py-3">
          <div className="text-xs text-[hsl(215,20%,50%)]">{formatDate(skill.lastScannedAt)}</div>
        </td>
        <td className="px-4 py-3">
          <ScanStatusBadge result={skill.scanResult} clawhavocMatch={skill.clawhavocMatch} />
        </td>
        <td className="px-4 py-3">
          <div className="flex items-center gap-2">
            {skill.suspicionReasons.length > 0 && (
              <button
                className="text-[10px] text-yellow-400 hover:text-yellow-300 transition-colors"
                onClick={() => setShowReasons(!showReasons)}
              >
                {showReasons ? "Hide" : `${skill.suspicionReasons.length} reason${skill.suspicionReasons.length !== 1 ? "s" : ""}`}
              </button>
            )}
            {isFlagged && !skill.quarantined && (
              <button
                className="text-[10px] bg-red-500/10 hover:bg-red-500/20 text-red-400 border border-red-500/30 px-2 py-0.5 rounded transition-colors"
                onClick={() => onQuarantine(skill.name)}
              >
                Quarantine
              </button>
            )}
          </div>
        </td>
      </tr>
      {showReasons && skill.suspicionReasons.length > 0 && (
        <tr className="border-b border-[hsl(222,47%,12%)] bg-yellow-500/5">
          <td colSpan={6} className="px-4 py-2">
            <div className="space-y-1">
              {skill.suspicionReasons.map((reason, i) => (
                <div key={i} className="text-[10px] text-yellow-400 flex gap-2">
                  <span>⚠</span>
                  <span>{reason}</span>
                </div>
              ))}
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

interface SupplyChainViewProps {
  onScanAll?: () => void;
}

export function SupplyChainView({ onScanAll }: SupplyChainViewProps) {
  const skills = useQuery(api.skillInventory.all);
  const flagged = useQuery(api.skillInventory.flagged);
  const quarantine = useMutation(api.skillInventory.quarantine);
  const [isScanning, setIsScanning] = useState(false);

  const handleQuarantine = async (name: string) => {
    await quarantine({ name, reason: "Manually quarantined via Mission Control" });
  };

  const handleScanAll = async () => {
    if (!onScanAll) return;
    setIsScanning(true);
    try {
      onScanAll();
    } finally {
      setTimeout(() => setIsScanning(false), 3000);
    }
  };

  const flaggedCount = flagged?.length ?? 0;
  const totalSkills = skills?.length ?? 0;
  const unscannedCount = skills?.filter((s: SkillRecord) => s.scanResult === "unscanned").length ?? 0;

  return (
    <div className="space-y-4">
      {/* Header stats */}
      <div className="flex items-center gap-4">
        <div className="flex items-center gap-2">
          <Shield size={16} className="text-emerald-400" />
          <span className="text-sm text-[hsl(213,31%,91%)]">
            {totalSkills} skill{totalSkills !== 1 ? "s" : ""} installed
          </span>
        </div>
        {flaggedCount > 0 && (
          <div className="flex items-center gap-1.5">
            <ShieldAlert size={14} className="text-red-400" />
            <span className="text-sm text-red-400 font-medium">
              {flaggedCount} flagged
            </span>
          </div>
        )}
        {unscannedCount > 0 && (
          <div className="flex items-center gap-1.5">
            <HelpCircle size={14} className="text-[hsl(215,20%,45%)]" />
            <span className="text-sm text-[hsl(215,20%,45%)]">
              {unscannedCount} unscanned
            </span>
          </div>
        )}
        <div className="ml-auto">
          <Button
            size="sm"
            variant="outline"
            className="text-xs border-[hsl(222,47%,22%)] hover:border-[hsl(210,100%,60%,0.5)] hover:text-[hsl(210,100%,60%)]"
            onClick={handleScanAll}
            disabled={isScanning}
          >
            <RefreshCw size={12} className={cn("mr-1.5", isScanning && "animate-spin")} />
            {isScanning ? "Scanning…" : "Scan All"}
          </Button>
        </div>
      </div>

      {/* Flagged alert banner */}
      {flaggedCount > 0 && (
        <div className="rounded-lg border border-red-500/30 bg-red-500/5 px-4 py-3 flex items-start gap-3">
          <AlertTriangle size={16} className="text-red-400 shrink-0 mt-0.5" />
          <div>
            <div className="text-sm font-medium text-red-400">
              {flaggedCount} skill{flaggedCount !== 1 ? "s" : ""} flagged by ClawHavoc
            </div>
            <div className="text-xs text-[hsl(215,20%,50%)] mt-1">
              Review and quarantine suspicious or malicious skills immediately. Quarantined skills are disabled but not removed.
            </div>
          </div>
        </div>
      )}

      {/* Skills table */}
      <div className="rounded-lg border border-[hsl(222,47%,16%)] bg-[hsl(222,47%,8%)] overflow-hidden">
        {!skills ? (
          <div className="p-6 text-center text-sm text-[hsl(215,20%,40%)]">Loading skill inventory…</div>
        ) : skills.length === 0 ? (
          <div className="p-8 text-center">
            <div className="text-2xl mb-2">📦</div>
            <div className="text-sm text-[hsl(213,31%,91%)]">No skills in inventory</div>
            <div className="text-xs text-[hsl(215,20%,40%)] mt-1">
              Run a supply-chain audit to sync the skill inventory
            </div>
          </div>
        ) : (
          <table className="w-full">
            <thead>
              <tr className="border-b border-[hsl(222,47%,13%)] bg-[hsl(222,47%,10%)]">
                <th className="text-left px-4 py-2 text-[10px] font-medium text-[hsl(215,20%,40%)] uppercase tracking-wider">
                  Skill
                </th>
                <th className="text-left px-4 py-2 text-[10px] font-medium text-[hsl(215,20%,40%)] uppercase tracking-wider">
                  Source
                </th>
                <th className="text-left px-4 py-2 text-[10px] font-medium text-[hsl(215,20%,40%)] uppercase tracking-wider">
                  Installed
                </th>
                <th className="text-left px-4 py-2 text-[10px] font-medium text-[hsl(215,20%,40%)] uppercase tracking-wider">
                  Last Scanned
                </th>
                <th className="text-left px-4 py-2 text-[10px] font-medium text-[hsl(215,20%,40%)] uppercase tracking-wider">
                  ClawHavoc
                </th>
                <th className="text-left px-4 py-2 text-[10px] font-medium text-[hsl(215,20%,40%)] uppercase tracking-wider">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody>
              {(skills as SkillRecord[]).map((skill) => (
                <SkillRow
                  key={skill._id}
                  skill={skill}
                  onQuarantine={handleQuarantine}
                />
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
