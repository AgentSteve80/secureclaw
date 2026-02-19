"use client";

// SecurityScore.tsx
// Composite security risk score card combining SecureClaw (host) + Augustus (LLM) scores.

import { cn } from "@/lib/utils";

interface SecurityScoreProps {
  hostRiskScore: number;    // 0–100 from SecureClaw
  llmRiskScore: number;     // 0–100 from Augustus
  trend: "improving" | "degrading" | "stable";
  lastAuditAt: number | null;
  lastScanAt: number | null;
  openCriticals?: number;
  openHighs?: number;
}

function formatRelativeTime(ts: number | null): string {
  if (!ts) return "Never";
  const diff = Date.now() - ts;
  const minutes = Math.floor(diff / 60000);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

function scoreToColor(score: number): {
  bg: string;
  text: string;
  border: string;
  label: string;
} {
  if (score <= 25) return {
    bg: "bg-emerald-500/10",
    text: "text-emerald-400",
    border: "border-emerald-500/30",
    label: "Secure",
  };
  if (score <= 50) return {
    bg: "bg-yellow-500/10",
    text: "text-yellow-400",
    border: "border-yellow-500/30",
    label: "Low Risk",
  };
  if (score <= 75) return {
    bg: "bg-orange-500/10",
    text: "text-orange-400",
    border: "border-orange-500/30",
    label: "At Risk",
  };
  return {
    bg: "bg-red-500/10",
    text: "text-red-400",
    border: "border-red-500/30",
    label: "Critical",
  };
}

function TrendArrow({ trend }: { trend: "improving" | "degrading" | "stable" }) {
  if (trend === "degrading") {
    return (
      <span className="text-red-400 text-lg" title="Risk increasing">↑</span>
    );
  }
  if (trend === "improving") {
    return (
      <span className="text-emerald-400 text-lg" title="Risk decreasing">↓</span>
    );
  }
  return (
    <span className="text-slate-400 text-lg" title="Stable">→</span>
  );
}

function ScoreBar({ score, label, color }: { score: number; label: string; color: string }) {
  return (
    <div className="space-y-1">
      <div className="flex justify-between text-xs text-[hsl(215,20%,45%)]">
        <span>{label}</span>
        <span className={color}>{score}</span>
      </div>
      <div className="h-1.5 rounded-full bg-[hsl(222,47%,14%)] overflow-hidden">
        <div
          className={cn("h-full rounded-full transition-all duration-500", {
            "bg-emerald-500": score <= 25,
            "bg-yellow-500": score > 25 && score <= 50,
            "bg-orange-500": score > 50 && score <= 75,
            "bg-red-500": score > 75,
          })}
          style={{ width: `${score}%` }}
        />
      </div>
    </div>
  );
}

export function SecurityScore({
  hostRiskScore,
  llmRiskScore,
  trend,
  lastAuditAt,
  lastScanAt,
  openCriticals = 0,
  openHighs = 0,
}: SecurityScoreProps) {
  // Composite: host 60%, LLM 40%
  const compositeScore = Math.round(hostRiskScore * 0.6 + llmRiskScore * 0.4);
  const { bg, text, border, label } = scoreToColor(compositeScore);

  return (
    <div className={cn(
      "rounded-xl border p-5 space-y-4",
      bg,
      border,
      "bg-[hsl(222,47%,8%)]"
    )}>
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h3 className="text-xs font-medium text-[hsl(215,20%,45%)] uppercase tracking-wider">
            Security Posture
          </h3>
          <div className="flex items-center gap-2 mt-1">
            <span className={cn("text-4xl font-bold tabular-nums", text)}>
              {compositeScore}
            </span>
            <div className="flex flex-col">
              <TrendArrow trend={trend} />
              <span className={cn("text-xs font-medium mt-0.5", text)}>{label}</span>
            </div>
          </div>
        </div>

        {/* Alert badges */}
        <div className="flex flex-col items-end gap-1.5">
          {openCriticals > 0 && (
            <span className="text-[10px] bg-red-500/20 text-red-400 border border-red-500/30 px-2 py-0.5 rounded-full font-medium">
              {openCriticals} CRITICAL
            </span>
          )}
          {openHighs > 0 && (
            <span className="text-[10px] bg-orange-500/20 text-orange-400 border border-orange-500/30 px-2 py-0.5 rounded-full font-medium">
              {openHighs} HIGH
            </span>
          )}
          {openCriticals === 0 && openHighs === 0 && (
            <span className="text-[10px] bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 px-2 py-0.5 rounded-full font-medium">
              No alerts
            </span>
          )}
        </div>
      </div>

      {/* Score breakdown bars */}
      <div className="space-y-2.5">
        <ScoreBar
          score={hostRiskScore}
          label="Host Risk (SecureClaw)"
          color={scoreToColor(hostRiskScore).text}
        />
        <ScoreBar
          score={llmRiskScore}
          label="LLM Risk (Augustus)"
          color={scoreToColor(llmRiskScore).text}
        />
      </div>

      {/* Timestamps */}
      <div className="flex justify-between pt-1 border-t border-[hsl(222,47%,14%)]">
        <div className="text-[10px] text-[hsl(215,20%,35%)]">
          <span className="text-[hsl(215,20%,50%)]">Host audit:</span>{" "}
          {formatRelativeTime(lastAuditAt)}
        </div>
        <div className="text-[10px] text-[hsl(215,20%,35%)]">
          <span className="text-[hsl(215,20%,50%)]">LLM scan:</span>{" "}
          {formatRelativeTime(lastScanAt)}
        </div>
      </div>
    </div>
  );
}
