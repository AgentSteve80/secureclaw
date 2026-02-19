"use client";

// SecurityView.tsx — Updated unified 6-tab security dashboard
// Integrates Augustus (LLM scans) + SecureClaw (host audits) into one view.
// This replaces the Augustus SecurityView.tsx when SecureClaw is deployed.

import { useState } from "react";
import { useQuery } from "convex/react";
import { api } from "../../../convex/_generated/api";
import { Id } from "../../../convex/_generated/dataModel";
import { cn } from "@/lib/utils";
import { Shield } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";

// SecureClaw components
import { SecurityScore } from "./SecurityScore";
import { OWASPCoverageMap } from "./OWASPCoverageMap";
import { AuditHistory } from "./AuditHistory";
import { AuditDiff } from "./AuditDiff";
import { FindingsBoard } from "./FindingsBoard";
import { SupplyChainView } from "./SupplyChainView";

// Augustus components (from AgentSteve80/augustus, already in mission-control)
// These imports will resolve once the Augustus security components are merged:
// import { VulnerabilityBoard } from "./VulnerabilityBoard";
// import { ScanHistory } from "./ScanHistory";
// import { ScanTrigger } from "./ScanTrigger";

// Placeholder components for Augustus tabs until they're merged
function VulnerabilityBoardPlaceholder() {
  return (
    <div className="rounded-lg border border-[hsl(222,47%,16%)] bg-[hsl(222,47%,8%)] p-8 text-center">
      <div className="text-2xl mb-2">🔬</div>
      <div className="text-sm text-[hsl(213,31%,91%)]">Augustus Vulnerability Board</div>
      <div className="text-xs text-[hsl(215,20%,40%)] mt-1">
        Merge augustus/src/components/security/ to enable LLM vulnerability tracking
      </div>
    </div>
  );
}

function ScanHistoryPlaceholder() {
  return (
    <div className="rounded-lg border border-[hsl(222,47%,16%)] bg-[hsl(222,47%,8%)] p-8 text-center">
      <div className="text-2xl mb-2">📈</div>
      <div className="text-sm text-[hsl(213,31%,91%)]">Augustus Scan History</div>
      <div className="text-xs text-[hsl(215,20%,40%)] mt-1">
        Merge augustus/src/components/security/ to enable LLM scan history
      </div>
    </div>
  );
}

interface SecurityEvent {
  _id: Id<"securityEvents">;
  eventType: string;
  severity: string;
  source: string;
  message: string;
  acknowledged: boolean;
  createdAt: number;
}

function SecurityEventsPanel() {
  const events = useQuery(api.securityEvents.unacknowledged, { limit: 5 });

  if (!events || events.length === 0) return null;

  return (
    <div className="space-y-2">
      <h3 className="text-xs font-medium text-[hsl(215,20%,45%)] uppercase tracking-wider">
        Unacknowledged Alerts
      </h3>
      <div className="space-y-2">
        {(events as SecurityEvent[]).map((event) => (
          <div
            key={event._id}
            className={cn(
              "rounded-lg border px-4 py-3 flex items-start gap-3",
              event.severity === "critical"
                ? "bg-red-500/5 border-red-500/30"
                : "bg-yellow-500/5 border-yellow-500/30"
            )}
          >
            <span className="text-lg shrink-0">
              {event.severity === "critical" ? "🚨" : "⚠️"}
            </span>
            <div className="flex-1 min-w-0">
              <div className="text-xs font-medium text-[hsl(213,31%,91%)]">
                {event.message.slice(0, 120)}
              </div>
              <div className="text-[10px] text-[hsl(215,20%,40%)] mt-0.5">
                {event.source} · {new Date(event.createdAt).toLocaleString()}
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

export function SecurityView() {
  const [activeTab, setActiveTab] = useState("overview");
  const [activeFindingsCategory, setActiveFindingsCategory] = useState<string | null>(null);

  // Fetch data for the overview
  const posture = useQuery(api.security?.posture as never) as {
    hostRiskScore: number;
    llmRiskScore: number;
    compositeScore: number;
    trend: "improving" | "degrading" | "stable";
    lastAuditAt: number | null;
    lastScanAt: number | null;
    openCriticals: number;
    openHighs: number;
  } | undefined;

  // Fetch latest two audits for diff view
  const diffData = useQuery(api.audits.diff);

  const currentAuditId = diffData?.current?._id ?? null;
  const previousAuditId = diffData?.previous?._id ?? null;

  const handleCategoryClick = (categoryId: string) => {
    setActiveFindingsCategory(categoryId);
    setActiveTab("audit-findings");
  };

  return (
    <div className="flex flex-col h-full overflow-hidden">
      {/* Page header */}
      <div className="flex items-center justify-between px-6 py-4 border-b border-[hsl(222,47%,16%)] shrink-0">
        <div className="flex items-center gap-2.5">
          <Shield size={20} className="text-[hsl(210,100%,60%)]" />
          <h1 className="text-lg font-semibold text-[hsl(213,31%,91%)]">Security</h1>
          <div className="flex items-center gap-1.5 ml-2">
            {posture && posture.openCriticals > 0 && (
              <span className="text-[10px] font-bold bg-red-500/20 text-red-400 border border-red-500/30 px-2 py-0.5 rounded-full">
                {posture.openCriticals} CRITICAL
              </span>
            )}
          </div>
        </div>
        <Button
          size="sm"
          className="bg-[hsl(210,100%,60%)] hover:bg-[hsl(210,100%,55%)] text-white text-xs"
          onClick={() => {
            // Trigger a new audit via the Convex HTTP API
            const convexUrl = process.env.NEXT_PUBLIC_CONVEX_SITE_URL;
            const apiKey = process.env.NEXT_PUBLIC_CLAW_API_KEY;
            if (convexUrl && apiKey) {
              fetch(`${convexUrl}/api/audits`, {
                method: "POST",
                headers: { "Content-Type": "application/json", "x-claw-api-key": apiKey },
                body: JSON.stringify({ type: "full", triggeredBy: "manual" }),
              }).catch(console.error);
            }
          }}
        >
          Run Audit
        </Button>
      </div>

      {/* Tabs */}
      <Tabs
        value={activeTab}
        onValueChange={setActiveTab}
        className="flex-1 flex flex-col overflow-hidden"
      >
        <div className="px-6 border-b border-[hsl(222,47%,16%)] shrink-0">
          <TabsList className="h-9 bg-transparent border-0 gap-0 p-0">
            {[
              { value: "overview", label: "Overview" },
              { value: "vulnerabilities", label: "Vulnerabilities" },
              { value: "audit-findings", label: "Audit Findings" },
              { value: "scan-history", label: "Scan History" },
              { value: "audit-history", label: "Audit History" },
              { value: "supply-chain", label: "Supply Chain" },
            ].map((tab) => (
              <TabsTrigger
                key={tab.value}
                value={tab.value}
                className={cn(
                  "text-xs px-4 py-2 rounded-none border-b-2 border-transparent data-[state=active]:border-[hsl(210,100%,60%)] data-[state=active]:text-[hsl(210,100%,60%)] data-[state=inactive]:text-[hsl(215,20%,45%)] bg-transparent",
                  "hover:text-[hsl(213,31%,91%)] transition-colors"
                )}
              >
                {tab.label}
              </TabsTrigger>
            ))}
          </TabsList>
        </div>

        <div className="flex-1 overflow-y-auto">
          {/* Tab 1: Overview */}
          <TabsContent value="overview" className="p-6 space-y-6 mt-0">
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
              {/* Security score card */}
              <div className="lg:col-span-1">
                <SecurityScore
                  hostRiskScore={posture?.hostRiskScore ?? 0}
                  llmRiskScore={posture?.llmRiskScore ?? 0}
                  trend={posture?.trend ?? "stable"}
                  lastAuditAt={posture?.lastAuditAt ?? null}
                  lastScanAt={posture?.lastScanAt ?? null}
                  openCriticals={posture?.openCriticals ?? 0}
                  openHighs={posture?.openHighs ?? 0}
                />
              </div>

              {/* OWASP coverage map */}
              <div className="lg:col-span-2">
                <div className="rounded-xl border border-[hsl(222,47%,16%)] bg-[hsl(222,47%,8%)] p-5">
                  <OWASPCoverageMap
                    auditId={currentAuditId}
                    onCategoryClick={handleCategoryClick}
                  />
                </div>
              </div>
            </div>

            {/* Security events */}
            <SecurityEventsPanel />
          </TabsContent>

          {/* Tab 2: Vulnerabilities (Augustus) */}
          <TabsContent value="vulnerabilities" className="p-6 mt-0">
            <VulnerabilityBoardPlaceholder />
          </TabsContent>

          {/* Tab 3: Audit Findings (SecureClaw) */}
          <TabsContent value="audit-findings" className="p-6 space-y-6 mt-0">
            {/* Diff view */}
            <div className="rounded-xl border border-[hsl(222,47%,16%)] bg-[hsl(222,47%,8%)] p-5">
              <h2 className="text-sm font-semibold text-[hsl(213,31%,91%)] mb-4">
                Week-over-Week Diff
              </h2>
              <AuditDiff
                currentAuditId={currentAuditId}
                previousAuditId={previousAuditId}
              />
            </div>

            {/* Findings board */}
            <div>
              <h2 className="text-sm font-semibold text-[hsl(213,31%,91%)] mb-3">
                Open Findings by OWASP Category
              </h2>
              <FindingsBoard />
            </div>
          </TabsContent>

          {/* Tab 4: Scan History (Augustus) */}
          <TabsContent value="scan-history" className="p-6 mt-0">
            <ScanHistoryPlaceholder />
          </TabsContent>

          {/* Tab 5: Audit History (SecureClaw) */}
          <TabsContent value="audit-history" className="p-6 mt-0">
            <AuditHistory limit={30} />
          </TabsContent>

          {/* Tab 6: Supply Chain */}
          <TabsContent value="supply-chain" className="p-6 mt-0">
            <SupplyChainView />
          </TabsContent>
        </div>
      </Tabs>
    </div>
  );
}
