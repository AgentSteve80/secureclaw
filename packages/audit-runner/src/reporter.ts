// packages/audit-runner/src/reporter.ts
// ConvexReporter: batch upserts findings to Convex HTTP API, updates audit record status

import {
  AuditDiff,
  AuditStatus,
  AuditSummary,
  AuditType,
  ConvexAuditRecord,
  ConvexFindingRecord,
  FindingStatus,
  NormalizedFinding,
  SecurityEventPayload,
  SkillInventoryEntry,
  TriggerSource,
} from "./types.js";

interface ReporterConfig {
  convexUrl: string;       // e.g. https://curious-wolverine-246.convex.site
  apiKey: string;
  verbose?: boolean;
}

interface CreateAuditBody {
  type: AuditType;
  modules?: string[];
  triggeredBy: TriggerSource;
  status: AuditStatus;
  secureclawVersion: string;
  startedAt: number;
  checksRun: number;
  checksPassed: number;
  checksFailed: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  hostRiskScore: number;
  newFindingsCount: number;
  resolvedFindingsCount: number;
  riskScoreDelta: number;
}

interface UpsertFindingBody extends NormalizedFinding {
  auditId: string;
  isNew: boolean;
  status: FindingStatus;
  firstSeenAt: number;
  lastSeenAt: number;
}

const BATCH_SIZE = 20;

export class ConvexReporter {
  private readonly baseUrl: string;
  private readonly headers: Record<string, string>;
  private readonly verbose: boolean;

  constructor(config: ReporterConfig) {
    this.baseUrl = config.convexUrl.replace(/\/$/, "");
    this.headers = {
      "Content-Type": "application/json",
      "x-claw-api-key": config.apiKey,
    };
    this.verbose = config.verbose ?? false;
  }

  private async post<T>(path: string, body: unknown): Promise<T> {
    const url = `${this.baseUrl}${path}`;
    if (this.verbose) console.error(`[ConvexReporter] POST ${url}`);

    const res = await fetch(url, {
      method: "POST",
      headers: this.headers,
      body: JSON.stringify(body),
    });

    if (!res.ok) {
      const text = await res.text();
      throw new Error(`HTTP ${res.status} on POST ${path}: ${text.slice(0, 300)}`);
    }

    return res.json() as Promise<T>;
  }

  private async patch<T>(path: string, body: unknown): Promise<T> {
    const url = `${this.baseUrl}${path}`;
    if (this.verbose) console.error(`[ConvexReporter] PATCH ${url}`);

    const res = await fetch(url, {
      method: "PATCH",
      headers: this.headers,
      body: JSON.stringify(body),
    });

    if (!res.ok) {
      const text = await res.text();
      throw new Error(`HTTP ${res.status} on PATCH ${path}: ${text.slice(0, 300)}`);
    }

    return res.json() as Promise<T>;
  }

  private async get<T>(path: string): Promise<T> {
    const url = `${this.baseUrl}${path}`;
    if (this.verbose) console.error(`[ConvexReporter] GET ${url}`);

    const res = await fetch(url, {
      method: "GET",
      headers: this.headers,
    });

    if (!res.ok) {
      const text = await res.text();
      throw new Error(`HTTP ${res.status} on GET ${path}: ${text.slice(0, 300)}`);
    }

    return res.json() as Promise<T>;
  }

  // Create an audit record in Convex, returns the audit ID
  async createAudit(summary: Omit<AuditSummary, "finishedAt" | "durationMs">): Promise<string> {
    const body: CreateAuditBody = {
      type: summary.type,
      triggeredBy: summary.triggeredBy,
      status: "running",
      secureclawVersion: summary.secureclawVersion,
      startedAt: summary.startedAt,
      checksRun: summary.checksRun,
      checksPassed: summary.checksPassed,
      checksFailed: summary.checksFailed,
      criticalCount: summary.criticalCount,
      highCount: summary.highCount,
      mediumCount: summary.mediumCount,
      lowCount: summary.lowCount,
      hostRiskScore: summary.hostRiskScore,
      newFindingsCount: summary.newFindingsCount,
      resolvedFindingsCount: summary.resolvedFindingsCount,
      riskScoreDelta: summary.riskScoreDelta,
    };

    const res = await this.post<{ id: string }>("/api/audits", body);
    return res.id;
  }

  // Update audit status
  async updateAuditStatus(auditId: string, status: AuditStatus): Promise<void> {
    await this.patch(`/api/audit-findings`, { auditId, action: "update-status", status });
  }

  // Complete an audit with final summary
  async completeAudit(auditId: string, summary: AuditSummary): Promise<void> {
    await this.post("/api/audit-results", {
      auditId,
      action: "complete",
      finishedAt: summary.finishedAt,
      durationMs: summary.durationMs,
      checksRun: summary.checksRun,
      checksPassed: summary.checksPassed,
      checksFailed: summary.checksFailed,
      criticalCount: summary.criticalCount,
      highCount: summary.highCount,
      mediumCount: summary.mediumCount,
      lowCount: summary.lowCount,
      hostRiskScore: summary.hostRiskScore,
      newFindingsCount: summary.newFindingsCount,
      resolvedFindingsCount: summary.resolvedFindingsCount,
      riskScoreDelta: summary.riskScoreDelta,
      status: "complete",
    });
  }

  // Batch upsert findings to Convex
  async upsertFindings(
    auditId: string,
    findings: NormalizedFinding[],
    diff: AuditDiff
  ): Promise<string[]> {
    const newCheckIds = new Set(diff.newFindings.map((f) => f.checkId));
    const now = Date.now();
    const allIds: string[] = [];

    const findingBodies: UpsertFindingBody[] = findings
      .filter((f) => !f.passed)
      .map((f) => ({
        ...f,
        auditId,
        isNew: newCheckIds.has(f.checkId),
        status: "open" as FindingStatus,
        firstSeenAt: now,
        lastSeenAt: now,
      }));

    // Process in batches
    for (let i = 0; i < findingBodies.length; i += BATCH_SIZE) {
      const batch = findingBodies.slice(i, i + BATCH_SIZE);
      const res = await this.post<{ findingIds: string[] }>("/api/audit-results", {
        auditId,
        findings: batch,
      });
      allIds.push(...res.findingIds);
    }

    return allIds;
  }

  // Update a finding's status
  async updateFindingStatus(
    findingId: string,
    status: FindingStatus,
    remediationNote?: string
  ): Promise<void> {
    await this.patch(`/api/audit-findings`, {
      id: findingId,
      status,
      ...(remediationNote ? { remediationNote } : {}),
    });
  }

  // Sync skill inventory
  async syncSkillInventory(skills: SkillInventoryEntry[]): Promise<number> {
    const res = await this.post<{ updated: number }>("/api/skill-inventory/sync", { skills });
    return res.updated;
  }

  // Post a security event (for critical findings)
  async createSecurityEvent(event: SecurityEventPayload): Promise<string> {
    const res = await this.post<{ id: string }>("/api/security-events", {
      ...event,
      acknowledged: false,
      createdAt: Date.now(),
    });
    return res.id;
  }

  // Get the security posture composite score
  async getSecurityPosture(): Promise<unknown> {
    return this.get("/api/security/posture");
  }

  // Fetch the most recent completed audit findings for diff computation
  async getPreviousAuditFindings(): Promise<{
    auditId: string;
    findings: NormalizedFinding[];
    hostRiskScore: number;
  } | null> {
    try {
      const res = await this.get<{
        audit: ConvexAuditRecord | null;
        findings: (ConvexFindingRecord & NormalizedFinding)[] | null;
      }>("/api/audits/latest");

      if (!res.audit || !res.findings) return null;

      return {
        auditId: res.audit.id,
        findings: res.findings as NormalizedFinding[],
        hostRiskScore: res.audit.hostRiskScore,
      };
    } catch {
      return null;
    }
  }
}
