// packages/audit-runner/src/differ.ts
// AuditDiffer: computes new/resolved/persisting findings vs previous audit

import { AuditDiff, NormalizedFinding } from "./types.js";

// A finding is identified by its checkId for deduplication purposes.
// Two findings with the same checkId are considered the "same" finding.

function makeFindingKey(f: NormalizedFinding): string {
  return `${f.source}::${f.checkId}`;
}

export interface PreviousAuditFindings {
  auditId: string;
  findings: NormalizedFinding[];
  hostRiskScore: number;
}

export class AuditDiffer {
  compute(
    currentAuditId: string,
    currentFindings: NormalizedFinding[],
    currentRiskScore: number,
    previous: PreviousAuditFindings | null
  ): AuditDiff {
    const currentFailed = currentFindings.filter((f) => !f.passed);

    // No previous audit — all failed findings are "new"
    if (!previous) {
      const criticals = currentFailed.filter((f) => f.severity === "critical");
      return {
        auditId: currentAuditId,
        previousAuditId: null,
        newFindings: currentFailed,
        resolvedFindings: [],
        persistingFindings: [],
        riskScoreDelta: currentRiskScore,
        newCriticals: criticals,
      };
    }

    const previousFailed = previous.findings.filter((f) => !f.passed);

    // Build lookup maps by checkId
    const currentKeys = new Set(currentFailed.map(makeFindingKey));
    const previousKeys = new Set(previousFailed.map(makeFindingKey));

    const newFindings: NormalizedFinding[] = [];
    const resolvedFindings: NormalizedFinding[] = [];
    const persistingFindings: NormalizedFinding[] = [];

    // New = in current but not in previous
    for (const finding of currentFailed) {
      const key = makeFindingKey(finding);
      if (!previousKeys.has(key)) {
        newFindings.push(finding);
      } else {
        persistingFindings.push(finding);
      }
    }

    // Resolved = in previous but not in current (i.e., now passing)
    for (const finding of previousFailed) {
      const key = makeFindingKey(finding);
      if (!currentKeys.has(key)) {
        resolvedFindings.push(finding);
      }
    }

    const newCriticals = newFindings.filter((f) => f.severity === "critical");
    const riskScoreDelta = currentRiskScore - previous.hostRiskScore;

    return {
      auditId: currentAuditId,
      previousAuditId: previous.auditId,
      newFindings,
      resolvedFindings,
      persistingFindings,
      riskScoreDelta,
      newCriticals,
    };
  }

  summarize(diff: AuditDiff): string {
    const lines: string[] = [
      `Audit diff (vs ${diff.previousAuditId ?? "baseline"}):`,
      `  New findings:       ${diff.newFindings.length}`,
      `  Resolved findings:  ${diff.resolvedFindings.length}`,
      `  Persisting:         ${diff.persistingFindings.length}`,
      `  New criticals:      ${diff.newCriticals.length}`,
      `  Risk score delta:   ${diff.riskScoreDelta > 0 ? "+" : ""}${diff.riskScoreDelta}`,
    ];
    return lines.join("\n");
  }
}
