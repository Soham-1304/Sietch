import type { RuleContext } from "../context.js";

export type Severity = "Low" | "Medium" | "High" | "Critical";
export const SEVERITY_RANK: Readonly<Record<Severity, number>> = { Low: 1, Medium: 2, High: 3, Critical: 4 };

export type RuleId = "R1" | "R2" | "R3" | "R4" | "R5" | "R6" | "R7" | "R8" | "R9" | "R10" | "R13";

export interface FindingDraft {
  readonly severity: Severity;
  readonly explanation: string;
  readonly evidence: readonly number[];
}

export interface Rule {
  readonly id: RuleId;
  readonly title: string;
  evaluate(ctx: RuleContext): FindingDraft[];
}

/** Group drafts by a key, so one finding covers every event about the same subject. */
export class Grouper {
  private readonly groups = new Map<
    string,
    { severity: Severity; explanation: string; evidence: number[] }
  >();

  add(key: string, severity: Severity, explanation: string, seq: number): void {
    const g = this.groups.get(key);
    if (g === undefined) {
      this.groups.set(key, { severity, explanation, evidence: [seq] });
      return;
    }
    g.evidence.push(seq);
    if (SEVERITY_RANK[severity] > SEVERITY_RANK[g.severity]) g.severity = severity;
  }

  drafts(): FindingDraft[] {
    return [...this.groups.values()];
  }
}
