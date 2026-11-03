import type { DualProverVerdict, GraphResult, Remediation, Severity } from '../types.ts';
import { redactSecrets } from '../airlock/sanitizer.ts';

export const severityRank: Record<Severity, number> = { blocker: 0, high: 1, medium: 2, low: 3, info: 4 };

export function meetsThreshold(graph: GraphResult, threshold: Severity): boolean {
  return [...graph.findings, ...graph.paths].some(item => severityRank[item.severity] <= severityRank[threshold]);
}

// Terminal control sequences and bidirectional controls cannot change the apparent report.
export function displayText(text: string): string {
  return redactSecrets(text).replace(/[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]/g, ' ');
}

export function formatTable(graph: GraphResult, prover?: DualProverVerdict, remediations: Remediation[] = []): string {
  const lines = ['Atlas Shield', 'SEVERITY  LOCATION  FINDING'];
  for (const finding of graph.findings) {
    lines.push(`${finding.severity.toUpperCase().padEnd(8)}  ${displayText(finding.location.file)}:${finding.location.line}  ${displayText(finding.title)} [${finding.ruleId}]`);
    lines.push(`          ${displayText(finding.message)}`);
  }
  if (!graph.findings.length) lines.push('No findings in the analyzed inputs; this is not a completeness guarantee.');
  for (const path of graph.paths) lines.push(`PATH ${path.severity.toUpperCase()} (${path.confidence}): ${displayText(path.description)}`);
  for (const limitation of graph.limitations) lines.push(`LIMITATION: ${displayText(limitation)}`);
  if (prover) {
    lines.push(`PROVER ${prover.mode}: ${prover.status}`);
    for (const [lane, verdict] of Object.entries(prover.lanes)) lines.push(`  ${lane}: ${verdict.status} — ${displayText(verdict.rationale)}`);
  }
  for (const remediation of remediations) {
    lines.push(`PROPOSAL ${remediation.findingId}: ${displayText(remediation.description)}`);
    if (remediation.diff) lines.push(remediation.diff.trimEnd());
  }
  return lines.join('\n') + '\n';
}
