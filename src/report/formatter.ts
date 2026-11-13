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

function controlDomain(ruleId: string): string {
  if (ruleId.startsWith('firebase/')) return 'Firebase Data Perimeter';
  if (ruleId.startsWith('iam/') || ruleId.startsWith('wif/')) return 'Identity & Workload Federation';
  if (ruleId.startsWith('gke/') || ruleId.startsWith('sql/') || ruleId.startsWith('gcp/')) return 'Cloud Workload & Database Hardening';
  if (ruleId.startsWith('audit/') || ruleId.startsWith('scc/')) return 'Runtime Threat & Posture Telemetry';
  return 'Scan Completeness & Input Safety';
}

export function formatBlueprint(graph: GraphResult, prover?: DualProverVerdict, remediations: Remediation[] = []): string {
  const counts: Record<Severity, number> = { blocker: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const finding of graph.findings) counts[finding.severity]++;
  const incomplete = graph.findings.some(finding => finding.ruleId.startsWith('scan/'));
  const lines = [
    '# Atlas Shield — Autonomous Security & DX Blueprint',
    '',
    '## 1. Executive Risk Summary',
    `- Scan Status: ${incomplete ? 'INCOMPLETE (resolve scan/* diagnostics first)' : 'COMPLETE'}`,
    `- Findings: ${graph.findings.length} total (BLOCKER: ${counts.blocker}, HIGH: ${counts.high}, MEDIUM: ${counts.medium}, LOW: ${counts.low})`,
    `- Reachable Cross-Boundary Attack Paths: ${graph.paths.length}`,
  ];
  if (prover) {
    lines.push(`- Sovereign Prover (${prover.mode}): ${prover.status}`);
    for (const [lane, verdict] of Object.entries(prover.lanes)) {
      lines.push(`  - ${lane} (${displayText(verdict.model)}): ${verdict.status} — ${displayText(verdict.rationale)}`);
    }
  }
  lines.push(
    '',
    '## 2. Autonomous 30 / 60 / 90-Day Remediation Roadmap',
    '- **Phase 1 (Day 1-30 — Immediate Containment & AI Airlock)**: Eliminate BLOCKER and confirmed public exposures (Firebase rules, 0.0.0.0/0 Cloud SQL, public invokers, logging tampering) and wrap internal AI MCP servers with `atlas-shield mcp-config --client gemini`.',
    '- **Phase 2 (Day 31-60 — Identity & Workload Hardening)**: Replace default Compute/AppEngine/CloudBuild/GKE service accounts with least-privilege identities, enable GKE Workload Identity, enforce Cloud SQL TLS, and pin GitHub WIF `attribute.repository`.',
    '- **Phase 3 (Day 61-90 — Continuous Self-Driving CI/CD Gate)**: Enforce `atlas-shield audit` in GitHub Actions pull-request checks so posture drift is blocked automatically without external consultants.',
    '',
    '## 3. Prioritized Findings & Control Domains',
  );
  if (!graph.findings.length) {
    lines.push('No findings in the analyzed inputs; this is not a completeness guarantee.');
  } else {
    for (const finding of [...graph.findings].sort((a, b) => severityRank[a.severity] - severityRank[b.severity])) {
      lines.push(`- **[${finding.severity.toUpperCase()}]** \`${displayText(finding.location.file)}:${finding.location.line}\` — **${displayText(finding.title)}** (\`${finding.ruleId}\` · *${controlDomain(finding.ruleId)}*)`);
      lines.push(`  - ${displayText(finding.message)}`);
    }
  }
  lines.push('', '## 4. Reachable Cross-Boundary Attack Paths');
  if (!graph.paths.length) {
    lines.push('No reachable cross-boundary attack paths were enumerated in the analyzed inputs.');
  } else {
    for (const path of graph.paths) {
      lines.push(`- **PATH ${path.severity.toUpperCase()} (${path.confidence})**: ${displayText(path.description)}`);
    }
  }
  if (remediations.length) {
    lines.push('', '## 5. Review-Only Remediation Proposals');
    for (const remediation of remediations) {
      lines.push(`- **PROPOSAL ${remediation.findingId}** (\`${displayText(remediation.file)}\`): ${displayText(remediation.description)}`);
      if (remediation.diff) lines.push('```diff', remediation.diff.trimEnd(), '```');
    }
  }
  if (graph.limitations.length) {
    lines.push('', '## 6. Scan Scope & Limitations');
    for (const limitation of graph.limitations) lines.push(`- LIMITATION: ${displayText(limitation)}`);
  }
  lines.push(
    '',
    '## 7. Execution Mode (Free Self-Service vs 2-Hour Online Sprint)',
    '- **Tier 0 — Free Self-Service (Apache-2.0, ¥0)**: Feed this blueprint into your internal AI agent, review and apply the proposed diffs, and enable the GitHub Actions CI gate.',
    '- **Tier 1 — Optional 2-Hour Online Implementation Sprint**: Share this redacted blueprint (no cloud credentials required) for a focused 2-hour live remediation, MCP Airlock onboarding, and CI gate verification session.',
  );
  return lines.join('\n') + '\n';
}
