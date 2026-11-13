import { createHash } from 'node:crypto';
import type { DualProverVerdict, GraphResult, Remediation, SarifLog, Severity } from '../types.ts';
import { displayText } from './formatter.ts';

const level = (severity: Severity): 'error' | 'warning' | 'note' =>
  severity === 'blocker' || severity === 'high' ? 'error' : severity === 'medium' ? 'warning' : 'note';

export function toSarif(graph: GraphResult, version = '0.1.0', prover?: DualProverVerdict, remediations: Remediation[] = []): SarifLog {
  const ids = [...new Set(graph.findings.map(finding => finding.ruleId))].sort();
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: { driver: {
        name: 'atlas-GCP', version, informationUri: 'https://github.com/Atlas-Associates-Inc/atlas-GCP',
        rules: ids.map(id => {
          const finding = graph.findings.find(item => item.ruleId === id)!;
          return { id, name: id.replace(/[^A-Za-z0-9]/g, '_'), shortDescription: { text: displayText(finding.title) }, defaultConfiguration: { level: level(finding.severity) } };
        }),
      } },
      results: graph.findings.map(finding => ({
        ruleId: finding.ruleId, ruleIndex: ids.indexOf(finding.ruleId), level: level(finding.severity),
        message: { text: displayText(finding.message) },
        locations: [{ physicalLocation: {
          artifactLocation: { uri: finding.location.file.split('/').map(encodeURIComponent).join('/'), uriBaseId: '%SRCROOT%' },
          region: { startLine: Math.max(1, finding.location.line), startColumn: Math.max(1, finding.location.column ?? 1) },
        } }],
        partialFingerprints: { primaryLocationLineHash: createHash('sha256').update(`${finding.ruleId}\0${finding.location.file}\0${finding.evidence}`).digest('hex') },
        properties: { severity: finding.severity, findingId: finding.id },
      })),
      properties: { paths: graph.paths, limitations: graph.limitations, ...(prover ? { prover } : {}), ...(remediations.length ? { remediations } : {}) },
    }],
  };
}
