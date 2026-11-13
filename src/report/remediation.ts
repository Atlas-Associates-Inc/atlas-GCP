import { isAbsolute } from 'node:path';
import type { Finding, Remediation } from '../types.ts';
import { sanitizeTelemetry } from '../airlock/sanitizer.ts';
import { scanAllowClauses, stripComments } from '../graph/firebase-rules-parser.ts';
import { readSafeSource } from '../graph/attack-graph.ts';

const advice: Record<string, string> = {
  'firebase/public-read': 'Deny public access until an application-specific authorization rule is reviewed. This proposal may interrupt intended public reads.',
  'firebase/public-write': 'Deny public writes until ownership and field validation are defined. Review availability impact before applying.',
  'firebase/recursive-wildcard': 'Restrict recursive matches to intended collections or object prefixes and enforce ownership at every matching allow clause.',
  'firebase/privilege-fields': 'Use keys().hasOnly(approvedFields) for creates and diff(resource.data).affectedKeys().hasOnly(approvedFields) for updates. Choose allowed fields from the application schema.',
  'gcp/public-service': 'Remove allUsers/allAuthenticatedUsers invoker grants and grant invocation to the required identities only.',
  'gcp/public-ingress': 'Restrict ingress to internal traffic; verify that required callers still have a supported route.',
  'iam/default-service-account': 'Use a dedicated runtime service account with resource-scoped permissions required by this workload.',
  'iam/privilege-escalation': 'Remove unnecessary impersonation or policy-administration grants; scope necessary grants to named service accounts.',
  'wif/unpinned-provider': 'Bind the provider to an exact trusted repository and owner using a restrictive attribute condition; validate subject and branch claims.',
  'wif/unpinned-workflow': 'Pin the workload identity provider and service account, restrict token permissions to the deployment job, and constrain repository claims on the provider.',
  'audit/logging-tampering': 'Review the recorded logging change, restore required audit collection and sink routing through an approved change, and restrict logging administration to designated responders.',
  'audit/iam-persistence': 'Investigate the recorded identity or IAM policy change; revoke unapproved credentials and grants through incident response, and constrain workload identity providers to trusted subjects.',
  'audit/impersonation-chain': 'Review the observed caller and service account delegation chain, remove unnecessary impersonation grants, and scope approved delegation to named identities and resources.',
  'audit/sensitive-data-access': 'Validate the observed data access against workload requirements, investigate unapproved access, and restrict resource permissions to the intended identities.',
  'scc/active-finding': 'Review the active Security Command Center finding and affected resource configuration, confirm the exposure, and apply a resource-specific remediation through the approved change process.',
  'gke/node-identity-exposure': 'Configure workload_identity_config on the cluster and assign a dedicated, least-privilege service_account to every node pool instead of the default Compute Engine account.',
  'sql/public-authorized-network': 'Remove 0.0.0.0/0 from authorized_networks and connect through Cloud SQL Auth Proxy, Private Service Connect, or private IP.',
  'sql/unencrypted-public-ip': 'Set ssl_mode = "ENCRYPTED_ONLY" (or require_ssl = true) and disable public IPv4 (ipv4_enabled = false) where private connectivity is available.',
};

function readSource(root: string, file: string): string | undefined {
  if (isAbsolute(file) || file.split(/[\\/]/).some(part => part === '..') || /[\x00-\x1f\x7f-\x9f\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]/.test(file)) return;
  const result = readSafeSource(root, file);
  if ('reason' in result) throw new Error(result.reason);
  return result.source;
}

export function proposeRemediations(findings: Finding[], directory: string): Remediation[] {
  const proposals: Remediation[] = [];
  const seenEdits = new Set<string>();
  const sources = new Map<string, { source: string | undefined; lines: string[]; strippedLines: string[] } | Error>();
  for (const finding of findings) {
    const description = advice[finding.ruleId];
    if (!description) continue;
    const proposal: Remediation = { findingId: finding.id, file: finding.location.file, description, diff: '', automatic: false };
    // Application-specific policy cannot safely be invented. Emit only exact, reviewable edits.
    if (['firebase/public-read', 'firebase/public-write', 'gcp/public-ingress', 'sql/public-authorized-network'].includes(finding.ruleId)) {
      try {
        const file = finding.location.file;
        if (!sources.has(file)) {
          try {
            const source = readSource(directory, file);
            sources.set(file, { source, lines: source?.split('\n') ?? [],
              strippedLines: source === undefined ? [] : stripComments(source).split('\n') });
          } catch {
            // Cache failures too, so many findings cannot repeatedly retry an unsafe path.
            sources.set(file, new Error('Source could not be read safely'));
          }
        }
        const cached = sources.get(file)!;
        if (cached instanceof Error) throw cached;
        const { source, lines, strippedLines } = cached;
        const line = lines[finding.location.line - 1];
        if (line !== undefined && line.length < 4096 && !/[\x00-\x08\x0b-\x1f\x7f-\x9f\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]/.test(line) && sanitizeTelemetry(line).redactions === 0) {
          let updated = line;
          if (finding.ruleId === 'gcp/public-ingress') {
            updated = line.replace(/\bINGRESS_TRAFFIC_ALL\b/g, 'INGRESS_TRAFFIC_INTERNAL_ONLY')
              .replace(/\bALLOW_ALL\b/g, 'ALLOW_INTERNAL_ONLY');
          } else if (finding.ruleId === 'sql/public-authorized-network') {
            updated = line.replace(/"0\.0\.0\.0\/0"/g, '"127.0.0.1/32"');
          } else {
            // Use source offsets so comments and quoted values on the line stay untouched.
            const code = strippedLines[finding.location.line - 1]
              .replace(/"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'/g, value => ' '.repeat(value.length));
            const grants = [...scanAllowClauses(code)].filter(grant =>
              /^\(*\s*true\s*\)*$/.test(grant.condition));
            for (const grant of grants.reverse()) {
              const conditional = grant.evidence.includes(':');
              const offset = grant.offset + (conditional ? grant.evidence.lastIndexOf('true') : grant.evidence.length - 1);
              updated = updated.slice(0, offset) + (conditional ? 'false' : ': if false')
                + updated.slice(offset + (conditional ? 4 : 0));
            }
          }
          const key = `${finding.location.file}:${finding.location.line}`;
          if (updated !== line && !seenEdits.has(key)) {
            const path = (prefix: string) => JSON.stringify(`${prefix}/${finding.location.file}`);
            const noNewline = source !== undefined && !source.endsWith('\n') && finding.location.line === lines.length;
            const marker = noNewline ? '\n\\ No newline at end of file' : '';
            proposal.diff = `--- ${path('a')}\n+++ ${path('b')}\n@@ -${finding.location.line},1 +${finding.location.line},1 @@\n-${line}${marker}\n+${updated}${marker}\n`;
            seenEdits.add(key);
          }
        }
      } catch {
        proposal.description += ' Source could not be read safely; no diff was produced.';
      }
    }
    proposals.push(proposal);
  }
  return proposals;
}
