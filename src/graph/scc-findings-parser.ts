import type { GraphNode, GraphResult, Severity, SourceLocation } from '../types.ts';
import { redactSecrets } from '../airlock/sanitizer.ts';
import { addFinding, createLineIndex, emptyGraph } from './firebase-rules-parser.ts';

const publicCategory = /(?:^|_)(?:PUBLIC|OPEN_FIREWALL|OPEN_PORT|OPEN_SSH|OPEN_RDP|ANONYMOUS|UNAUTHENTICATED|WORLD_READABLE|WORLD_WRITABLE|ALL_USERS|ALL_AUTHENTICATED_USERS)(?:_|$)/i;
const unsafeCharacters = /[\x00-\x1f\x7f-\x9f\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]/g;
const severityMap: Record<string, Severity> = {
  CRITICAL: 'blocker', HIGH: 'high', MEDIUM: 'medium', LOW: 'low', SEVERITY_UNSPECIFIED: 'low',
};

function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function textField(value: unknown, limit = 2048): value is string {
  return typeof value === 'string' && value.length <= limit;
}

export function cleanTelemetryString(value: string): string {
  return redactSecrets(value).replace(unsafeCharacters, ' ').replace(/\s+/g, ' ').trim();
}

/** JSON must be valid; track only direct array records, never nested metadata lookalikes. */
export function telemetryRecordOffsets(source: string, envelopeKey?: string): number[] {
  let searchFrom = 0, depth = 0, arrayDepth = -1;
  let arrayStart = envelopeKey === undefined ? source.indexOf('[') : -1;
  let offsets: number[] = [];
  while (searchFrom < source.length) {
    const character = source[searchFrom];
    if (character === '"') {
      const start = searchFrom++;
      while (searchFrom < source.length) {
        if (source[searchFrom] === '\\') searchFrom += 2;
        else if (source[searchFrom++] === '"') break;
      }
      if (envelopeKey !== undefined && depth === 1) {
        let valueStart = searchFrom;
        while (/\s/.test(source[valueStart] ?? '') && valueStart < source.length) valueStart++;
        if (source[valueStart] === ':' && JSON.parse(source.slice(start, searchFrom)) === envelopeKey) {
          valueStart++;
          while (/\s/.test(source[valueStart] ?? '') && valueStart < source.length) valueStart++;
          if (source[valueStart] === '[') {
            arrayStart = valueStart;
            // JSON.parse retains the final duplicate key, so locations must do the same.
            offsets = [];
          }
        }
      }
      continue;
    }
    if (character === '{') {
      if (arrayDepth > 0 && depth === arrayDepth) offsets.push(searchFrom);
      depth++;
    } else if (character === '[') {
      depth++;
      if (searchFrom === arrayStart) arrayDepth = depth;
    } else if (character === '}' || character === ']') {
      if (character === ']' && depth === arrayDepth) arrayDepth = -1;
      depth--;
    }
    searchFrom++;
  }
  return offsets;
}

function resourceNode(resource: string, location: SourceLocation): GraphNode {
  const run = resource.match(/^(?:\/\/run\.googleapis\.com\/)?projects\/([^/]+)\/(?:locations|regions)\/([^/]+)\/services\/([^/]+)$/);
  const functions = resource.match(/^(?:\/\/cloudfunctions\.googleapis\.com\/)?projects\/([^/]+)\/(?:locations|regions)\/([^/]+)\/functions\/([^/]+)$/);
  const service = run ?? functions;
  if (service) {
    const name = `projects/${service[1]}/locations/${service[2]}/${run ? 'services' : 'functions'}/${service[3]}`;
    return { id: `resource:${name}`, kind: 'resource', label: name.slice(0, 512), location };
  }
  const account = resource.match(/^(?:\/\/iam\.googleapis\.com\/)?projects\/[^/]+\/serviceAccounts\/([^/@]+@[^/@]+\.gserviceaccount\.com)$/);
  if (account) return { id: `identity:${account[1]}`, kind: 'identity', label: account[1].slice(0, 512), location };
  const bucket = resource.match(/^(?:\/\/storage\.googleapis\.com\/)?(?:projects\/[^/]+\/)?buckets\/([^/]+)$/);
  if (bucket) return { id: `data:bucket:${bucket[1]}:Cloud Storage objects`, kind: 'data',
    label: `Cloud Storage objects in ${bucket[1]}`.slice(0, 512), location };
  const secret = resource.match(/^(?:\/\/secretmanager\.googleapis\.com\/)?(projects\/[^/]+\/secrets\/[^/]+)$/);
  if (secret) return { id: `data:${secret[1]}:Secret Manager secrets`, kind: 'data',
    label: `Secret Manager secrets in ${secret[1]}`.slice(0, 512), location };
  const dataset = resource.match(/^(?:\/\/bigquery\.googleapis\.com\/)?(projects\/[^/]+\/datasets\/[^/]+)$/);
  if (dataset) return { id: `data:${dataset[1]}:BigQuery datasets`, kind: 'data',
    label: `BigQuery datasets in ${dataset[1]}`.slice(0, 512), location };
  return { id: `resource:${resource}`, kind: 'resource', label: resource.slice(0, 512), location };
}

function invalid(file: string, limit = false): GraphResult {
  const graph = emptyGraph();
  addFinding(graph, file, 1, limit ? 'scan/input-limit' : 'scan/invalid-input', 'high',
    limit ? 'SCC finding limit exceeded' : 'Invalid SCC findings',
    limit ? 'SCC exports may contain at most 10,000 findings.'
      : 'Expected an SCC findings array with valid category/resource strings, severity and state values; telemetry strings must not exceed 2048 characters and mute must not exceed 64 characters.',
    limit ? 'SCC export exceeds 10,000 findings' : 'Invalid SCC JSON or finding shape');
  return graph;
}

export function parseSccFindings(source: string, file: string): GraphResult {
  let parsed: unknown;
  try { parsed = JSON.parse(source); } catch { return invalid(file); }
  let findings: unknown[], envelopeKey: string | undefined;
  if (Array.isArray(parsed)) findings = parsed;
  else if (record(parsed)) {
    envelopeKey = Object.hasOwn(parsed, 'findings') ? 'findings' : 'listFindingsResults';
    const entries = parsed[envelopeKey];
    if (!Array.isArray(entries)) return invalid(file);
    findings = entries;
  } else return invalid(file);
  if (findings.length > 10_000) return invalid(file, true);

  const graph = emptyGraph();
  const lineIndex = createLineIndex(source);
  const offsets = telemetryRecordOffsets(source, envelopeKey);
  if (offsets.length !== findings.length) return invalid(file);
  for (let index = 0; index < findings.length; index++) {
    const item = findings[index];
    if (!record(item)) return invalid(file);
    const wrapped = Object.hasOwn(item, 'finding');
    const finding = wrapped ? item.finding : item;
    if (!record(finding)) return invalid(file);
    let fallbackResource: string | undefined;
    if (wrapped && Object.hasOwn(item, 'resource')) {
      if (!record(item.resource)) return invalid(file);
      if (Object.hasOwn(item.resource, 'name')) {
        if (!textField(item.resource.name) || !cleanTelemetryString(item.resource.name)) return invalid(file);
        fallbackResource = item.resource.name;
      }
    }
    if (!textField(finding.category)) return invalid(file);
    const category = cleanTelemetryString(finding.category);
    if (!category) return invalid(file);
    for (const field of ['resourceName', 'externalUri', 'name']) {
      if (Object.hasOwn(finding, field) && !textField(finding[field])) return invalid(file);
    }
    const resource = finding.resourceName ?? fallbackResource;
    if (!textField(resource)) return invalid(file);
    const resourceName = cleanTelemetryString(resource);
    if (!resourceName) return invalid(file);
    if (Object.hasOwn(finding, 'state') && !['ACTIVE', 'INACTIVE', 'STATE_UNSPECIFIED'].includes(finding.state as string)) return invalid(file);
    if (Object.hasOwn(finding, 'mute') && !textField(finding.mute, 64)) return invalid(file);
    const severity = finding.severity ?? 'SEVERITY_UNSPECIFIED';
    if (typeof severity !== 'string' || !Object.hasOwn(severityMap, severity) || finding.severity === null) return invalid(file);
    // A suppressed finding still has to validate before it can be omitted safely.
    if (finding.state === 'INACTIVE' || finding.mute === 'MUTED') continue;

    const line = lineIndex(offsets[index]);
    const location = { file, line };
    const target = resourceNode(resourceName, location);
    const details = [category, resourceName];
    if (finding.name) details.push(cleanTelemetryString(finding.name as string));
    if (finding.externalUri) details.push(cleanTelemetryString(finding.externalUri as string));
    const evidence = details.join(' | ').slice(0, 512);
    const active = addFinding(graph, file, line, 'scc/active-finding', severityMap[severity],
      `SCC ${severity}: ${category}`.slice(0, 512),
      `Security Command Center reports ${category} on ${resourceName}. Review the exported finding and resource configuration.`.slice(0, 512), evidence);
    graph.nodes.push(target);
    if (publicCategory.test(category)) {
      const from = 'entry:scc:public';
      graph.nodes.push({ id: from, kind: 'entry', label: 'SCC active public exposure', location });
      graph.edges.push({ id: `${file}:${index}:scc-public-exposure`, from, to: target.id,
        kind: 'scc-public-exposure', findingIds: [active.id], evidence, confidence: 'confirmed' });
    }
  }
  return graph;
}
