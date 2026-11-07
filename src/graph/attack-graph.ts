import { hash as cryptoHash } from 'node:crypto';
import { closeSync, constants, fstatSync, lstatSync, openSync, readSync, readdirSync, realpathSync } from 'node:fs';
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import type { AttackPath, GraphEdge, GraphNode, GraphResult, Severity } from '../types.ts';
import { addFinding, buildBraceMap, createLineIndex, emptyGraph, parseFirebaseConfig, parseFirebaseRules, stripHclCommentsAndHeredocs } from './firebase-rules-parser.ts';
import { parseIamPolicy, parseTerraform, parseWifWorkflow, scanTerraformBlocks } from './gcp-iam-parser.ts';
import { parseAuditLogs } from './audit-log-parser.ts';
import { parseSccFindings } from './scc-findings-parser.ts';

// Skip local IDE/agent state, SDK caches, build outputs, and nested worktrees.
export const EXCLUDED_DIRS: ReadonlySet<string> = new Set([
  '.git', 'node_modules', '.pnpm-store', '.yarn', 'Pods',
  '.fvm', '.dart_tool', '.symlinks', '.plugin_symlinks',
  '.venv', 'venv', '__pycache__', '.pytest_cache', '.mypy_cache', '.ruff_cache',
  '.gradle', 'build', '.build', '_build', 'dist', 'target', 'DerivedData',
  '.next', '.nuxt', '.svelte-kit', '.astro', '.turbo', '.parcel-cache',
  '.firebase', '.terraform', '.wrangler', '.vercel',
  '.worktrees', '.claude', '.agents', '.codex', '.gemini', 'coverage',
]);

const rank: Record<Severity, number> = { blocker: 0, high: 1, medium: 2, low: 3, info: 4 };
const compare = (a: string, b: string): number => a < b ? -1 : a > b ? 1 : 0;
const unique = (values: string[]): string[] => [...new Set(values)].sort();
const hash = (value: unknown): string => cryptoHash('sha256', JSON.stringify(value), 'hex').slice(0, 20);

const HEX_NIBBLE = new Int8Array(128).fill(-1);
for (let c = 48; c <= 57; c++) HEX_NIBBLE[c] = c - 48;
for (let c = 97; c <= 102; c++) HEX_NIBBLE[c] = c - 97 + 10;

function sortByHexPrefix<T>(items: readonly T[], getId: (item: T) => string): T[] {
  const len = items.length;
  if (len < 512) {
    return items.slice().sort((a, b) => compare(getId(a), getId(b)));
  }
  const counts = new Uint32Array(65536);
  const buckets = new Uint16Array(len);
  for (let i = 0; i < len; i++) {
    const id = getId(items[i]);
    if (id.length < 4) {
      return items.slice().sort((a, b) => compare(getId(a), getId(b)));
    }
    const c0 = id.charCodeAt(0);
    const c1 = id.charCodeAt(1);
    const c2 = id.charCodeAt(2);
    const c3 = id.charCodeAt(3);
    if (c0 >= 128 || c1 >= 128 || c2 >= 128 || c3 >= 128) {
      return items.slice().sort((a, b) => compare(getId(a), getId(b)));
    }
    const d0 = HEX_NIBBLE[c0];
    const d1 = HEX_NIBBLE[c1];
    const d2 = HEX_NIBBLE[c2];
    const d3 = HEX_NIBBLE[c3];
    if (d0 < 0 || d1 < 0 || d2 < 0 || d3 < 0) {
      return items.slice().sort((a, b) => compare(getId(a), getId(b)));
    }
    const bucket = (d0 << 12) | (d1 << 8) | (d2 << 4) | d3;
    buckets[i] = bucket;
    counts[bucket]++;
  }
  let maxBucket = 0;
  let sum = 0;
  for (let b = 0; b < 65536; b++) {
    const c = counts[b];
    if (c > maxBucket) maxBucket = c;
    counts[b] = sum;
    sum += c;
  }
  if (maxBucket > 64) {
    return items.slice().sort((a, b) => compare(getId(a), getId(b)));
  }
  const out = new Array<T>(len);
  for (let i = 0; i < len; i++) {
    out[counts[buckets[i]]++] = items[i];
  }
  for (let i = 1; i < len; i++) {
    const cur = out[i];
    const curId = getId(cur);
    let j = i - 1;
    while (j >= 0 && getId(out[j]) > curId) {
      out[j + 1] = out[j];
      j--;
    }
    out[j + 1] = cur;
  }
  return out;
}

function byId<T extends { id: string }>(items: readonly T[]): T[] {
  if (items.length === 0) return [];
  const sorted = sortByHexPrefix(items, item => item.id);
  const result: T[] = [sorted[0]];
  for (let i = 1; i < sorted.length; i++) {
    const item = sorted[i];
    const previous = result[result.length - 1];
    if (item.id === previous.id) {
      if (item !== previous && compare(JSON.stringify(item), JSON.stringify(previous)) > 0) {
        result[result.length - 1] = item;
      }
    } else {
      result.push(item);
    }
  }
  return result;
}

function uniqueSortedStrings(values: readonly string[]): string[] {
  if (values.length === 0) return [];
  const sorted = sortByHexPrefix(values, s => s);
  const result: string[] = [sorted[0]];
  for (let i = 1; i < sorted.length; i++) {
    const cur = sorted[i];
    if (cur !== result[result.length - 1]) {
      result.push(cur);
    }
  }
  return result;
}

/** Merge without modifying parser results; output order is independent of traversal order. */
export function mergeGraphs(graphs: readonly GraphResult[]): GraphResult {
  const result = emptyGraph();
  const nodes = new Map<string, { node: GraphNode; serialized: string }>();
  type EdgeAccumulator = { raw: GraphEdge; edge: GraphEdge; findingIds: string[] };
  const edges = new Map<string, EdgeAccumulator>();
  let mru0: EdgeAccumulator | undefined, mru1: EdgeAccumulator | undefined;
  for (const graph of graphs) {
    for (const node of graph.nodes) {
      const previous = nodes.get(node.id);
      if (previous && previous.node.kind === node.kind && previous.node.label === node.label &&
        !!previous.node.location === !!node.location && previous.node.location?.file === node.location?.file &&
        previous.node.location?.line === node.location?.line && previous.node.location?.column === node.location?.column) continue;
      const serialized = JSON.stringify(node);
      // Prefer a declaration's location over a reference's placeholder metadata.
      if (!previous || (!previous.node.location && node.location) ||
        (!!previous.node.location === !!node.location && compare(serialized, previous.serialized) < 0)) {
        nodes.set(node.id, { node: { ...node }, serialized });
      }
    }
    for (const edge of graph.edges) {
      let entry: EdgeAccumulator | undefined;
      if (mru0 && mru0.raw.from === edge.from && mru0.raw.to === edge.to && mru0.raw.kind === edge.kind &&
        mru0.raw.confidence === edge.confidence && mru0.raw.evidence === edge.evidence) {
        entry = mru0;
      } else if (mru1 && mru1.raw.from === edge.from && mru1.raw.to === edge.to && mru1.raw.kind === edge.kind &&
        mru1.raw.confidence === edge.confidence && mru1.raw.evidence === edge.evidence) {
        entry = mru1;
        mru1 = mru0;
        mru0 = entry;
      } else {
        const key = `${edge.from.length}:${edge.from}|${edge.to.length}:${edge.to}|${edge.kind.length}:${edge.kind}|${edge.confidence.length}:${edge.confidence}|${edge.evidence}`;
        entry = edges.get(key);
        if (!entry) {
          entry = { raw: edge, edge: { ...edge }, findingIds: [] };
          edges.set(key, entry);
        }
        mru1 = mru0;
        mru0 = entry;
      }
      if (compare(edge.id, entry.edge.id) < 0) entry.edge.id = edge.id;
      for (const id of edge.findingIds) entry.findingIds.push(id);
    }
  }
  result.nodes = [...nodes.values()].map(entry => entry.node).sort((a, b) => compare(a.id, b.id));
  const nonEmptyFindings = graphs.filter(g => g.findings.length > 0);
  result.findings = nonEmptyFindings.length === 1
    ? byId(nonEmptyFindings[0].findings)
    : byId(graphs.flatMap(graph => graph.findings));
  let lastRawIds: readonly string[] | undefined;
  let lastSortedIds: readonly string[] | undefined;
  const processedEdges: GraphEdge[] = [];
  for (const entry of edges.values()) {
    let findingIds: string[];
    if (lastRawIds && lastSortedIds && lastRawIds.length === entry.findingIds.length &&
      lastRawIds.every((id, k) => id === entry.findingIds[k])) {
      findingIds = lastSortedIds.slice();
    } else {
      findingIds = uniqueSortedStrings(entry.findingIds);
      lastRawIds = entry.findingIds;
      lastSortedIds = findingIds;
    }
    processedEdges.push({ ...entry.edge, findingIds });
  }
  result.edges = processedEdges.sort((a, b) => compare(a.id, b.id));
  result.paths = byId(graphs.flatMap(graph => graph.paths));
  result.limitations = unique(graphs.flatMap(graph => graph.limitations));
  return result;
}

function isStrictlySorted(ids: readonly string[]): boolean {
  for (let i = 1; i < ids.length; i++) {
    if (!(ids[i - 1] < ids[i])) return false;
  }
  return true;
}

function mergeTwoSortedUnique(a: readonly string[], b: readonly string[]): readonly string[] {
  if (a.length === b.length && a.every((val, i) => val === b[i])) return a;
  const merged: string[] = [];
  let i = 0, j = 0;
  while (i < a.length && j < b.length) {
    const va = a[i], vb = b[j];
    if (va === vb) {
      merged.push(va);
      i++;
      j++;
    } else if (va < vb) {
      merged.push(va);
      i++;
    } else {
      merged.push(vb);
      j++;
    }
  }
  while (i < a.length) merged.push(a[i++]);
  while (j < b.length) merged.push(b[j++]);
  return merged;
}

/** Enumerate simple paths, including transitive impersonation; cycles never recurse. */
export function findAttackPaths(graph: GraphResult): AttackPath[] {
  const nodes = new Map(graph.nodes.map(node => [node.id, node]));
  let hasEscalationFindings = false;
  let minGraphRank = Infinity;
  let findingsSorted = true;
  for (let i = 0; i < graph.findings.length; i++) {
    const finding = graph.findings[i];
    if (i > 0 && !(graph.findings[i - 1].id < finding.id)) findingsSorted = false;
    if (finding.ruleId === 'iam/privilege-escalation') hasEscalationFindings = true;
    const r = rank[finding.severity];
    if (r < minGraphRank) minGraphRank = r;
  }
  const fallbackMap = findingsSorted ? undefined : new Map<string, GraphResult['findings'][number]>(
    graph.findings.map(finding => [finding.id, finding])
  );
  const getFinding = (id: string): GraphResult['findings'][number] | undefined => {
    if (fallbackMap) return fallbackMap.get(id);
    let low = 0, high = graph.findings.length - 1;
    while (low <= high) {
      const mid = (low + high) >>> 1;
      const midFinding = graph.findings[mid];
      if (midFinding.id === id) return midFinding;
      if (midFinding.id < id) low = mid + 1;
      else high = mid - 1;
    }
    return undefined;
  };
  const outgoing = new Map<string, GraphEdge[]>();
  for (const edge of graph.edges) {
    if (!nodes.has(edge.from) || !nodes.has(edge.to)) continue;
    const list = outgoing.get(edge.from) ?? [];
    list.push(edge);
    outgoing.set(edge.from, list);
  }
  for (const list of outgoing.values()) list.sort((a, b) => compare(a.id, b.id));
  const paths: AttackPath[] = [];
  let steps = 0, limited = false;
  const visit = (ids: string[], links: GraphEdge[]): void => {
    const current = ids.at(-1)!;
    const last = links.at(-1);
    const terminal = nodes.get(current)!.kind === 'data' || last?.kind === 'service-account-impersonation' ||
      (hasEscalationFindings && last?.findingIds.some(id => getFinding(id)?.ruleId === 'iam/privilege-escalation'));
    if (last && terminal) {
      if (paths.length >= 1000) { limited = true; return; }
      let findingIds: string[];
      if (links.every(edge => isStrictlySorted(edge.findingIds))) {
        let merged: readonly string[] = links[0].findingIds;
        for (let i = 1; i < links.length; i++) merged = mergeTwoSortedUnique(merged, links[i].findingIds);
        findingIds = merged.slice();
      } else {
        const linkedFindingIds = new Set<string>();
        for (const edge of links) for (const id of edge.findingIds) linkedFindingIds.add(id);
        findingIds = [...linkedFindingIds].sort();
      }
      let severity: Severity | undefined;
      for (const id of findingIds) {
        const candidate = getFinding(id)?.severity;
        if (candidate && (severity === undefined || rank[candidate] < rank[severity])) severity = candidate;
        if (severity !== undefined && rank[severity] <= minGraphRank) break;
      }
      paths.push({ id: hash(links.map(edge => edge.id)), nodes: [...ids], edges: links.map(edge => edge.id), findingIds,
        severity: severity ?? 'medium',
        confidence: links.some(edge => edge.confidence === 'potential') ? 'potential' : 'confirmed',
        description: ids.map(id => nodes.get(id)!.label).join(' -> ') });
    }
    if (nodes.get(current)!.kind === 'data') return;
    for (const edge of outgoing.get(current) ?? []) {
      if (ids.includes(edge.to)) continue;
      if (++steps > 20_000 || ids.length >= 64) { limited = true; return; }
      visit([...ids, edge.to], [...links, edge]);
      if (limited) return;
    }
  };
  for (const node of [...nodes.values()].filter(node => node.kind === 'entry').sort((a, b) => compare(a.id, b.id))) {
    visit([node.id], []);
    if (limited) break;
  }
  if (limited && !graph.findings.some(finding => finding.ruleId === 'scan/path-limit')) {
    addFinding(graph, '.', 1, 'scan/path-limit', 'high', 'Attack path enumeration was bounded',
      'The path count, depth or traversal budget was exceeded; the scan is incomplete.', 'Limits: 1000 paths, 64 nodes, 20000 traversals');
  }
  return paths.sort((a, b) => compare(a.id, b.id));
}

interface TerraformResource {
  id: string;
  type: string;
  body: string;
  file: string;
  line: number;
}

// Read only top-level fields/blocks, ignoring quoted text and nested blocks. This
// keeps build identities distinct from runtime identities without evaluating HCL.
function field(body: string, name: string, block = false, allowSingleQuotes = false): string | undefined {
  const bracePairs = block ? buildBraceMap(body, allowSingleQuotes) : new Map<number, number>();
  const identifier = /[A-Za-z_][\w-]*/y;
  let depth = 0;
  for (let i = 0; i < body.length;) {
    if (body[i] === '"' || (allowSingleQuotes && body[i] === "'")) {
      const quote = body[i++];
      while (i < body.length) {
        if (body[i] === '\\') i += 2;
        else if (body[i++] === quote) break;
      }
      continue;
    }
    if (body[i] === '{') { depth++; i++; continue; }
    if (body[i] === '}') { depth--; i++; continue; }
    identifier.lastIndex = i;
    const token = identifier.exec(body)?.[0];
    if (!token) { i++; continue; }
    i += token.length;
    if (depth || token !== name) continue;
    while (/\s/.test(body[i] ?? '') && i < body.length) i++;
    if (block && body[i] === '{') {
      const end = bracePairs.get(i) ?? -1;
      return end < 0 ? undefined : body.slice(i + 1, end);
    }
    if (!block && body[i] === '=') return body.slice(i + 1).trimStart().match(/^("(?:\\.|[^"\\])*"|[^\s{}]+)/)?.[0];
  }
  return undefined;
}

function literal(body: string, name: string): string | undefined {
  const raw = field(body, name);
  if (!raw?.startsWith('"')) return;
  try {
    const value: unknown = JSON.parse(raw);
    return typeof value === 'string' && !/\$\{|%\{/.test(value) ? value : undefined;
  } catch { return; }
}

function resources(source: string, file: string): TerraformResource[] {
  const result: TerraformResource[] = [], { text } = stripHclCommentsAndHeredocs(source);
  const lineIndex = createLineIndex(text);
  for (const { offset, open, close, type, name } of scanTerraformBlocks(text)) {
    if (close >= 0 && type && name) result.push({ id: `tf:${dirname(file)}:${type}.${name}`, type,
      body: text.slice(open + 1, close), file, line: lineIndex(offset) });
  }
  return result;
}

function correlateResources(graph: GraphResult, declarations: TerraformResource[], grantSources: Map<string, string>): void {
  const services = declarations.filter(item => /^google_(?:cloud_run(?:_v2)?_service|cloudfunctions2?_function)$/.test(item.type));
  const descriptors = services.map(service => ({ ...service, name: literal(service.body, 'name'),
    project: literal(service.body, 'project'), region: literal(service.body, 'location') ?? literal(service.body, 'region'),
    family: service.type.includes('cloud_run') ? 'run' : 'cloudfunctions' }));
  const serviceIds = new Set(services.map(service => service.id));
  // Rebuild runtime connections once, without rescanning all edges for each service.
  graph.edges = graph.edges.filter(edge => !serviceIds.has(edge.from) || edge.kind !== 'potential-runtime-identity-access');
  const grantsByTarget = new Map<string, GraphEdge[]>(), grantsBySource = new Map<string, GraphEdge[]>();
  for (const edge of graph.edges) {
    if (edge.kind !== 'iam-grant' && edge.kind !== 'scc-public-exposure') continue;
    const targets = grantsByTarget.get(edge.to) ?? [];
    targets.push(edge);
    grantsByTarget.set(edge.to, targets);
    const prefix = grantSources.get(edge.id);
    if (prefix !== undefined) {
      const sources = grantsBySource.get(prefix) ?? [];
      sources.push(edge);
      grantsBySource.set(prefix, sources);
    }
  }
  const descriptorsByName = new Map<string, typeof descriptors>();
  for (const service of descriptors) {
    if (!service.name || !service.project || !service.region) continue;
    const key = JSON.stringify([service.family, service.project, service.region, service.name]);
    const matches = descriptorsByName.get(key) ?? [];
    matches.push(service);
    descriptorsByName.set(key, matches);
  }
  const resolvedLimitations = new Set<string>();
  const runtimeConnections = new Map<string, GraphEdge>();
  for (const service of descriptors) {
    if (service.name && service.project && service.region &&
      descriptorsByName.get(JSON.stringify([service.family, service.project, service.region, service.name]))?.length === 1) {
      const suffix = `projects/${service.project}/locations/${service.region}/${service.family === 'run' ? 'services' : 'functions'}/${service.name}`;
      const aliases = new Set([`resource:${suffix}`, `resource://${service.family}.googleapis.com/${suffix}`]);
      for (const alias of aliases) {
        for (const edge of grantsByTarget.get(alias) ?? []) {
          if (edge.to === alias && (edge.kind === 'scc-public-exposure' || / -> roles\/(?:run|cloudfunctions)\.invoker on /.test(edge.evidence))) edge.to = service.id;
        }
        grantsByTarget.delete(alias);
      }
    }
    // Reconstruct this one connection with the correct runtime block. The parser's
    // generic nested-field reader can otherwise select Functions' build account.
    const runtime = service.type === 'google_cloudfunctions2_function' ? field(service.body, 'service_config', true) ?? ''
      : service.type === 'google_cloud_run_v2_service' ? field(service.body, 'template', true) ?? ''
      : service.type === 'google_cloud_run_service' ? field(field(service.body, 'template', true) ?? '', 'spec', true) ?? ''
      : service.body;
    const key = service.type === 'google_cloud_run_v2_service' ? 'service_account'
      : service.type === 'google_cloud_run_service' ? 'service_account_name' : 'service_account_email';
    const raw = field(runtime, key);
    let expression = raw;
    if (raw?.startsWith('"')) { try { expression = JSON.parse(raw); } catch { expression = undefined; } }
    let principal: string | undefined, inferred = false;
    if (expression) {
      const email = expression.replace(/^serviceAccount:/, '').match(/^(?:projects\/[^/]+\/serviceAccounts\/)?([\w.+-]+@[\w.-]+\.gserviceaccount\.com)$/)?.[1];
      const ref = expression.match(/^(?:\$\{)?(google_service_account\.[\w-]+)\.(?:email|id|name)(?:\})?$/)?.[1];
      principal = email ? `identity:${email}` : ref ? `identity:tf:${dirname(service.file)}:${ref}` : undefined;
    } else if (raw === undefined && service.project) {
      // Never infer a project number from a grant to a cross-project account.
      const email = service.type === 'google_cloudfunctions_function' && /^[a-z][a-z0-9-]*$/.test(service.project)
        ? `${service.project}@appspot.gserviceaccount.com`
        : /^\d+$/.test(service.project) ? `${service.project}-compute@developer.gserviceaccount.com` : undefined;
      if (email) { principal = `identity:${email}`; inferred = true; }
    }
    runtimeConnections.delete(service.id);
    if (principal) {
      graph.nodes.push({ id: principal, kind: 'identity', label: principal.replace(/^identity:/, '') });
      runtimeConnections.set(service.id, { id: `${service.id}:runtime`, from: service.id, to: principal,
        kind: 'potential-runtime-identity-access', findingIds: [], confidence: 'potential',
        evidence: `${inferred ? 'Default runtime identity inferred from explicit project' : 'Declared runtime identity'}; application behavior or exploitation is required to use its permissions.` });
      resolvedLimitations.add(`${service.file}:${service.line}: Runtime service account is absent or unresolved; no default identity was inferred.`);
      if (inferred) graph.limitations.push(`${service.file}:${service.line}: Runtime identity uses a service default inferred from the explicit project; deployed identity and account existence were not verified.`);
    } else graph.limitations.push(`${service.file}:${service.line}: Runtime identity could not be resolved safely; explicit account or project-number evidence is required for cross-file correlation.`);
    // A grant to inspect a service does not grant execution as its runtime identity.
    for (const edge of grantsByTarget.get(service.id) ?? []) if (edge.to === service.id &&
      !/ -> roles\/(?:run|cloudfunctions)\.invoker on /.test(edge.evidence)) {
      edge.to = `resource:${service.id}:non-invocation`;
      graph.nodes.push({ id: edge.to, kind: 'resource', label: `Non-invocation IAM access to ${service.id}` });
    }
    grantsByTarget.delete(service.id);
  }
  for (const edge of runtimeConnections.values()) graph.edges.push(edge);
  graph.limitations = graph.limitations.filter(value => !resolvedLimitations.has(value));
  // Literal IAM service names are scoped by service family, project and region.
  // Direct Terraform references are already connected by parseTerraform.
  const invocationTargets = new Map<string, string>();
  for (const grant of declarations.filter(item => /_iam_(?:member|binding)$/.test(item.type))) {
    const family = grant.type.startsWith('google_cloud_run') ? 'run' : grant.type.startsWith('google_cloudfunctions') ? 'cloudfunctions' : undefined;
    if (!family) continue;
    const name = literal(grant.body, 'service') ?? literal(grant.body, 'cloud_run_service') ?? literal(grant.body, 'cloud_function')
      ?? (grant.type.startsWith('google_cloud_run_v2_service_iam_') ? literal(grant.body, 'name') : undefined);
    const project = literal(grant.body, 'project'), region = literal(grant.body, 'location') ?? literal(grant.body, 'region');
    if (!name || !project || !region) continue;
    const matches = descriptorsByName.get(JSON.stringify([family, project, region, name])) ?? [];
    if (matches.length !== 1) continue;
    invocationTargets.set(`${grant.file}:${grant.line}:`, matches[0].id);
  }
  for (const [prefix, target] of invocationTargets) {
    for (const edge of grantsBySource.get(prefix) ?? []) if (
      / -> roles\/(?:run|cloudfunctions)\.invoker on /.test(edge.evidence)) edge.to = target;
  }
}

/** Shared by scans and proposed diffs: verify the opened descriptor and bound the
 * actual read, since the path's type and size can change after inspection. */
export function readSafeSource(directory: string, file: string, remainingBytes = 32 * 1024 * 1024):
  { source: string; bytes: number } | { rule: string; reason: string; bytes: number } {
  let fd: number | undefined, length = 0;
  try {
    const root = realpathSync(directory), target = resolve(root, file);
    const inside = (path: string): boolean => {
      const part = relative(root, path);
      return !!part && !isAbsolute(part) && part !== '..' && !part.startsWith(`..${sep}`);
    };
    if (!inside(target) || relative(root, target).split(sep).some(part => part === '.git' || part === 'node_modules')) {
      return { rule: 'scan/unsafe-path', reason: 'Configured input is outside the root or in an excluded directory.', bytes: 0 };
    }
    let component = root;
    for (const part of relative(root, target).split(sep)) {
      component = join(component, part);
      if (lstatSync(component).isSymbolicLink()) {
        return { rule: 'scan/unsafe-path', reason: 'Configured input contains a symbolic link.', bytes: 0 };
      }
    }
    if (!inside(realpathSync(target))) {
      return { rule: 'scan/unsafe-path', reason: 'Input resolves outside the scan root.', bytes: 0 };
    }
    fd = openSync(target, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.size > 1024 * 1024 || stat.size > remainingBytes) {
      return { rule: 'scan/input-limit', reason: 'Input is not a regular file or exceeds the 1 MiB file / 32 MiB scan limit.', bytes: 0 };
    }
    const content = Buffer.alloc(1024 * 1024 + 1);
    while (length < content.length) {
      const count = readSync(fd, content, length, content.length - length, null);
      if (!count) break;
      length += count;
    }
    if (length > 1024 * 1024 || length > remainingBytes) {
      return { rule: 'scan/input-limit', reason: 'Input grew beyond the scan limit.', bytes: length };
    }
    return { source: content.toString('utf8', 0, length), bytes: length };
  } catch {
    return { rule: 'scan/unreadable-input', reason: 'Could not safely open or read an input file.', bytes: length };
  } finally { if (fd !== undefined) closeSync(fd); }
}

export function isAuditLogFilename(name: string): boolean {
  if (!/\.(?:nd)?json$/i.test(name)) return false;
  const stem = name.replace(/\.(?:nd)?json$/i, '');
  // Require explicit cloud/gcp audit or audit-log(s) tokens; keep trailing boundary case-sensitive.
  return /(?:^|[-_.\s])(?:(?:[Cc][Ll][Oo][Uu][Dd]|[Gg][Cc][Pp])[-_.]?[Aa][Uu][Dd][Ii][Tt](?:[-_.]?[Ll][Oo][Gg][Ss]?)?|[Aa][Uu][Dd][Ii][Tt][-_.]?[Ll][Oo][Gg][Ss]?)(?=[-_.\sA-Z0-9]|$)|[a-z0-9](?:(?:Cloud|GCP|Gcp)Audit(?:Logs?)?|AuditLogs?)(?=[-_.\sA-Z0-9]|$)/.test(stem);
}

export function isSccFindingsFilename(name: string): boolean {
  return /\.json$/i.test(name) && /(?:^|[-_.\s])[Ss][Cc][Cc](?=[-_.\sA-Z0-9]|$)|[a-z0-9](?:Scc|SCC)(?=[-_.\sA-Z0-9]|$)/.test(name.replace(/\.json$/i, ''));
}

function isRecognizedInputFile(file: string, name: string): boolean {
  return name === 'firebase.json'
    || /^(?:firestore|storage)\.rules$|\.(?:firestore|storage)\.rules\.sample$/.test(name)
    || isAuditLogFilename(name)
    || isSccFindingsFilename(name)
    || (/(?:^|[-_.\s])[Ii][Aa][Mm](?=[-_.\sA-Z0-9])|[a-z0-9](?:Iam|IAM)(?=[-_.\sA-Z0-9])/.test(name) && /\.json$/i.test(name))
    || /\.tf$/i.test(name)
    || (/\.ya?ml$/i.test(name) && (/(?:^|\/)\.github\/workflows\/[^/]+$/.test(file) || /wif/i.test(name)));
}

/** Offline scan. Symlinks are deliberately not followed, including config references. */
export function scanDirectory(directory: string): GraphResult {
  const diagnostics = emptyGraph(), graphs: GraphResult[] = [diagnostics];
  const declarations: TerraformResource[] = [], files: string[] = [];
  const grantSources = new Map<string, string>();
  const ruleFiles = new Map<string, 'firestore' | 'storage'>();
  const fail = (file: string, reason: string, rule = 'scan/unreadable-input'): void => {
    addFinding(diagnostics, file, 1, rule, 'high', 'Scan input could not be analyzed', reason, reason);
  };
  let root: string;
  try {
    root = realpathSync(resolve(directory));
    if (!lstatSync(root).isDirectory()) throw new Error('Not a directory');
  } catch {
    fail('.', 'The requested root is not a readable directory.');
    return mergeGraphs(graphs);
  }
  const inside = (file: string): boolean => {
    const path = relative(root, file);
    return !isAbsolute(path) && path !== '..' && !path.startsWith(`..${sep}`);
  };
  const display = (file: string): string => relative(root, file).split(sep).join('/') || '.';
  const skipped = new Set<string>();
  let entries = 0;
  const walk = (path: string, depth: number): void => {
    if (depth > 64 || entries > 20_000) { fail(display(path), 'Directory traversal limit exceeded.', 'scan/traversal-limit'); return; }
    try {
      if (lstatSync(path).isSymbolicLink() || !inside(realpathSync(path))) {
        fail(display(path), 'Symbolic links and paths outside the scan root are not followed.', 'scan/unsafe-path'); return;
      }
      const names = readdirSync(path).sort(compare);
      for (const name of names) {
        const child = join(path, name), file = display(child);
        if (EXCLUDED_DIRS.has(name)) {
          try { if (lstatSync(child).isFile()) continue; } catch {}
          if (name !== '.git' && name !== 'node_modules') skipped.add(name);
          continue;
        }
        if (++entries > 20_000) { fail(display(path), 'Directory entry limit exceeded.', 'scan/traversal-limit'); break; }
        try {
          const stat = lstatSync(child);
          if (stat.isSymbolicLink()) {
            const unsafe = (): void => fail(file, 'Symbolic links are not followed; linked inputs were not analyzed.', 'scan/unsafe-path');
            if (isRecognizedInputFile(file, name) || file.split('/').includes('.github')) { unsafe(); continue; }
            try {
              const targetReal = realpathSync(child), targetStat = lstatSync(targetReal);
              if (!inside(targetReal)) { unsafe(); continue; }
              const targetFile = display(targetReal);
              const parts = relative(root, targetReal).split(sep).filter(Boolean);
              if (parts.includes('.github')) { unsafe(); continue; }
              if (parts.some(part => EXCLUDED_DIRS.has(part))) {
                fail(file, 'Symbolic links to excluded directories are not followed.', 'scan/unsafe-path'); continue;
              }
              let component = root;
              if (parts.some(part => { component = join(component, part); return lstatSync(component).isSymbolicLink(); })) {
                unsafe(); continue;
              }
              if (targetStat.isFile()) {
                if (isRecognizedInputFile(targetFile, basename(targetFile))) unsafe();
                continue;
              }
              if (!targetStat.isDirectory()) { unsafe(); continue; }
              diagnostics.limitations.push(`${file}: Intra-repository directory symlink was not re-traversed; canonical target ${targetFile} is scanned directly.`);
            } catch { unsafe(); }
          }
          else if (stat.isDirectory()) walk(child, depth + 1);
          else if (stat.isFile()) { if (isRecognizedInputFile(file, name)) files.push(file); }
          else fail(file, 'Non-regular filesystem entries are not read.', 'scan/unsafe-path');
        } catch { fail(file, 'Could not inspect a directory entry.'); }
      }
    } catch { fail(display(path), 'Could not read a directory.'); }
  };
  walk(root, 0);
  if (skipped.size) diagnostics.limitations.push(`Excluded generated, cache, or worktree directories were not traversed: ${[...skipped].sort(compare).join(', ')}. Audit a subdirectory directly if infrastructure configs reside there.`);
  let totalBytes = 0;
  const read = (file: string): string | undefined => {
    const result = readSafeSource(root, file, 32 * 1024 * 1024 - totalBytes);
    totalBytes += result.bytes;
    if ('reason' in result) { fail(file, result.reason, result.rule); return; }
    return result.source;
  };
  for (const file of files.filter(file => basename(file) === 'firebase.json').sort(compare)) {
    const source = read(file);
    if (source === undefined) continue;
    const config = parseFirebaseConfig(source, file);
    graphs.push(config.graph);
    if (config.graph.findings.some(finding => finding.ruleId.startsWith('scan/'))) continue;
    const parsed = JSON.parse(source);
    for (const kind of ['firestore', 'storage'] as const) {
      const entries = Array.isArray(parsed[kind]) ? parsed[kind] : parsed[kind] ? [parsed[kind]] : [];
      for (const entry of entries) if (typeof entry.rules === 'string') {
        const target = resolve(root, dirname(file), entry.rules);
        if (!inside(target)) { fail(file, 'Configured rules path escapes the scan root.', 'scan/unsafe-path'); continue; }
        const path = display(target);
        if (ruleFiles.has(path) && ruleFiles.get(path) !== kind) fail(file, 'One rules file is configured for incompatible services.', 'scan/invalid-input');
        else ruleFiles.set(path, kind);
      }
    }
  }
  for (const file of unique([...files, ...ruleFiles.keys()])) {
    const name = basename(file);
    if (name === 'firebase.json') continue;
    const ruleKind = ruleFiles.get(file) ?? (/^(?:firestore|storage)\.rules$|\.(?:firestore|storage)\.rules\.sample$/.test(name)
      ? name.includes('storage.rules') ? 'storage' : 'firestore' : undefined);
    const parser = ruleKind ? (source: string) => parseFirebaseRules(source, file, ruleKind)
      : isAuditLogFilename(name) ? (source: string) => parseAuditLogs(source, file)
      : isSccFindingsFilename(name) ? (source: string) => parseSccFindings(source, file)
      : /(?:^|[-_.\s])[Ii][Aa][Mm](?=[-_.\sA-Z0-9])|[a-z0-9](?:Iam|IAM)(?=[-_.\sA-Z0-9])/.test(name) && /\.json$/i.test(name)
        ? (source: string) => parseIamPolicy(source, file)
      : /\.tf$/i.test(name) ? (source: string) => {
        declarations.push(...resources(source, file));
        const parsed = parseTerraform(source, file);
        for (const edge of parsed.edges) if (edge.kind === 'iam-grant') {
          // The known filename disambiguates colons in paths from the source line delimiter.
          grantSources.set(edge.id, edge.id.slice(0, edge.id.indexOf(':', file.length + 1) + 1));
        }
        return parsed;
      }
      : /\.ya?ml$/i.test(name) && (/(?:^|\/)\.github\/workflows\/[^/]+$/.test(file) || /wif/i.test(name))
        ? (source: string) => parseWifWorkflow(source, file) : undefined;
    if (!parser) continue;
    const source = read(file);
    if (source === undefined) continue;
    try { graphs.push(parser(source)); }
    catch { fail(file, 'The parser could not complete this input.', 'scan/invalid-input'); }
  }
  let graph = mergeGraphs(graphs);
  if (declarations.length > 0) {
    correlateResources(graph, declarations, grantSources);
    graph = mergeGraphs([graph]);
  }
  const findingCount = graph.findings.length;
  graph.paths = findAttackPaths(graph);
  // Path enumeration can append an incomplete-scan finding after merge ordering.
  if (graph.findings.length !== findingCount) graph.findings.sort((a, b) => compare(a.id, b.id));
  graph.limitations.push('Static analysis does not establish deployed policy, runtime exploitability or completeness for unsupported syntax; files must remain stable during scanning.');
  return graph;
}
