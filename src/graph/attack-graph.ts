import { createHash } from 'node:crypto';
import { closeSync, constants, fstatSync, lstatSync, openSync, readSync, readdirSync, realpathSync } from 'node:fs';
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import type { AttackPath, GraphEdge, GraphNode, GraphResult, Severity } from '../types.ts';
import { addFinding, buildBraceMap, createLineIndex, emptyGraph, parseFirebaseConfig, parseFirebaseRules, stripHclCommentsAndHeredocs } from './firebase-rules-parser.ts';
import { parseIamPolicy, parseTerraform, parseWifWorkflow, scanTerraformBlocks } from './gcp-iam-parser.ts';

const rank: Record<Severity, number> = { blocker: 0, high: 1, medium: 2, low: 3, info: 4 };
const compare = (a: string, b: string): number => a < b ? -1 : a > b ? 1 : 0;
const unique = (values: string[]): string[] => [...new Set(values)].sort();
const hash = (value: unknown): string => createHash('sha256').update(JSON.stringify(value)).digest('hex').slice(0, 20);

function byId<T extends { id: string }>(items: T[]): T[] {
  const map = new Map<string, T>();
  for (const item of items) {
    const previous = map.get(item.id);
    if (!previous) map.set(item.id, item);
    else if (previous !== item && compare(JSON.stringify(item), JSON.stringify(previous)) > 0) map.set(item.id, item);
  }
  return [...map.keys()].sort().map(id => map.get(id)!);
}

/** Merge without modifying parser results; output order is independent of traversal order. */
export function mergeGraphs(graphs: readonly GraphResult[]): GraphResult {
  const result = emptyGraph();
  const nodes = new Map<string, { node: GraphNode; serialized: string }>();
  const edges = new Map<string, { edge: GraphEdge; findingIds: Set<string> }>();
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
      const key = `${edge.from.length}:${edge.from}|${edge.to.length}:${edge.to}|${edge.kind.length}:${edge.kind}|${edge.confidence.length}:${edge.confidence}|${edge.evidence}`;
      let entry = edges.get(key);
      if (!entry) {
        entry = { edge: { ...edge }, findingIds: new Set<string>() };
        edges.set(key, entry);
      } else if (compare(edge.id, entry.edge.id) < 0) entry.edge.id = edge.id;
      for (const id of edge.findingIds) entry.findingIds.add(id);
    }
  }
  result.nodes = [...nodes.values()].map(entry => entry.node).sort((a, b) => compare(a.id, b.id));
  result.findings = byId(graphs.flatMap(graph => graph.findings));
  const orderedFindingIds = result.findings.map(finding => finding.id);
  result.edges = [...edges.values()].map(entry => ({ ...entry.edge,
    // Dense grants can share the complete finding set; reuse its ordering only
    // after checking membership, since edges may also reference unknown IDs.
    findingIds: entry.findingIds.size === orderedFindingIds.length && orderedFindingIds.every(id => entry.findingIds.has(id))
      ? orderedFindingIds.slice() : [...entry.findingIds].sort() }))
    .sort((a, b) => compare(a.id, b.id));
  result.paths = byId(graphs.flatMap(graph => graph.paths));
  result.limitations = unique(graphs.flatMap(graph => graph.limitations));
  return result;
}

/** Enumerate simple paths, including transitive impersonation; cycles never recurse. */
export function findAttackPaths(graph: GraphResult): AttackPath[] {
  const nodes = new Map(graph.nodes.map(node => [node.id, node]));
  const findings = new Map<string, GraphResult['findings'][number]>();
  for (const finding of graph.findings) findings.set(finding.id, finding);
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
      last?.findingIds.some(id => findings.get(id)?.ruleId === 'iam/privilege-escalation');
    if (last && terminal) {
      if (paths.length >= 1000) { limited = true; return; }
      const linkedFindingIds = new Set<string>();
      for (const edge of links) for (const id of edge.findingIds) linkedFindingIds.add(id);
      const findingIds = [...linkedFindingIds].sort();
      let severity: Severity | undefined;
      for (const id of findingIds) {
        const candidate = findings.get(id)?.severity;
        if (candidate && (severity === undefined || rank[candidate] < rank[severity])) severity = candidate;
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
    if (edge.kind !== 'iam-grant') continue;
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
          if (edge.to === alias && / -> roles\/(?:run|cloudfunctions)\.invoker on /.test(edge.evidence)) edge.to = service.id;
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
  let entries = 0;
  const walk = (path: string, depth: number): void => {
    if (depth > 64 || entries > 20_000) { fail(display(path), 'Directory traversal limit exceeded.', 'scan/traversal-limit'); return; }
    try {
      if (lstatSync(path).isSymbolicLink() || !inside(realpathSync(path))) {
        fail(display(path), 'Symbolic links and paths outside the scan root are not followed.', 'scan/unsafe-path'); return;
      }
      const names = readdirSync(path).sort(compare);
      for (const name of names) {
        if (name === '.git' || name === 'node_modules') continue;
        if (++entries > 20_000) { fail(display(path), 'Directory entry limit exceeded.', 'scan/traversal-limit'); break; }
        const child = join(path, name), file = display(child);
        try {
          const stat = lstatSync(child);
          if (stat.isSymbolicLink()) fail(file, 'Symbolic links are not followed; linked inputs were not analyzed.', 'scan/unsafe-path');
          else if (stat.isDirectory()) walk(child, depth + 1);
          else if (stat.isFile()) files.push(file);
          else fail(file, 'Non-regular filesystem entries are not read.', 'scan/unsafe-path');
        } catch { fail(file, 'Could not inspect a directory entry.'); }
      }
    } catch { fail(display(path), 'Could not read a directory.'); }
  };
  walk(root, 0);
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
      : /(?:^|[-_.\s])[Ii][Aa][Mm](?=[-_.\sA-Z0-9])|[a-z0-9](?:Iam|IAM)(?=[-_.\sA-Z0-9])/.test(name) && /\.json$/i.test(name)
        ? (source: string) => parseIamPolicy(source, file)
      : name.endsWith('.tf') ? (source: string) => {
        declarations.push(...resources(source, file));
        const parsed = parseTerraform(source, file);
        for (const edge of parsed.edges) if (edge.kind === 'iam-grant') {
          // The known filename disambiguates colons in paths from the source line delimiter.
          grantSources.set(edge.id, edge.id.slice(0, edge.id.indexOf(':', file.length + 1) + 1));
        }
        return parsed;
      }
      : /\.ya?ml$/.test(name) && (/(?:^|\/)\.github\/workflows\/[^/]+$/.test(file) || /wif/i.test(name))
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
