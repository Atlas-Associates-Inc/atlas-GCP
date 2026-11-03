import { dirname } from 'node:path';
import type { GraphResult } from '../types.ts';
import { addFinding, buildBraceMap, createLineIndex, emptyGraph, stripHclCommentsAndHeredocs } from './firebase-rules-parser.ts';

const powerfulRoles = new Set(['roles/owner', 'roles/editor', 'roles/secretmanager.secretAccessor',
  'roles/bigquery.dataEditor', 'roles/storage.admin']);
const escalationRoles = new Set(['roles/iam.serviceAccountUser', 'roles/iam.serviceAccountTokenCreator',
  'roles/iam.securityAdmin', 'roles/iam.serviceAccountAdmin', 'iam.serviceAccounts.actAs',
  'iam.serviceAccounts.getAccessToken', 'roles/iam.workloadIdentityUser',
  'roles/iam.workloadIdentityPoolAdmin', 'iam.serviceAccounts.implicitDelegation']);
const dataRoles: Record<string, string> = { 'roles/secretmanager.secretAccessor': 'Secret Manager secrets',
  'roles/bigquery.dataEditor': 'BigQuery datasets', 'roles/storage.admin': 'Cloud Storage objects',
  'roles/storage.objectViewer': 'Cloud Storage objects', 'roles/datastore.user': 'Firestore data',
  'roles/owner': 'Project administration', 'roles/editor': 'Project resources' };

function identity(member: string): string {
  return `identity:${member.replace(/^serviceAccount:/, '')}`;
}

function addGrant(graph: GraphResult, file: string, line: number, member: string, role: string,
  scope: string, targetIdentity?: string, conditional = false): void {
  const publicMember = member === 'allUsers' || member === 'allAuthenticatedUsers';
  const external = publicMember || /^principal(?:Set)?:\/\//.test(member);
  const from = publicMember ? `entry:iam:${member}` : identity(member);
  const findings: string[] = [];
  const evidence = `${member} -> ${role} on ${scope}${conditional ? ' (conditional)' : ''}`;
  graph.nodes.push({ id: from, kind: external ? 'entry' : 'identity', label: member, location: { file, line } });
  if (/^(?:serviceAccount:)?(?:[^@]+-compute@developer\.gserviceaccount\.com|[^@]+@appspot\.gserviceaccount\.com)$/.test(member) && powerfulRoles.has(role)) {
    findings.push(addFinding(graph, file, line, 'iam/default-service-account', 'high',
      'Default service account has a powerful role', `${role} is granted to a default service account; use a dedicated identity with only required permissions.`, evidence).id);
  }
  if (escalationRoles.has(role)) findings.push(addFinding(graph, file, line, 'iam/privilege-escalation',
    'high', 'Service account or IAM escalation capability',
    `${role} can participate in privilege escalation. Resource scope, conditions, and required execution permissions must be verified.`, evidence).id);
  if (publicMember) findings.push(addFinding(graph, file, line, 'gcp/public-service', 'high',
    'Public IAM grant', `${member} has ${role} on ${scope}; allAuthenticatedUsers includes identities outside the organization.`, evidence).id);
  const impersonation = targetIdentity && escalationRoles.has(role);
  const destination = impersonation ? targetIdentity : dataRoles[role] ? `data:${scope}:${dataRoles[role]}` : `resource:${scope}`;
  graph.nodes.push({ id: destination, kind: impersonation ? 'identity' : dataRoles[role] ? 'data' : 'resource',
    label: impersonation ? targetIdentity.replace(/^identity:/, '') : dataRoles[role] ? `${dataRoles[role]} in ${scope}` : scope, location: { file, line } });
  const prerequisite = role === 'roles/iam.serviceAccountUser' || role === 'iam.serviceAccounts.actAs' || role.includes('Admin');
  graph.edges.push({ id: `${file}:${line}:${from}:${destination}:${role}`, from, to: destination,
    kind: impersonation ? 'service-account-impersonation' : 'iam-grant', findingIds: findings, evidence,
    confidence: conditional || prerequisite ? 'potential' : 'confirmed' });
}

export function parseIamPolicy(source: string, file: string): GraphResult {
  const graph = emptyGraph();
  const lineIndex = createLineIndex(source);
  let searchFrom = 0;
  try {
    const policy: unknown = JSON.parse(source);
    if (!policy || typeof policy !== 'object' || Array.isArray(policy)) throw new Error('Invalid policy');
    const record = policy as Record<string, unknown>;
    if (!Array.isArray(record.bindings)) throw new Error('Missing bindings');
    if ([record.resource, record.name].some(value => typeof value === 'string' && value.length > 2048)) {
      throw new Error('IAM resource exceeds the 2048 character limit');
    }
    const resource = typeof record.resource === 'string' ? record.resource : typeof record.name === 'string' ? record.name : undefined;
    const scope = resource || `unresolved IAM resource in ${file}`;
    const target = resource?.match(/(?:^|\/)serviceAccounts\/([^/@]+@[^/@]+)$/)?.[1];
    if (!resource) graph.limitations.push(`${file}: IAM policy resource is unspecified; grants remain scoped to this file and cannot establish cross-resource escalation.`);
    for (const binding of record.bindings) {
      if (!binding || typeof binding !== 'object' || typeof binding.role !== 'string' ||
        !Array.isArray(binding.members) || !binding.members.every((member: unknown) => typeof member === 'string')) throw new Error('Invalid binding');
      const conditional = binding.condition !== undefined && binding.condition !== null;
      if (conditional && (typeof binding.condition !== 'object' || Array.isArray(binding.condition))) throw new Error('Invalid condition');
      const roleText = JSON.stringify(binding.role), offset = source.indexOf(roleText, searchFrom);
      const line = lineIndex(Math.max(0, offset));
      // Escaped spellings may not occur verbatim; never rescan a failed suffix.
      searchFrom = offset < 0 ? source.length : offset + roleText.length;
      for (const member of binding.members) addGrant(graph, file, line, member, binding.role, scope,
        target ? identity(target) : undefined, conditional);
    }
  } catch {
    addFinding(graph, file, 1, 'scan/invalid-input', 'high', 'Invalid IAM policy',
      'Expected a JSON IAM policy object containing bindings with string roles and members, and resource/name strings of at most 2048 characters.', 'Invalid IAM policy shape or JSON');
  }
  return graph;
}

interface Attribute { raw: string; offset: number; depth: number }
interface Attributes { top: Map<string, Attribute>; nested: Map<string, Attribute> }
interface Resource { type: string; name: string; body: string; attributes: Attributes; offset: number; line: number }

function quoted(value: string): string | undefined {
  if (!/^"(?:\\.|[^"\\])*"$/.test(value)) return undefined;
  try { return JSON.parse(value); } catch { return undefined; }
}

/** Consume each attribute/value once, excluding identifiers inside quoted values. */
function indexAttributes(body: string, allowSingleQuotes = false): Attributes {
  const top = new Map<string, Attribute>(), nested = new Map<string, Attribute>();
  const identifier = /[A-Za-z_][\w-]*/y;
  let cursor = 0, depth = 0;
  const skipQuote = (): void => {
    const quote = body[cursor++];
    while (cursor < body.length) {
      if (body[cursor] === '\\') cursor += 2;
      else if (body[cursor++] === quote) break;
    }
  };
  while (cursor < body.length) {
    const c = body[cursor];
    if (c === '"' || (allowSingleQuotes && c === "'")) { skipQuote(); continue; }
    if (c === '{') { depth++; cursor++; continue; }
    if (c === '}') { depth--; cursor++; continue; }
    identifier.lastIndex = cursor;
    const match = identifier.exec(body);
    if (!match) { cursor++; continue; }
    const offset = cursor, key = match[0];
    cursor = identifier.lastIndex;
    while (cursor < body.length && /\s/.test(body[cursor])) cursor++;
    if (body[cursor] !== '=') continue;
    cursor++;
    while (cursor < body.length && /\s/.test(body[cursor])) cursor++;
    const start = cursor;
    if (body[cursor] === '"' || (allowSingleQuotes && body[cursor] === "'")) skipQuote();
    else if (body[cursor] === '[') {
      let brackets = 0;
      do {
        const c = body[cursor];
        if (c === '"' || (allowSingleQuotes && c === "'")) { skipQuote(); continue; }
        if (c === '[') brackets++;
        else if (c === ']') brackets--;
        cursor++;
      } while (cursor < body.length && brackets > 0);
    } else {
      while (cursor < body.length && !/[\s{}]/.test(body[cursor])) cursor++;
    }
    if (cursor === start) continue;
    const attribute = { raw: body.slice(start, cursor), offset, depth };
    if (!nested.has(key)) nested.set(key, attribute);
    if (depth === 0 && !top.has(key)) top.set(key, attribute);
  }
  return { top, nested };
}

function attr(attributes: Attributes, key: string, nested = false): Attribute | undefined {
  return (nested ? attributes.nested : attributes.top).get(key);
}

function value(attributes: Attributes, key: string, nested = false): string | undefined {
  const raw = attr(attributes, key, nested)?.raw;
  return raw === undefined ? undefined : quoted(raw) ?? raw;
}

function referenceId(expression: string, module: string): string | undefined {
  const match = expression.match(/^(?:\$\{)?(google_[a-z0-9_]+\.[A-Za-z0-9_-]+)\.(?:name|id|email)(?:\})?$/);
  return match ? `tf:${module}:${match[1]}` : undefined;
}

function serviceIdentity(expression: string, module: string, accounts: Map<string, string>): string | undefined {
  const member = expression.replace(/^serviceAccount:/, '');
  if (/^[\w.+-]+@[\w.-]+\.gserviceaccount\.com$/.test(member)) return identity(member);
  const account = member.match(/(?:^|\/)serviceAccounts\/([^/@]+@[^/@]+)$/)?.[1];
  if (account) return identity(account);
  const ref = referenceId(member, module);
  return ref ? accounts.get(ref) ?? `identity:${ref}` : undefined;
}

/** Mask comments/heredocs first. Skip every top-level block, including non-resources,
 * so all emitted bodies are disjoint and nested declarations cannot be borrowed. */
export function* scanTerraformBlocks(text: string): Generator<{
  offset: number; open: number; close: number; type?: string; name?: string;
}> {
  const bracePairs = buildBraceMap(text, false);
  const identifier = /[A-Za-z_][\w-]*/y;
  const resource = /resource\s+"([^"\\]+)"\s+"([^"\\]+)"\s*\{/y;
  for (let cursor = 0; cursor < text.length;) {
    if (text[cursor] === '"') {
      cursor++;
      while (cursor < text.length) {
        if (text[cursor] === '\\') cursor += 2;
        else if (text[cursor++] === '"') break;
      }
      continue;
    }
    const offset = cursor;
    identifier.lastIndex = cursor;
    const token = identifier.exec(text);
    resource.lastIndex = cursor;
    const header = token?.[0] === 'resource' ? resource.exec(text) : null;
    const open = header ? resource.lastIndex - 1 : text[cursor] === '{' ? cursor : -1;
    if (open >= 0) {
      const close = bracePairs.get(open) ?? -1;
      yield { offset, open, close, type: header?.[1], name: header?.[2] };
      if (close < 0) return;
      cursor = close + 1;
    } else cursor = token ? identifier.lastIndex : cursor + 1;
  }
}

export function parseTerraform(source: string, file: string): GraphResult {
  const graph = emptyGraph(), { text, hasHeredoc } = stripHclCommentsAndHeredocs(source), module = dirname(file);
  const lineIndex = createLineIndex(text);
  const resources: Resource[] = [];
  for (const { offset, open, close, type, name } of scanTerraformBlocks(text)) {
    if (close < 0) {
      addFinding(graph, file, lineIndex(open), 'scan/invalid-input', 'high',
        'Unbalanced Terraform block', 'The input could not be completely parsed.', 'Unclosed Terraform block');
      break;
    } else if (type && name) {
      const body = text.slice(open + 1, close);
      resources.push({ type, name, body, attributes: indexAttributes(body),
        offset: open + 1, line: lineIndex(offset) });
    }
  }
  if (hasHeredoc) graph.limitations.push(`${file}: Terraform heredocs are not evaluated; resources using them require manual review.`);
  const accounts = new Map<string, string>();
  for (const resource of resources.filter(item => item.type === 'google_service_account')) {
    const account = value(resource.attributes, 'account_id'), project = value(resource.attributes, 'project');
    const ref = `tf:${module}:${resource.type}.${resource.name}`;
    const email = account && project && /^[a-z0-9-]+$/.test(account) && /^[a-z0-9-]+$/.test(project)
      ? identity(`${account}@${project}.iam.gserviceaccount.com`) : `identity:${ref}`;
    accounts.set(ref, email);
    graph.nodes.push({ id: email, kind: 'identity', label: email.replace(/^identity:/, ''), location: { file, line: resource.line } });
    // Retain symbolic aliases so references in other files in this module can join exactly.
    if (email !== `identity:${ref}`) {
      graph.nodes.push({ id: `identity:${ref}`, kind: 'identity', label: `${resource.type}.${resource.name}` });
      for (const [from, to] of [[`identity:${ref}`, email], [email, `identity:${ref}`]]) graph.edges.push({
        id: `${from}->${to}`, from, to, kind: 'declared-identity-alias', findingIds: [], evidence: 'Explicit Terraform account_id and project', confidence: 'confirmed' });
    }
  }
  for (const resource of resources) {
    const { type, body, attributes, line } = resource;
    const id = `tf:${module}:${type}.${resource.name}`;
    if (/^google_(?:cloud_run(?:_v2)?_service|cloudfunctions2?_function)$/.test(type)) {
      graph.nodes.push({ id, kind: 'resource', label: `${type}.${resource.name}`, location: { file, line } });
      const account = value(attributes, 'service_account', true) ?? value(attributes, 'service_account_name', true) ?? value(attributes, 'service_account_email', true);
      const principal = account ? serviceIdentity(account, module, accounts) : undefined;
      if (principal) {
        graph.nodes.push({ id: principal, kind: 'identity', label: principal.replace(/^identity:/, '') });
        graph.edges.push({ id: `${id}:runtime`, from: id, to: principal, kind: 'potential-runtime-identity-access', findingIds: [],
          evidence: 'Service declares this runtime identity; exploitation or application behavior is required to access its credentials.', confidence: 'potential' });
      } else graph.limitations.push(`${file}:${line}: Runtime service account is absent or unresolved; no default identity was inferred.`);
      const ingressAttribute = attr(attributes, 'ingress', true) ?? attr(attributes, 'ingress_settings', true);
      const ingress = ingressAttribute ? quoted(ingressAttribute.raw) ?? ingressAttribute.raw : undefined;
      if (ingress === 'INGRESS_TRAFFIC_ALL' || ingress === 'ALLOW_ALL') addFinding(graph, file,
        lineIndex(resource.offset + ingressAttribute!.offset), 'gcp/public-ingress', 'medium',
        'Service permits external ingress', 'External ingress is enabled. Authentication policy must be checked separately; this does not prove public access.', `ingress = ${ingress}`);
    }
    if (type === 'google_iam_workload_identity_pool_provider') {
      const issuer = value(attributes, 'issuer_uri', true), condition = value(attributes, 'attribute_condition');
      if (issuer === 'https://token.actions.githubusercontent.com') {
        const pinned = !!condition && !/\|\|/.test(condition) && /\b(?:attribute|assertion)\.repository\s*==\s*(['"])[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+\1/.test(condition);
        if (!pinned) {
          const finding = addFinding(graph, file, line, 'wif/unpinned-provider', 'high', 'GitHub WIF provider lacks a recognized repository restriction',
            'No mandatory literal attribute.repository or assertion.repository equality was recognized. Review the provider condition and IAM principal bindings before trusting external GitHub identities.', condition ? `attribute_condition = ${condition}` : 'Missing attribute_condition');
          const entry = `entry:wif:${id}`;
          graph.nodes.push({ id: entry, kind: 'entry', label: 'GitHub OIDC identities' },
            { id, kind: 'resource', label: `${type}.${resource.name}`, location: { file, line } });
          graph.edges.push({ id: finding.id, from: entry, to: id, kind: 'unrestricted-provider-candidate', findingIds: [finding.id],
            evidence: finding.evidence, confidence: 'potential' });
        }
      }
    }
    if (!/_iam_(?:member|binding|policy)$/.test(type)) continue;
    if (type.endsWith('_iam_policy')) {
      graph.limitations.push(`${file}:${line}: Embedded Terraform policy_data is not evaluated; provide the exported IAM JSON policy.`);
      continue;
    }
    const roleRaw = attr(attributes, 'role')?.raw, role = roleRaw ? quoted(roleRaw) : undefined;
    const membersRaw = attr(attributes, 'members')?.raw, memberRaw = attr(attributes, 'member')?.raw;
    const members = membersRaw ? [...membersRaw.matchAll(/"(?:\\.|[^"\\])*"/g)].map(match => quoted(match[0])!).filter(Boolean)
      : memberRaw && quoted(memberRaw) ? [quoted(memberRaw)!] : [];
    if (!role || members.length === 0) {
      graph.limitations.push(`${file}:${line}: IAM role or members are dynamic or unsupported; this grant was not resolved.`);
      continue;
    }
    const service = value(attributes, 'service') ?? value(attributes, 'cloud_run_service') ?? value(attributes, 'cloud_function')
      ?? (type.startsWith('google_cloud_run_v2_service_iam_') ? value(attributes, 'name') : undefined);
    const targetService = service ? referenceId(service, module) : undefined;
    const targetAccount = value(attributes, 'service_account_id');
    const target = targetAccount ? serviceIdentity(targetAccount, module, accounts) : undefined;
    const project = value(attributes, 'project');
    const serviceFamily = type.startsWith('google_cloud_run') ? 'run' : type.startsWith('google_cloudfunctions') ? 'cloudfunctions' : undefined;
    let scope: string;
    if (serviceFamily && !targetService) {
      const region = value(attributes, 'location') ?? value(attributes, 'region');
      scope = service && !/\$\{|%\{/.test(service) && project && /^[a-z0-9-]+$/.test(project) && region && /^[a-z0-9-]+$/.test(region)
        ? `projects/${project}/locations/${region}/${serviceFamily === 'run' ? 'services' : 'functions'}/${service}`
        : `${id}:unresolved-resource`;
    } else scope = target ? target.replace(/^identity:/, '') : targetService ?? (project && /^[a-z0-9-]+$/.test(project) ? `project:${project}` : `${id}:unresolved-resource`);
    const conditional = /\bcondition\s*\{/.test(body);
    for (const member of members) {
      const principal = serviceIdentity(member, module, accounts);
      const resolved = principal ? principal.replace(/^identity:/, '') : member;
      const before = graph.edges.length;
      addGrant(graph, file, line, resolved, role, scope, target, conditional);
      if (targetService) {
        const grant = graph.edges[before];
        grant.to = targetService;
        graph.nodes.push({ id: targetService, kind: 'resource', label: service! });
      }
    }
  }
  graph.limitations.push(`${file}: Terraform analysis covers literal resources and direct references within one module; variables, provider defaults, modules, count/for_each, custom roles and dynamic expressions are not evaluated.`);
  return graph;
}

function isYamlBlockScalar(content: string): boolean {
  let quote = '', start = 0;
  for (let i = 0; i < content.length; i++) {
    const c = content[i];
    if (quote) {
      if (quote === '"' && c === '\\') i++;
      else if (quote === "'" && c === "'" && content[i + 1] === "'") i++;
      else if (c === quote) quote = '';
    } else if (c === '"' || c === "'") quote = c;
    else if (c === ':') { start = i + 1; break; }
  }
  return /^[ \t]*[|>](?:[+-][1-9]?|[1-9][+-]?)?[ \t]*(?:#.*)?$/.test(content.slice(start));
}

export function parseWifWorkflow(source: string, file: string): GraphResult {
  const graph = emptyGraph();
  const lines: Array<{ lineNumber: number; indent: number; content: string; keyIndent?: number }> = [];
  let scalarIndent: number | undefined, lineNumber = 0;
  // Blank/comment/scalar lines never affect structural boundaries or get copied
  // into every enclosing step. Indents consistently count spaces and tabs once.
  for (let offset = 0; offset < source.length;) {
    const newline = source.indexOf('\n', offset), end = newline < 0 ? source.length : newline;
    const raw = source.slice(offset, end).replace(/\r$/, '');
    offset = newline < 0 ? source.length : newline + 1;
    lineNumber++;
    let indent = 0;
    while (raw[indent] === ' ' || raw[indent] === '\t') indent++;
    let content = raw.slice(indent);
    const isBlankOrComment = !content || content[0] === '#';
    if (isBlankOrComment) continue;
    if (scalarIndent !== undefined && indent > scalarIndent) continue;
    scalarIndent = undefined;
    const step = /^-[ \t]+/.exec(content);
    const keyIndent = step ? indent + step[0].length : undefined;
    if (step) content = content.slice(step[0].length);
    lines.push({ lineNumber, indent, content, keyIndent });
    if (isYamlBlockScalar(content)) {
      scalarIndent = step && /^[|>]/.test(content) ? indent : keyIndent ?? indent;
    }
  }
  interface Step {
    keyIndent: number; line?: number; withSeen: boolean; withActive: boolean;
    childIndent?: number; provider?: string; account?: string;
  }
  const steps: Step[] = [], active: Step[] = [];
  const peer = (step: Step, content: string, line: number): void => {
    step.withActive = false;
    if (step.line === undefined && /^uses\s*:\s*['"]?google-github-actions\/auth@[^\s'"#]+/.test(content)) step.line = line;
    if (!step.withSeen && /^with\s*:\s*(?:#.*)?$/.test(content)) {
      step.withSeen = true;
      step.withActive = true;
    }
  };
  // Each frame is pushed and popped once. Only the innermost frame can own a
  // line, so nested steps/mappings never lend keys to their ancestors.
  for (const row of lines) {
    while (active.length && row.indent < active.at(-1)!.keyIndent) active.pop();
    const parent = active.at(-1);
    if (parent?.withActive && row.indent > parent.keyIndent && parent.childIndent === undefined) parent.childIndent = row.indent;
    if (row.keyIndent !== undefined) {
      const step: Step = { keyIndent: row.keyIndent, withSeen: false, withActive: false };
      steps.push(step);
      active.push(step);
      peer(step, row.content, row.lineNumber);
    } else if (parent && row.indent === parent.keyIndent) peer(parent, row.content, row.lineNumber);
    else if (parent?.withActive && row.indent === parent.childIndent) {
      const input = /^(workload_identity_provider|service_account)[ \t]*:[ \t]*['"]?([^'"#\n]+)/.exec(row.content);
      if (input) {
        if (input[1] === 'workload_identity_provider') parent.provider ??= input[2].trim();
        else parent.account ??= input[2].trim();
      }
    }
  }
  for (const { line, provider, account } of steps) {
    if (line === undefined) continue;
    if (!provider && !account) continue;
    if (!provider || !/^projects\/\d+\/locations\/global\/workloadIdentityPools\/[^/]+\/providers\/[^/]+$/.test(provider) ||
      !account || !/^[\w.+-]+@[\w.-]+\.gserviceaccount\.com$/.test(account)) {
      graph.limitations.push(`${file}:${line}: GitHub auth inputs are dynamic, incomplete or unsupported; no identity connection was inferred.`);
      continue;
    }
    const entry = `entry:workflow:${file}:${line}`, target = identity(account);
    graph.nodes.push({ id: entry, kind: 'entry', label: `GitHub workflow using ${provider}`, location: { file, line } },
      { id: target, kind: 'identity', label: account });
    graph.edges.push({ id: `${entry}:identity`, from: entry, to: target, kind: 'declared-wif-authentication', findingIds: [],
      evidence: `The workflow requests ${account} through ${provider}; provider policy, IAM trust, triggers and id-token permissions are not proven.`, confidence: 'potential' });
  }
  if (/google-github-actions\/auth@/.test(source)) graph.limitations.push(`${file}: Workflow analysis reads literal auth-step inputs only; YAML aliases, expressions, triggers, repository restrictions and live IAM trust require review.`);
  return graph;
}
