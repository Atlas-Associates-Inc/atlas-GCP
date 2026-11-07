import { hash } from 'node:crypto';
import type { Finding, GraphNode, GraphResult, Severity } from '../types.ts';

export function emptyGraph(): GraphResult {
  return { nodes: [], edges: [], findings: [], paths: [], limitations: [] };
}

export function addFinding(graph: GraphResult, file: string, line: number, ruleId: string,
  severity: Severity, title: string, message: string, evidence: string): Finding {
  const id = hash('sha256', `${file}\0${line}\0${ruleId}\0${evidence}`, 'hex').slice(0, 20);
  const finding = { id, ruleId, severity, title, message, location: { file, line }, evidence };
  graph.findings.push(finding);
  return finding;
}

/** Preserve offsets while ignoring comments, including URLs inside quoted literals. */
export function stripComments(source: string, hashComments = false, allowSingleQuotes = true): string {
  return maskComments(source, hashComments, allowSingleQuotes).text;
}

export function stripHclCommentsAndHeredocs(source: string): { text: string; hasHeredoc: boolean } {
  return maskComments(source, true, false);
}

function maskComments(source: string, hashComments: boolean, allowSingleQuotes: boolean):
  { text: string; hasHeredoc: boolean } {
  // Without introducers there is nothing to mask; avoid rebuilding the source one character at a time.
  if (!source.includes('//') && !source.includes('/*') && (!hashComments || !source.includes('#')) &&
    (allowSingleQuotes || !source.includes('<<'))) return { text: source, hasHeredoc: false };
  let result = '', quote = '', escaped = false, hasHeredoc = false;
  const heredoc = /<<(-?)([A-Za-z_][A-Za-z0-9_]*)[ \t]*\r?\n/y;
  for (let i = 0; i < source.length; i++) {
    const c = source[i], next = source[i + 1];
    if (quote) {
      result += c;
      if (escaped) escaped = false;
      else if (c === '\\') escaped = true;
      else if (c === quote) quote = '';
    } else if (c === '"' || (allowSingleQuotes && c === "'")) { quote = c; result += c; }
    else if (!allowSingleQuotes && c === '<' && next === '<') {
      heredoc.lastIndex = i;
      const marker = heredoc.exec(source);
      if (!marker) { result += c; continue; }
      hasHeredoc = true;
      // Keep the introducer as an unsupported value so the next attribute cannot
      // be consumed as this attribute's value. Mask body and terminator together.
      result += marker[0];
      const start = heredoc.lastIndex;
      let end = start;
      while (end < source.length) {
        const newline = source.indexOf('\n', end);
        const lineEnd = newline < 0 ? source.length : newline;
        let left = end, right = lineEnd;
        if (source[right - 1] === '\r') right--;
        while (right > left && (source[right - 1] === ' ' || source[right - 1] === '\t')) right--;
        if (marker[1]) while (left < right && (source[left] === ' ' || source[left] === '\t')) left++;
        const terminator = source.slice(left, right);
        end = newline < 0 ? source.length : newline + 1;
        if (terminator === marker[2]) break;
      }
      result += source.slice(start, end).replace(/[^\r\n]/g, ' ');
      i = end - 1;
    }
    else if ((c === '/' && next === '/') || (hashComments && c === '#')) {
      while (i < source.length && source[i] !== '\n') { result += ' '; i++; }
      if (i < source.length) result += '\n';
    } else if (c === '/' && next === '*') {
      result += '  '; i += 2;
      while (i < source.length && !(source[i] === '*' && source[i + 1] === '/')) {
        result += source[i] === '\n' ? '\n' : ' '; i++;
      }
      if (i < source.length) { result += '  '; i++; }
    } else result += c;
  }
  return { text: result, hasHeredoc };
}

/** Build once per source; offsets refer to UTF-16 positions, like RegExp.index. */
export function createLineIndex(source: string): (offset: number) => number {
  const newlines: number[] = [];
  for (let i = 0; i < source.length; i++) if (source[i] === '\n') newlines.push(i);
  return (offset) => {
    let low = 0, high = newlines.length;
    while (low < high) {
      const middle = low + Math.floor((high - low) / 2);
      if (newlines[middle] < offset) low = middle + 1;
      else high = middle;
    }
    return low + 1;
  };
}

export function sourceLine(source: string, offset: number): number {
  return createLineIndex(source)(offset);
}

/** Comments must already be masked; quoted and escaped braces are not syntax. */
export function buildBraceMap(source: string, allowSingleQuotes = true): Map<number, number> {
  const pairs = new Map<number, number>(), stack: number[] = [];
  let quote = '', escaped = false;
  for (let i = 0; i < source.length; i++) {
    const c = source[i];
    if (quote) {
      if (escaped) escaped = false;
      else if (c === '\\') escaped = true;
      else if (c === quote) quote = '';
    } else if (c === '"' || (allowSingleQuotes && c === "'")) quote = c;
    else if (c === '{') stack.push(i);
    else if (c === '}') {
      const open = stack.pop();
      if (open !== undefined) pairs.set(open, i);
    }
  }
  return pairs;
}

export function closingBrace(source: string, open: number, allowSingleQuotes = true): number {
  let depth = 0, quote = '', escaped = false;
  for (let i = open; i < source.length; i++) {
    const c = source[i];
    if (quote) {
      if (escaped) escaped = false;
      else if (c === '\\') escaped = true;
      else if (c === quote) quote = '';
    } else if (c === '"' || (allowSingleQuotes && c === "'")) quote = c;
    else if (c === '{') depth++;
    else if (c === '}' && --depth === 0) return i;
  }
  return -1;
}

function parseAllowHeader(text: string, start: number, end: number):
  { operations: string[]; condition: string } | undefined {
  const operations: string[] = [];
  let cursor = start + 'allow'.length;
  for (;;) {
    while (cursor < end && /\s/.test(text[cursor])) cursor++;
    const operationStart = cursor;
    while (cursor < end && /[a-z]/.test(text[cursor])) cursor++;
    if (cursor === operationStart) return undefined;
    operations.push(text.slice(operationStart, cursor));
    while (cursor < end && /\s/.test(text[cursor])) cursor++;
    if (text[cursor] !== ',') break;
    cursor++;
  }
  if (cursor === end) return { operations, condition: 'true' };
  if (text[cursor++] !== ':') return undefined;
  while (cursor < end && /\s/.test(text[cursor])) cursor++;
  if (!text.startsWith('if', cursor) || /[A-Za-z0-9_]/.test(text[cursor + 2] ?? '')) return undefined;
  cursor += 2;
  while (cursor < end && /\s/.test(text[cursor])) cursor++;
  const condition = text.slice(cursor, end).trim();
  return condition ? { operations, condition } : undefined;
}

/** Consume each candidate once, including unterminated clauses and quoted semicolons. */
export function* scanAllowClauses(text: string): Generator<{
  offset: number; operations: string[]; condition: string; evidence: string;
}> {
  let start = -1, quote = '', escaped = false, parens = 0, boundary = true;
  let afterColon = false, braces = 0, colonOffset = 0;
  for (let cursor = 0; cursor < text.length; cursor++) {
    const character = text[cursor];
    if (quote) {
      if (escaped) escaped = false;
      else if (character === '\\') escaped = true;
      else if (character === quote) quote = '';
      continue;
    }
    if (character === '"' || character === "'") { quote = character; boundary = false; continue; }
    if (character === '(') parens++;
    else if (character === ')') parens = Math.max(0, parens - 1);
    if (start >= 0 && !afterColon && parens === 0 && character === ':') {
      afterColon = true;
      colonOffset = cursor + 1;
    }
    if (afterColon && parens === 0 && character === '{') {
      // A missing semicolon must not turn the next rules block into a CEL map.
      const header = braces === 0 && /\b(?:match|function|service)\b[^{;]*$/.test(
        text.slice(colonOffset, cursor).replace(/"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'/g, ' '));
      if (!header) { braces++; boundary = false; continue; }
    }
    if (afterColon && parens === 0 && character === '}' && braces > 0) {
      if (--braces === 0) colonOffset = cursor + 1;
      continue;
    }
    if (parens === 0 && (character === '{' || character === '}')) {
      start = -1;
      afterColon = false;
      braces = 0;
      boundary = true;
    } else if (parens === 0 && braces === 0 && character === ';') {
      const offset = start;
      start = -1;
      afterColon = false;
      braces = 0;
      boundary = true;
      const clause = offset >= 0 ? parseAllowHeader(text, offset, cursor) : undefined;
      if (clause) yield { offset, ...clause, evidence: text.slice(offset, cursor + 1).trim() };
    } else if (boundary && start < 0 && text.startsWith('allow', cursor) && !/[A-Za-z0-9_.]/.test(text[cursor - 1] ?? '') &&
      /\s/.test(text[cursor + 5] ?? '')) {
      start = cursor;
      boundary = false;
    } else {
      // Relational/logical operators delimit map operands; '/' and '-' can be match path syntax.
      if (afterColon && parens === 0 && braces === 0 && (/[=:?!&|<>+*%]/.test(character)
        || (text.startsWith('in', cursor) && !/[A-Za-z0-9_]/.test(text[cursor - 1] ?? '')
          && !/[A-Za-z0-9_]/.test(text[cursor + 2] ?? '')))) colonOffset = cursor + 1;
      if (!/\s/.test(character)) boundary = false;
    }
  }
}

export function parseFirebaseRules(source: string, file: string,
  kind: 'firestore' | 'storage' = file.includes('storage') ? 'storage' : 'firestore'): GraphResult {
  const graph = emptyGraph(), text = stripComments(source);
  const nodes = new Map<string, GraphNode>();
  const addNode = (id: string, kind: GraphNode['kind'], label: string, line?: number): void => {
    const previous = nodes.get(id);
    if (previous && previous.label === label) {
      // Matching parser nodes differ only in line; include the JSON closing brace
      // to preserve mergeGraphs' lexical tie-break (e.g. line 10 precedes line 2).
      if (line !== undefined && previous.location && `${line}}` < `${previous.location.line}}`) previous.location.line = line;
      return;
    }
    const node: GraphNode = { id, kind, label, ...(line === undefined ? {} : { location: { file, line } }) };
    if (!previous || JSON.stringify(node) < JSON.stringify(previous)) nodes.set(id, node);
  };
  const lineIndex = createLineIndex(text), bracePairs = buildBraceMap(text);
  const scopes: Array<{ path: string; start: number; end: number; recursive: boolean; limited: boolean;
    data: string; resource: string; resourceLabel: string; dataLabel: string }> = [];
  const active: typeof scopes = [];
  let traversalLimited = false;
  // Keep segments separate so a wildcard's opening brace cannot become the block brace.
  for (const match of text.matchAll(/\bmatch\s+((?:\/(?:[^/{}\s]|\{[^/{}\s]+\})+)+)\s*\{/g)) {
    const start = match.index! + match[0].length - 1;
    const end = bracePairs.get(start) ?? -1;
    if (end < 0) {
      addFinding(graph, file, lineIndex(start), 'scan/invalid-input', 'high',
        'Unbalanced Firebase rules', 'The rules could not be completely parsed.', 'Unclosed match block');
      continue;
    }
    while (active.length && active.at(-1)!.end <= start) active.pop();
    const parent = active.at(-1);
    if (parent?.limited) continue;
    const limited = active.length >= 64 || (parent?.path.length ?? 0) + match[1].length > 4096;
    if (limited && !traversalLimited) {
      addFinding(graph, file, lineIndex(start), 'scan/traversal-limit', 'high', 'Firebase scope expansion was bounded',
        'Match nesting exceeds 64 levels or the joined path exceeds 4096 characters; the scan is incomplete.',
        'Limits: 64 match levels, 4096 path characters');
      traversalLimited = true;
    }
    // A bounded sentinel also suppresses allow clauses inside the skipped subtree.
    const path = limited ? '' : (parent?.path ?? '') + match[1];
    const scope = { start, end, limited, path, data: `data:${kind}:${file}:${path}`, resource: `rules:${file}:${start}`,
      resourceLabel: `${kind} rules ${path}`, dataLabel: `${kind} data matching ${path}`,
      recursive: (parent?.recursive ?? false) || /\{[^}]+=\*\*\}/.test(match[1]) };
    active.push(scope);
    scopes.push(scope);
  }
  if (!/\bservice\s+(?:cloud\.firestore|firebase\.storage)\s*\{/.test(text) || scopes.length === 0) {
    addFinding(graph, file, 1, 'scan/invalid-input', 'high', 'Unsupported Firebase rules',
      'Expected a service and match blocks; this file was not treated as a clean ruleset.', 'Missing supported rules structure');
  }
  const entry = 'entry:firebase:public';
  // matchAll already emits scopes in source order.
  active.length = 0;
  let nextScope = 0;
  for (const allow of scanAllowClauses(text)) {
    const { offset, operations, condition, evidence } = allow;
    const line = lineIndex(offset);
    while (active.length && active.at(-1)!.end <= offset) active.pop();
    while (nextScope < scopes.length && scopes[nextScope].start < offset) {
      const scope = scopes[nextScope++];
      if (scope.end > offset) active.push(scope);
    }
    if (!active.length || active.at(-1)!.limited) continue;
    const scope = active.at(-1)!;
    const { path, data, resource, resourceLabel, dataLabel } = scope;
    let read = false, write = false, writeCreateUpdate = false;
    for (const op of operations) {
      if (op === 'read' || op === 'get' || op === 'list') read = true;
      if (op === 'write' || op === 'create' || op === 'update' || op === 'delete') write = true;
      if (op === 'write' || op === 'create' || op === 'update') writeCreateUpdate = true;
    }
    const publicAccess = condition === 'true' || /^\(*\s*true\s*\)*$/.test(condition);
    if (publicAccess && (read || write)) {
      const findings: Finding[] = [];
      for (const access of [read ? 'read' : '', write ? 'write' : ''].filter(Boolean)) {
        findings.push(addFinding(graph, file, line, `firebase/public-${access}`, 'high',
          `Public ${kind} ${access}`, `The unconditional grant permits unauthenticated ${access} at ${path}.`, evidence));
      }
      if (read && scope.recursive) findings.push(addFinding(graph, file, line,
        'firebase/recursive-wildcard', 'high', 'Recursive wildcard exposes descendants',
        `The public read grant covers the recursive match ${path}.`, evidence));
      addNode(entry, 'entry', 'Unauthenticated Firebase client');
      addNode(resource, 'resource', resourceLabel, line);
      addNode(data, 'data', dataLabel, line);
      const findingIds = findings.map(value => value.id);
      graph.edges.push({ id: `${findings[0].id}:entry`, from: entry, to: resource, kind: 'public-rule-grant',
        findingIds, evidence, confidence: 'confirmed' },
      { id: `${findings[0].id}:data`, from: resource, to: data, kind: read ? 'read-data' : 'write-data',
        findingIds, evidence, confidence: 'confirmed' });
    }
    if (kind === 'firestore' && writeCreateUpdate &&
      /request\.auth/.test(condition) && /\/(?:users|profiles|accounts|members)(?:\/|$)/i.test(path) &&
      !/\.hasOnly\s*\(/.test(condition)) {
      const finding = addFinding(graph, file, line, 'firebase/privilege-fields', 'medium',
        'User document writes lack an explicit field allowlist',
        'If this document stores trusted role or privilege fields, authenticated writers may be able to modify them. Function-based validation and application trust require review.', evidence);
      const authenticated = 'entry:firebase:authenticated';
      addNode(authenticated, 'entry', 'Authenticated Firebase client');
      addNode(data, 'data', `Potential privilege fields at ${path}`, line);
      graph.edges.push({ id: finding.id, from: authenticated, to: data, kind: 'potential-privilege-field-write',
        findingIds: [finding.id], evidence, confidence: 'potential' });
    }
  }
  graph.nodes = [...nodes.values()];
  graph.limitations.push(`${file}: Static rules analysis recognizes literal public grants and potential field-allowlist omissions; it does not evaluate functions, compound expressions, rule validity, or deployed configuration.`);
  return graph;
}

export interface FirebaseConfigResult { graph: GraphResult; rulesFiles: string[] }

export function parseFirebaseConfig(source: string, file: string): FirebaseConfigResult {
  const graph = emptyGraph(), rulesFiles: string[] = [];
  try {
    const config: unknown = JSON.parse(source);
    if (!config || typeof config !== 'object' || Array.isArray(config)) throw new Error('Expected an object');
    for (const service of ['firestore', 'storage']) {
      const value = (config as Record<string, unknown>)[service];
      for (const entry of Array.isArray(value) ? value : value === undefined ? [] : [value]) {
        if (!entry || typeof entry !== 'object' || Array.isArray(entry)) throw new Error(`Invalid ${service} configuration`);
        const rules = (entry as Record<string, unknown>).rules;
        if (rules !== undefined && (typeof rules !== 'string' || !rules.trim())) throw new Error(`Invalid ${service} rules path`);
        if (typeof rules === 'string') rulesFiles.push(rules);
      }
    }
  } catch {
    addFinding(graph, file, 1, 'scan/invalid-input', 'high', 'Invalid Firebase configuration',
      'firebase.json must be valid JSON with string rules paths in supported service configurations.', 'Invalid configuration shape or JSON');
  }
  return { graph, rulesFiles };
}
