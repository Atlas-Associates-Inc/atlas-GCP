import type { SanitizedTelemetry } from '../types.ts';
import { createLineIndex } from '../graph/firebase-rules-parser.ts';

const REDACTED = '[REDACTED]';
const invisible = /[\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]/gu;
const secretField = /^(?:privatekey|clientsecret|accesstoken|refreshtoken|idtoken|token|password|passwd|apikey|authorization|credential|credentials|secret)$/i;
const privateKeyPattern = new RegExp(
  ['-----BEGIN', '(?:[A-Z0-9]+ )*PRIVATE KEY-----'].join(' ') +
  '[\\s\\S]*?(?:' + ['-----END', '(?:[A-Z0-9]+ )*PRIVATE KEY-----'].join(' ') + '|$)',
  'g',
);
const instructionPattern = /(?:<\/?(?:system|developer|assistant|user|untrusted_telemetry)\b|<\|[^<>|\r\n]{1,128}\|>|\[\/?(?:INST|SYSTEM|DEVELOPER|ASSISTANT)\]|(?:^|[\s"{,])(?:system|developer|assistant)\s*:\s+|\b(?:ignore|disregard|override|forget)\b[\s\S]{0,100}\b(?:instructions?|prompts?|rules?|previous|above)\b|\byou are now\b|\b(?:reveal|print|exfiltrate)\b[\s\S]{0,100}\b(?:secrets?|credentials?|tokens?|system\s+prompts?)\b)/i;
const QUARANTINED = '[QUARANTINED: instruction-like telemetry]';

function* quotedInstructions(value: string): Generator<RegExpMatchArray> {
  // JSON.stringify re-escapes tabs/newlines; inspect decoded contents in plain and nested logs.
  for (const match of value.matchAll(/"(?:\\.|[^"\\])*"/g)) {
    try {
      if (instructionPattern.test(JSON.parse(match[0]))) yield match;
    } catch { /* Malformed literals are inspected as plain text by the caller. */ }
  }
}

function isSecretField(key: string): boolean {
  return secretField.test(key.replace(/[^a-z0-9]/gi, ''));
}

export function mapObject(value: object, transform: (key: string, entry: unknown) => [string, unknown]): object {
  const entries = Object.entries(value), reserved = new Set(entries.map(([key]) => key));
  let suffix = 0;
  return Object.fromEntries(entries.map(([key, entry]) => {
    const [candidate, result] = transform(key, entry);
    let safeKey = candidate;
    if (candidate !== key) {
      while (reserved.has(safeKey)) safeKey = `${candidate} #${++suffix}`;
      reserved.add(safeKey);
    }
    return [safeKey, result];
  }));
}

function redact(input: string): { text: string; count: number } {
  let count = 0;
  const replace = (value: string): string => {
    if (value !== REDACTED) count += 1;
    return REDACTED;
  };
  const tokens = (value: string): string => value
    .replace(privateKeyPattern, replace)
    .replace(/\bya29\.[A-Za-z0-9._~-]+/g, replace)
    .replace(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+(?![A-Za-z0-9_-])/g, replace)
    .replace(/\bAIza[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])/g, replace)
    .replace(/\b(?:gh[pousr]_[A-Za-z0-9_]+|github_pat_[A-Za-z0-9_]+)\b/g, replace)
    .replace(/\bBearer[ \t]+[A-Za-z0-9._~+\/-]+=*/gi, replace);
  const keyValuePattern = /\b(authorization\s*[=:]\s*(?:[a-z][a-z0-9_-]*[ \t]+)?|(?:private[_-]?key|client[_-]?secret|access[_-]?token|refresh[_-]?token|id[_-]?token|api[_-]?key|password|passwd|token|credentials?|secret)\s*[=:]\s*)('[^']*'|"(?:\\.|[^"\\])*"|[^\s,;}"']+)/gi;
  const keyValue = (value: string): string => value.replace(keyValuePattern,
    (_match, prefix: string, secret: string) => prefix.split(/[=:]/, 1)[0].trim() + '=' + replace(secret));
  const plain = (value: string): string => tokens(value)
    .replace(/("(?:\\.|[^"\\])*"\s*:\s*)("(?:\\.|[^"\\])*")/g, (match, prefix: string, quoted: string) => {
      try {
        const colon = prefix.lastIndexOf(':');
        const rawKey: string = JSON.parse(prefix.slice(0, colon).trim());
        const rawValue: string = JSON.parse(quoted);
        const key = rawKey.replace(invisible, ''), cleanValue = rawValue.replace(invisible, '');
        const safeKey = keyValue(tokens(key));
        const safeValue = keyValue(tokens(isSecretField(key) ? replace(cleanValue) : cleanValue));
        return /\\u/.test(match) || safeKey !== rawKey || safeValue !== rawValue
          ? JSON.stringify(safeKey) + prefix.slice(colon) + JSON.stringify(safeValue) : match;
      } catch {
        return match;
      }
    })
    .replace(/"(?:\\.|[^"\\])*"/g, (quoted: string) => {
      try {
        // Logs can contain JSON keys with non-string values, arrays or standalone literals.
        const raw: string = JSON.parse(quoted);
        const safe = keyValue(tokens(raw.replace(invisible, '')));
        return /\\u/.test(quoted) || safe !== raw ? JSON.stringify(safe) : quoted;
      } catch {
        return quoted;
      }
    })
    // Decoded literals were handled above; only raw log assignments remain.
    .replace(new RegExp('"(?:\\\\.|[^"\\\\])*"|(' + keyValuePattern.source + ')', 'gi'),
      (match, assignment: string | undefined) => assignment ? keyValue(assignment) : match);

  const visit = (value: unknown, depth: number): unknown => {
    if (depth > 32) return replace('[nested telemetry exceeds safety limit]');
    if (typeof value === 'string') return processString(value, depth + 1);
    if (Array.isArray(value)) return value.map((entry) => visit(entry, depth + 1));
    if (value !== null && typeof value === 'object') {
      return mapObject(value, (key, entry) => {
        const cleanKey = key.replace(invisible, '');
        return [plain(cleanKey), isSecretField(cleanKey) ? replace(typeof entry === 'string' ? entry : '') : visit(entry, depth + 1)];
      });
    }
    return value;
  };
  const processString = (value: string, depth: number): string => {
    if (depth > 32) return replace('[nested telemetry exceeds safety limit]');
    if (/^[\s]*[\[{]/.test(value)) {
      try {
        // Normalize parsed keys individually so distinct source keys cannot collapse in JSON.parse.
        return JSON.stringify(visit(JSON.parse(value), depth + 1));
      } catch {
        // Non-JSON logs still receive the same token and field redaction.
      }
    }
    return plain(value.replace(invisible, ''));
  };
  return { text: processString(input, 0), count };
}

export function redactSecrets(text: string): string {
  return redact(text).text;
}

export function sanitizeTelemetry(input: string): SanitizedTelemetry {
  const result = redact(input);
  let quarantined = false;
  const visit = (value: unknown, depth = 0): unknown => {
    if (depth > 32) {
      result.count += 1;
      return REDACTED;
    }
    if (typeof value === 'string') {
      if (/^\s*[\[{]/.test(value)) {
        let nested: unknown;
        try { nested = JSON.parse(value); } catch { /* Non-JSON leaves are checked as text below. */ }
        if (nested !== null && typeof nested === 'object') {
          return JSON.stringify(visit(nested, depth + 1));
        }
      }
      if (instructionPattern.test(value) || !quotedInstructions(value).next().done) {
        quarantined = true;
        return QUARANTINED;
      }
      return value;
    }
    if (Array.isArray(value)) return value.map(entry => visit(entry, depth + 1));
    if (value !== null && typeof value === 'object') {
      return mapObject(value, (key, entry) => {
        let safeKey = key.replace(invisible, '');
        if (instructionPattern.test(safeKey)) {
          quarantined = true;
          safeKey = QUARANTINED;
        }
        return [safeKey, visit(entry, depth + 1)];
      });
    }
    return value;
  };
  let structured: unknown;
  try { structured = JSON.parse(result.text); } catch { /* Plain telemetry is handled below. */ }
  let text: string;
  if (structured !== null && typeof structured === 'object') {
    // Quarantine only the offending leaf; graph topology and sibling evidence survive.
    text = JSON.stringify(visit(structured));
  } else {
    const lines = result.text.split(/\r?\n/);
    const lineIndex = createLineIndex(result.text);
    const blocked = new Set<number>();
    const block = (offset: number, length: number): void => {
      const start = lineIndex(offset) - 1;
      const end = lineIndex(offset + length) - 1;
      for (let line = start; line <= end; line++) blocked.add(line);
    };
    for (const match of result.text.matchAll(new RegExp(instructionPattern.source, 'gi'))) {
      block(match.index!, match[0].length);
    }
    for (const match of quotedInstructions(result.text)) {
      block(match.index!, match[0].length);
    }
    quarantined = blocked.size > 0;
    text = lines.map((line, index) => blocked.has(index) ? QUARANTINED : line).join('\n');
  }
  text = text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  return {
    text: '<untrusted_telemetry>\n' + text + '\n</untrusted_telemetry>',
    redactions: result.count,
    quarantined,
  };
}
