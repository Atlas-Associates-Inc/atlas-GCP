import { spawn } from 'node:child_process';
import { evaluateTool, isReadOnlyTool } from './mcp-guard.ts';
import { getAirlockProfile } from './profiles.ts';
import { mapObject, redactSecrets, sanitizeTelemetry } from './sanitizer.ts';

export interface StdioProxyOptions {
  command: string;
  args: string[];
  profile?: string;
  input?: NodeJS.ReadableStream;
  output?: NodeJS.WritableStream;
  env?: NodeJS.ProcessEnv;
}

type RpcId = string | number;
type ObjectValue = Record<string, unknown>;
interface Pending { id: RpcId; method: string; timer: ReturnType<typeof setTimeout>; progress?: RpcId }

const MAX_FRAME = 1024 * 1024;
const MAX_PENDING = 128;
const IO_TIMEOUT = 5_000;
const REQUEST_TIMEOUT = 30_000;
const requests = new Set(['initialize', 'ping', 'tools/list', 'tools/call', 'resources/list',
  'resources/templates/list', 'resources/read', 'prompts/list', 'prompts/get']);
const notifications = new Set(['notifications/message', 'notifications/progress',
  'notifications/tools/list_changed', 'notifications/resources/list_changed',
  'notifications/resources/updated', 'notifications/prompts/list_changed']);
const mutation = /\b(?:insert|update|delete|drop|alter|truncate|create|replace|merge|grant|revoke|execute|exec|call|export|load|copy|attach|detach|vacuum|pragma|into|outfile|dumpfile)\b/i;
const dangerousKey = /^(?:command|cmd|shell|script|code|executable|exec|evaluate|mutation|mutations|write|writes|update|updates|delete|deletes|deploy|create|insert|remove|destroy|apply|patch|set|grant|revoke|upload|publish|setiampolicy|updatemask|requestbody)$/;

function object(value: unknown): value is ObjectValue {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function rpcId(value: unknown): value is RpcId {
  return typeof value === 'number' && Number.isSafeInteger(value)
    || typeof value === 'string' && value.length > 0 && value.length <= 256;
}

function bounded(value: unknown): boolean {
  const stack = [{ value, depth: 0 }];
  let nodes = 0;
  while (stack.length) {
    const item = stack.pop()!;
    if (++nodes > 16_384 || item.depth > 32) return false;
    if (item.value && typeof item.value === 'object') {
      const entries = Object.values(item.value);
      if (entries.length + stack.length > 16_384) return false;
      for (const entry of entries) stack.push({ value: entry, depth: item.depth + 1 });
    }
  }
  return true;
}

/** Lexical defense in depth, not proof of a server's implementation or SQL semantics. */
function safeArguments(value: unknown, sql = false): boolean {
  if (typeof value === 'string') {
    return !(sql && (mutation.test(value) || /;|\/\*|\*\/|--|\b(?:remote|external_query|load_file|dblink)\b/i.test(value)))
      && !/[\u0000\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]/u.test(value);
  }
  if (Array.isArray(value)) return value.every(entry => safeArguments(entry, sql));
  if (!object(value)) return true;
  for (const [key, entry] of Object.entries(value)) {
    if (/[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]/u.test(key)) return false;
    const normalized = key.toLowerCase().replace(/[^a-z0-9]/g, '');
    if (dangerousKey.test(normalized) || ['__proto__', 'prototype', 'constructor'].includes(key)) return false;
    if (['readonly', 'dryrun'].includes(normalized) && entry !== true) return false;
    if (['action', 'operation', 'method', 'httpmethod', 'mode'].includes(normalized)
      && (typeof entry !== 'string' || !/^(?:get|head|options|list|query|read|describe|search|validate|status|inspect|select|readonly)$/i.test(entry))) return false;
    if (!safeArguments(entry, sql || ['sql', 'statement', 'dml', 'ddl', 'cypher', 'command', 'cmd'].includes(normalized))) return false;
  }
  return true;
}

function childEnvironment(source: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const result: NodeJS.ProcessEnv = {};
  // No credential, proxy, package-manager or interpreter/loader variables are inherited.
  for (const name of ['PATH', 'SYSTEMROOT', 'WINDIR', 'TMPDIR', 'TMP', 'TEMP', 'LANG', 'LC_ALL', 'LC_CTYPE', 'TZ']) {
    const value = source[name];
    if (typeof value === 'string' && value.length <= 16_384 && !value.includes('\0')) result[name] = value;
  }
  return result;
}

function cleanPayload(value: unknown): unknown {
  const visit = (entry: unknown, key = ''): unknown => {
    if (typeof entry === 'string') {
      const safe = sanitizeTelemetry(entry);
      return safe.quarantined || ['text', 'description', 'message', 'instructions'].includes(key)
        ? safe.text : redactSecrets(entry);
    }
    if (Array.isArray(entry)) return entry.map(item => visit(item));
    if (!object(entry)) return entry;
    return mapObject(entry, (name, item) => {
      const safe = sanitizeTelemetry(name);
      return [safe.quarantined ? '[QUARANTINED]' : redactSecrets(name), visit(item, name)];
    });
  };
  if (value === null || typeof value !== 'object') return visit(value);
  // Whole-object redaction catches secret-bearing field names as well as token syntax.
  const redacted: unknown = JSON.parse(redactSecrets(JSON.stringify(value)));
  return visit(redacted);
}

/** A transport policy for a caller-selected, trusted executable; this is not an OS sandbox. */
export async function runStdioProxy(options: StdioProxyOptions): Promise<number> {
  const input = options.input ?? process.stdin;
  const output = options.output ?? process.stdout;
  return new Promise<number>((resolve) => {
    const pending = new Map<number, Pending>();
    const cleanup: Array<() => void> = [];
    const readers: Array<() => void> = [];
    const writes = new Set<() => void>();
    let sequence = 0, stopping = false, settled = false, closed = false, stdoutEnded = false;
    let exitCode: number | null = null;
    let failureOutputDone = false;
    let eofTimer: ReturnType<typeof setTimeout> | undefined;
    let killTimer: ReturnType<typeof setTimeout> | undefined;
    let child: ReturnType<typeof spawn>;

    const write = (stream: NodeJS.WritableStream, message: unknown): Promise<void> => new Promise((done, reject) => {
      const data = JSON.stringify(message) + '\n';
      if (Buffer.byteLength(data) > 4 * MAX_FRAME) { reject(new Error('Output limit exceeded.')); return; }
      let complete = false;
      const finish = (error?: Error | null) => {
        if (complete) return;
        complete = true;
        clearTimeout(timer);
        writes.delete(cancel);
        if (error) reject(error); else done();
      };
      const cancel = () => finish(new Error('Transport closed.'));
      const timer = setTimeout(() => finish(new Error('Transport write timed out.')), IO_TIMEOUT);
      writes.add(cancel);
      try { stream.write(data, (error?: Error | null) => finish(error)); } catch { cancel(); }
    });
    const errorMessage = (id: RpcId | null, code: number, message: string) => ({ jsonrpc: '2.0', id, error: { code, message } });
    const kill = () => {
      if (!child || closed) return;
      try {
        if (process.platform !== 'win32' && child.pid) process.kill(-child.pid, 'SIGKILL');
        else child.kill('SIGKILL');
      } catch { child.kill('SIGKILL'); }
    };
    const finish = (code: number) => {
      if (settled) return;
      settled = true;
      if (eofTimer) clearTimeout(eofTimer);
      if (killTimer) clearTimeout(killTimer);
      for (const item of pending.values()) clearTimeout(item.timer);
      pending.clear();
      for (const dispose of cleanup) dispose();
      for (const cancel of [...writes]) cancel();
      kill();
      child?.stdin?.destroy();
      child?.stdout?.destroy();
      child?.stderr?.destroy();
      child?.unref();
      resolve(code);
    };
    const fail = (reason: string) => {
      if (stopping || settled) return;
      stopping = true;
      for (const dispose of readers) dispose();
      kill();
      const errors = [...pending.values()].map(item => errorMessage(item.id, -32000, reason));
      if (!errors.length) errors.push(errorMessage(null, -32000, reason));
      // A broken downstream cannot hold a killed child or this promise open indefinitely.
      killTimer = setTimeout(() => finish(2), IO_TIMEOUT);
      void (async () => {
        for (const error of errors) await write(output, error);
      })().then(() => {
        failureOutputDone = true;
        if (!child || closed) finish(2);
      }, () => {
        failureOutputDone = true;
        if (!child || closed) finish(2);
      });
    };
    const onInputError = () => fail('Client input failed.');
    const onOutputError = () => fail('Client output failed.');
    input.on('error', onInputError);
    output.on('error', onOutputError);
    cleanup.push(() => input.removeListener('error', onInputError), () => output.removeListener('error', onOutputError));

    if (options.profile !== undefined && !getAirlockProfile(options.profile)) {
      fail('Unknown airlock profile.');
      return;
    }
    if (typeof options.command !== 'string' || !options.command || options.command.includes('\0')
      || !Array.isArray(options.args) || !options.args.every(arg => typeof arg === 'string' && !arg.includes('\0'))) {
      fail('Invalid upstream command configuration.');
      return;
    }
    try {
      child = spawn(options.command, options.args, {
        shell: false, env: childEnvironment(options.env ?? process.env),
        stdio: ['pipe', 'pipe', 'pipe'], detached: process.platform !== 'win32',
      });
    } catch {
      fail('Upstream process could not start.');
      return;
    }

    const readLines = (stream: NodeJS.ReadableStream, handle: (line: string) => Promise<void>, end: () => void) => {
      let buffer = Buffer.alloc(0), busy = false, ended = false, disposed = false;
      const consume = async () => {
        if (busy || disposed) return;
        busy = true;
        stream.pause();
        try {
          while (!disposed && !stopping) {
            const newline = buffer.indexOf(10);
            if (newline < 0 && !ended) break;
            if (newline < 0 && !buffer.length) break;
            const length = newline < 0 ? buffer.length : newline;
            if (length > MAX_FRAME) throw new Error('Frame limit exceeded.');
            const line = buffer.subarray(0, length).toString('utf8');
            buffer = buffer.subarray(newline < 0 ? length : length + 1);
            if (line.trim()) await handle(line);
          }
          if (buffer.length > MAX_FRAME) throw new Error('Frame limit exceeded.');
          if (!disposed && !stopping) {
            if (ended) { dispose(); end(); }
            else stream.resume();
          }
        } catch { fail('Invalid or failed JSON-RPC transport.'); }
        finally { busy = false; }
      };
      const onData = (chunk: Buffer | string) => {
        const bytes = typeof chunk === 'string' ? Buffer.from(chunk) : chunk;
        if (!Buffer.isBuffer(bytes) || buffer.length + bytes.length > 2 * MAX_FRAME) {
          fail('JSON-RPC frame buffer limit exceeded.'); return;
        }
        buffer = Buffer.concat([buffer, bytes]);
        void consume();
      };
      const onEnd = () => { ended = true; void consume(); };
      const dispose = () => {
        disposed = true;
        buffer = Buffer.alloc(0);
        stream.pause();
        stream.removeListener('data', onData);
        stream.removeListener('end', onEnd);
      };
      cleanup.push(dispose);
      readers.push(dispose);
      stream.on('data', onData);
      stream.on('end', onEnd);
      if ((stream as NodeJS.ReadableStream & { readableEnded?: boolean }).readableEnded) onEnd();
    };

    const parse = (line: string): ObjectValue => {
      const value: unknown = JSON.parse(line);
      if (!object(value) || value.jsonrpc !== '2.0' || !bounded(value)) throw new Error('Invalid JSON-RPC envelope.');
      return value;
    };
    const clientLine = async (line: string) => {
      let message: ObjectValue;
      try { message = parse(line); }
      catch {
        await write(output, errorMessage(null, -32700, 'Invalid JSON-RPC input.'));
        fail('Client protocol validation failed.'); return;
      }
      const hasId = Object.hasOwn(message, 'id');
      const id = rpcId(message.id) ? message.id : null;
      const deny = () => write(output, errorMessage(id, -32600, 'Request denied by the read-only airlock policy.'));
      if (typeof message.method !== 'string' || hasId && id === null
        || Object.hasOwn(message, 'result') || Object.hasOwn(message, 'error')
        || message.params !== undefined && !object(message.params)) { await deny(); return; }
      const params = (message.params ?? {}) as ObjectValue;
      if (!hasId) {
        if (message.method === 'notifications/initialized') {
          await write(child.stdin!, { jsonrpc: '2.0', method: message.method });
        } else if (message.method === 'notifications/cancelled' && rpcId(params.requestId)) {
          const entry = [...pending.entries()].find(([, item]) => item.id === params.requestId);
          if (entry) await write(child.stdin!, { jsonrpc: '2.0', method: message.method, params: { requestId: entry[0] } });
        } else await deny();
        return;
      }
      if (!requests.has(message.method) || pending.size >= MAX_PENDING
        || [...pending.values()].some(item => item.id === id)) { await deny(); return; }
      if (message.method === 'tools/call' && (!evaluateTool(params.name, options.profile).allowed
        || Object.keys(params).some(key => !['name', 'arguments', '_meta'].includes(key))
        || params.arguments !== undefined && (!object(params.arguments) || !safeArguments(params.arguments)))) {
        await deny(); return;
      }
      if (message.method !== 'tools/call' && message.method !== 'initialize' && !safeArguments(params)) { await deny(); return; }
      const wireId = ++sequence;
      const forwarded = { ...params };
      // Never advertise executable client-side capabilities to an untrusted server.
      if (message.method === 'initialize') forwarded.capabilities = {};
      let progress: RpcId | undefined;
      if (object(forwarded._meta) && Object.hasOwn(forwarded._meta, 'progressToken')) {
        if (!rpcId(forwarded._meta.progressToken)) { await deny(); return; }
        progress = forwarded._meta.progressToken;
        forwarded._meta = { ...forwarded._meta, progressToken: wireId };
      }
      pending.set(wireId, { id: id!, method: message.method, progress,
        timer: setTimeout(() => fail('Upstream request timed out.'), REQUEST_TIMEOUT) });
      await write(child.stdin!, { jsonrpc: '2.0', id: wireId, method: message.method, params: forwarded });
    };

    const upstreamLine = async (line: string) => {
      const message = parse(line);
      if (Object.hasOwn(message, 'method')) {
        if (Object.hasOwn(message, 'id')) {
          // sampling, elicitation, roots and all other upstream requests are never relayed.
          if (!rpcId(message.id)) throw new Error('Invalid upstream request ID.');
          await write(child.stdin!, errorMessage(message.id, -32600, 'Server-initiated requests are prohibited.'));
          return;
        }
        if (typeof message.method !== 'string' || !notifications.has(message.method)
          || Object.hasOwn(message, 'result') || Object.hasOwn(message, 'error')
          || message.params !== undefined && !object(message.params)) throw new Error('Unverified upstream notification.');
        const params = cleanPayload(message.params ?? {}) as ObjectValue;
        if (message.method === 'notifications/progress') {
          const token = (message.params as ObjectValue | undefined)?.progressToken;
          const item = typeof token === 'number' ? pending.get(token) : undefined;
          if (!item || item.progress === undefined) return;
          params.progressToken = item.progress;
        }
        await write(output, { jsonrpc: '2.0', method: message.method, params });
        return;
      }
      const item = typeof message.id === 'number' ? pending.get(message.id) : undefined;
      if (!item || Object.hasOwn(message, 'result') === Object.hasOwn(message, 'error')) throw new Error('Unmatched upstream response.');
      let payload = message.result;
      if (Object.hasOwn(message, 'error')) {
        if (!object(message.error) || !Number.isInteger(message.error.code) || typeof message.error.message !== 'string') {
          throw new Error('Invalid upstream error.');
        }
        payload = message.error;
      } else if (item.method === 'tools/list') {
        if (!object(payload) || !Array.isArray(payload.tools)) throw new Error('Invalid tools list.');
        payload = { ...payload, tools: payload.tools.filter(tool => object(tool) && isReadOnlyTool(tool.name, options.profile)
          && redactSecrets(tool.name) === tool.name && !sanitizeTelemetry(tool.name).quarantined) };
      }
      const safe = cleanPayload(payload);
      await write(output, { jsonrpc: '2.0', id: item.id, [Object.hasOwn(message, 'error') ? 'error' : 'result']: safe });
      clearTimeout(item.timer);
      pending.delete(message.id as number);
    };

    const complete = () => {
      if (!closed || !stdoutEnded || stopping || settled) return;
      if (pending.size || exitCode !== 0) fail('Upstream process ended before a successful completion.');
      else finish(0);
    };
    const onChildError = () => fail('Upstream process could not start.');
    const onPipeError = () => fail('Upstream transport failed.');
    const onClose = (code: number | null) => {
      closed = true;
      exitCode = code;
      if (stopping && failureOutputDone) finish(2); else complete();
    };
    let stderrBytes = 0;
    const onStderr = (chunk: Buffer) => {
      // Drain diagnostics without exposing credentials or instruction-like content.
      stderrBytes += chunk.length;
      if (stderrBytes > MAX_FRAME) fail('Upstream diagnostic limit exceeded.');
    };
    child.on('error', onChildError);
    child.on('close', onClose);
    child.stdin!.on('error', onPipeError);
    child.stdout!.on('error', onPipeError);
    child.stderr!.on('error', onPipeError);
    child.stderr!.on('data', onStderr);
    cleanup.push(() => {
      child.removeListener('error', onChildError);
      child.removeListener('close', onClose);
      child.stdin!.removeListener('error', onPipeError);
      child.stdout!.removeListener('error', onPipeError);
      child.stderr!.removeListener('error', onPipeError);
      child.stderr!.removeListener('data', onStderr);
    });
    readLines(child.stdout!, upstreamLine, () => { stdoutEnded = true; complete(); });
    readLines(input, clientLine, () => {
      child.stdin!.end();
      eofTimer = setTimeout(() => fail('Upstream did not shut down after client EOF.'), IO_TIMEOUT);
    });
  });
}
