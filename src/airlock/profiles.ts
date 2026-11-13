import type { AirlockProfile, AirlockProfileId, McpConfigClient } from '../types.ts';

const profiles: Record<AirlockProfileId, AirlockProfile> = {
  scc: {
    id: 'scc', description: 'Security Command Center findings and posture reads.',
    upstreamCommand: 'uvx', upstreamArgs: ['mcp-security-scc'],
    allowedTokens: ['scc', 'securitycenter', 'finding', 'findings', 'asset', 'assets', 'posture', 'mute',
      'source', 'sources', 'resource', 'resources'],
  },
  secops: {
    id: 'secops', description: 'Security Operations telemetry and detection reads.',
    upstreamCommand: 'uvx', upstreamArgs: ['google-secops-mcp'],
    allowedTokens: ['secops', 'chronicle', 'udm', 'ioc', 'iocs', 'alert', 'alerts', 'case', 'cases', 'event',
      'events', 'rule', 'rules', 'detection', 'detections', 'entity', 'entities', 'threat'],
  },
  firebase: {
    id: 'firebase', description: 'Firebase project, application and data reads.',
    upstreamCommand: 'npx', upstreamArgs: ['--no-install', 'firebase-tools', 'experimental:mcp'],
    allowedTokens: ['firebase', 'firestore', 'storage', 'auth', 'crashlytics', 'remoteconfig', 'dataconnect',
      'apphosting', 'hosting', 'rules', 'project', 'projects', 'app', 'apps', 'collection', 'collections',
      'document', 'documents'],
  },
  cloudrun: {
    id: 'cloudrun', description: 'Cloud Run services, revisions, jobs and log reads.',
    upstreamCommand: 'npx', upstreamArgs: ['--no-install', '@google-cloud/cloud-run-mcp'],
    allowedTokens: ['cloudrun', 'service', 'services', 'revision', 'revisions', 'job', 'jobs', 'execution',
      'executions', 'log', 'logs'],
  },
  'developer-knowledge': {
    id: 'developer-knowledge', description: 'Developer documentation and reference reads.',
    upstreamCommand: 'uvx', upstreamArgs: ['google-developer-knowledge-mcp'],
    allowedTokens: ['developerknowledge', 'gemini', 'doc', 'docs', 'document', 'documents', 'chunk', 'chunks',
      'guide', 'guides', 'reference'],
  },
  prowler: {
    id: 'prowler', description: 'Prowler findings, checks and compliance reads.',
    upstreamCommand: 'uvx', upstreamArgs: ['prowler-mcp'],
    allowedTokens: ['prowler', 'check', 'checks', 'compliance', 'provider', 'providers', 'finding', 'findings',
      'overview', 'attack', 'cis'],
  },
  semgrep: {
    id: 'semgrep', description: 'Semgrep rule, finding and configuration reads.',
    upstreamCommand: 'uvx', upstreamArgs: ['semgrep-mcp'],
    allowedTokens: ['semgrep', 'rule', 'rules', 'finding', 'findings', 'ast', 'language', 'languages', 'version', 'config'],
  },
};

// Exported policy data cannot be changed by another importer at runtime.
for (const profile of Object.values(profiles)) {
  Object.freeze(profile.upstreamArgs);
  Object.freeze(profile.allowedTokens);
  Object.freeze(profile);
}
export const AIRLOCK_PROFILES: readonly AirlockProfile[] = Object.freeze(Object.values(profiles));

export function getAirlockProfile(id: unknown): AirlockProfile | undefined {
  return typeof id === 'string' && Object.hasOwn(profiles, id)
    ? profiles[id as AirlockProfileId] : undefined;
}

/** Templates for caller-installed upstream programs; no installation checks or execution. */
export function buildMcpConfig(options: { profiles?: readonly AirlockProfileId[]; client?: McpConfigClient } = {}) {
  const client = options.client === undefined ? 'gemini' : options.client;
  if (client !== 'agy' && client !== 'gemini') throw new Error('Unknown MCP config client.');
  if (options.profiles !== undefined && !Array.isArray(options.profiles)) throw new Error('Invalid airlock profiles.');
  const selected = options.profiles?.length ? options.profiles : AIRLOCK_PROFILES.map(profile => profile.id);
  const mcpServers: Record<string, { command: string; args: string[] }> = {};
  for (const id of selected) {
    const profile = getAirlockProfile(id);
    if (!profile) throw new Error('Unknown airlock profile.');
    const key = `atlas-gcp-${profile.id}`;
    if (Object.hasOwn(mcpServers, key)) continue;
    mcpServers[key] = {
      command: 'atlas-gcp',
      args: ['airlock', '--profile', profile.id, '--upstream-cmd', profile.upstreamCommand,
        ...profile.upstreamArgs.map(arg => `--upstream-arg=${arg}`)],
    };
  }
  return { mcpServers };
}
