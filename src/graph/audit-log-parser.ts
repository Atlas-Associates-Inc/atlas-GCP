import type { GraphNode, GraphResult, Severity } from '../types.ts';
import { addFinding, createLineIndex, emptyGraph } from './firebase-rules-parser.ts';
import { dataRoles, escalationRoles, powerfulRoles } from './gcp-iam-parser.ts';
import { cleanTelemetryString, telemetryRecordOffsets } from './scc-findings-parser.ts';

type RecordValue = Record<string, unknown>;
interface Grant { role: string; member: string }
interface AuditEvent {
  line: number;
  method: string;
  service: string;
  resource: string;
  requestName: string;
  email: string;
  subject: string;
  callerIp: string;
  delegators: string[];
  delegation: boolean;
  denied: boolean;
  disabledSink: boolean;
  removedAuditConfig: boolean;
  condition: string;
  issuer: string;
  grants: Grant[];
}

const MAX_RECORDS = 10_000;
const federated = /^principal(?:Set)?:\/\//;
const defaultAccount = /^(?:[^@]+-compute@developer\.gserviceaccount\.com|[^@]+@appspot\.gserviceaccount\.com)$/;
const credentialMethod = /(?:^|\.)(?:GenerateAccessToken|GenerateIdToken|SignBlob|SignJwt)$/;
const sensitiveMethod = /(?:^|\.)(?:AccessSecretVersion|ExportDocuments|GetDocument|RunQuery|BatchGetDocuments|ReadRows)$|(?:^|\.)storage\.objects\.(?:get|list)$|(?:^|\.)(?:JobService\.InsertJob|TableDataService\.List)$/;

function object(value: unknown): value is RecordValue {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function record(value: unknown): RecordValue {
  if (value === undefined) return {};
  if (!object(value)) throw new Error('Invalid audit object');
  return value;
}

function clean(value: string): string {
  return cleanTelemetryString(value).slice(0, 512);
}

function stringField(value: unknown): string {
  if (value === undefined) return '';
  if (typeof value !== 'string' || value.length > 2048) throw new Error('Invalid audit string');
  return cleanTelemetryString(value);
}

function publicCaller(value: string): boolean {
  return value === 'allUsers' || value === 'allAuthenticatedUsers';
}

function callerNode(email: string, subject = ''): GraphNode {
  const principal = federated.test(subject) ? subject : federated.test(email) ? email : email || subject;
  const normalized = principal.replace(/^serviceAccount:/, '');
  if (publicCaller(normalized)) return { id: `entry:iam:${normalized}`, kind: 'entry', label: normalized };
  if (!normalized || normalized.toLowerCase() === 'anonymous') {
    return { id: 'entry:audit:anonymous', kind: 'entry', label: 'Unauthenticated audit caller' };
  }
  return { id: `identity:${normalized}`, kind: federated.test(normalized) ? 'entry' : 'identity', label: normalized.slice(0, 512) };
}

function riskyCaller(node: GraphNode): boolean {
  return node.kind === 'entry' || defaultAccount.test(node.id.replace(/^identity:/, ''));
}

function targetAccount(value: string): string | undefined {
  return value.match(/(?:^|\/)projects\/[^/]+\/serviceAccounts\/([^/@\s]+@[^/@\s]+\.gserviceaccount\.com)(?:$|\/)/)?.[1];
}

/** Validate the entire export before emitting any finding or confirmed relationship. */
export function parseAuditLogs(source: string, file: string): GraphResult {
  const graph = emptyGraph(), lineIndex = createLineIndex(source);
  let issue = 'scan/invalid-input', issueTitle = 'Invalid Cloud Audit Logs', issueLine = 1;
  try {
    let parsed: unknown, parsedJson = true;
    try { parsed = JSON.parse(source); } catch { parsedJson = false; }
    let entries: unknown[], offsets: number[];
    if (parsedJson) {
      if (Array.isArray(parsed)) {
        entries = parsed;
        offsets = telemetryRecordOffsets(source);
      } else if (object(parsed) && Array.isArray(parsed.entries)) {
        entries = parsed.entries;
        offsets = telemetryRecordOffsets(source, 'entries');
      } else if (object(parsed) && Object.hasOwn(parsed, 'protoPayload')) {
        entries = [parsed]; offsets = [source.indexOf('{')];
      } else throw new Error('Invalid audit envelope');
    } else {
      entries = []; offsets = [];
      let searchFrom = 0;
      while (searchFrom < source.length) {
        const newline = source.indexOf('\n', searchFrom);
        const end = newline < 0 ? source.length : newline;
        const text = source.slice(searchFrom, end);
        if (text.trim()) {
          issueLine = lineIndex(searchFrom);
          if (entries.length === MAX_RECORDS) {
            issue = 'scan/input-limit'; issueTitle = 'Audit log entry limit exceeded';
            throw new Error('Entry limit');
          }
          entries.push(JSON.parse(text)); offsets.push(searchFrom);
        }
        searchFrom = end + 1;
      }
      if (!entries.length) throw new Error('Empty audit input');
    }
    if (entries.length > MAX_RECORDS) {
      issue = 'scan/input-limit'; issueTitle = 'Audit log entry limit exceeded';
      throw new Error('Entry limit');
    }
    let grantsExpanded = 0;
    const countGrant = (): void => {
      if (++grantsExpanded > MAX_RECORDS) {
        issue = 'scan/input-limit'; issueTitle = 'Audit log binding/member limit exceeded';
        throw new Error('Grant limit');
      }
    };
    const events: AuditEvent[] = [];
    for (let index = 0; index < entries.length; index++) {
      issueLine = lineIndex(offsets[index] ?? 0);
      const entry = entries[index];
      if (!object(entry) || !Object.hasOwn(entry, 'protoPayload') || !object(entry.protoPayload)) {
        throw new Error('Missing audit payload');
      }
      const payload = entry.protoPayload, auth = record(payload.authenticationInfo);
      const metadata = record(payload.requestMetadata), request = record(payload.request);
      const status = record(payload.status), policy = record(request.policy);
      const serviceData = record(payload.serviceData), delta = record(serviceData.policyDelta);
      const provider = record(request.workloadIdentityPoolProvider ?? request.workload_identity_pool_provider);
      const oidc = record(provider.oidc ?? request.oidc), sink = record(request.sink);
      const email = stringField(auth.principalEmail), subject = stringField(auth.principalSubject);
      const method = stringField(payload.methodName), service = stringField(payload.serviceName);
      const resource = stringField(payload.resourceName), requestName = stringField(request.name);
      const callerIp = stringField(metadata.callerIp);
      const condition = stringField(provider.attributeCondition ?? provider.attribute_condition ?? request.attributeCondition ?? request.attribute_condition);
      const issuer = stringField(oidc.issuerUri ?? oidc.issuer_uri);
      // Validate aliases independently; a valid preferred field must not hide a corrupt alternate.
      for (const candidate of [provider.attributeCondition, provider.attribute_condition, request.attributeCondition,
        request.attribute_condition, oidc.issuerUri, oidc.issuer_uri, policy.name, policy.resource]) stringField(candidate);
      const delegation = auth.serviceAccountDelegationInfo;
      if (delegation !== undefined && (!Array.isArray(delegation) || delegation.length > 32)) throw new Error('Invalid delegation');
      const delegators: string[] = [];
      for (const hop of (delegation ?? []) as unknown[]) {
        if (!object(hop)) throw new Error('Invalid delegation hop');
        const first = record(hop.firstPartyPrincipal), third = record(hop.thirdPartyPrincipal);
        const claims = record(third.thirdPartyClaims);
        const candidates = [stringField(first.principalEmail), stringField(hop.principalSubject),
          stringField(third.principalEmail), stringField(third.principalSubject),
          stringField(claims.principalEmail), stringField(claims.principalSubject), stringField(claims.sub), stringField(claims.subject)];
        delegators.push(candidates.find(value => federated.test(value)) || candidates.find(Boolean) || 'anonymous');
      }
      const authorization = payload.authorizationInfo;
      if (status.code !== undefined && (typeof status.code !== 'number' || !Number.isSafeInteger(status.code) || status.code < 0)) {
        throw new Error('Invalid status code');
      }
      if (authorization !== undefined && (!Array.isArray(authorization) || authorization.some(info => !object(info)
        || info.granted !== undefined && typeof info.granted !== 'boolean'))) {
        throw new Error('Invalid authorization');
      }
      const denied = typeof status.code === 'number' && status.code !== 0
        || Array.isArray(authorization) && authorization.length > 0 && authorization.every(info => info.granted === false);
      const grants: Grant[] = [];
      if (delta.bindingDeltas !== undefined) {
        if (!Array.isArray(delta.bindingDeltas)) throw new Error('Invalid binding deltas');
        for (const binding of delta.bindingDeltas) {
          countGrant();
          if (!object(binding)) throw new Error('Invalid binding delta');
          const action = stringField(binding.action), role = stringField(binding.role), member = stringField(binding.member);
          if (!role || !member || !action) throw new Error('Missing binding delta fields');
          countGrant();
          if (action === 'ADD') grants.push({ role, member });
        }
      }
      if (policy.bindings !== undefined) {
        if (!Array.isArray(policy.bindings)) throw new Error('Invalid bindings');
        for (const binding of policy.bindings) {
          countGrant();
          if (!object(binding) || !Array.isArray(binding.members)) throw new Error('Invalid binding');
          const role = stringField(binding.role);
          if (!role) throw new Error('Missing role');
          for (const value of binding.members) {
            countGrant(); const member = stringField(value);
            if (!member) throw new Error('Missing member');
            grants.push({ role, member });
          }
        }
      }
      events.push({ line: issueLine, method, service, resource, requestName, email, subject, callerIp, delegators,
        delegation: Array.isArray(delegation) && delegation.length > 0, denied, disabledSink: sink.disabled === true,
        removedAuditConfig: Array.isArray(policy.auditConfigs) && policy.auditConfigs.length === 0, condition, issuer, grants });
    }

    for (const [index, event] of events.entries()) {
      if (event.denied) continue;
      const caller = callerNode(event.email, event.subject);
      const origin = event.delegators.length ? callerNode(event.delegators[0]) : caller;
      const evidence = clean(`${event.method} on ${event.resource || event.requestName || '(unspecified resource)'} by ${caller.label}${event.callerIp ? ` from ${event.callerIp}` : ''}`);
      const finding = (rule: string, severity: Severity, title: string, message: string, detail = evidence) =>
        addFinding(graph, file, event.line, `audit/${rule}`, severity, title, clean(message), clean(detail));
      if (event.service === 'logging.googleapis.com' && /(?:^|\.)(?:DeleteSink|UpdateSink|CreateExclusion|UpdateExclusion)$/.test(event.method)) {
        const blocker = /(?:^|\.)DeleteSink$/.test(event.method) || /(?:^|\.)UpdateSink$/.test(event.method) && event.disabledSink;
        finding('logging-tampering', blocker ? 'blocker' : 'high', 'Audit logging configuration changed',
          'A successful logging configuration change can remove or suppress security evidence. Review the caller and resulting logging coverage.');
      }
      if (/(?:^|\.)SetIamPolicy$/.test(event.method) && event.removedAuditConfig) {
        finding('logging-tampering', 'blocker', 'Audit logging configuration removed', 'A successful policy change explicitly removed all auditConfigs. Restore required audit logging after review.');
      }
      if (/(?:^|\.)(?:CreateServiceAccountKey|UploadServiceAccountKey)$/.test(event.method)) {
        finding('iam-persistence', 'high', 'Persistent service account credential created', 'A successful key creation or upload established a long-lived credential. Review its authorization and intended lifecycle.');
      }
      if (/(?:^|\.)(?:CreateWorkloadIdentityPoolProvider|UpdateWorkloadIdentityPoolProvider)$/.test(event.method)
        && (!event.condition || event.condition.includes('||') || /token\.actions\.githubusercontent\.com|github/i.test(event.issuer)
          && !/(?:attribute|assertion)\.repository\s*==/.test(event.condition))) {
        finding('iam-persistence', 'high', 'Workload identity provider lacks a pinned trust condition', 'A successful provider change permits insufficiently constrained federated identities. Review issuer and repository restrictions.');
      }
      if (/(?:^|\.)SetIamPolicy$/.test(event.method)) {
        const scope = event.resource || event.requestName || `unresolved IAM resource in ${file}`;
        const target = targetAccount(scope);
        for (const [grantIndex, grant] of event.grants.entries()) {
          if (!powerfulRoles.has(grant.role) && !escalationRoles.has(grant.role) && !publicCaller(grant.member)) continue;
          const detail = clean(`${grant.member} -> ${grant.role} on ${scope}`);
          const observed = finding('iam-persistence', 'high', 'Powerful or public IAM grant observed', 'A successful policy change granted powerful, escalation or public access. Review the member and resource scope.', detail);
          const from = callerNode(grant.member), impersonation = target && escalationRoles.has(grant.role);
          const data = Object.hasOwn(dataRoles, grant.role) ? dataRoles[grant.role] : undefined;
          const to: GraphNode = impersonation ? { id: `identity:${target}`, kind: 'identity', label: target.slice(0, 512) }
            : data ? { id: `data:${scope}:${data}`, kind: 'data', label: clean(`${data} in ${scope}`) }
            : { id: `resource:${scope}`, kind: 'resource', label: clean(scope) };
          graph.nodes.push(from, to);
          graph.edges.push({ id: `${file}:audit:${index}:grant:${grantIndex}`, from: from.id, to: to.id,
            kind: impersonation ? 'service-account-impersonation' : 'iam-grant', findingIds: [observed.id], evidence: detail, confidence: 'confirmed' });
        }
      }
      const delegatedAccount = event.delegation
        ? event.email.replace(/^serviceAccount:/, '').match(/^[^/@\s]+@[^/@\s]+\.gserviceaccount\.com$/)?.[0] : undefined;
      const target = targetAccount(event.resource) ?? targetAccount(event.requestName) ?? delegatedAccount;
      const mint = event.service === 'iamcredentials.googleapis.com' && credentialMethod.test(event.method)
        || event.service === 'sts.googleapis.com' && /(?:^|\.)ExchangeToken$/.test(event.method);
      if ((mint || event.delegation) && (riskyCaller(caller) || riskyCaller(origin) || target !== undefined)) {
        const observed = finding('impersonation-chain', 'high', 'Runtime credential impersonation observed',
          'A successful credential operation or delegation chain used a risky caller or a target service account. Correlate the target identity with static IAM grants.');
        if (target) {
          const from = event.delegators.length ? origin : caller;
          graph.nodes.push(from, { id: `identity:${target}`, kind: 'identity', label: target.slice(0, 512) });
          graph.edges.push({ id: `${file}:audit:${index}:impersonation`, from: from.id, to: `identity:${target}`,
            kind: 'service-account-impersonation', findingIds: [observed.id], evidence, confidence: 'confirmed' });
        }
      }
      if (sensitiveMethod.test(event.method) && riskyCaller(caller)) {
        const observed = finding('sensitive-data-access', 'high', 'Sensitive data accessed by a risky caller', 'A successful sensitive data operation was performed by a public, anonymous, federated or default service identity. Review the access and affected data.');
        const resource = event.resource || event.requestName || `unresolved audit resource in ${file}`;
        const target = `data:${resource}:Runtime sensitive data access`;
        graph.nodes.push(caller, { id: target, kind: 'data', label: clean(`Runtime sensitive data access: ${resource}`) });
        graph.edges.push({ id: `${file}:audit:${index}:data`, from: caller.id, to: target,
          kind: 'audit-data-access', findingIds: [observed.id], evidence, confidence: 'confirmed' });
      }
    }
  } catch {
    const failure = emptyGraph();
    addFinding(failure, file, issueLine, issue, 'high', issueTitle,
      issue === 'scan/input-limit' ? 'At most 10000 audit entries and 10000 binding/member expansions are supported per file.'
        : 'Expected audit objects with protoPayload, supported envelopes, at most 32 delegation hops and string fields no longer than 2048 characters.',
      issueTitle);
    return failure;
  }
  return graph;
}
