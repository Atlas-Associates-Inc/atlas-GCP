export type Severity = 'blocker' | 'high' | 'medium' | 'low' | 'info';

export interface SourceLocation {
  file: string;
  line: number;
  column?: number;
}

export interface Finding {
  id: string;
  ruleId: string;
  severity: Severity;
  title: string;
  message: string;
  location: SourceLocation;
  evidence: string;
}

export interface GraphNode {
  id: string;
  kind: 'entry' | 'resource' | 'identity' | 'data';
  label: string;
  location?: SourceLocation;
}

export interface GraphEdge {
  id: string;
  from: string;
  to: string;
  kind: string;
  findingIds: string[];
  evidence: string;
  confidence: 'confirmed' | 'potential';
}

export interface AttackPath {
  id: string;
  nodes: string[];
  edges: string[];
  findingIds: string[];
  severity: Severity;
  confidence: 'confirmed' | 'potential';
  description: string;
}

export interface GraphResult {
  nodes: GraphNode[];
  edges: GraphEdge[];
  findings: Finding[];
  paths: AttackPath[];
  limitations: string[];
}

export interface Remediation {
  findingId: string;
  file: string;
  description: string;
  diff: string;
  automatic: false;
}

export interface AirlockDecision {
  allowed: boolean;
  reason: string;
}

export type AirlockProfileId = 'scc' | 'secops' | 'firebase' | 'cloudrun' | 'developer-knowledge' | 'prowler' | 'semgrep';
export type McpConfigClient = 'agy' | 'gemini';

export interface AirlockProfile {
  id: AirlockProfileId;
  description: string;
  upstreamCommand: string;
  upstreamArgs: readonly string[];
  allowedTokens: readonly string[];
}

export interface SanitizedTelemetry {
  text: string;
  redactions: number;
  quarantined: boolean;
}

export type ProverStatus = 'PASS' | 'BLOCKER' | 'ERROR';
export type ProverMode = 'gemini' | 'dual';
export type ProverLane = 'argonArchitect' | 'geminiRedTeam' | 'argonHigh' | 'astraUltra';
export interface ExploitProof {
  steps: string[];
  evidence: string[];
}

export interface LaneVerdict {
  family: 'google' | 'openai';
  model: string;
  status: ProverStatus;
  rationale: string;
  proof?: ExploitProof;
}

export type DualProverVerdict =
  | { mode: 'gemini'; status: ProverStatus; lanes: { argonArchitect: LaneVerdict; geminiRedTeam: LaneVerdict } }
  | { mode: 'dual'; status: ProverStatus; lanes: { argonHigh: LaneVerdict; astraUltra: LaneVerdict } };

export interface SarifLog {
  $schema: string;
  version: '2.1.0';
  runs: Array<{
    tool: { driver: { name: string; version: string; informationUri: string; rules: Array<{
      id: string;
      name: string;
      shortDescription: { text: string };
      defaultConfiguration: { level: 'error' | 'warning' | 'note' };
    }> } };
    results: Array<{
      ruleId: string;
      ruleIndex: number;
      level: 'error' | 'warning' | 'note';
      message: { text: string };
      locations: Array<{ physicalLocation: {
        artifactLocation: { uri: string; uriBaseId: string };
        region: { startLine: number; startColumn: number };
      } }>;
      partialFingerprints: { primaryLocationLineHash: string };
      properties: { severity: Severity; findingId: string };
    }>;
    properties?: Record<string, unknown>;
  }>;
}
