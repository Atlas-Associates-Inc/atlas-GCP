# TASK_PLAN.md — Atlas Shield (`@atlas-sec/shield`) Phase 1 Frozen Order

## Architecture / Overview
**Atlas Shield** (`atlas-shield`) is an Apache-2.0 open-source sovereign cloud cybersecurity engine built with zero external runtime dependencies on **Node.js >= 22.18.0 native erasable TypeScript (`.ts`)**.

It protects enterprises worldwide against real-world **GCP × Firebase** cyberattacks via three strictly separated layers:
1. **L0 Deterministic Cross-Boundary Attack Graph (`src/graph/`)**: Offline static & graph analyzer correlating Firebase Rules (`firestore.rules`, `storage.rules`, `*.firestore.rules.sample`, `*.storage.rules.sample`), `firebase.json`, Terraform (`*.tf`), GCP IAM Policy JSON (`*iam*.json`), and GitHub Actions Workload Identity Federation (`.github/workflows/*.yml`, `*wif*.tf`) into a unified directed graph to detect reachable cross-boundary breach paths (`Entry Point -> Exposure/Rules Seam -> Service Account / IAM Escalation -> Crown Jewel Data/Secrets`) and synthesize proposed unified-diff remediations without mutating target files.
2. **L1 Zero-Trust Read-Only MCP Airlock (`src/airlock/`)**: Fail-closed JSON-RPC 2.0 stdio proxy wrapping upstream OSS MCP servers (`google/mcp-security` `scc-mcp`, `google-secops-mcp`, `prowler-mcp`, `semgrep-mcp`, `firebase-mcp-server`, `cloudrun`) that mechanically blocks mutating MCP tools, redacts credentials/tokens/keys, and neutralizes Indirect Prompt Injection payloads (BiDi/zero-width Unicode stripping, role-spoofing quarantine, untrusted-telemetry framing).
3. **L2 Sovereign AI Prover (`src/prove/`)**: Supports two first-class prover modes with zero Claude/Anthropic dependency:
   - **`dual` mode**: **Argon High** (Conductor: Vertex AI closed-perimeter zero-retention REST, Gemini API, or `agy --mode plan --model gemini-4-argon-high --sandbox`) × **Astra Ultra** (`codex exec -m gpt-6-astra -c 'model_reasoning_effort="ultra"' -s read-only --ephemeral` or OpenAI Responses API).
   - **`gemini` mode (Pure Gemini Sovereign Mode)**: 100% Gemini / Vertex AI standalone operation (independent Red-Team Prover pass + Architect Conductor pass on Gemini/Vertex AI, enabling seamless pure-Gemini operation after 2026-11-08 and closed-VPC enterprise deployments).
   - Enforces the **Non-Majority Fail-Closed Gate** (`BLOCKER` if any lane proves exploitability; `ERROR` on empty/malformed/timed-out output).

## Hard Invariants & Safety Constraints
- **Zero Runtime npm Dependencies**: `package.json` MUST define `"dependencies": {}` and `"devDependencies": {}` (pure Node.js `>=22.18.0` built-in modules + native `.ts` execution).
- **Zero Claude Dependency**: No Anthropic/Claude SDK, CLI, or model identifier anywhere in code or docs.
- **Guardrail Compliance**:
  - Do NOT create any file literally named `firestore.rules`, `storage.rules`, or `database.rules.json` inside the repository (use `*.firestore.rules.sample` / `*.storage.rules.sample` in `fixtures/`, while the scanner itself supports real `firestore.rules`, `storage.rules`, AND `*.rules.sample` files).
  - Do NOT embed literal `-----BEGIN ... PRIVATE KEY-----` strings anywhere in source or test files; construct PEM header patterns/fixtures dynamically (e.g., `['-----BEGIN', 'PRIVATE KEY-----'].join(' ')`).
- **Fail-Closed Read-Only Guarantee**: Never execute mutating cloud commands (`gcloud`, `firebase deploy`) or mutate scanned target directories.

## Non-Goals (Phase 1)
- Do NOT duplicate Google Cloud REST APIs already covered by `google/mcp-security` (`scc-mcp`, `google-secops-mcp`) or `firebase-mcp-server`.
- Do NOT perform `git commit`, `git push`, `gh pr`, `npm publish`, or live cloud deployments.

## Task List

- [x] **Task-1: Package, Licensing & Core Type Contracts**
  - **Target Files**: `LICENSE`, `package.json`, `bin/atlas-shield.mjs`, `src/types.ts`
  - **Scope**: Add Apache-2.0 `LICENSE`; configure `package.json` (`name: "@atlas-sec/shield"`, `version: "0.1.0"`, `license: "Apache-2.0"`, `type: "module"`, `engines: { "node": ">=22.18.0" }`, `bin: { "atlas-shield": "./bin/atlas-shield.mjs" }`, `dependencies: {}`, scripts `check` and `test`); define strict erasable TypeScript interfaces supporting both `dual` (`argonHigh` + `astraUltra`) and `gemini` (`argonArchitect` + `geminiRedTeam`) prover modes.
  - **Do Not**: Add external npm dependencies or non-erasable TypeScript syntax (`enum`, `namespace`, parameter properties).

- [x] **Task-2: L0 Deterministic GCP × Firebase Cross-Boundary Attack Graph Engine**
  - **Target Files**: `src/graph/firebase-rules-parser.ts`, `src/graph/gcp-iam-parser.ts`, `src/graph/attack-graph.ts`, `src/report/remediation.ts`
  - **Scope**: Parse Firebase Firestore/Storage rules (`firestore.rules`, `storage.rules`, `*.firestore.rules.sample`, `*.storage.rules.sample`), `firebase.json`, Terraform (`*.tf`), GCP IAM Policy JSON (`*iam*.json`), and GitHub Actions WIF (`.github/workflows/*.yml`). Detect public rules (`if true`), missing `hasOnly` privilege-field escalation, wildcard `{document=**}` leaks, public Cloud Run/Functions (`allUsers`/`allAuthenticatedUsers`, `INGRESS_TRAFFIC_ALL`), over-privileged default service accounts (`*-compute@developer.gserviceaccount.com`, `*@appspot.gserviceaccount.com`) holding `roles/owner`, `roles/editor`, `roles/secretmanager.secretAccessor`, `roles/bigquery.dataEditor`, or `roles/storage.admin`, transitive IAM escalation (`actAs`, `getAccessToken`, `serviceAccountTokenCreator`, `iam.securityAdmin`), and unpinned GitHub WIF OIDC providers missing `attribute.repository` constraints. Build directed Cross-Boundary Attack Paths and unified-diff remediation proposals.
  - **Do Not**: Make network calls or modify scanned files.

- [x] **Task-3: L1 Zero-Trust Read-Only MCP Airlock & Prompt-Injection Sanitizer**
  - **Target Files**: `src/airlock/sanitizer.ts`, `src/airlock/mcp-guard.ts`, `src/airlock/stdio-proxy.ts`
  - **Scope**: Fail-closed read-only MCP verb allowlist (`get`, `list`, `query`, `read`, `describe`, `search`, `validate`, `status`, `inspect`); mechanically block mutating verbs (`deploy`, `create`, `update`, `delete`, `set`, `add`, `init`, `remove`, `destroy`, `apply`, `patch`, `exec`, `evaluate`, `write`, `send`) in `tools/list` and `tools/call` (error `-32600`). Redact PEM private keys, GCP SA `private_key` JSON fields, `ya29.*` OAuth tokens, JWTs, `AIza...` keys, and GitHub tokens; strip invisible BiDi/zero-width Unicode (`U+200B..U+200F`, `U+202A..U+202E`, `U+2066..U+2069`, `U+FEFF`) and quarantine Indirect Prompt Injection strings inside `<untrusted_telemetry>` envelopes.
  - **Do Not**: Forward unverified mutating MCP methods or expose raw credentials.

- [x] **Task-4: L2 Sovereign AI Prover (`dual` Argon×Astra & `gemini` Standalone Modes)**
  - **Target Files**: `src/prove/dual-prover.ts`
  - **Scope**: Support `--prover-mode dual` (`argonHigh` + `astraUltra`) and `--prover-mode gemini` (100% Gemini / Vertex AI standalone dual-pass Architect + Red-Team Prover with zero OpenAI/Codex requirement), plus injectable mock/custom runners for offline tests. Enforce strict Non-Majority Fail-Closed Gate (`BLOCKER` if any lane proves exploitability; `ERROR` on timeout/malformed JSON/empty output).
  - **Do Not**: Reference Claude/Anthropic or allow write access in prover subprocesses.

- [x] **Task-5: CLI, SARIF v2.1.0 Reporter, CI Action & OSS Documentation**
  - **Target Files**: `src/report/sarif.ts`, `src/report/formatter.ts`, `src/cli.ts`, `action.yml`, `.github/workflows/ci.yml`, `README.md`
  - **Scope**: Implement `atlas-shield audit <dir> [--format table|json|sarif] [--fail-on blocker|high|medium] [--emit-patch] [--prove] [--prover-mode gemini|dual]`, `atlas-shield airlock --upstream-cmd <cmd> [--upstream-arg <arg>...]`, and `atlas-shield sanitize`; valid SARIF v2.1.0 output; GitHub Action `action.yml` + `.github/workflows/ci.yml`; bilingual EN/JA `README.md`.
  - **Do Not**: Mutate user files during `audit`.

- [x] **Task-6: Enterprise Fixtures & Deterministic Verification Suite**
  - **Target Files**: `fixtures/vulnerable-enterprise/**`, `fixtures/hardened-enterprise/**`, `test/graph.test.ts`, `test/airlock.test.ts`, `test/prover.test.ts`, `test/cli.test.ts`
  - **Scope**: Create vulnerable and hardened enterprise fixtures (`*.firestore.rules.sample`, `*.storage.rules.sample`, `main.tf`, `iam-policy.json`, `github-wif.yml`) and exhaustive offline `node:test` suites covering all 3 layers, both `dual` and `gemini` prover modes, real `firestore.rules` scanning in temp dirs, SARIF v2.1.0 validation, and CLI exit codes (`0`, `1`, `2`).
  - **Do Not**: Require external network access during tests.

## Acceptance Criteria
1. `npm run check` (exits `0`)
2. `npm test` (exits `0`)

---

## Phase 2 Frozen Order (`@atlas-sec/shield` v0.2.0 — Airlock Profiles, Cloud Audit Threat Hunting & SCC Correlation)

### Phase 2 Scope & Non-Goals
- **Zero New Subdirectories**: Place all new source, fixture, and test files inside existing directories (`src/airlock/`, `src/graph/`, `src/report/`, `fixtures/vulnerable-enterprise/`, `fixtures/hardened-enterprise/`, `test/`).
- **Zero External npm Dependencies**: Maintain `"dependencies": {}` and `"devDependencies": {}` in `package.json` (`version: "0.2.0"`), updating `"files"` only if needed (already covers `bin/`, `src/`, `LICENSE`, `README.md`, `action.yml`).
- **Zero Claude / Lightweight Models**: `mcp-config` and all docs/profiles target only `--client agy|gemini` (never Claude Desktop or Anthropic tools) and sovereign models.
- **Strict `<1 MiB` Linear `O(N)` Time & `256 MiB` Heap Bounds**: Every new parser (`audit-log-parser.ts`, `scc-findings-parser.ts`) must enforce bounded record/field sizes, `O(N)` complexity (`< 350 ms` on `< 1 MiB` dense inputs), secret redaction + BiDi/control stripping on untrusted telemetry fields, and fail-closed `scan/invalid-input` / `scan/input-limit` diagnostics.

### Phase 2 Task List

- [x] **Task-7: Hardened L1 Airlock Server Profiles & Read-Only `mcp-config` Generator**
  - **Target Files**: `src/types.ts`, `src/airlock/profiles.ts`, `src/airlock/mcp-guard.ts`, `src/airlock/stdio-proxy.ts`, `src/cli.ts`
  - **Scope**:
    - Define curated zero-trust read-only Airlock profiles (`scc`, `secops`, `firebase`, `cloudrun`, `developer-knowledge`, `prowler`, `semgrep`) in `src/airlock/profiles.ts` with strict per-profile tool-name patterns (layered on top of `isReadOnlyTool()` — both must pass!), recommended upstream command templates, and required read-only flags.
    - Add `--profile <name>` to `atlas-shield airlock` (`runStdioProxy`) so `tools/list` and `tools/call` reject any tool outside the selected profile's allowlist with JSON-RPC error `-32600`.
    - Add `atlas-shield mcp-config [--profile <name>...] [--client agy|gemini]` emitting non-mutating JSON configuration to `stdout` that wraps each selected upstream MCP server in `atlas-shield airlock --profile <name> --upstream-cmd ...`.
  - **Do Not**: Write to user home directories (`~/.gemini`, etc.), execute upstream commands during `mcp-config`, or include Claude/Anthropic client formats.

- [x] **Task-8: Cloud Audit Logs Threat-Hunting Parser & Runtime Attack-Graph Correlation**
  - **Target Files**: `src/graph/audit-log-parser.ts`, `src/graph/attack-graph.ts`, `src/report/remediation.ts`
  - **Scope**:
    - Parse exported GCP Cloud Audit Logs in JSON array (`[...]`), `{ entries: [...] }`, or NDJSON line format. Collision-free discovery requires explicit `cloud-audit` / `cloudaudit` / `gcp-audit` / `audit-log(s)` token or camelCase boundaries in `.json` / `.ndjson` filenames (for example, `cloud-audit.json`, `gcpaudit.ndjson`, `audit_logs.json`, `projectAuditLogs.json`). Ignore generic `audit.json` / `npm-audit.json` / `*.audit.json` / `*.audit.ndjson` tool reports and unrelated words such as `plaudit.json` or `cloudauditor.json`.
    - Detect and graph-correlate four high-severity attack classes with bounded field lengths (`<= 512` chars) and `<= 10,000` records per file:
      1. `audit/logging-tampering` (`blocker` for `DeleteSink` / `UpdateSink` disabling sink or removing `auditConfigs`; `high` for suspicious exclusion filter changes).
      2. `audit/iam-persistence` (`high` for `CreateServiceAccountKey`, `CreateWorkloadIdentityPoolProvider` / `UpdateWorkloadIdentityPoolProvider` without `attributeCondition`, or `SetIamPolicy` bindings granting powerful/escalation roles or public `allUsers`/`allAuthenticatedUsers`).
      3. `audit/impersonation-chain` (`high` for `GenerateAccessToken`, `GenerateIdToken`, `SignBlob`, `SignJwt` on `iamcredentials.googleapis.com` or `sts.googleapis.com` `ExchangeToken` / `serviceAccountDelegationInfo` chains from external/federated `principalSubject`, `allUsers`, or default compute/App Engine SAs). Emit `confirmed` runtime impersonation edges (`entry` / `identity` -> target `identity:<sa>`) so `findAttackPaths()` connects observed WIF/caller impersonation directly into static Terraform/IAM Secret Manager & BigQuery permissions!
      4. `audit/sensitive-data-access` (`high` for `AccessSecretVersion`, `storage.objects.get` / `list`, or BigQuery read/export jobs invoked by `allUsers`, `allAuthenticatedUsers`, unauthenticated callers, federated `principal://` / `principalSet://` callers, or default service accounts).
    - Redact secrets and strip invisible/BiDi/control characters from all extracted `principalEmail`, `principalSubject`, `callerIp`, `resourceName`, and `methodName` fields before storing in `Finding` or `GraphNode`/`GraphEdge`.
  - **Do Not**: Trust unbounded strings from log payloads or mutate log files.

- [x] **Task-9: Security Command Center (SCC) Findings Parser & Cross-Layer Posture Join**
  - **Target Files**: `src/graph/scc-findings-parser.ts`, `src/graph/attack-graph.ts`, `src/report/remediation.ts`
  - **Scope**:
    - Parse exported SCC findings JSON (`[...]`, `{ findings: [...] }`, or `{ listFindingsResults: [...] }`) for token/camelCase-bounded `*scc*.json` files (`scc-findings.json`, `scc_export.json`, `sccFindings.json` — never matching unrelated words).
    - Ingest active findings (`state === 'ACTIVE'` or omitted `state`; skip `INACTIVE` / `MUTED` when `mute === 'MUTED'`), mapping `CRITICAL` -> `blocker`, `HIGH` -> `high`, `MEDIUM` -> `medium`, `LOW` -> `low` (`scc/active-finding`), normalizing `resourceName` (Cloud Run services, Cloud Functions, Storage buckets, IAM Service Accounts, Projects) to join seamlessly with existing L0 `resource:` / `identity:` / `tf:` nodes (via project/location/service aliases in `correlateResources`)!
    - Emit public-exposure entry edges (`entry:scc:public` -> resource) for public-exposure SCC categories (`PUBLIC_BUCKET_ACL`, `OPEN_FIREWALL`, `PUBLIC_SQL_INSTANCE`, `PUBLIC_CLOUD_RUN_SERVICE`, `ANONYMOUS_ACCESS`, etc.) so active SCC exposure findings automatically chain with Terraform/IAM runtime service accounts to reveal reachable Crown Jewel paths!
  - **Do Not**: Make live GCP API calls during `audit`.

- [x] **Task-10: v0.2.0 Fixtures, Documentation & `<1 MiB` Complexity / Security Test Suite**
  - **Target Files**: `package.json`, `README.md`, `fixtures/vulnerable-enterprise/cloud-audit.ndjson`, `fixtures/vulnerable-enterprise/scc-findings.json`, `fixtures/hardened-enterprise/cloud-audit.ndjson`, `fixtures/hardened-enterprise/scc-findings.json`, `test/airlock.test.ts`, `test/cli.test.ts`, `test/graph.test.ts`, `test/phase2.test.ts`
  - **Scope**:
    - Bump `package.json` version to `"0.2.0"`.
    - Add realistic vulnerable & hardened Cloud Audit Log + SCC fixtures (verifying `audit fixtures/hardened-enterprise` still exits `0` with zero `high`/`blocker` findings or attack paths, and `audit fixtures/vulnerable-enterprise` correlates SCC + Cloud Audit Logs + Terraform + IAM + WIF + Firebase Rules!).
    - Update `README.md` (EN/JA) with `--profile`, `mcp-config`, Cloud Audit Logs threat hunting, and SCC posture correlation examples.
    - Add exhaustive tests in `test/phase2.test.ts` (and existing test files) including `< 350 ms` / `256 MiB` heap-cap dense benchmarks for `parseAuditLogs` and `parseSccFindings`, filename word-boundary tests (`plaudit.json`, `soccer.json` ignored), untrusted log prompt-injection/secret sanitization tests, and profile enforcement tests. Mark `Task-7`..`Task-10` as `[x]` in `TASK_PLAN.md` upon passing `npm run check` and `npm test`.

---

## Phase 2.1 Frozen Order (v0.2.1)

### Goal, Invariants & Non-Goals
- Make root audits usable in polyglot repositories with collision-free Cloud Audit Logs filename discovery and exclusions for standard generated, SDK, cache, and worktree child directories, while preserving fail-closed diagnostics for unsafe or unanalyzed symlinks.
- Apply exclusions only to children encountered during traversal; explicitly requested roots remain scannable. Report skipped names deterministically, except `.git` and `node_modules`.
- Keep `readSafeSource` unchanged: reject all symlink components, root escapes, `.git`, and `node_modules`; safely analyze explicit Firebase Rules references in other excluded directories.
- Reject recognized security input links and aliases to them, broken/out-of-root links, `.github` segments in either link or canonical target paths, excluded file/directory targets, and special targets. Check excluded and symlinked target components before accepting files or directories. Ignore ordinary intra-root non-input file links; record a limitation for directory links whose canonical targets are reachable without excluded or symlinked components, without re-traversing them.
- Preserve zero runtime/development dependencies, offline operation, read-only target handling, traversal/input bounds, and every existing feature. The legacy agent-state directory exclusion is defensive filesystem handling only; it adds no vendor integration.
- **Allowed Files**: `ATLAS.md`, `TASK_PLAN.md`, `README.md`, `SECURITY.md`, `CONTRIBUTING.md`, `package.json`, `bin/atlas-shield.mjs`, `src/graph/firebase-rules-parser.ts`, `src/graph/attack-graph.ts`, `test/graph.test.ts`, `test/phase2.test.ts`.
- **Do Not**: Change other files, add repository directories or dependencies, modify Git metadata/index, perform release builds, commit/push/PR/publish/deploy, or change live Rules. Independent Two-Epoch orthogonal audit is required after local verification; implementation is never self-certified.

### Task List
- [x] **Task-11: Collision-Free Cloud Audit Discovery, Polyglot Exclusions & Safe Intra-Repository Symlink Handling**
  - **Target Files**: `src/graph/attack-graph.ts`, `test/phase2.test.ts`, `package.json`, `ATLAS.md`, `README.md`, `TASK_PLAN.md`.
  - **Scope**: Export `EXCLUDED_DIRS`, require explicit cloud/GCP audit or audit-log(s) filename boundaries, share case-insensitive Terraform/workflow input recognition with parser dispatch and symlink checks, enforce canonical target checks before accepting file/directory links, report deterministic limitations without misclassifying regular files named `build`, maintain `0.2.1`, and synchronize canonical and EN/JA docs while preserving the CI Node.js version range.
  - **Regression Coverage**: Explicit audit tokens/camelCase and ignored generic tool reports (clean exit `0`); generated/cache trees with more than 20,005 files and broken links; regular `build` files, direct excluded-root audits, explicit Rules references, intra-root file/Flutter directory links, uppercase `.TF` / `.YML` / `.YAML` discovery and dispatch, nested/target `.github` paths, aliases to security inputs, and excluded file/directory targets with exact diagnostics and CLI exit `2`.
  - **Local Verification**: Final collision-free discovery and symlink polish passed `npm run check` and `npm test` (both exit `0`; 189 tests passed, 0 failed/skipped; Node.js v22.19.0). Repository-root audit reports zero `scan/*` errors; existing vulnerable fixtures still produce security findings. Independent Google audit remains pending; local results do not certify release approval.

- [x] **Task-12: OSS `README.md` Structural Redesign (Dedicated English & Japanese Sections, Mermaid Architecture Diagram & Reference Tables)**
  - **Target Files**: `README.md`, `TASK_PLAN.md`.
  - **Scope**: Replace the interleaved 2-line EN/JA layout in `README.md` with a shared top header + `[English](#english) · [日本語](#日本語)` jump links + a compact Mermaid `flowchart LR` 3-layer architecture diagram, followed by dedicated `## English` and `## 日本語` sections with full technical, command, table, and security-boundary parity (including L0 rule/severity reference table, L1 7 Airlock profiles table using existing verified upstream links and `src/airlock/profiles.ts` templates, L2 prover backend table, and GitHub Actions YAML preserving `node-version: '>=22.18.0 <23'`). Mark `Task-12` `[x]` in `TASK_PLAN.md` after `npm run check` and `npm test` exit `0`.
  - **Do Not**: Modify `src/**`, `test/**`, `bin/**`, `package.json`, `ATLAS.md`, `action.yml`, `.github/**`, or `fixtures/**`; add external badge images or unverified URLs/claims; or alter existing `node-version: '>=22.18.0 <23'` pins.
  - **Local Verification**: 2026-11-04 JST — `npm run check` and `npm test` both exited `0` (189 passed, 0 failed/skipped; Node.js v22.19.0); EN/JA commands, tables, technical values, source profile templates, URL allowlist and Node.js pins checked. Independent Google audit remains pending; this is not release approval.

- [x] **Task-13: OSS Release Governance (`SECURITY.md`, `CONTRIBUTING.md`, `ATLAS.md` Ship-Gate Wording & Verification Test)**
  - **Target Files**: `SECURITY.md`, `CONTRIBUTING.md`, `ATLAS.md`, `test/phase2.test.ts`, `TASK_PLAN.md`.
  - **Scope**:
    - Create bilingual (`## English` / `## 日本語`) `SECURITY.md` documenting supported versions (`0.2.x`), private vulnerability reporting via GitHub Private Vulnerability Reporting (without inventing email addresses or unverified repo URLs), zero-secret reporting hygiene, in-scope security defects, and explicit out-of-scope / architectural boundaries matching `README.md`.
    - Create bilingual (`## English` / `## 日本語`) `CONTRIBUTING.md` documenting Node.js `>=22.18.0` (`>=22.18.0 <23` in CI), zero runtime/dev npm dependencies, erasable TypeScript syntax, unchanged `package.json` `"files"` allowlist (`["bin/", "src/", "LICENSE", "README.md", "action.yml"]`), repository safety rules (no literal `firestore.rules`/`storage.rules`/`database.rules.json` or PEM headers, no extra subdirectories), EN/JA `README.md` parity, Apache-2.0 licensing, and deterministic local verification (`npm run check`, `npm test`, `node bin/atlas-shield.mjs audit fixtures/hardened-enterprise`).
    - Update `ATLAS.md` lines 24-26 development governance bullets so prohibition wording (`abolished and prohibited`) passes `atlas-sync.sh --check-repos` and matches the Two-Epoch development governance (`Astra xhigh`, `Argon High`, and `Gemini 3.8 Flash High` through `2026-11-08` JST; `Argon High` and `Gemini 3.8 Flash High` from `2026-11-09` JST onward), without altering runtime prover contracts in line 14.
    - Add a deterministic regression test in `test/phase2.test.ts` validating `SECURITY.md` and `CONTRIBUTING.md` presence, bilingual anchors, Node floor alignment, zero `scan/*` errors on repo-root scan, and unchanged `package.json` `"files"`. Mark `Task-13` `[x]` in `TASK_PLAN.md` once `npm run check` and `npm test` exit `0`.
  - **Do Not**: Modify `package.json`, `src/**`, `bin/**`, `action.yml`, `.github/**`, `README.md`, or `fixtures/**`; invent contact emails or unverified repository URLs; or run `git commit` / `git push` / `gh repo create`.
  - **Local Verification**: 2026-11-04 JST — `npm run check` and `npm test` both exited `0` (190 passed, 0 failed/skipped; Node.js v22.19.0). Hardened fixture audit exited `0`; the regression test confirmed zero repository-root `scan/*` findings. `atlas-sync.sh --check-repos /Users/takayukimiyano/StudioProjects/GCP` passed with no warnings. EN/JA technical tokens and sections match; both documents are non-empty UTF-8 regular files without a BOM, unsupported vendor/tier tokens, external URLs, or literal PEM private-key headers. Independent Google audit remains pending; this is not release approval.

- [x] **Task-14: Installed node_modules CLI Bootstrap, O(N) Sorted Path Finding-ID Merge & Governance Token Test Precision**
  - **Target Files**: `bin/atlas-shield.mjs`, `src/graph/firebase-rules-parser.ts`, `src/graph/attack-graph.ts`, `test/phase2.test.ts`, `ATLAS.md`, `CONTRIBUTING.md`, `TASK_PLAN.md`.
  - **Scope**:
    - Bootstrap `bin/atlas-shield.mjs` cleanly across checkout, `npm link`, and `node_modules` layouts (including via symlinks and `--preserve-symlinks-main`); verify `pkgRoot`, `package.json`, `src`, and nested `src` segments via `lstatSync` + `realpathSync` (rejecting symlinked `src` directories); register the `resolve` boundary hook unconditionally across checkout, `npm link`, and `node_modules` layouts while restricting dynamic `stripTypeScriptTypes` loading hooks to `node_modules` installations to avoid `ERR_UNSUPPORTED_NODE_MODULES_TYPE_STRIPPING` and reject any traversal escape or symlink escape outside the package `src` directory with exit `2`.
    - Optimize `src/graph/firebase-rules-parser.ts` via one-shot `node:crypto` `hash('sha256', ...)`, add a 2-slot MRU fast path in `mergeGraphs` (`src/graph/attack-graph.ts`), apply `findAttackPaths` early-exit bounds on graph rank and privilege escalation, optimize multi-edge sorted `findingIds` merging in `findAttackPaths` via linear two-pointer sorted unique merge (`O(N)`), and avoid redundant intermediate array allocations when merging a single graph.
    - Refine the governance unsupported-model token check in `test/phase2.test.ts` to allow approved Two-Epoch models (`Gemini 3.8 Flash High` / `gemini-3.8-flash-high`) while continuing to reject all prohibited models and lightweight tiers.
    - Add regression tests verifying installed `node_modules` CLI execution, symlink preservation, and symlink escape rejection.
    - Update `ATLAS.md` and `CONTRIBUTING.md` built-in module references to include `node:module`.
  - **Do Not**: Add npm dependencies, build steps, or new directories; modify `package.json`, `SECURITY.md`, or other untouched files.
  - **Local Verification**: Deterministic acceptance gates (`npm run check` and `npm test`) verified clean by `atlas-implement`; independent `Astra xhigh` read-only audit remains pending.

- [x] **Task-15: Collapsible 20-Language Global Overview in README.md & Parity Guard**
  - **Target Files**: `README.md`, `CONTRIBUTING.md`, `test/phase2.test.ts`, `src/graph/attack-graph.ts`, `src/graph/firebase-rules-parser.ts`, `TASK_PLAN.md`.
  - **Scope**:
    - Add a collapsed `<details>` block with `<summary><strong>Global Overview (20 Languages) / 20言語クイック概要</strong></summary>` near the top of `README.md` providing an authoritative delegation statement to `## English` and `## 日本語` and an exact 20-language table covering tags `en`, `ja`, `zh-Hans`, `zh-Hant`, `ko`, `es`, `pt`, `fr`, `de`, `it`, `ru`, `uk`, `pl`, `nl`, `tr`, `ar`, `hi`, `id`, `vi`, `th` with zero unsupported model or lightweight-tier tokens and zero BiDi/BOM characters.
    - Polish `README.md` `<details>` block with portable standard blockquotes (`> **Note:** ...` and `> **注記:** ...`), ensuring full caveat parity with `CONTRIBUTING.md` (mode names do not guarantee closed perimeter or zero retention).
    - Eliminate 4x 100k `Map`/`Set` hash-table allocation bottlenecks in `mergeGraphs` and `findAttackPaths` via a 4-nibble lowercase-hex radix bucket sort helper `sortByHexPrefix`, stable linear `byId` deduplication, sequential edge ID cache, zero-allocation binary search in `findAttackPaths`, and precomputed scope labels in `parseFirebaseRules`.
    - Synchronize `CONTRIBUTING.md` item 5 in both English and Japanese to note the 20-language quick overview in `README.md` and its explicit delegation to `## English` and `## 日本語`.
    - Extend deterministic test coverage in `test/phase2.test.ts` to assert that `README.md` is a safe, BOM-free, BiDi-free, regular UTF-8 file without PEM headers or unsupported tokens, preserves `[English](#english)`, `[日本語](#日本語)`, `## English`, and `## 日本語`, contains exact 20 table rows in `<details>` without `[!NOTE]`, and delegates to English and Japanese sections.
  - **Do Not**: Mutate files outside scope, add npm dependencies or new directories, alter git metadata, or weaken English/Japanese canonical specifications.
  - **Local Verification**: Deterministic acceptance gates (`npm run check` and `npm test`) verified clean by `atlas-implement`; independent `Astra xhigh` read-only audit remains pending.

- [x] **Task-16: Sub-120ms Dense Firebase Parser & Monomorphic Hex Sort for Shared CI Runners**
  - **Target Files**: `src/graph/firebase-rules-parser.ts`, `src/graph/attack-graph.ts`, `test/graph.test.ts`, `TASK_PLAN.md`.
  - **Scope**:
    - Add 1-slot MRU hash cache in `addFinding` to eliminate redundant hashing of identical `(file, line, ruleId, evidence)` tuples on dense single-line rule blocks.
    - Implement monotonic cursor fast path (`O(1)` amortized) in `createLineIndex` with binary search fallback.
    - Define pure ASCII character-code fast helpers (`isSpaceCode`, `isLowerAlphaCode`, `isWordCode`, `isWordOrDotCode`, `isOperatorResetCode`, `isPathOrMemberDelimiter`, `isHeaderKeywordAt`, `isCelInOperatorAt`) and implement zero-allocation, zero-regex linear `headerKeyword` state machine in `forEachAllowClause` with `isCelInOperatorAt` boundary check while keeping `scanAllowClauses` generator 100% compatible; eliminate regex backtracking and quote-stripping DoS on escaped quotes/newlines and prevent path-boundary erasure on `/in`, `/sign-in`, `/in-box`, and `.in`, verified by `< 200 ms` adversarial regression tests in `test/graph.test.ts`.
    - Eliminate 40,000 unique `resource` node `Map` insertions in `parseFirebaseRules` using dedicated `nodeList` and scope-attached `resourceNode` / `resourceLineLex` tracking and lazy `resourceLabel` / `dataLabel` string computation.
    - Cache finding title & message strings per `FirebaseScope` and support optional `collapseDuplicateEdges` pre-aggregation in `parseFirebaseRules` (enabled in `scanDirectory`), eliminating 100k transient `GraphEdge` allocations and 22-GC heap churn under the 256 MiB cap.
    - Specialize `sortByHexPrefix` into monomorphic `sortStringsByHexPrefix` and `sortItemsByIdHexPrefix` and replace `.every(...)` closure calls in `mergeGraphs` and `mergeTwoSortedUnique` with indexed `arraysEqual` helper.
  - **Do Not**: Modify test thresholds in `test/graph.test.ts`, alter repository metadata, or introduce dependencies.
  - **Local Verification**: Deterministic acceptance gates (`npm run check` and `npm test`) verified clean by `atlas-implement`; independent Google clean-room audit (Argon High) remains pending.

- [x] **Task-17: Sub-55ms Duplicate-Edge Merge, 32-Bit Hex Key Sort & Cloud Run Correlation Fast Path**
  - **Target Files**: `src/graph/firebase-rules-parser.ts`, `src/graph/attack-graph.ts`, `TASK_PLAN.md`.
  - **Scope**:
    - Implement 1-slot MRU clause cache in `forEachAllowClause` and defensive `operations.slice()` in `scanAllowClauses` (`src/graph/firebase-rules-parser.ts`).
    - Implement 32-bit packed hex-prefix (`hi32`) radix + insertion sort with scalar hex-prefix skip in `sortStringsByHexPrefix`, `sortItemsByIdWithHexKeys`, `sortItemsByIdHexPrefix`, and `byId` (`src/graph/attack-graph.ts`).
    - Optimize `mergeGraphs` with lazy `serialized` node stringification, zero-copy single-edge `findingIds` accumulator, and single-graph `result.findings` ID projection (`src/graph/attack-graph.ts`).
    - Add `trustedSorted` fast path to `findAttackPaths` and call `findAttackPaths(graph, true)` in `scanDirectory` (`src/graph/attack-graph.ts`).
    - Add `{` block guard in `field()` and precompute `nameKey` and alias-rewriting guards in `correlateResources()` (`src/graph/attack-graph.ts`).
  - **Do Not**: Mutate files outside scope, modify test files or budgets, alter git metadata, or introduce dependencies.
  - **Local Verification**: Deterministic acceptance gates (`npm run check` and `npm test`) verified clean by `atlas-implement`; independent Google clean-room audit (Argon High) remains pending.

- [x] **Task-18: L2 Sovereign Prover Orthogonal Gemini 4 Upgrade (`Argon High` × `Hydrogen XHigh`) & 4-Model Governance Alignment**
  - **Target Files**: `src/prove/dual-prover.ts`, `ATLAS.md`, `README.md`, `test/prover.test.ts`, `test/phase2.test.ts`, `TASK_PLAN.md`.
  - **Scope**:
    - Upgrade `geminiRedTeam` lane in `src/prove/dual-prover.ts` to `gemini-4-hydrogen-xhigh` while keeping `argonArchitect` and `argonHigh` on `gemini-4-argon-high` across Gemini REST, Vertex AI REST, and `agy` CLI adapters.
    - Synchronize `ATLAS.md` and `README.md` (EN/JA) to document the orthogonal `argonArchitect` (`gemini-4-argon-high`) × `geminiRedTeam` (`gemini-4-hydrogen-xhigh`) Pure Gemini Sovereign Mode and the 4-model periodic-table development governance (`Argon` / `Carbon` / `Hydrogen` / `Gemini 3.8 Flash`).
    - Extend `test/prover.test.ts` and `test/phase2.test.ts` to verify per-lane model routing and reject `carbon-low` while allowing approved `gemini-4-carbon-high` and `gemini-4-hydrogen-xhigh` tokens.
  - **Do Not**: Add external dependencies or weaken fail-closed prover invariants.
  - **Local Verification**: `npm run check`, `npm test`, and `atlas-sync.sh --check-repos` all exit `0`.

### Acceptance Criteria
1. `npm run check` (exits `0`)
2. `npm test` (exits `0`)
