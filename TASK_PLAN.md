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
