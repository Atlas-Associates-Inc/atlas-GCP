# ATLAS.md — Atlas Shield (`atlas-shield`) Canonical SSoT

## 1. Mission & Identity
- **Product Name**: **Atlas Shield** (`@atlas-sec/shield` / CLI: `atlas-shield`)
- **License**: Apache-2.0 (Enterprise-ready Open Source Software with explicit patent grant)
- **Mission**: Protect enterprises and engineering teams worldwide from cloud cyberattacks by deterministically discovering and formally proving **GCP × Firebase cross-boundary attack paths**, while eliminating AI SecOps self-compromise (credential leaks, cloud mis-mutations, and indirect prompt injection).

## 2. First-Principles Architectural Pillars

| Layer | Module Scope | Responsibility | Security Invariant |
| :--- | :--- | :--- | :--- |
| **L0: Deterministic Attack Graph** | `src/graph/**` | Parse `firestore.rules`, `storage.rules`, `firebase.json`, Terraform (`*.tf`), GCP IAM Policy JSON, GitHub Actions WIF (`*.yml`), Cloud Audit Logs (`*cloud-audit*.json`, `*cloud-audit*.ndjson`, `*cloudaudit*.json`, `*gcp-audit*.json`, `*audit-log*.json`, `*audit-logs*.ndjson` with token/camelCase boundaries), and Security Command Center findings (`*scc*.json`) into a unified directed graph; enumerate static and runtime-observed cross-boundary attack paths offline in milliseconds. | Zero LLM dependency, zero network access, deterministic exit codes for CI/CD PR gates. |
| **L1: Zero-Trust MCP Airlock** | `src/airlock/**` | Thin JSON-RPC 2.0 stdio proxy with per-server hardened profiles (`scc`, `secops`, `firebase`, `cloudrun`, `developer-knowledge`, `prowler`, `semgrep`) wrapping official OSS & Google MCP servers. | **Fail-closed Read-Only tool & profile allowlists**, private-key/JWT/token redaction, and Indirect Prompt Injection neutralization on untrusted cloud logs. |
| **L2: Sovereign AI Prover** | `src/prove/**` | Supports two first-class execution modes:<br/>1. **`dual` Mode**: **Argon High** (Conductor / Patch Synthesis) × **Astra Ultra** (`gpt-6-astra`, `effort="ultra"`, `-s read-only --ephemeral` Counterexample Prover).<br/>2. **`gemini` Mode (Pure Gemini Sovereign Mode)**: 100% Gemini / Vertex AI closed-perimeter zero-retention execution (independent Architect + Red-Team Prover passes with zero non-Google provider dependency). | **Non-Majority Fail-Closed Gate**: Any reproducible exploit proof triggers a `BLOCKER` verdict; empty/malformed/timed-out output fails closed as `ERROR`. |
| **CLI & SARIF/Diff Reporter** | `src/cli.ts`, `src/report/**` | Single-command developer UX (`atlas-shield audit <dir>`, `atlas-shield airlock [--profile <name>]`, `atlas-shield mcp-config`, `atlas-shield sanitize`) outputting human-readable tables, GitHub Code Scanning SARIF v2.1.0, Airlock MCP configs, and minimal remediation diffs. | Never mutates cloud state or local user repositories; outputs proposed configs and diffs to `stdout` only. |

## 3. Hard Engineering & Supply-Chain Invariants
1. **Zero Runtime npm Supply-Chain Surface**: Built on **Node.js `>=22.18.0` native erasable TypeScript (`.ts`)** using exclusively Node built-in modules (`node:fs`, `node:path`, `node:module`, `node:crypto`, `node:child_process`, `node:util`, `node:readline`, `node:test`). `package.json` MUST keep `"dependencies": {}`.
2. **Mechanical Write Prohibition**: Atlas Shield MUST NEVER execute mutating cloud commands (`firebase deploy`, `gcloud ... update/delete/deploy/set-iam-policy`) or forward mutating MCP tool calls (`deploy`, `create`, `update`, `delete`, `set`, `init`, `evaluate`).
3. **Untrusted Telemetry Isolation**: All cloud log entries, resource labels, and third-party MCP responses MUST pass through deterministic secret redaction and prompt-injection boundary sanitization before entering any model prompt.
4. **Model & Repository Governance (Zero-Claude Policy)**:
   - Canonical repository root: `/Users/takayukimiyano/StudioProjects/GCP`
   - Planning & Frozen Implementation Orders live in `/Users/takayukimiyano/StudioProjects/GCP/TASK_PLAN.md`.
   - **Claude / Anthropic and non-approved lightweight models are abolished and prohibited** across development governance and runtime prover adapters.
   - **Through 2026-11-08 JST**: **Astra xhigh (`gpt-6-astra`, `effort=xhigh`)**, **Argon High (`gemini-4-argon-high`)**, and **Gemini 3.8 Flash High (`gemini-3.8-flash-high`)** operate under orthogonal Two-Epoch development governance (`Argon High` conducts orchestration and Google clean-room audit; `Astra xhigh` executes cross-layer implementation and OpenAI clean-room audit; `Gemini 3.8 Flash High` supports rapid iteration and parallel research).
   - **From 2026-11-09 JST onward**: Pure **Gemini (`gemini-4-argon-high` and `gemini-3.8-flash-high` / Vertex AI)** sovereign development and clean-room `Argon High` audit.
   - `git commit`, `git push`, `gh pr`, `npm publish`, and cloud deployments require explicit Go from `taka-san`.
