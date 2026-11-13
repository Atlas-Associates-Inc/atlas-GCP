# Atlas Shield v0.2.1

Offline GCP × Firebase attack-path analysis, a read-only MCP Airlock, and optional AI evidence review for enterprise security teams. GCP × Firebase の攻撃経路をオフラインで解析し、読み取り専用 MCP Airlock と任意の AI 証拠レビューを提供します。

[English](#english) · [日本語](#日本語)

- **Apache-2.0** — open source / オープンソース
- **Node.js >=22.18.0** — native erasable TypeScript / ネイティブ実行可能な erasable TypeScript
- **0 npm dependencies** — runtime and development / 実行時・開発時ともに依存パッケージなし
- **Read-only & offline by default** — local audit / ローカル監査は既定で読み取り専用・オフライン

```mermaid
flowchart LR
  inputs["L0: Static and exported telemetry inputs"] --> graph["Unified Attack Graph"]
  graph --> reports["Table / JSON / SARIF v2.1.0 and review-only diffs (stdout)"]
  client["L1: MCP Client"] <--> airlock["Stdio JSON-RPC 2.0 Read-Only Airlock: 7 profiles and secret/injection sanitizer"]
  airlock <--> upstream["Caller-installed upstream MCP server"]
  evidence["L2: Sanitized evidence (--prove)"] --> passes["Independent Prover passes: gemini or dual"]
  passes --> gate["Non-Majority Fail-Closed Gate: BLOCKER / ERROR / PASS"]
```

<details>
<summary><strong>Global Overview (20 Languages) / 20言語クイック概要</strong></summary>

> **Note:** The [English](#english) and [日本語](#日本語) sections below are the sole authoritative technical and security-boundary specifications for Atlas Shield, defining all CLI flags, input bounds, and operational guarantees. In particular: exit code `0` is not an absolute completeness or security guarantee, lexical MCP Airlock filtering does not mathematically prove semantic read-only execution, secret and prompt sanitization is not an exhaustive prompt-injection defense, and `--prove` transmits sanitized evidence under caller-configured provider settings and mode names do not guarantee a closed perimeter or zero retention.
>
> **注記:** 以下の [English](#english) および [日本語](#日本語) セクションが、すべてのCLIフラグ、入力上限、および運用上の保証を規定する唯一の正式な技術・セキュリティ境界仕様です。特に、終了コード `0` は完全性や安全性の絶対的保証ではなく、Airlockの字句フィルタリングは意味論的な読み取り専用動作を完全に証明するものではなく、サニタイズは網羅的なプロンプト注入防御ではなく、`--prove` は呼び出し側が設定したプロバイダー設定の下でサニタイズ済み証拠を送信し、モード名は閉じた境界やゼロ保持を保証しません。

| Language | Tag | Summary |
| --- | --- | --- |
| English | `en` | An offline-by-default GCP × Firebase cross-boundary attack-path analyzer, read-only MCP Airlock, and optional AI evidence reviewer (Apache-2.0, Node.js >=22.18.0, 0 npm dependencies). Authoritative specifications and security limits are governed exclusively by the [English](#english) and [日本語](#日本語) sections. |
| 日本語 (Japanese) | `ja` | 既定でオフライン動作するGCP × Firebase横断攻撃経路アナライザー、読み取り専用MCP Airlock、および任意のAI証拠レビュー機能を提供します（Apache-2.0、Node.js >=22.18.0、npm依存関係0）。完全な仕様およびセキュリティ境界は [English](#english) および [日本語](#日本語) セクションが正本となります。 |
| 简体中文 (Simplified Chinese) | `zh-Hans` | 默认离线的 GCP × Firebase 跨边界攻击路径分析器、只读 MCP Airlock 以及可选的 AI 证据审查工具（Apache-2.0、Node.js >=22.18.0、0 npm 依赖）。权威技术规范与安全边界完全由 [English](#english) 与 [日本語](#日本語) 章节规定。 |
| 繁體中文 (Traditional Chinese) | `zh-Hant` | 預設離線的 GCP × Firebase 跨邊界攻擊路徑分析器、唯讀 MCP Airlock 以及選配的 AI 證據審查工具（Apache-2.0、Node.js >=22.18.0、0 npm 相依性）。正式技術規範與安全邊界完全由 [English](#english) 與 [日本語](#日本語) 章節規範。 |
| 한국어 (Korean) | `ko` | 기본 오프라인으로 동작하는 GCP × Firebase 교차 경계 공격 경로 분석기, 읽기 전용 MCP Airlock 및 선택적 AI 증거 검토 도구입니다(Apache-2.0, Node.js >=22.18.0, npm 의존성 0개). 공식 기술 사양 및 보안 경계는 [English](#english) 및 [日本語](#日本語) 섹션에 따릅니다. |
| Español (Spanish) | `es` | Analizador de rutas de ataque entre límites de GCP y Firebase sin conexión por defecto, Airlock MCP de solo lectura y revisor de evidencia de IA opcional (Apache-2.0, Node.js >=22.18.0, 0 dependencias npm). Las especificaciones autorizadas y límites de seguridad se rigen por las secciones [English](#english) y [日本語](#日本語). |
| Português (Portuguese) | `pt` | Analisador de caminhos de ataque entre fronteiras GCP e Firebase padrão offline, Airlock MCP somente leitura e revisor de evidências de IA opcional (Apache-2.0, Node.js >=22.18.0, 0 dependências npm). Especificações oficiais e limites de segurança são regidos pelas seções [English](#english) e [日本語](#日本語). |
| Français (French) | `fr` | Analyseur de chemins d'attaque inter-frontières GCP et Firebase hors ligne par défaut, Airlock MCP en lecture seule et réviseur de preuves IA optionnel (Apache-2.0, Node.js >=22.18.0, 0 dépendance npm). Les spécifications officielles et limites de sécurité sont régies par les sections [English](#english) et [日本語](#日本語). |
| Deutsch (German) | `de` | Standardmäßig offline arbeitender Analyse-Dienst für GCP × Firebase grenzüberschreitende Angriffspfade, schreibgeschützter MCP-Airlock und optionale KI-Beweisprüfung (Apache-2.0, Node.js >=22.18.0, 0 npm-Abhängigkeiten). Maßgebliche Spezifikationen und Sicherheitsgrenzen werden ausschließlich durch die Abschnitte [English](#english) und [日本語](#日本語) geregelt. |
| Italiano (Italian) | `it` | Analizzatore di percorsi di attacco tra confini GCP e Firebase offline per impostazione predefinita, MCP Airlock di sola lettura e revisore opzionale delle prove IA (Apache-2.0, Node.js >=22.18.0, 0 dipendenze npm). Le specifiche autorevoli e i limiti di sicurezza sono regolati dalle sezioni [English](#english) e [日本語](#日本語). |
| Русский (Russian) | `ru` | Работающий по умолчанию офлайн анализатор путей атак между периметрами GCP и Firebase, доступный только для чтения шлюз MCP Airlock и опциональный инструмент проверки свидетельств с помощью ИИ (Apache-2.0, Node.js >=22.18.0, 0 зависимостей npm). Полные официальные спецификации и границы безопасности определяются разделами [English](#english) и [日本語](#日本語). |
| Українська (Ukrainian) | `uk` | Аналізатор міжпериметрових шляхів атак GCP та Firebase, що за замовчуванням працює офлайн, доступний лише для читання шлюз MCP Airlock і додатковий інструмент перевірки доказів засобами ШІ (Apache-2.0, Node.js >=22.18.0, 0 залежностей npm). Офіційні специфікації та межі безпеки регулюються виключно розділами [English](#english) і [日本語](#日本語). |
| Polski (Polish) | `pl` | Domyślnie działający offline analizator ścieżek ataków ponad granicami GCP i Firebase, blokada MCP Airlock tylko do odczytu oraz opcjonalny moduł weryfikacji dowodów przez SI (Apache-2.0, Node.js >=22.18.0, 0 zależności npm). Wiążące specyfikacje i ograniczenia bezpieczeństwa są określone w sekcjach [English](#english) i [日本語](#日本語). |
| Nederlands (Dutch) | `nl` | Standaard offline analyseprogramma voor aanvalspaden over GCP- en Firebase-grenzen, alleen-lezen MCP Airlock en optionele AI-bewijsevaluatie (Apache-2.0, Node.js >=22.18.0, 0 npm-afhankelijkheden). Gezaghebbende specificaties en veiligheidsgrenzen worden bepaald door de secties [English](#english) en [日本語](#日本語). |
| Türkçe (Turkish) | `tr` | Varsayılan olarak çevrimdışı çalışan GCP × Firebase sınırlar arası saldırı yolu analizcisi, salt okunur MCP Airlock ve isteğe bağlı yapay zeka kanıt inceleyicisi (Apache-2.0, Node.js >=22.18.0, 0 npm bağımlılığı). Yetkili özellikler ve güvenlik sınırları yalnızca [English](#english) ve [日本語](#日本語) bölümleri tarafından belirlenir. |
| العربية (Arabic) | `ar` | محلل مسارات الهجوم عبر حدود GCP و Firebase يعمل دون اتصال بشكل افتراضي، مع حاجز MCP Airlock للقراءة فقط ومراجع أدلة اختياري بالذكاء الاصطناعي (ترخيص Apache-2.0، وNode.js >=22.18.0، و0 تبعيات npm). المواصفات المعتمدة وحدود الأمان محددة حصريا في قسمي [English](#english) و[日本語](#日本語). |
| हिन्दी (Hindi) | `hi` | डिफ़ॉल्ट रूप से ऑफ़लाइन GCP × Firebase क्रॉस-बाउंड्री अटैक-पाथ विश्लेषक, केवल-पढ़ने योग्य MCP Airlock, और वैकल्पिक AI साक्ष्य समीक्षक (Apache-2.0, Node.js >=22.18.0, 0 npm निर्भरताएँ)। आधिकारिक विनिर्देश और सुरक्षा सीमाएँ [English](#english) और [日本語](#日本語) अनुभागों द्वारा शासित हैं। |
| Bahasa Indonesia (Indonesian) | `id` | Penganalisis jalur serangan lintas batas GCP × Firebase yang default offline, MCP Airlock khusus baca, dan peninjau bukti AI opsional (Apache-2.0, Node.js >=22.18.0, 0 dependensi npm). Spesifikasi resmi dan batasan keamanan diatur oleh bagian [English](#english) dan [日本語](#日本語). |
| Tiếng Việt (Vietnamese) | `vi` | Công cụ phân tích đường dẫn tấn công xuyên ranh giới GCP × Firebase mặc định ngoại tuyến, MCP Airlock chỉ đọc và bộ đánh giá bằng chứng AI tùy chọn (Apache-2.0, Node.js >=22.18.0, 0 phụ thuộc npm). Quy chuẩn kỹ thuật chính thức và giới hạn an ninh được quy định bởi phần [English](#english) và [日本語](#日本語). |
| ไทย (Thai) | `th` | เครื่องมือวิเคราะห์เส้นทางการโจมตีข้ามขอบเขต GCP × Firebase ที่ทำงานแบบออฟไลน์โดยเริ่มต้น, MCP Airlock แบบอ่านอย่างเดียว และตัวตรวจสอบหลักฐาน AI ทางเลือก (Apache-2.0, Node.js >=22.18.0, 0 การพึ่งพา npm) ข้อมูลจำเพาะและขอบเขตความปลอดภัยอย่างเป็นทางการถูกกำหนดโดยส่วน [English](#english) และ [日本語](#日本語) |

</details>

## English

### Why Atlas Shield

Isolated scanners can identify an exposed resource without connecting it to the identity and permissions that make the exposure consequential. Atlas Shield correlates supported evidence across GCP × Firebase boundaries: public Firebase Rules, Cloud Run exposure, or Workload Identity Federation (WIF) can form entry points into paths involving runtime or federated identities, IAM privilege escalation, and access to Secret Manager, BigQuery, or Cloud Storage. The graph distinguishes observed or statically established relationships from `potential` transitions that depend on application behavior or deployment context.

AI SecOps adds another boundary: an assistant may receive hostile cloud logs or invoke tools with excessive privileges. The MCP Airlock mechanically restricts forwarded requests through fail-closed tool-name policies, while secret redaction and injection sanitization prepare untrusted telemetry for review. These controls have explicit limits; they do not establish that an upstream program is trustworthy or that every model instruction attack is neutralized.

### Quickstart & CLI

Use this checkout with Node.js **>=22.18.0**; no install or build step is required:

```sh
node bin/atlas-shield.mjs audit .
node bin/atlas-shield.mjs audit /path/to/repository --format sarif
node bin/atlas-shield.mjs audit /path/to/repository --format json --emit-patch
node bin/atlas-shield.mjs audit fixtures/hardened-enterprise
```

This checkout contains intentional vulnerable fixtures in `fixtures/vulnerable-enterprise`, so `audit .` exits `1`. The `audit fixtures/hardened-enterprise` command is the clean `0`-exit example.

npm package publication has **not been verified**. Once a trusted release is available on npm, the package entry point is:

```sh
npx @atlas-sec/shield audit .
```

Defaults are `--format table`, `--fail-on high`, and `--prover-mode gemini`. Formats are `table|json|sarif`; failure thresholds are `blocker|high|medium`. Reports and proposed changes go to `stdout` only. `--emit-patch` includes review-only unified diffs in the selected report format; it never applies them or modifies target files or cloud resources.

| Exit code | Meaning |
| --- | --- |
| `0` | Findings and paths are below the selected threshold, with no incomplete scan or prover error/blocker. |
| `1` | Findings or paths meet the selected threshold, or the prover returns `BLOCKER`. |
| `2` | Invalid arguments, an incomplete scan, prover `ERROR`, or proxy failure. Incomplete scans and prover errors take precedence over threshold findings. |

### L0: Deterministic Cross-Boundary Attack Graph

`audit` reads supported local inputs into a unified directed graph. Without `--prove`, analysis is offline, makes no network calls, and uses no model.

Supported inputs are Firebase `firestore.rules` / `storage.rules` and `*.firestore.rules.sample` / `*.storage.rules.sample` files, Rules paths declared in `firebase.json`, Terraform `*.tf`, exported IAM policy JSON `*iam*.json` with IAM token/camelCase boundaries, GitHub Actions WIF workflows (`.github/workflows/*.yml` / `*.yaml` and WIF-named YAML files), exported Cloud Audit Logs, and exported SCC findings. Terraform and workflow extensions are case-insensitive.

**Rule reference**

| Rule ID | Severity | Detection / interpretation |
| --- | --- | --- |
| `firebase/public-read` | `high` | Unconditional public Rules reads. |
| `firebase/public-write` | `high` | Unconditional public Rules writes. |
| `firebase/recursive-wildcard` | `high` | Public reads through a recursive wildcard expose descendants. |
| `firebase/privilege-fields` | `medium` | Authenticated user-document writes lack a recognized field allowlist; application trust and validation need review. |
| `gcp/public-service` | `high` | Public IAM grants to `allUsers` or `allAuthenticatedUsers`. |
| `gcp/public-ingress` | `medium` | External service ingress is enabled; this alone does not prove unauthenticated access. |
| `iam/default-service-account` | `high` | A default service account holds a recognized powerful role. |
| `iam/privilege-escalation` | `high` | Recognized service-account or IAM escalation capabilities; scope, conditions, and prerequisites need review. |
| `wif/unpinned-provider` | `high` | A GitHub WIF provider lacks a recognized mandatory literal repository restriction. Workflow authentication declarations also add `potential` edges, without proving provider trust. |
| `audit/logging-tampering` | `blocker` / `high` | Logging sink deletion/disablement or audit configuration removal; suspicious exclusion changes. |
| `audit/iam-persistence` | `high` | Service-account key creation, insufficiently constrained WIF provider changes, or powerful/public IAM grants. |
| `audit/impersonation-chain` | `high` | Supported credential issuance, token exchange, or delegation chains involving suspicious callers. |
| `audit/sensitive-data-access` | `high` | Supported secret, storage, or BigQuery access by public, federated, unauthenticated, or default-account callers. |
| `scc/active-finding` | `blocker` / `high` / `medium` / `low` | Active SCC findings map from `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` respectively. |
| `scan/*` | `high` | Unsafe, unreadable, malformed, unsupported, or bounded inputs/path enumeration make the scan incomplete: exit `2` and no `--prove` invocation. |

**Workspace traversal and symlinks**

Standard generated, SDK, cache, local agent/IDE state, and worktree child directories in `EXCLUDED_DIRS` are skipped. Skipped names are recorded deterministically in `limitations`, except `.git` and `node_modules`. Audit a subdirectory directly to include infrastructure configs beneath an otherwise excluded child. A regular file named `build` is not reported as an excluded directory.

Explicit `firebase.json` Rules paths such as `build/custom.rules` are still analyzed when they contain no symlinks, root escapes, `.git`, or `node_modules` components. Ordinary intra-repository non-input file links are ignored. Intra-repository directory links are not re-traversed when their canonical targets are reachable for direct scanning; a limitation is recorded.

Symlinked security inputs or aliases to them, broken or out-of-root links, links into excluded targets, symlinked canonical-target ancestors, and non-regular entries encountered during traversal fail closed with exit `2`. A symlink with `.github` in any source or canonical-target path segment also fails closed; regular workflow files remain supported.

**Exported telemetry and correlation**

Cloud Audit Logs accept JSON arrays, `{ "entries": [...] }`, a single object containing `protoPayload`, or NDJSON. Discovery requires explicit `cloud-audit` / `cloudaudit` / `gcp-audit` / `audit-log(s)` token or camelCase boundaries in `.json` / `.ndjson` filenames. Examples: `cloud-audit.json`, `cloud-audit.ndjson`, `cloudaudit.json`, `gcp-audit.json`, `audit-log.json`, `audit_logs.ndjson`, and `projectAuditLogs.json`. Generic `audit.json`, `npm-audit.json`, `*.audit.json`, and `*.audit.ndjson` tool reports are ignored. Explicitly denied calls are ignored as compromise evidence. Successful credential events can join static IAM grants through shared `identity:<service-account>` nodes.

SCC accepts arrays, `{ "findings": [...] }`, `{ "listFindingsResults": [...] }`, and `{ finding, resource }` items from `gcloud` exports. Discovery of `*scc*.json` requires a token/camelCase boundary, as in `scc-findings.json` or `projectSccReport.json`; unrelated names such as `soccer.json` are ignored. `INACTIVE` findings and records marked `MUTED` are excluded. Active public exposure joins uniquely matched Terraform Cloud Run/Functions runtime identities and normalized storage, secret, and dataset nodes. Application-mediated runtime identity hops remain `potential`; exported observations do not verify current cloud state.

Both telemetry parsers redact recognized secrets and remove controls from stored text. Malformed exports or oversized key fields fail closed. Telemetry remediation is review-only advice, with no generated patch.

| Bound | Maximum |
| --- | --- |
| Workspace traversal | Depth `<= 64`; `<= 20,000` entries. |
| Input bytes | `<= 1 MiB` per file; `<= 32 MiB` per scan. |
| Firebase Rules scope expansion | Match depth `<= 64`; joined path `<= 4096` characters. |
| Telemetry records | `<= 10,000` records per file. |
| Audit-log grant expansion | `<= 10,000` combined binding/member expansions per file. |
| Stored telemetry text / key fields | Labels and evidence `<= 512` characters; key fields `<= 2048` characters. |
| Attack-path enumeration | `<= 1,000` paths, `<= 64` nodes per path, `<= 20,000` traversals. |

**Analysis limits:** Rules expressions, Terraform variables/modules/dynamic expressions, custom roles, and workflow expressions are not fully evaluated. Static analysis does not prove live policy or runtime exploitability. Review `limitations` and `potential` paths against deployment context; **exit `0` is not a security guarantee**. Keep input files stable while scanning.

### L1: Zero-Trust Read-Only MCP Airlock

The Airlock proxies newline-delimited **stdio JSON-RPC 2.0**, filters tool names through a fail-closed read-verb policy and an optional server profile, redacts recognized secrets, and sanitizes untrusted responses. Both the global policy and selected profile must permit a tool; a profile never relaxes the global mutation block.

Configure your MCP client to launch the Airlock with a trusted upstream program. `sanitize` reads telemetry from standard input:

```sh
node bin/atlas-shield.mjs airlock --profile scc --upstream-cmd /path/to/trusted-mcp-server
node bin/atlas-shield.mjs sanitize < telemetry.txt
node bin/atlas-shield.mjs mcp-config --profile scc --profile firebase --client gemini
node bin/atlas-shield.mjs mcp-config --client agy
```

Repeat `--upstream-arg` for each argument; use `--upstream-arg=<value>` for flags, for example `--upstream-arg=--flag`. Installed CLI forms are `atlas-shield airlock [--profile <name>] --upstream-cmd <cmd> [--upstream-arg <arg>...]` and `atlas-shield mcp-config [--profile <name>...] [--client agy|gemini]`.

`mcp-config` defaults to `gemini` and all seven profiles. Both clients receive `mcpServers` JSON on `stdout` only. This generator never runs or verifies upstream binaries, writes configuration files, or touches home directories. Generated wrappers expect `atlas-shield` on the client’s executable path. The `npx` templates use `--no-install` and preserve upstream flags as `--upstream-arg=<value>`.

**Airlock profiles** — commands are templates from `src/airlock/profiles.ts` for caller-installed upstreams, not verified live integrations.

| Profile ID | Read scope | Upstream template command | Upstream reference |
| --- | --- | --- | --- |
| `scc` | Security Command Center findings and posture | `uvx mcp-security-scc` | [google/mcp-security](https://github.com/google/mcp-security) |
| `secops` | Security Operations telemetry and detections | `uvx google-secops-mcp` | [google/mcp-security](https://github.com/google/mcp-security) |
| `firebase` | Firebase projects, applications, and data | `npx --no-install firebase-tools experimental:mcp` | [Firebase MCP documentation](https://firebase.google.com/docs/ai-assistance/mcp-server) |
| `cloudrun` | Cloud Run services, revisions, jobs, and logs | `npx --no-install @google-cloud/cloud-run-mcp` | Caller-installed `@google-cloud/cloud-run-mcp` package |
| `developer-knowledge` | Developer documentation and references | `uvx google-developer-knowledge-mcp` | [Google Developer Knowledge MCP](https://developers.google.com/knowledge/mcp) |
| `prowler` | Prowler findings, checks, and compliance | `uvx prowler-mcp` | [Prowler MCP announcement](https://prowler.com/blog/prowler-launches-lighthouse-ai-and-mcp-server-bringing-autonomous-security-to-devsecops-teams) |
| `semgrep` | Semgrep rules, findings, and configuration | `uvx semgrep-mcp` | [Semgrep MCP repository](https://github.com/semgrep/mcp) |

**Security boundaries:** Atlas Shield has no HTTP MCP transport. HTTP-only services such as Google Developer Knowledge require a separately trusted stdio bridge; the template is not evidence of a working bridge. Live integrations are unverified. The caller must independently restrict and verify upstream binaries, arguments, and credentials. **Lexical tool-name filtering does not prove semantic read-only behavior**; profiles do not authenticate server identity. Sanitization is not a complete prompt-injection defense.

### L2: Optional Sovereign AI Prover

```sh
node bin/atlas-shield.mjs audit . --prove --prover-mode gemini
node bin/atlas-shield.mjs audit . --prove --prover-mode dual
```

**Pure Gemini Sovereign Mode** (`gemini`, the default) runs independent `argonArchitect` (`gemini-4-argon-high`) and `geminiRedTeam` (`gemini-4-hydrogen-xhigh`) passes through Gemini, Vertex AI, or the configured `agy` adapter. It requires no non-Google prover backend.

`dual` runs `argonHigh` on `gemini-4-argon-high` plus `astraUltra` through an installed, authenticated `codex` CLI with `gpt-6-astra`, ultra reasoning, a read-only sandbox, and an ephemeral session. The adapter forwards `CODEX_HOME` and `OPENAI_API_KEY` when set. Both modes pass identical sanitized evidence to their lanes without sharing responses across lanes.

| Configuration | Required setup |
| --- | --- |
| `ATLAS_GEMINI_BACKEND=gemini` (default) | `GEMINI_API_KEY` |
| `ATLAS_GEMINI_BACKEND=vertex` | `GOOGLE_CLOUD_PROJECT`, `GOOGLE_CLOUD_LOCATION`, `GOOGLE_OAUTH_ACCESS_TOKEN` |
| `ATLAS_GEMINI_BACKEND=agy` | Installed, authenticated `agy` CLI supporting plan mode and sandbox. |
| `--prover-mode dual` | One Google backend above plus an installed, authenticated `codex` CLI; `CODEX_HOME` and `OPENAI_API_KEY` are forwarded when set. |

The **Non-Majority Fail-Closed Gate** does not vote away a lane’s exploit claim:

| Verdict | Meaning |
| --- | --- |
| `BLOCKER` | Any lane returns a schema-valid exploit proof with steps and evidence, even if another lane passes or fails. |
| `ERROR` | No valid exploit proof, but a lane returns empty/malformed output, fails, or times out. |
| `PASS` | Both lanes return valid passes; neither establishes an exploit from the supplied evidence. |

Proofs are **model-generated claims, not automatically executed exploits**. `PASS` is not a security guarantee. An incomplete local scan exits `2` without invoking the prover.

`--prove` transmits sanitized evidence to the selected provider/CLI. Credentials, data perimeter, retention, model access, and CLI sandbox enforcement require environment configuration. Mode names do not guarantee a closed perimeter or zero retention. Live provider integrations and model availability are **unverified**.

### GitHub Actions & Verification

The composite action requires Node.js **>=22.18.0**. This example runs from an Atlas Shield checkout using `uses: ./`; point `directory` at the checked-out target. It runs offline and preserves CLI exit codes. Inputs are `directory` (default `.`), `format` (default `table`), and `fail-on` (default `high`). Scanning this entire checkout includes the intentional vulnerable fixtures and therefore exits `1`.

```yaml
permissions:
  contents: read
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with:
          persist-credentials: false
      - uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020 # v4.4.0
        with:
          node-version: '>=22.18.0 <23'
      - uses: ./
        with:
          directory: .
          format: table
          fail-on: high
```

Action pins: [checkout v4.2.2](https://github.com/actions/checkout/releases/tag/v4.2.2), [setup-node v4.4.0](https://github.com/actions/setup-node/releases/tag/v4.4.0).

Run local verification in order:

```sh
npm run check
npm test
```

Test files run sequentially so deterministic wall-clock parser budgets do not compete with other test workers. Assertions and heap limits remain enabled.

## 日本語

### なぜ Atlas Shield か

個別のスキャナーでは、公開されたリソースを検出できても、その影響を決める ID と権限のつながりを見落とす場合があります。Atlas Shield は、GCP × Firebase の境界をまたぐ対応済みの証拠を関連付けます。公開された Firebase Rules、Cloud Run、Workload Identity Federation（WIF）を入口として、実行 ID またはフェデレーション ID、IAM 権限昇格、Secret Manager・BigQuery・Cloud Storage へのアクセスに至る経路を扱います。グラフでは、観測済みまたは静的に確認できた関係と、アプリケーションの動作やデプロイ環境に依存する `potential` な遷移を区別します。

AI SecOps には別の境界もあります。アシスタントは攻撃用の指示を含むクラウドログを受け取ったり、過剰な権限を持つツールを呼び出したりする可能性があります。MCP Airlock は、安全側に拒否するツール名ポリシーで転送要求を機械的に制限し、秘密情報の除去とインジェクションのサニタイズによって、信頼できないテレメトリーをレビュー可能な形にします。これらの制御には限界があり、上流プログラムの信頼性や、モデルへのあらゆる指示攻撃の無効化を証明するものではありません。

### クイックスタート・CLI

Node.js **>=22.18.0** で、この checkout から実行できます。インストール・ビルドは不要です。

```sh
node bin/atlas-shield.mjs audit .
node bin/atlas-shield.mjs audit /path/to/repository --format sarif
node bin/atlas-shield.mjs audit /path/to/repository --format json --emit-patch
node bin/atlas-shield.mjs audit fixtures/hardened-enterprise
```

この checkout には `fixtures/vulnerable-enterprise` に意図的な脆弱性を持つ fixture があるため、`audit .` は終了コード `1` を返します。`audit fixtures/hardened-enterprise` が終了コード `0` の正常例です。

npm パッケージの公開状況は**未確認**です。信頼できるリリースが npm で提供された場合の実行形式は次のとおりです。

```sh
npx @atlas-sec/shield audit .
```

既定値は `--format table`、`--fail-on high`、`--prover-mode gemini` です。出力形式は `table|json|sarif`、失敗とする重大度のしきい値は `blocker|high|medium` から選択します。レポートと変更案は `stdout`（標準出力）のみに出力します。`--emit-patch` は選択した形式のレポートにレビュー専用の unified diff を含めますが、適用は行わず、対象ファイルやクラウドリソースを変更しません。

| 終了コード | 意味 |
| --- | --- |
| `0` | 指摘と経路が指定しきい値未満で、不完全な走査や Prover のエラー・ブロッカーがない。 |
| `1` | 指定しきい値以上の指摘または経路がある、または Prover が `BLOCKER` を返した。 |
| `2` | 引数不正、不完全な走査、Prover の `ERROR`、またはプロキシ障害。不完全な走査と Prover のエラーは、しきい値以上の指摘より優先される。 |

### L0: 決定論的クロス境界攻撃グラフ

`audit` は対応するローカル入力を読み込み、統合された有向グラフを構築します。`--prove` を指定しなければオフラインで解析し、ネットワーク通信もモデルも使用しません。

対応入力は、Firebase の `firestore.rules` / `storage.rules` と `*.firestore.rules.sample` / `*.storage.rules.sample`、`firebase.json` に宣言された Rules パス、Terraform の `*.tf`、IAM の単語・camelCase 境界を持つエクスポート済み IAM ポリシー JSON `*iam*.json`、GitHub Actions の WIF ワークフロー（`.github/workflows/*.yml` / `*.yaml` およびファイル名に WIF を含む YAML）、エクスポート済み Cloud Audit Logs、SCC findings です。Terraform とワークフローの拡張子は大文字・小文字を区別しません。

**検出ルール一覧**

| ルール ID | 重大度 | 検出内容・解釈 |
| --- | --- | --- |
| `firebase/public-read` | `high` | Rules による無条件の公開読み取り。 |
| `firebase/public-write` | `high` | Rules による無条件の公開書き込み。 |
| `firebase/recursive-wildcard` | `high` | 再帰ワイルドカードを通じた公開読み取りによる子孫データの露出。 |
| `firebase/privilege-fields` | `medium` | 認証済みユーザーによるユーザードキュメントへの書き込みに、認識可能なフィールド許可リストがない。アプリケーションの信頼境界と検証処理の確認が必要。 |
| `gcp/public-service` | `high` | `allUsers` または `allAuthenticatedUsers` への公開 IAM 権限付与。 |
| `gcp/public-ingress` | `medium` | サービスの外部 ingress が有効。これだけでは未認証アクセスを証明しない。 |
| `iam/default-service-account` | `high` | 既定のサービスアカウントが、検出対象の強力なロールを保有。 |
| `iam/privilege-escalation` | `high` | 検出対象のサービスアカウント・IAM 権限昇格能力。適用範囲、条件、前提権限の確認が必要。 |
| `wif/unpinned-provider` | `high` | GitHub WIF プロバイダーに、認識可能な必須のリテラルリポジトリ制約がない。ワークフローの認証宣言も `potential` な辺を追加するが、プロバイダーの信頼設定を証明しない。 |
| `audit/logging-tampering` | `blocker` / `high` | ログシンクの削除・無効化、監査設定の除去、または疑わしい除外設定の変更。 |
| `audit/iam-persistence` | `high` | サービスアカウント鍵の作成、制約が不十分な WIF プロバイダー変更、または強力な権限・公開 IAM 権限の付与。 |
| `audit/impersonation-chain` | `high` | 疑わしい呼び出し元が関与する、対応済みの認証情報発行・トークン交換・委任チェーン。 |
| `audit/sensitive-data-access` | `high` | 公開・フェデレーション・未認証・既定アカウントによる、対応済みの機密情報・ストレージ・BigQuery アクセス。 |
| `scc/active-finding` | `blocker` / `high` / `medium` / `low` | 有効な SCC findings の `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` をそれぞれ対応付ける。 |
| `scan/*` | `high` | 危険・読み取り不能・形式不正・非対応の入力、または入力や経路列挙の上限到達により走査が不完全となる。終了コード `2` を返し、`--prove` は呼び出さない。 |

**ワークスペース走査とシンボリックリンク**

`EXCLUDED_DIRS` に含まれる、標準の生成物・SDK・キャッシュ・ローカルエージェント／IDE 状態・worktree の子ディレクトリは除外します。除外名は決定論的に `limitations` へ記録しますが、`.git` と `node_modules` は記録対象外です。除外される子ディレクトリ内のインフラ設定を含めるには、そのサブディレクトリを直接監査してください。`build` という名前の通常ファイルは、除外ディレクトリとして報告しません。

`firebase.json` が明示した `build/custom.rules` などの Rules パスは、シンボリックリンク、ルート外への逸脱、`.git`、`node_modules` のパス要素を含まなければ解析します。リポジトリ内の入力対象ではない通常ファイルへのリンクは無視します。リポジトリ内のディレクトリリンクは、正規の参照先を直接走査できる場合には再走査せず、その制約を記録します。

セキュリティ入力やその別名へのリンク、壊れたリンク、ルート外へのリンク、除外先へのリンク、正規の参照先の祖先にシンボリックリンクを含むもの、走査中に検出した通常ファイル・ディレクトリ以外のエントリーは、安全側に拒否して終了コード `2` を返します。リンク元または正規の参照先のパス要素に `.github` があるシンボリックリンクも拒否します。通常のワークフローファイルは引き続き解析対象です。

**エクスポート済みテレメトリーと関連付け**

Cloud Audit Logs は JSON 配列、`{ "entries": [...] }`、`protoPayload` を含む単一オブジェクト、NDJSON に対応します。発見対象は、`.json` / `.ndjson` のファイル名に明示的な `cloud-audit` / `cloudaudit` / `gcp-audit` / `audit-log(s)` の単語境界または camelCase 境界があるものです。例は `cloud-audit.json`、`cloud-audit.ndjson`、`cloudaudit.json`、`gcp-audit.json`、`audit-log.json`、`audit_logs.ndjson`、`projectAuditLogs.json` です。一般的なツールの `audit.json`、`npm-audit.json`、`*.audit.json`、`*.audit.ndjson` レポートは無視します。明示的に拒否された呼び出しは侵害の根拠として扱いません。成功した認証情報イベントは、共通の `identity:<service-account>` ノードを通じて静的 IAM 権限と結合できます。

SCC は配列、`{ "findings": [...] }`、`{ "listFindingsResults": [...] }`、`gcloud` エクスポートの `{ finding, resource }` 項目に対応します。`*scc*.json` の発見には単語・camelCase 境界が必要です。`scc-findings.json` や `projectSccReport.json` が該当し、`soccer.json` のような無関係な名前は無視します。`INACTIVE` の findings と `MUTED` のレコードは除外します。有効な公開露出を、一意に対応する Terraform の Cloud Run／Functions の実行 ID と、正規化したストレージ・機密情報・データセットのノードへ関連付けます。アプリケーションを介した実行 ID への遷移は `potential` のままです。エクスポート済みの観測結果は、現在のクラウド状態を検証するものではありません。

両テレメトリーパーサーは、認識した秘密情報を除去し、保存するテキストから制御文字を取り除きます。形式不正のエクスポートや上限を超えた主要フィールドは安全側に拒否します。テレメトリーの修正案はレビュー用の助言のみで、パッチは生成しません。

| 制限対象 | 上限 |
| --- | --- |
| ワークスペース走査 | 深さ `<= 64`、エントリー数 `<= 20,000`。 |
| 入力バイト数 | 1 ファイル `<= 1 MiB`、1 回の走査 `<= 32 MiB`。 |
| Firebase Rules のスコープ展開 | match の深さ `<= 64`、結合パス長 `<= 4096` 文字。 |
| テレメトリーレコード | 1 ファイル `<= 10,000` 件。 |
| 監査ログの権限展開 | 1 ファイルの binding/member 展開の合計 `<= 10,000` 件。 |
| 保存するテレメトリーテキスト・主要フィールド | ラベルと証拠は `<= 512` 文字、主要フィールドは `<= 2048` 文字。 |
| 攻撃経路の列挙 | 経路数 `<= 1,000`、1 経路のノード数 `<= 64`、遷移の探索回数 `<= 20,000`。 |

**解析の限界:** Rules 式、Terraform の変数・モジュール・動的な式、カスタムロール、ワークフロー式は完全には評価しません。静的解析は、実環境のポリシーや実行時の攻撃成立を証明しません。`limitations` と `potential` な経路をデプロイ環境に照らして確認してください。**終了コード `0` は安全性の保証ではありません**。走査中は入力ファイルを変更しないでください。

### L1: ゼロトラスト読み取り専用 MCP Airlock

Airlock は改行区切りの **stdio JSON-RPC 2.0** を仲介し、安全側に拒否する読み取り動詞ポリシーと任意のサーバープロファイルでツール名を制限します。認識した秘密情報を除去し、信頼できない応答をサニタイズします。ツールは共通ポリシーと選択したプロファイルの両方で許可される必要があり、プロファイルが共通の変更操作禁止を緩和することはありません。

信頼できる上流プログラムを指定して Airlock を起動するよう、MCP クライアントを設定します。`sanitize` は標準入力からテレメトリーを読み込みます。

```sh
node bin/atlas-shield.mjs airlock --profile scc --upstream-cmd /path/to/trusted-mcp-server
node bin/atlas-shield.mjs sanitize < telemetry.txt
node bin/atlas-shield.mjs mcp-config --profile scc --profile firebase --client gemini
node bin/atlas-shield.mjs mcp-config --client agy
```

引数ごとに `--upstream-arg` を繰り返します。フラグには `--upstream-arg=<value>` 形式を使い、例えば `--upstream-arg=--flag` と記述します。インストール済み CLI の形式は `atlas-shield airlock [--profile <name>] --upstream-cmd <cmd> [--upstream-arg <arg>...]` と `atlas-shield mcp-config [--profile <name>...] [--client agy|gemini]` です。

`mcp-config` の既定クライアントは `gemini`、既定の対象は全 7 プロファイルです。どちらのクライアントにも `mcpServers` JSON を `stdout` のみに出力します。この生成処理は上流バイナリーの実行・検証、設定ファイルへの書き込み、ホームディレクトリへの変更を行いません。生成したラッパーは、クライアントの実行可能ファイル検索パスに `atlas-shield` があることを前提とします。`npx` テンプレートは `--no-install` を使い、上流のフラグを `--upstream-arg=<value>` として保持します。

**Airlock プロファイル** — コマンドは `src/airlock/profiles.ts` にある利用者導入済み上流用のテンプレートであり、実接続を検証済みという意味ではありません。

| プロファイル ID | 読み取り範囲 | 上流コマンドのテンプレート | 上流の参照先 |
| --- | --- | --- | --- |
| `scc` | Security Command Center の findings・セキュリティ状態 | `uvx mcp-security-scc` | [google/mcp-security](https://github.com/google/mcp-security) |
| `secops` | Security Operations のテレメトリー・検出結果 | `uvx google-secops-mcp` | [google/mcp-security](https://github.com/google/mcp-security) |
| `firebase` | Firebase のプロジェクト・アプリケーション・データ | `npx --no-install firebase-tools experimental:mcp` | [Firebase MCP ドキュメント](https://firebase.google.com/docs/ai-assistance/mcp-server) |
| `cloudrun` | Cloud Run のサービス・リビジョン・ジョブ・ログ | `npx --no-install @google-cloud/cloud-run-mcp` | 利用者が導入する `@google-cloud/cloud-run-mcp` パッケージ |
| `developer-knowledge` | 開発者向けドキュメント・リファレンス | `uvx google-developer-knowledge-mcp` | [Google Developer Knowledge MCP](https://developers.google.com/knowledge/mcp) |
| `prowler` | Prowler の findings・チェック・コンプライアンス | `uvx prowler-mcp` | [Prowler MCP 発表](https://prowler.com/blog/prowler-launches-lighthouse-ai-and-mcp-server-bringing-autonomous-security-to-devsecops-teams) |
| `semgrep` | Semgrep のルール・findings・設定 | `uvx semgrep-mcp` | [Semgrep MCP リポジトリ](https://github.com/semgrep/mcp) |

**セキュリティ境界:** Atlas Shield は HTTP MCP トランスポートを備えていません。Google Developer Knowledge のような HTTP 専用サービスには、別途信頼性を確認した stdio ブリッジが必要です。テンプレートはブリッジの動作を示す証拠ではありません。実接続は未検証です。上流バイナリー・引数・認証情報の制限と検証は利用者の責任です。**ツール名の字句的なフィルタリングでは、意味的な読み取り専用動作を証明できません**。プロファイルはサーバーの身元を認証しません。サニタイズもプロンプトインジェクションに対する完全な防御ではありません。

### L2: 任意の Sovereign AI Prover

```sh
node bin/atlas-shield.mjs audit . --prove --prover-mode gemini
node bin/atlas-shield.mjs audit . --prove --prover-mode dual
```

**Pure Gemini Sovereign Mode**（既定の `gemini`）は、`gemini-4-argon-high` による `argonArchitect` と `gemini-4-hydrogen-xhigh` による `geminiRedTeam` の独立した検証を、Gemini、Vertex AI、または設定した `agy` アダプターで実行します。Google 以外の Prover バックエンドは必要ありません。

`dual` は、`gemini-4-argon-high` による `argonHigh` と、導入・認証済みの `codex` CLI による `astraUltra` を実行します。後者は `gpt-6-astra`、ultra 推論、読み取り専用 sandbox、一時セッションを使用します。アダプターは、設定されていれば `CODEX_HOME` と `OPENAI_API_KEY` を引き継ぎます。どちらのモードも各系統に同一のサニタイズ済み証拠を渡し、系統間で回答を共有しません。

| 設定 | 必要な準備 |
| --- | --- |
| `ATLAS_GEMINI_BACKEND=gemini`（既定） | `GEMINI_API_KEY` |
| `ATLAS_GEMINI_BACKEND=vertex` | `GOOGLE_CLOUD_PROJECT`、`GOOGLE_CLOUD_LOCATION`、`GOOGLE_OAUTH_ACCESS_TOKEN` |
| `ATLAS_GEMINI_BACKEND=agy` | plan モードと sandbox に対応する、導入・認証済みの `agy` CLI。 |
| `--prover-mode dual` | 上記 Google バックエンドのいずれかと、導入・認証済みの `codex` CLI。設定済みの `CODEX_HOME` と `OPENAI_API_KEY` を引き継ぐ。 |

**Non-Majority Fail-Closed Gate** は、ある系統の攻撃成立の主張を多数決で打ち消しません。

| 判定 | 意味 |
| --- | --- |
| `BLOCKER` | いずれかの系統が手順と証拠を伴うスキーマに適合した攻撃証明を返した。他方が成功・失敗していても優先する。 |
| `ERROR` | 有効な攻撃証明がなく、いずれかの系統で空・形式不正の出力、失敗、またはタイムアウトが発生した。 |
| `PASS` | 両系統が有効な成功応答を返し、与えた証拠から攻撃を成立させられなかった。 |

攻撃証明は**モデルが生成した主張であり、自動実行した攻撃ではありません**。`PASS` は安全性の保証ではありません。ローカル走査が不完全な場合は、Prover を呼び出さず終了コード `2` を返します。

`--prove` はサニタイズ済みの証拠を、選択したプロバイダーまたは CLI に送信します。認証情報、データ境界、保持期間、モデル利用権限、CLI sandbox の強制は環境側で設定する必要があります。モード名は閉域境界や保持ゼロを保証しません。プロバイダーとの実接続とモデルの提供状況は**未検証**です。

### GitHub Actions とローカル検証

Composite action には Node.js **>=22.18.0** が必要です。次の例は Atlas Shield の checkout 内から `uses: ./` を使います。`directory` には checkout 済みの対象を指定してください。オフラインで実行し、CLI の終了コードを保持します。入力は `directory`（既定 `.`）、`format`（既定 `table`）、`fail-on`（既定 `high`）です。この checkout 全体を走査すると意図的な脆弱性 fixture を含むため、終了コード `1` になります。

```yaml
permissions:
  contents: read
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with:
          persist-credentials: false
      - uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020 # v4.4.0
        with:
          node-version: '>=22.18.0 <23'
      - uses: ./
        with:
          directory: .
          format: table
          fail-on: high
```

固定した Action のバージョン: [checkout v4.2.2](https://github.com/actions/checkout/releases/tag/v4.2.2)、[setup-node v4.4.0](https://github.com/actions/setup-node/releases/tag/v4.4.0)。

ローカル検証は次の順で実行します。

```sh
npm run check
npm test
```

決定論的なパーサーの実時間上限テストが他のテストワーカーと競合しないよう、テストファイルは直列実行します。アサーションとヒープ上限は有効なまま維持します。
