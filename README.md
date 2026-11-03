# Atlas Shield v0.2.0

Offline GCP × Firebase attack-path analysis with Cloud Audit Logs threat hunting and SCC posture correlation, seven read-only MCP Airlock profiles, and optional AI evidence review. Apache-2.0; Node.js **>=22.18.0**; no runtime or development npm dependencies.

GCP × Firebase の攻撃経路に Cloud Audit Logs の脅威検出と SCC の構成評価を関連付け、7 種の MCP 読み取り専用プロファイルと任意の AI 検証を提供します。Apache-2.0、Node.js **>=22.18.0**、npm 依存パッケージなし。

## Quickstart / はじめに

From this checkout; no install or build step is required. この checkout ではインストール・ビルド不要です。

```sh
node bin/atlas-shield.mjs audit .
node bin/atlas-shield.mjs audit /path/to/repository --format sarif
node bin/atlas-shield.mjs audit /path/to/repository --format json --emit-patch
```

This checkout includes intentionally vulnerable fixtures, so `audit .` exits `1`. For a clean example, use `audit fixtures/hardened-enterprise`.
この checkout 全体の監査は脆弱fixtureにより `1` で終了します。正常例は `audit fixtures/hardened-enterprise` です。

Package publication has **not been verified**. Once a trusted release is available on npm, the package entry point is:
パッケージの公開状況は**未確認**です。信頼できるリリースが npm で提供された場合の実行形式:

```sh
npx @atlas-sec/shield audit .
```

Defaults: `--format table`, `--fail-on high`, `--prover-mode gemini`. Formats: `table|json|sarif`; thresholds: `blocker|high|medium`. Reports go to stdout. `--emit-patch` includes proposed unified diffs for review; it never applies them. Audit does not modify target files or cloud resources.

既定値は上記のとおりです。レポートは標準出力へ出力します。`--emit-patch` はレビュー用の修正案を含めるだけで、対象ファイルやクラウドを変更しません。

| Exit | Meaning / 意味 |
| --- | --- |
| `0` | Findings below the selected threshold / 指定しきい値未満 |
| `1` | Threshold met or prover `BLOCKER` / しきい値以上、または検証が `BLOCKER` |
| `2` | Invalid arguments, incomplete scan, prover `ERROR`, or proxy failure / 引数不正・不完全な走査・検証 `ERROR`・プロキシ障害 |

## L0: Cross-Boundary Attack Graph / 境界をまたぐ攻撃グラフ

`audit` reads Firebase rules and `firebase.json`, Terraform, exported IAM policy JSON, GitHub Actions WIF declarations, exported Cloud Audit Logs, and SCC findings. It connects supported evidence across entry points, runtime identities, IAM grants, and data access. Without `--prove`, analysis is offline and uses no model.

Firebase Rules・設定、Terraform、IAM ポリシー JSON、GitHub Actions の WIF 宣言、エクスポート済み Cloud Audit Logs・SCC findings を読み、入口・実行 ID・IAM 権限・データアクセスを関連付けます。`--prove` がなければ、通信やモデルを使用しません。

Cloud Audit Logs accept JSON arrays, `{ "entries": [...] }`, a single `protoPayload` object, or NDJSON. Discovery recognizes `*.audit.json`, `*.audit.ndjson`, and token/camelCase forms such as `cloudaudit.json`, `cloud-audit.ndjson`, `audit-logs.json`, and `projectAuditLogs.json`. The four rule families cover logging tampering, identity persistence, impersonation, and sensitive data access. Explicitly denied calls do not establish compromise. Successful credential events can join static IAM grants through `identity:<service-account>` nodes.

Cloud Audit Logs は配列・`entries`・単一の `protoPayload` 付きオブジェクト・NDJSON に対応します。上記のファイル名を単語境界で識別し、ログ設定改変・永続的な認証権限・なりすまし・機密データアクセスを検出します。明示的に拒否された呼び出しを侵害として扱いません。成功した認証情報の発行は、同じサービスアカウントの静的 IAM 権限へ結合します。

SCC accepts arrays, `{ "findings": [...] }`, `{ "listFindingsResults": [...] }`, and `{ finding, resource }` items from `gcloud` exports. `*scc*.json` discovery requires a token/camelCase boundary, as in `scc-findings.json` or `projectSccReport.json`; unrelated names such as `soccer.json` are ignored. `INACTIVE` and `MUTED` records are excluded. Active public exposure joins uniquely matched Terraform Cloud Run/Functions runtime identities and normalized storage, secret, and dataset nodes. Runtime identity transitions remain `potential` because application behavior is required; exported observations do not verify current cloud state.

SCC は配列・`findings`・`listFindingsResults` と `gcloud` の `{ finding, resource }` 形式に対応します。`scc` の単語・camelCase 境界でファイルを識別し、`INACTIVE`・`MUTED` を除外します。有効な公開露出を Terraform の Cloud Run／Functions の実行 ID やストレージ・機密情報・データセットへ関連付けます。アプリケーション経由の実行 ID への遷移は `potential` のままです。エクスポート内容は現在のクラウド状態を保証しません。

Both telemetry parsers redact recognized secrets, remove controls from stored text, cap labels/evidence at 512 characters, and reject malformed exports or key fields longer than 2048 characters. Each file permits at most 10,000 records; audit bindings/members share a 10,000-expansion budget. Incomplete scans exit `2` and suppress `--prove`. Telemetry remediation is review-only advice with no generated patch.

両パーサーは認識した秘密情報を除去し、制御文字を処理して表示・証跡を 512 文字以内にします。形式不正・2048 文字を超える主要項目・1 ファイル 10,000 件超を拒否します。監査ログの binding/member 展開も合計 10,000 件以内です。不完全な走査は終了コード `2` となり、`--prove` を呼びません。テレメトリーの修正案はレビュー用の助言のみです。

Deterministic, bounded static analysis does not prove deployed policy or runtime exploitability. Rules expressions, Terraform variables/modules/dynamic expressions, custom roles, and workflow expressions are not fully evaluated. Review `limitations` and potential paths against deployment context; exit `0` is not a security guarantee. Keep input files stable while scanning.

決定論的な静的解析ですが、上記の構文や動的設定は完全には評価しません。`limitations` と候補経路を実環境に照らして確認してください。終了コード `0` は安全性の保証ではありません。走査中は入力を変更しないでください。

## L1: Zero-Trust MCP Airlock / MCP 読み取り専用ポリシー

The Airlock proxies newline-delimited JSON-RPC 2.0 over **stdio**, filters tool names through a fail-closed read-verb policy and an optional server profile, redacts recognized secrets, and sanitizes untrusted response text. A profile never relaxes the global mutation block. Configure your MCP client to launch:

Airlock は **stdio** の改行区切り JSON-RPC 2.0 を仲介し、読み取り動詞と任意のサーバープロファイルでツール名を制限します。プロファイル指定でも更新操作の禁止は維持されます。認識した秘密情報や不審な応答テキストを処理し、MCP クライアントから以下の形式で起動します。

```sh
node bin/atlas-shield.mjs airlock --profile scc --upstream-cmd /path/to/trusted-mcp-server
# Repeat --upstream-arg for each argument; use --upstream-arg=--flag for flags.
node bin/atlas-shield.mjs sanitize < telemetry.txt
node bin/atlas-shield.mjs mcp-config --profile scc --profile firebase --client gemini
node bin/atlas-shield.mjs mcp-config --client agy
```

Installed CLI forms: `atlas-shield airlock --profile <scc|secops|firebase|cloudrun|developer-knowledge|prowler|semgrep> --upstream-cmd ...` and `atlas-shield mcp-config [--profile <name>...] [--client agy|gemini]`.

`mcp-config` prints JSON templates wrapping caller-installed MCP binaries, with all seven profiles by default. It does not execute or verify upstream installations, write configuration files, or change home directories. Both supported clients receive the `mcpServers` format. The `npx` templates use `--no-install` and preserve flags as `--upstream-arg=<value>`.

`mcp-config` は利用者が導入した MCP バイナリーを包む JSON テンプレートを標準出力へ出します。既定は全 7 プロファイル、クライアントは `gemini` です。上流の実行・インストール確認・設定ファイルやホームの変更は行いません。`agy` と `gemini` は同じ `mcpServers` 形式を使用し、`npx` テンプレートは `--no-install`、引数は `--upstream-arg=<value>` 形式です。

Upstream references / 上流サーバーの参照先:

| Server | Primary source / 一次資料 |
| --- | --- |
| `scc-mcp`, `google-secops-mcp` | [google/mcp-security](https://github.com/google/mcp-security) |
| `google-developer-knowledge` | [Official Google developer documentation MCP / Google 公式開発資料 MCP](https://developers.google.com/knowledge/mcp) |
| `prowler-mcp` | [Prowler MCP announcement](https://prowler.com/blog/prowler-launches-lighthouse-ai-and-mcp-server-bringing-autonomous-security-to-devsecops-teams) |
| `semgrep-mcp` | [Semgrep MCP repository](https://github.com/semgrep/mcp) |
| `firebase-mcp-server` | [Firebase MCP documentation](https://firebase.google.com/docs/ai-assistance/mcp-server) |

Live integrations are unverified. HTTP-only services such as Google Developer Knowledge require a separately trusted stdio bridge; Atlas Shield has no HTTP MCP transport. Independently restrict and verify upstream binaries, arguments, and credentials. **Lexical tool-name filtering does not prove semantic read-only behavior**; sanitization is not a complete prompt-injection defense.

実接続は未検証です。HTTP サービスには信頼できる stdio ブリッジが別途必要です。上流プログラム・引数・認証情報は個別に信頼性と権限を確認してください。**ツール名だけでは読み取り専用を証明できず**、サニタイズも完全な防御ではありません。

## L2: Sovereign Prover / 任意の AI 検証

```sh
node bin/atlas-shield.mjs audit . --prove --prover-mode gemini
node bin/atlas-shield.mjs audit . --prove --prover-mode dual
```

**Pure Gemini Sovereign Mode** (`gemini`) runs standalone with two independent passes, `argonArchitect` and `geminiRedTeam`, using Gemini/Vertex AI (or the configured `agy` adapter). `dual` uses `argonHigh` plus `astraUltra`; the latter invokes an authenticated `codex` CLI with `gpt-6-astra`, ultra reasoning, a read-only sandbox, and an ephemeral session. Google lanes use `gemini-4-argon-high`.

`gemini` は Gemini / Vertex AI 単独で Architect と Red Team の 2 系統を実行します。`dual` は Argon High と Astra Ultra を使用します。各系統にはサニタイズ済みの同じ根拠を渡し、他方の回答は共有しません。

| Configuration | Required setup / 必要な設定 |
| --- | --- |
| `ATLAS_GEMINI_BACKEND=gemini` (default / 既定) | `GEMINI_API_KEY` |
| `ATLAS_GEMINI_BACKEND=vertex` | `GOOGLE_CLOUD_PROJECT`, `GOOGLE_CLOUD_LOCATION`, `GOOGLE_OAUTH_ACCESS_TOKEN` |
| `ATLAS_GEMINI_BACKEND=agy` | Installed, authenticated `agy` CLI supporting plan mode and sandbox / 対応 CLI の導入・認証 |
| `--prover-mode dual` | Google backend above plus installed, authenticated `codex`; its adapter forwards `CODEX_HOME` and `OPENAI_API_KEY` when set / Google 側設定と認証済み `codex` |

Any schema-valid exploit proof yields `BLOCKER`; otherwise an empty, malformed, failed, or timed-out lane yields `ERROR`. Proofs are model-generated claims with steps and evidence, not automatically executed exploits. `PASS` only means neither pass established an exploit from the supplied evidence. An incomplete local scan exits `2` without invoking the prover.

有効な形式の攻撃手順・根拠があれば `BLOCKER`、それがなく出力不正・失敗・タイムアウトがあれば `ERROR` です。攻撃手順はモデルの提示であり、自動再現はしません。ローカル走査が不完全なら、モデルを呼ばず終了コード `2` を返します。

`--prove` sends sanitized evidence to the selected provider/CLI. Credentials, data perimeter, retention, model access, and CLI sandbox enforcement require environment configuration. Zero retention is not guaranteed; live providers and model availability are unverified.

根拠は選択したプロバイダーまたは CLI に送信されます。認証・データ境界・保持期間・モデル利用権限・sandbox は環境側で設定してください。保持ゼロは保証せず、実接続とモデル提供状況は未検証です。

## GitHub Actions

The composite action requires Node.js >=22.18.0. This example runs from an Atlas Shield checkout using `uses: ./`; point `directory` at the checked-out target. It runs offline and preserves CLI exit codes. Inputs: `directory` (default `.`), `format` (`table`), `fail-on` (`high`).

以下は Atlas Shield の checkout 内で使う例です。対象 checkout のパスを `directory` に指定します。オフラインで実行し、CLI の終了コードを維持します。

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

Action pins: [checkout v4.2.2](https://github.com/actions/checkout/releases/tag/v4.2.2), [setup-node v4.4.0](https://github.com/actions/setup-node/releases/tag/v4.4.0). For local development / ローカル検証:

```sh
npm run check
npm test
```

Test files run sequentially so the fixed wall-clock parser budgets do not compete with other test workers. Existing assertions and heap limits remain enabled.
固定の処理時間を測る性能テスト同士の競合を避けるため、テストファイルは直列実行します。検証条件とヒープ上限は維持しています。
