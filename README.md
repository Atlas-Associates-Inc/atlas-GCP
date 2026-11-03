# Atlas Shield

Offline GCP × Firebase attack-path analysis, a read-only MCP Airlock, and optional AI evidence review. Apache-2.0; Node.js **>=22.18.0**; no runtime or development npm dependencies.

GCP × Firebase の境界をまたぐ攻撃経路を静的解析し、MCP の読み取り専用ポリシーと任意の AI 検証を提供します。Apache-2.0、Node.js **>=22.18.0**、npm 依存パッケージなし。

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

`audit` reads Firebase rules and `firebase.json`, Terraform, exported IAM policy JSON, and GitHub Actions WIF declarations. It connects supported evidence across entry points, runtime identities, IAM grants, and data access. Without `--prove`, analysis is offline and uses no model.

Firebase Rules・設定、Terraform、IAM ポリシー JSON、GitHub Actions の WIF 宣言を読み、入口・実行 ID・IAM 権限・データアクセスを関連付けます。`--prove` がなければ、通信やモデルを使用しません。

Deterministic, bounded static analysis does not prove deployed policy or runtime exploitability. Rules expressions, Terraform variables/modules/dynamic expressions, custom roles, and workflow expressions are not fully evaluated. Review `limitations` and potential paths against deployment context; exit `0` is not a security guarantee. Keep input files stable while scanning.

決定論的な静的解析ですが、上記の構文や動的設定は完全には評価しません。`limitations` と候補経路を実環境に照らして確認してください。終了コード `0` は安全性の保証ではありません。走査中は入力を変更しないでください。

## L1: Zero-Trust MCP Airlock / MCP 読み取り専用ポリシー

The Airlock proxies newline-delimited JSON-RPC 2.0 over **stdio**, filters tool names through a fail-closed read-verb policy, redacts recognized secrets, and sanitizes untrusted response text. Configure your MCP client to launch:

Airlock は **stdio** の改行区切り JSON-RPC 2.0 を仲介し、許可された読み取り動詞を含むツール名だけを通し、認識した秘密情報や不審な応答テキストを処理します。MCP クライアントから以下の形式で起動します。

```sh
node bin/atlas-shield.mjs airlock --upstream-cmd /path/to/trusted-mcp-server
# Repeat --upstream-arg for each argument; use --upstream-arg=--flag for flags.
node bin/atlas-shield.mjs sanitize < telemetry.txt
```

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
