# Security Policy / セキュリティポリシー

[English](#english) · [日本語](#日本語)

## English

### Supported Versions

| Version | Security support |
| --- | --- |
| `0.2.x` | Supported |
| `< 0.2.0` | Unsupported |

### Reporting a Vulnerability

Use **GitHub Private Vulnerability Reporting** on the GitHub repository hosting this project: open the **Security** tab, then **Report a vulnerability**. Do not open public Issues, Discussions, or Pull Requests containing undisclosed vulnerability or exploit details. If private reporting is unavailable, keep those details private. No response-time SLA or monetary bounty is promised.

**Zero-secret hygiene:** Never attach live GCP service-account keys, OAuth/JWT tokens, PEM private keys, customer Cloud Audit Logs, or production resource identifiers. Construct a minimal synthetic reproduction, similar to the examples in `fixtures/`, using only invented data.

Include the following in your private report:

- Atlas Shield version or commit hash, and Node.js version.
- The exact CLI command, Airlock profile (if applicable), and flags.
- Synthetic reproduction input and steps to reproduce.
- Expected versus actual security behavior.

### In-Scope Security Defects

- Scan-root or symlink escape in `scanDirectory` / `readSafeSource`, or unintended mutation of scanned files, user home directories, or cloud state.
- Bypass of the Airlock's lexical read-verb policy (`isReadOnlyTool`) or selected profile allowlist (`AIRLOCK_PROFILES`) on stdio JSON-RPC `tools/list` / `tools/call`.
- Credential redaction bypass for documented secret formats in `redactSecrets`, or bypass of BiDi/control-character stripping.
- Algorithmic complexity or memory exhaustion, including ReDoS or unbounded allocation, within the documented input bounds: `<= 1 MiB` per file, `<= 32 MiB` per scan, `<= 10,000` telemetry records per file, and `<= 10,000` combined binding/member grant expansions per file.
- Fail-open exit codes or prover verdict handling, including `runProver` returning `PASS` on malformed or timed-out lane output or a lane's valid exploit proof, or `--prove` running on an incomplete local scan.

### Documented Architectural Boundaries (Not Standalone Bypasses)

These documented limits alone do not establish a security bypass. A reproducible violation of the protections above remains in scope.

- Unmodeled Firebase Rules functions or compound expressions; dynamic Terraform variables, modules, `count`, `for_each`, or custom roles; and dynamic GitHub workflow expressions. Exit `0` is not a completeness or security guarantee.
- Malicious or semantically mutating upstream MCP binaries disguised behind read-only tool names. Callers must independently trust and restrict upstream binaries, arguments, and credentials; lexical filtering cannot prove semantic read-only behavior.
- Novel natural-language prompt-injection phrasing outside heuristic quarantine patterns. `sanitizeTelemetry` and `<untrusted_telemetry>` framing are defense in depth, not a complete prompt-injection proof.
- Provider-side data retention, perimeter configuration, and CLI sandbox setup when the caller explicitly enables `--prove`. This option transmits sanitized evidence to the selected provider/CLI; mode names do not guarantee a closed perimeter or zero retention.

## 日本語

### サポート対象バージョン

| バージョン | セキュリティサポート |
| --- | --- |
| `0.2.x` | サポート対象 |
| `< 0.2.0` | サポート対象外 |

### 脆弱性の報告

このプロジェクトをホストするGitHubリポジトリの **GitHub Private Vulnerability Reporting** を使用してください。**Security** タブから **Report a vulnerability** を開きます。未公開の脆弱性や攻撃手順の詳細を含む公開Issue、Discussion、Pull Requestは作成しないでください。非公開報告機能が利用できない場合も、詳細を公開しないでください。応答時間のSLAや金銭的な報奨金は約束していません。

**秘密情報を含めない報告:** 有効なGCPサービスアカウントキー、OAuth/JWTトークン、PEM秘密鍵、顧客のCloud Audit Logs、本番リソースの識別子は絶対に添付しないでください。`fixtures/` の例と同様に、架空のデータだけを使った最小限の再現例を作成してください。

非公開報告には次の情報を含めてください。

- Atlas Shieldのバージョンまたはコミットハッシュ、およびNode.jsのバージョン。
- 正確なCLIコマンド、該当する場合はAirlockプロファイル、およびフラグ。
- 合成した再現入力と再現手順。
- セキュリティ上の期待する挙動と実際の挙動。

### 報告対象のセキュリティ欠陥

- `scanDirectory` / `readSafeSource` における走査ルート外への逸脱やシンボリックリンクによる逸脱、または走査対象ファイル、ユーザーのホームディレクトリ、クラウド状態への意図しない変更。
- stdio JSON-RPCの `tools/list` / `tools/call` における、Airlockの読み取り動詞に基づく字句ポリシー（`isReadOnlyTool`）や選択されたプロファイルの許可リスト（`AIRLOCK_PROFILES`）の回避。
- `redactSecrets` で文書化された秘密情報形式の秘匿化の回避、またはBiDi文字・制御文字の除去の回避。
- 文書化された入力上限内で発生する、ReDoSや無制限のメモリ確保を含む計算量の問題・メモリ枯渇。上限は1ファイル `<= 1 MiB`、1回の走査 `<= 32 MiB`、1ファイルのテレメトリーレコード `<= 10,000` 件、1ファイルのbinding/member権限展開の合計 `<= 10,000` 件です。
- fail-openとなる終了コードやprover判定の処理。不正形式・タイムアウトしたレーン出力や、レーンからの有効な攻撃成立の証拠に対して `runProver` が `PASS` を返す場合、不完全なローカル走査で `--prove` が実行される場合を含みます。

### 文書化された設計上の境界（それ自体は防御の回避ではないもの）

次の文書化された限界だけでは、セキュリティ上の防御を回避したことにはなりません。上記の保護に対する再現可能な違反は、引き続き報告対象です。

- モデル化されていないFirebase Rulesの関数・複合式、動的なTerraform変数・モジュール・`count`・`for_each`・カスタムロール、動的なGitHubワークフロー式。終了コード `0` は解析の完全性や安全性を保証しません。
- 読み取り専用のツール名を装った、悪意ある上流MCPバイナリや実際には変更操作を行う上流MCPバイナリ。呼び出し側は、上流バイナリ・引数・認証情報の信頼性を独立に確認し、制限する必要があります。字句フィルタリングでは、実際の動作が読み取り専用であることを証明できません。
- ヒューリスティックな隔離パターンに該当しない、新しい自然言語のプロンプト注入表現。`sanitizeTelemetry` と `<untrusted_telemetry>` による囲い込みは多層防御であり、プロンプト注入を完全に防ぐ証明ではありません。
- 呼び出し側が明示的に `--prove` を有効にした場合の、プロバイダー側のデータ保持、境界設定、CLIサンドボックスの設定。このオプションはサニタイズ済みの証拠を選択されたプロバイダー／CLIへ送信します。モード名は閉じた境界やゼロ保持を保証しません。
