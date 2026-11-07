# Contributing to Atlas Shield / コントリビューションガイド

[English](#english) · [日本語](#日本語)

## English

### Runtime & Zero-Build Setup

Use Node.js **`>=22.18.0`**; CI pins `'>=22.18.0 <23'`. Atlas Shield runs directly on Node.js native erasable TypeScript support. No install or build step is required. From the repository root, run:

```sh
node bin/atlas-shield.mjs --help
```

### Core Engineering Invariants

1. **Zero npm dependencies:** Keep `"dependencies": {}` and `"devDependencies": {}` in `package.json`. Use only Node.js built-in modules, such as `node:fs`, `node:path`, `node:module`, `node:crypto`, `node:child_process`, `node:util`, `node:readline`, and `node:test`. Use erasable TypeScript syntax: no `enum`, `namespace`, or parameter properties.
2. **Distribution file allowlist:** Keep `package.json` `"files"` strictly set to `["bin/", "src/", "LICENSE", "README.md", "action.yml"]`.
3. **Read-only, offline-default operation and bounded complexity:** Never mutate target repositories, user home directories, or cloud resources. Keep audits offline unless the caller passes `--prove`. Preserve linear-time `O(N)` parser budgets, `<= 1 MiB` per-file and `<= 32 MiB` per-scan caps, `256 MiB` test heap bounds, and fail-closed `scan/*` diagnostics. An incomplete scan must exit `2` without starting the prover.
4. **Repository hygiene:** Place source, tests, and synthetic fixtures in the existing `src/`, `test/`, and `fixtures/` directories without adding unnecessary subdirectories. Never create files literally named `firestore.rules`, `storage.rules`, or `database.rules.json` in this repository; use `*.firestore.rules.sample` / `*.storage.rules.sample` in `fixtures/`. Never include real credentials or literal PEM private-key headers in code, tests, or fixtures. Save text as UTF-8 without a BOM.
5. **Bilingual documentation parity:** Keep `## English` and `## 日本語` in `README.md`, `SECURITY.md`, and `CONTRIBUTING.md` factually synchronized, including exact CLI flags, bounds, and honest security caveats. Do not overclaim guarantees or add unverified external links or badges. Preserve the documented limits: exit `0` is not a completeness guarantee, lexical Airlock filtering does not prove semantic read-only behavior, sanitization is not a complete prompt-injection defense, and prover mode names do not guarantee provider data retention or perimeter settings. `README.md` also provides a collapsed `<details>` 20-language quick overview that delegates authoritative technical and security-boundary specifications to `## English` and `## 日本語`.

### Deterministic Verification Before Submitting Changes

Run these commands from the repository root and require exit `0` for each:

```sh
npm run check
npm test
node bin/atlas-shield.mjs audit fixtures/hardened-enterprise
```

`npm test` runs test files sequentially (`--test-concurrency=1`) so deterministic wall-clock parser benchmarks do not compete across workers.

### License

By contributing, you agree that your contributions are licensed under **Apache-2.0**, as specified in [LICENSE](LICENSE).

## 日本語

### 実行環境とビルド不要のセットアップ

Node.js **`>=22.18.0`** を使用してください。CIでは `'>=22.18.0 <23'` に固定しています。Atlas ShieldはNode.jsのネイティブなerasable TypeScript対応を利用して直接実行します。インストールやビルドは不要です。リポジトリルートで次を実行してください。

```sh
node bin/atlas-shield.mjs --help
```

### 開発で守る不変条件

1. **npm依存関係ゼロ:** `package.json` の `"dependencies": {}` と `"devDependencies": {}` を維持してください。`node:fs`、`node:path`、`node:module`、`node:crypto`、`node:child_process`、`node:util`、`node:readline`、`node:test` など、Node.js組み込みモジュールだけを使ってください。erasable TypeScript構文を使用し、`enum`、`namespace`、parameter propertiesは使用しないでください。
2. **配布ファイルの許可リスト:** `package.json` の `"files"` は、厳密に `["bin/", "src/", "LICENSE", "README.md", "action.yml"]` のまま維持してください。
3. **読み取り専用・既定でオフラインの動作と計算量の上限:** 対象リポジトリ、ユーザーのホームディレクトリ、クラウドリソースを変更しないでください。監査は呼び出し側が `--prove` を指定しない限りオフラインで動作させてください。パーサーの線形時間 `O(N)` の処理予算、1ファイル `<= 1 MiB`・1回の走査 `<= 32 MiB` の上限、テスト時の `256 MiB` ヒープ上限、fail-closedな `scan/*` 診断を維持してください。不完全な走査はproverを起動せず、終了コード `2` で終了しなければなりません。
4. **リポジトリの衛生管理:** ソース、テスト、合成fixtureは既存の `src/`、`test/`、`fixtures/` に置き、不要なサブディレクトリを追加しないでください。このリポジトリ内に `firestore.rules`、`storage.rules`、`database.rules.json` という名前そのもののファイルを作成しないでください。`fixtures/` では `*.firestore.rules.sample` / `*.storage.rules.sample` を使ってください。実際の認証情報やPEM秘密鍵ヘッダーのリテラルをコード・テスト・fixtureへ含めないでください。テキストはBOMなしのUTF-8で保存してください。
5. **日英ドキュメントの同等性:** `README.md`、`SECURITY.md`、`CONTRIBUTING.md` の `## English` と `## 日本語` は、正確なCLIフラグ、上限値、誠実なセキュリティ上の注意点を含め、事実を一致させてください。保証を過大に表現せず、未検証の外部リンクやバッジを追加しないでください。文書化された限界を維持してください。終了コード `0` は解析の完全性を保証せず、Airlockの字句フィルタリングは実際の動作が読み取り専用であることを証明せず、サニタイズは完全なプロンプト注入対策ではなく、proverのモード名はプロバイダーのデータ保持や境界設定を保証しません。`README.md` には折りたたみ式 `<details>` の20言語クイック概要も用意されていますが、正式な技術仕様およびセキュリティ境界は `## English` と `## 日本語` に委譲されます。

### 変更提出前の決定論的な検証

リポジトリルートで次のコマンドを実行し、すべて終了コード `0` となることを確認してください。

```sh
npm run check
npm test
node bin/atlas-shield.mjs audit fixtures/hardened-enterprise
```

`npm test` はテストファイルを逐次実行します（`--test-concurrency=1`）。これにより、決定論的な実時間ベースのパーサーベンチマークが複数ワーカー間で競合するのを防ぎます。

### ライセンス

コントリビューションを行うことで、提供した変更が [LICENSE](LICENSE) に定める **Apache-2.0** の下でライセンスされることに同意するものとします。
