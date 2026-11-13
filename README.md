# idp

> **免責事項**
>
> - このプロジェクトは趣味の範囲で開発しています。
> - 脆弱性など、セキュリティインシデントにつながる指摘があっても、責任を持って対応することはありません。したがって、セキュリティの窓口も設けていません。
> - このプロジェクトの名前などを商標として使うことは推奨しません。

Cloudflare Workers の無料枠と D1 だけで動く、パスキー専用の最小構成 OIDC IdP です。
管理は、別の管理用の Worker を、手元の Go の CLI `idpctl` から呼んで行います。管理者は、`idpctl` が要求ごとに付ける HTTP Message Signatures（RFC 9421）の署名で確かめます。

リポジトリを fork し、自分の Cloudflare アカウントの情報を入れるだけで、自分のセルフホストのアプリのための IdP を持てることを目指しています。

## 主な機能

- ユーザーの認証手段はパスキーだけです。パスワード、メール、SMS は使いません。
- OIDC の認可コードフローで RP にサインインを提供します。PKCE（`S256`）とユーザー検証（UV）は必須で、リフレッシュトークンは発行しません。
- アプリ（RP）ごとに、どのユーザーやグループが使えるかを管理できます。
- サインイン中の本人は、アカウントページで自分のパスキーを一覧し、追加し、失効させられます。
- RP はサインアウトのとき、IdP のセッションも終わらせられます（RP-Initiated Logout）。
- 管理操作は `idpctl` からだけ行い、IdP の Worker には管理 UI も管理用のエンドポイントも置きません。

## 準拠する標準

仕様の MUST だけでなく、セキュリティ上の SHOULD にも従います。詳細と、意図して外している箇所は [標準準拠](docs/design/standards-compliance.md) にあります。

| 分野 | 標準 |
| --- | --- |
| OIDC | OpenID Connect Core 1.0、Discovery 1.0、RP-Initiated Logout 1.0 |
| OAuth | RFC 6749、Security BCP（RFC 9700）、PKCE（RFC 7636）、認可レスポンスの `iss`（RFC 9207）、ネイティブアプリ（RFC 8252） |
| トークン | JWT（RFC 7519、RFC 8725）、JWT アクセストークン（RFC 9068）、JWS と JWK（RFC 7515、RFC 7517）、完全指定のアルゴリズム（RFC 9864） |
| パスキー | WebAuthn Level 3 |
| 管理者の認証 | HTTP Message Signatures（RFC 9421）と `Content-Digest`（RFC 9530） |

## 構成

利用者と RP に公開する IdP の Worker と、別のホスト名の管理用の Worker が、同じ D1 を使います。管理用の Worker は `idpctl` の RFC 9421 の署名で管理者を確かめます。
要素のつながりとデプロイのパイプラインは [インフラの構成](docs/design/infrastructure.md) にあります。

## ホスティングのモード

2 つの Worker は、自分のドメインのカスタムドメイン（`custom_domain`）か、ドメインを持たない人のための `workers.dev`（`workers_dev`）で公開します。モードは issuer を決めるので、最初のデプロイの前に選び、後から切り替えません（[ホスティングのモード](docs/design/hosting-modes.md)）。

`workers.dev` のモードを選ぶ前に、必ず [fork する人への警告](docs/design/hosting-modes.md#24-fork-する人への警告) を読んでください。

## 現在の状態

検証用の Cloudflare アカウントに `workers_dev` のモードでデプロイしてあり、動いています。
RP のサンプルからのパスキーによるサインインと、RP-Initiated Logout によるサインアウトを、端から端まで確かめました。

## ドキュメント

| ドキュメント | 内容 |
| --- | --- |
| [docs/philosophy/](docs/philosophy/README.md) | OJILab の設計思想とエンジニアリング原則 |
| [docs/design/](docs/design/README.md) | IdP の設計ドキュメントの索引。ゴール、設計原則、全体構成、各トピックの設計 |
| [docs/design/infrastructure.md](docs/design/infrastructure.md) | 要素のつながりとデプロイのパイプラインの図 |
| [docs/design/hosting-modes.md](docs/design/hosting-modes.md) | 2 つのホスティングのモードと、RFC 9421 の署名による管理者の認証 |
| [docs/design/standards-compliance.md](docs/design/standards-compliance.md) | 準拠する標準と、その例外 |
| [docs/design/security-checklist.md](docs/design/security-checklist.md) | セキュリティ要件のチェックリスト |
| [docs/deployment/bootstrap.md](docs/deployment/bootstrap.md) | 空の Cloudflare アカウントから最初のユーザーと RP をつなぐまでの手順の設計 |
| [docs/deployment/runbook.md](docs/deployment/runbook.md) | ブートストラップを実行するときの運用者の操作の順番 |
| [docs/deployment/agent-setup.md](docs/deployment/agent-setup.md) | 秘密の値をコンテキストに入れずに、エージェントが認証情報を準備する方法 |
| [docs/deployment/secret.md](docs/deployment/secret.md) | 1Password Environments と GitHub Actions による CD 用 Secret の扱い |
| [docs/development.md](docs/development.md) | 開発に必要なツール、コマンド、リポジトリの運用 |
| [AGENT.md](AGENT.md) | このリポジトリを変更する人とエージェントの契約 |
