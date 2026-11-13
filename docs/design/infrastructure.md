# インフラの構成

Cloudflare の上で、どの要素がどうつながり、どうデプロイされるかを図で示す。
要素の役割と設計の理由は、[設計ドキュメントの索引](README.md)の全体構成と、各トピックの設計に置く。ここでは繰り返さず、つながりだけを示す。

## 要素

| 要素 | 役割 | 詳細 |
| --- | --- | --- |
| IdP の Worker（TypeScript + Hono） | 利用者と RP に公開する要素。OIDC エンドポイント、パスキー API、サインイン・登録・アカウントページを提供する | [認証フロー](authentication.md)、[トークン設計](tokens.md) |
| 管理用の Worker（TypeScript） | 別のホスト名に置く管理 API。要求ごとの RFC 9421 の署名を署名鍵の許可リストで検証して、Worker 自身が管理者を確かめる | [管理 CLI と管理用の Worker](idpctl.md)、[ホスティングのモード](hosting-modes.md)の 3 |
| 共有コア（TypeScript） | ドメインの規則、入力の検証、SQL、ユースケースを 1 か所に持ち、2 つの Worker が使う | [技術選定](technology.md) |
| D1 | IdP の全状態を置くデータベース。2 つの Worker が同じものをバインドする | [データモデル](data-model.md) |
| `idpctl`（Go） | 手元で動かす管理 CLI。管理 API を呼ぶだけの薄いクライアントで、ドメインの規則は評価しない | [管理 CLI と管理用の Worker](idpctl.md) |
| RP のサンプル | 別の Worker として動く、標準どおりの RP の参照実装。IdP からは import しない | [クライアントの種類](clients.md) |

IdP の Worker には管理用のエンドポイントや管理 UI を置かない。

## 実行時のつながり

```mermaid
flowchart LR
  browser["ブラウザ<br/>パスキー（WebAuthn）"]
  rp["RP<br/>rp-sample など"]
  idpctl["idpctl（Go）<br/>管理者の秘密鍵"]

  subgraph cf["Cloudflare アカウント"]
    subgraph idpw["IdP の Worker"]
      public["公開のエントリーポイント<br/>OIDC · パスキー API · 静的ページ"]
    end
    adminw["管理用の Worker<br/>別のホスト名"]
    rpw["RP のサンプルの Worker"]
    d1[("D1")]
    secret["Worker Secret<br/>署名鍵"]
    rl["Rate Limiting<br/>Worker ごとの名前空間"]
  end

  browser -->|"サインイン・登録・end_session"| public
  rp -->|"discovery · jwks · token · userinfo"| public
  rpw -->|"discovery · jwks · token · userinfo"| public
  browser --> rpw
  idpctl -->|"HTTPS（RFC 9421 の署名）"| adminw
  public --> d1
  adminw --> d1
  public --> secret
  public --> rl
  adminw --> rl
```

- 2 つの Worker の間にバインディングはない。RS256 が有効かどうかは、デプロイの設定ファイルの `rs256_enabled` を 2 つの Worker が同じ変数 `RS256_ENABLED` で受け取って決め、デプロイの後の確認が、discovery がそのとおりに `RS256` を載せているかを確かめる（[デプロイと設定](deployment.md)のデプロイのパイプライン）。
- 2 つの Worker は同じ D1 をバインドする。レート制限の名前空間は Worker ごとに別にする（[技術選定](technology.md)）。
- 公開するホスト名は、モードによってカスタムドメインか `workers.dev` になる（[ホスティングのモード](hosting-modes.md)）。

## デプロイのパイプライン

```mermaid
flowchart LR
  merge["main へのマージ<br/>か手動の起動"]
  validate["設定ファイルの検証<br/>認証情報なし"]
  creds["1Password Environment<br/>GitHub の OIDC で読み込み"]
  tf["Terraform の apply"]
  build["入力の検証とビルド"]
  mig["D1 のマイグレーション"]
  idp["IdP の Worker の deploy"]
  admin["管理用の Worker の deploy"]
  check["外からの確認<br/>discovery の RS256 と rs256_enabled の一致を含む"]

  merge --> validate --> creds --> tf --> build --> mig --> idp --> admin --> check
```

各段の中身、順番の保証、認証情報の渡し方、残るリスクは [デプロイと設定](deployment.md)のデプロイのパイプラインに置く。最初のデプロイは [ブートストラップ](../deployment/bootstrap.md)と[実行手順](../deployment/runbook.md)に沿って運用者が行う。
