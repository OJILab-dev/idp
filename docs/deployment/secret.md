# 1Password EnvironmentsとGitHub Actions

## セキュリティ境界

OJILabのCloudflare CDでは、1Passwordの**Credential Broker**が提供するGitHub Actions integrationを使います。
GitHub Actionsが発行するOIDC tokenを1Passwordが検証し、許可されたjobへ**Environment**の変数を実行時だけ渡します。

境界ごとの責任は次のとおりです。

| 境界 | 用途 |
| --- | --- |
| Vault | 人間が使うcredential、復旧用credential、Integration Keyの保管 |
| Environment | workloadへ渡す変数の正本 |
| Workload Identity Provider | OJILab GitHub ActionsとのOrganization共通の信頼関係 |
| Destination | repository、workflow、branch、GitHub Environmentの許可条件 |
| GitHub Environment | production jobの保護規則 |

VaultからEnvironmentへ値を登録しても自動同期はされません。
CDでローテーションする値はEnvironment側を必ず更新します。
break-glass credentialはEnvironmentへ登録せず、通常のCDから到達できない状態を保ちます。

## 命名規則

| 対象 | 名前 |
| --- | --- |
| Environment | `<stack-name>-<stage>` |
| Workload Identity Provider | `OJILab GitHub Actions` |
| GitHub Environment | `<environment>` |
| GitHub repository variable | `OP_WORKLOAD_ID` |
| GitHub repository variable | `OP_ENVIRONMENT_ID` |
| GitHub repository secret | `OP_INTEGRATION_KEY` |

例:

```text
1Password Environment: cloudflare-zero-trust-prod
GitHub repository: OJILab-dev/cloudflare-zero-trust
GitHub Environment: production
```

### IdPのデプロイごとの名前

IdPは、最初に検証用のアカウントへデプロイし、本番はIdPのホスト名を持つzoneのCloudflare account（典型的にはIdPが仕えるサービスのaccount。[ドメインの置き場所](../design/domain-placement.md)）へ同じ構成で作り直します。そのaccountをサービスと共有しても、IdPのcredentialはサービスのものと共有しません。
そのため、IdPのEnvironment、Vault item、GitHub Environmentの名前は上の例のように固定せず、[デプロイと設定](../design/deployment.md)の「デプロイごとの入力」としてdeployment設定ファイルに書きます。workflowとscriptはその値を読み、名前を直接書きません。

- Environmentはdeploymentごと（Cloudflare accountごと）に分け、別のaccountとcredentialを共有しません。
- `CLOUDFLARE_ACCOUNT_ID`はEnvironmentにだけ置き、repositoryには書きません（repositoryは公開しているため）。
- Workload IDとEnvironment IDは`setup-1password-integration.sh`がGitHubの変数へ登録し、手で書き写しません。

## Environment変数

変数名は、`cf` CLI、Terraform provider、S3互換backendなどが読む名前に合わせます。`cf` は `CLOUDFLARE_API_TOKEN` と `CLOUDFLARE_ACCOUNT_ID` を読みます（Cloudflare「Use cf in CI」の「Provide credentials」）。
workflowに値の対応表を重複して持たせないためです。

| Variable | 内容 | Secret |
| --- | --- | --- |
| `CLOUDFLARE_API_TOKEN` | 対象リソースだけに制限したCloudflare API Token | yes |
| `CLOUDFLARE_ACCOUNT_ID` | Cloudflare Account ID（deploymentごとの入力。repositoryには書かない） | no |

R2をTerraform backendとして使うstackでは、必要に応じて次も登録します。

```text
AWS_ACCESS_KEY_ID
AWS_SECRET_ACCESS_KEY
```

Environmentには対象workflowが必要とする値だけを登録します。
異なるstackやproduction以外の環境とcredentialを共有しません。

## 初期セットアップ

Organization管理者が一度だけ行う操作:

1. 1PasswordでWorkload Identity Provider `OJILab GitHub Actions`を作成する。
2. 発行されたIntegration KeyをVault `github-organization`のItem `OP_INTEGRATION_KEY`へ保存する。

stackごとに行う操作:

1. 1Passwordに`<stack-name>-prod` Environmentを作成する。
2. workflowが必要とする変数だけを登録する。
3. `Destinations > GitHub Actions`から対象repositoryを接続する。
4. destinationを`main` branch、deploy workflow、GitHub Environment `production`へ限定する。
   例外として、IdPのPRの`terraform plan`に使う読み取り専用の`<stack-name>-plan` Environmentは、下の「制約」の例外の条件へ限定します。
5. 表示されたWorkload IDとEnvironment IDを控える。
6. 生成後のrepositoryで次を実行する。

```sh
OP_WORKLOAD_ID='<workload-id>' \
OP_ENVIRONMENT_ID='<environment-id>' \
./setup-1password-integration.sh
```

このscriptは2つのIDをrepository variablesへ登録し、VaultのIntegration Keyを値を表示せずrepository secretへ渡します。
GitHub Freeのprivate repositoryでも一貫して参照できるよう、これら3つはGitHub Environmentではなくrepository levelへ置きます。

## Workflowでの参照

deploy jobだけに`id-token: write`を付与します（例外はIdPのPRの`terraform plan` jobで、下の「制約」を参照）。
`1password/load-secrets-action`はEnvironmentの変数をmaskし、`export-env: true`によって後続stepへ公開します。

```yaml
- name: Load deployment secrets
  uses: 1password/load-secrets-action@70062d7a876d3eb6334754fa26efd2fbd90c32f2 # v5.0.1
  with:
    export-env: true
  env:
    OP_WORKLOAD_ID: ${{ vars.OP_WORKLOAD_ID }}
    OP_ENVIRONMENT_ID: ${{ vars.OP_ENVIRONMENT_ID }}
    OP_INTEGRATION_KEY: ${{ secrets.OP_INTEGRATION_KEY }}
```

pull requestのvalidation jobにはOIDC権限も1Password credentialも渡しません。
例外として、IdPの`terraform plan` jobにだけ、読み取り専用のcredentialを入れた別のEnvironmentを渡します。条件と理由は[デプロイと設定](../design/deployment.md)の「PR の `terraform plan` の認証情報（例外）」を参照してください。
依存取得がある場合は、依存を取得してからSecretを読み込み、credentialの生存範囲をdeploy直前以降に限定します。

## 既存Secretsからの移行

旧GitHub Secretsを先に削除してはいけません。

1. Environmentとdestinationを作成する。
2. repository variablesとIntegration Keyを設定する。
3. workflowへ1Password stepを追加し、旧Secretsの直接参照を外す。
4. `workflow_dispatch`で1Password読み込みと実際のdeployが成功することを確認する。
5. planやdeploy結果に意図しない変更がないことを確認する。
6. 成功したrun URLを変更記録へ残す。
7. その後にだけ旧GitHub Secretsを削除する。
8. 再度`workflow_dispatch`を実行し、旧Secretsなしでdeployが成功することを確認する。

## Rotationと失効

Cloudflare API Tokenなどをrotationするときは、1Password Environmentの対応する変数を更新します。
Workload ID、Environment ID、workflowは変更不要です。

Integration Keyが漏洩した場合:

1. 1PasswordでOrganization共通ProviderのIntegration Keyをrotationする。
2. Vault `github-organization`のItemを更新する。
3. 接続する各repositoryの`OP_INTEGRATION_KEY`を置換する。
4. 1Passwordのusage reportとaudit logでアクセス履歴を確認する。
5. destination条件を再確認し、必要ならEnvironment内のcredentialもrotationする。

## 制約

`OP_INTEGRATION_KEY`はGitHub Secretsに残る長寿命のbootstrap credentialです。
ただし、単独ではEnvironmentへアクセスできず、許可条件に一致するGitHub OIDC token、Workload ID、Environment IDも必要です。

destinationはrepository名だけで許可せず、少なくとも次を固定します。

- Organizationとrepository
- deploy workflowの名前（workflowのYAMLの先頭の`name:`。IdPでは`Deploy`。destinationのworkflowの条件はファイルのpathではなくこの名前）
- `main` branch
- GitHub Environment `production`（IdPでは、deployment設定ファイルのデプロイ用のGitHub Environmentの名前）

例外として、IdPのPRの`terraform plan`に使う読み取り専用のEnvironmentのdestinationは、`main` branch、deploy workflow、GitHub Environment `production`の代わりに、次を固定します。

- Organizationとrepository
- plan workflowの名前（`name:`）
- 同じrepositoryのbranchからの`pull_request` eventだけ（forkからのPRには渡さない）
- GitHub Environment `production`を使わない
- EnvironmentのCloudflare API Tokenに、D1の権限を読み取りも含めて一切持たせない

workflowの名前の固定は、そのcredentialで何が動くかを限りません。同じrepositoryのPRはplan workflowもTerraformのコードも書き換えられるため、残るリスクはこのcredentialで読めるものの機密性です。条件と理由は[デプロイと設定](../design/deployment.md)の「PR の `terraform plan` の認証情報（例外）」を参照してください。
これらの条件で限定できない場合は、PRの`terraform plan`をやめます。

destinationのworkflowの条件はworkflowの名前（YAMLの先頭の`name:`）で、ファイルのpathではありません。
workflowの`name:`を変えるとdestination条件と一致しなくなります（ファイルのrenameだけでは変わりません）。
deploy workflowの`name:`は、それを条件にするすべてのdestinationを同時に更新しない限り変えません。名前の変更と条件の更新は同じ移行作業として扱います。

workflowの名前はrepositoryの中で一意ではありません。
同じ`name:`を持つ別のworkflowを足すと、workflowの条件だけはそのworkflowでも満たされます。
残りの条件（`main` branch、`main`に限ったGitHub Environment、repository）があるので、そのworkflowがcredentialを得るには`main`へマージされる必要があります。
そのため、workflowの追加と変更を含むPRのレビューが、この条件を守る関門です。レビューでは、deploy workflowと同じ`name:`を持つworkflowがほかにないことを確かめます。
