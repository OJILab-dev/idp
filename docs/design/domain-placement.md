# ドメインの置き場所（決定記録）

IdP のドメインと Cloudflare アカウントの関係についての決定と、その理由、代わりの案を選ぶ条件、ゾーンをサービスと共有するときの共存の設計、残るリスクを記録する。決定は 2026-11-09 に運用者が行った。ゾーンのルールセットを持たない決定（共存の設計の決定 ③）は、その後に運用者が行った。決定に伴う変更は、[デプロイと設定](deployment.md)、[管理 CLI と管理用の Worker](idpctl.md)、[無料枠](free-tier.md)、[セキュリティ要件チェックリスト](security-checklist.md)、[操作とリスク](operations-and-risks.md)、[ブートストラップ](../deployment/bootstrap.md)、[実行手順](../deployment/runbook.md)に反映した。後半の「検討した選択肢」は、決定の前の提案の内容を経緯として残したもの。

## 決定

下の選択肢の A2 を採る。IdP の 2 つの Worker と D1 は、IdP のホスト名（issuer と管理用のホスト名）を持つゾーンと同じ Cloudflare アカウントに置く。

- 典型的には、そのアカウントは IdP が専属で仕えるサービス 1 つのアカウントで、IdP のインスタンスはサービスごとに 1 つ置く。そのゾーンには、サービスのほかのホスト名も載る。
- これまでの「IdP 専用の Cloudflare アカウントに置く」という制約は外す。
- サービスの運用者が IdP の管理者と同じでないときは、IdP 専用のアカウントを持つ B か A1 を選ぶ（下の「B か A1 を選ぶとき」）。
- 移植性は、fork して自分のアカウントとドメインの情報を入れればデプロイできること（fork できること）を指す。稼働中の IdP をアカウントの間で移すことではない。A2 でも、ゾーンを IdP だけで使うデプロイ（A1 と同じ形）でも、同じコードと同じ手順で動き、違いはデプロイごとの入力だけにする。

## 理由

運用者と次の理由を確認した。

- 1 つの IdP は 1 つのサービスに仕える。そのサービスのアカウントを共有しても、影響の範囲（漏えいや誤操作の及ぶ範囲）と可用性の結び付き（1 日の上限の共有など）は、1 つの信頼の範囲の中に収まる。サービスが止まれば IdP の利用者もいなくなり、IdP が止まればサービスにサインインできないので、可用性はもともと結び付いている。
- 複数の IdP を 1 つのアカウントに置く形は、危険が大きすぎるとして退けた。D1 の権限と managed CA がアカウント単位なので、1 つの IdP の基盤の権限がほかの IdP の全利用者に及ぶため。
- A2 は追加のドメインを要らない。A1 と B は IdP のアカウントにゾーン（ドメインの購入とネームサーバーの切り替え）を要る。
- 提案の時点では、IdP 専用アカウントの性質を保つ B を第 1 に推していた。A2 で失うのはアカウントの分離で、上の 1 つ目の理由により、1 つのサービスに専属の IdP ではそれが新しい信頼を足さないと判断した。

## B か A1 を選ぶとき

次のどれかに当たるときは、A2 ではなく、IdP 専用のアカウントを持つ B（Cloudflare for SaaS）か A1（IdP のアカウントの専用のドメイン）を選ぶ。どちらも下の「検討した選択肢」に評価がある。

- サービスの運用者（アカウントのメンバーと、アカウント単位の API トークンを持つ人）が、IdP の管理者と同じでない。A2 では、サービスのアカウントの Workers と D1 の権限を持つ人は、IdP の全利用者の全 RP への権限を持つ（下の「残るリスク」）。
- 1 つの IdP を複数のサービスで使う。どのサービスのアカウントに置いても、ほかのサービスから見て IdP の信頼の範囲が広がる。
- ドメインが Cloudflare 以外の DNS 事業者にあり、ゾーンごと Cloudflare に移せない（B）。
- サービスも同じゾーンで mTLS（managed CA のホスト名の割り当て）を使う。割り当てはゾーンに 1 つで、IdP の Terraform が持つ（下の共存の設計の 2）。
- 1 日のリクエスト上限を、大量の要求から Worker の前で守る必要がある。IdP はゾーンのルールを持たない（下の共存の設計の決定 ③）ので、それが要るなら、IdP のためだけのゾーンを持ち、その持ち主として WAF のルールを置く。

## ゾーンをサービスと共有するときの共存の設計

ゾーンをサービスのほかのホスト名と共有しても、IdP の設定がサービスのホスト名に効かず、サービスの設定が IdP の保護を外さないようにする。ゾーンを IdP だけで使うときも同じ設計で、同じコードと同じ入力で動く。

### 決定 ③：IdP はゾーンのルールセットを持たない

A2 を採った後、運用者は、ゾーンのルールの扱いについて ③ を選んだ。IdP は、どのデプロイでも、ゾーンのルールセット（WAF のカスタムルール、レート制限ルール、シングルリダイレクト）を持たず、頼らない。ゾーン全体の設定（Always Use HTTPS と TLS の最小バージョン）も持たない。それらが担っていた保護は、IdP の 2 つの Worker の中に移す。

IdP がゾーンに置くものは、次の 3 つだけにする。

- Worker のカスタムドメイン（issuer と管理用のホスト名の 2 つ）と、その DNS のレコード。`cf deploy` が付ける（今と同じ）。
- 管理用のホスト名の mTLS のホスト名の割り当て（managed CA）。IdP の Terraform が持つ（下の 2）。
- 管理者のクライアント証明書。IdP の Terraform が持つ。1 枚ごとに別の資源で、ゾーンのほかのものと取り合わない。

移した保護と、失うもの：

| 外したゾーンの機能 | 移した先 | 失うもの |
| --- | --- | --- |
| 管理用のホスト名の WAF のカスタムルール（有効で失効していない証明書のない要求を止める） | 管理用の Worker のゲート（ホスト名、スキーム、TLS のバージョン、証明書の検証と失効の結果、許可リスト。fail-closed）。以前から同じ確認を持っていた | 証明書のない要求を Worker の前で止める性質。その要求も管理用の Worker に届き、1 日のリクエスト上限に数えられる |
| WAF のレート制限ルール（IdP のパス） | IdP の Worker の Rate Limiting バインディング（下の 4） | 1 日のリクエスト上限の保護。大量の要求で上限を使い切れる |
| issuer のシングルリダイレクト（平文の HTTP を HTTPS へ） | IdP の Worker の 308 のリダイレクト。Worker をすべての要求で先に動かす（下の 3） | 静的なページの要求も Worker を起動し、上限に数えられる（[無料枠](free-tier.md)） |

理由：

- 運用者のゾーンは、サービスのほかのホスト名と共有していて、DNS のレコードは別のリポジトリで管理している。運用者は、IdP のリポジトリがそのゾーンのルールセットを持つことを望まない。
- Terraform では、ルールセットの一部だけを適用できない。エントリポイントのルールセットはフェーズごとにゾーンに 1 つしかなく（[C12]）、`cloudflare_ruleset` はルールの一覧を丸ごと持つので、IdP の Terraform がルールを 1 つ足すには、そのフェーズのルールセット全体（サービスのルールも含む）を持つしかない。2 つのリポジトリが同じフェーズを持つと、片方の apply がもう片方のルールを消す。
- 前の形（ゾーンの単一資源の持ち主を `idp` と `external` で選び、`external` では IdP の Terraform がルールの定義を出力して、ゾーンの持ち主が自分のルールセットに足して適用する）は退けた。共有するゾーンでは `external` しか選べず、IdP の保護がほかのリポジトリの適用に依存し、適用されたルールと定義の食い違いを IdP の plan で検出できない。IdP のルールを変えるたびに、ゾーンの持ち主のリポジトリへの PR が要る。
- ルールを 1 つずつ API（Rulesets API のルールの追加と更新）で足すスクリプトも退けた。Terraform の状態の外で変更するので、plan で食い違いを検出できない。冪等性と削除をスクリプトで実装することになる。スクリプトのトークンは、ゾーンの WAF とリダイレクトの編集の権限を持ち、その権限はホスト名に絞れないので、サービスのルールも変えられる。
- Worker に移しても、IdP の安全性（不正なサインインや管理操作を許さないこと）は変わらない。2 つの Worker は、以前から、ゾーンのルールが適用されていない場合に備えて同じ確認を持っていた（fail-closed）。失うのは、上の表の「失うもの」に書いた可用性の性質と、無料枠の余裕だけ。
- ゾーンを IdP だけで使う fork でも同じ形にする。デプロイごとの入力で形が分かれないので、手順と確認が 1 つで済む。そうしたゾーンの持ち主（fork した人）が WAF のルールを自分で置くことは妨げないが、IdP のリポジトリはその定義を持たない。

### 1. IdP のホスト名に絞る

IdP が置くものは、すべて IdP のホスト名に絞る。

- Worker のカスタムドメインは、issuer と管理用のホスト名の 2 つだけにする（今と同じ）。
- mTLS のホスト名の割り当ては、管理用のホスト名だけにする。
- リダイレクト、TLS のバージョン、レート制限は Worker の中にあるので、IdP のホスト名にだけ効く。以前の Free のレート制限ルール（条件にホスト名を使えない。[C6]）のように、サービスのホスト名の同じパスに効くものはない。

### 2. mTLS のホスト名の割り当ての持ち主

mTLS のホスト名の割り当て（`cloudflare_certificate_authorities_hostname_associations`）は、ゾーンの managed CA に割り当てたホスト名の一覧を丸ごと持つので、ゾーンに 1 つしかない。エントリポイントのルールセットと同じ性質を持つが、IdP がゾーンに置くもののうち、この性質を持つのは ③ の後はこれだけになった。

決定：IdP の Terraform が、デプロイによらず、これを持つ。前の形の入力「ゾーンの単一資源の持ち主」（`zone_singletons_owner`）と、ルールの定義の出力（`zone_singletons`）は外した。持ち主を切り替える入力は残さない。

理由：

- 運用者は、管理用のホスト名の mTLS のホスト名の割り当てを IdP の Terraform が持つと決めた。運用者のゾーンでは、サービスは mTLS を使っていない。
- 資源 1 つのために持ち主の切り替えを残すと、使われない方の形の手順と確認が残り、③ の単純さを失う。
- 割り当てがなくても安全性は崩れない。管理用の Worker は、証明書の検証の結果がない要求を拒否する（fail-closed）。割り当てが外れると、管理者も管理 API を使えなくなるだけ。

受け入れること：

- ブートストラップの前提として、ゾーンの managed CA にほかのホスト名が割り当てられていないことを確かめる。割り当てがあれば、最初の apply がそれを外してしまう（[ブートストラップ](../deployment/bootstrap.md)）。
- サービスが後で同じゾーンで mTLS を使うときは、この決定を見直す。割り当てるホスト名の一覧を、ゾーンの持ち主と 1 か所にまとめる必要がある。

### 3. Always Use HTTPS と TLS の最小バージョン

IdP は、ゾーン全体に効く設定（Always Use HTTPS と TLS の最小バージョン）も、シングルリダイレクトも持たない（決定 ③）。ゾーンの設定はゾーンの持ち主が決めるもので、IdP のデプロイがサービスのホスト名の動きを変えないようにするため。

- Worker を先に動かす：IdP の Worker を、静的なページを含むすべての要求で先に動かす（`run_worker_first` を真にする。費用とパスの一覧に絞らない理由は[無料枠](free-tier.md)）。Worker が見ない要求があると、その要求には平文の HTTP でも TLS 1.2 未満でもページが返ってしまうため。Worker は、ホスト名、スキーム、TLS のバージョンを確かめてから、静的アセットのバインディングでページを返す。
- HTTPS への誘導：IdP の Worker は、issuer のホスト名への平文の HTTP の要求のうち、安全なメソッド（`GET` と `HEAD`）で、IdP の資格情報を運ばないもの（`Authorization` ヘッダーがなく、名前が `__Host-` で始まる Cookie もない）を、設定した issuer の同じパスとクエリへ 308 でリダイレクトする（RFC 9110 §15.4.9）。リダイレクト先のスキーム、ホスト名、ポートは要求から取らず、設定した issuer から作る。ホスト名の確認をスキームの確認より先に行うので、issuer 以外のホスト名の要求はリダイレクトされず、404 で拒否される。Always Use HTTPS のドキュメントも、一部のホスト名だけを HTTPS にするときは Always Use HTTPS を使わず選んでリダイレクトするよう勧めている（[C8]）。
- それ以外の平文の HTTP の要求（`POST` などの安全でないメソッド、`Authorization` か `__Host-` の名前の Cookie を持つ要求）は、何も処理せずに 404 で拒否する。平文で送られたクライアントシークレット、認可コード、Bearer トークン、セッションの Cookie はすでに露出していて、リダイレクトはクライアントに同じものをもう一度送らせることになるため（308 はメソッドと本文を保つ）。`/token` への平文の要求は、この規則で拒否される。
- Cookie は名前で区別する：IdP の Cookie は `__Host-` 接頭辞（Secure）なので、ブラウザーが平文で送ることはない。平文の要求に `__Host-` の名前の Cookie があれば、値によらず、IdP のセッションを再生しうる異常なクライアントとして拒否する。ほかの名前の Cookie は拒否の理由にしない。ゾーンをサービスと共有すると、サービスが親のドメインに付けた Secure でない Cookie が IdP のホスト名への平文の要求にも付くので、それで拒否すると、そうした利用者の平文の訪問がすべて 404 になるため。それらの Cookie は IdP の資格情報ではない。
- 管理用のホスト名はリダイレクトしない。管理用の Worker は、平文の HTTP の要求を、ゲートの最初の確認（ホスト名とスキーム）で `forbidden` として拒否する。`idpctl` はリダイレクトに従わない（[管理 CLI と管理用の Worker](idpctl.md)）。
- ゾーンの持ち主が Always Use HTTPS を有効にしていれば、平文の要求は Worker に届く前にエッジでリダイレクトされる。そのときも Worker の確認は変わらず、二重になるだけ。
- TLS の最小バージョン：2 つの Worker は、公開の経路（インターネットから届く `fetch`）で、`request.cf.tlsVersion`（クライアントと Cloudflare の間の TLS のバージョン。[W4]）が `TLSv1.2` か `TLSv1.3` のどちらかでない要求を、何も処理せずに拒否する（IdP の Worker は 404、管理用の Worker は `forbidden`）。値がない、文字列でない、知らない値（将来の版の名前を含む）も拒否する（fail-closed の許可リスト）。将来の TLS の版を受け入れるには、コードの変更が要る。IdP の Worker は先に動くので、この確認は静的なページにも効く。
- RFC 8996 の例外：Worker の拒否は TLS のハンドシェイクの後に行うので、ゾーンの TLS の最小バージョンが 1.2 より低いと、TLS 1.0 と 1.1 の接続そのものは成立する。RFC 8996 §4 と §5 の「TLS 1.0 と 1.1 を使ってはならない（MUST NOT）」は、ゾーンの設定が 1.2 以上のときだけエッジで満たされる。IdP はゾーン全体の設定を持たないので、これを例外として記録する。抑え方として、ブートストラップの前提で、ゾーンの TLS の最小バージョンが 1.2 以上であることをゾーンの持ち主に確かめ、低ければ 1.2 以上にするよう合意する。合意できなくても、TLS 1.2 未満の接続で届いた要求は Worker が処理しないので、IdP はその接続で、ページも、トークンも返さず、クライアントシークレットや認可コードを受け付けない。残るのは、その接続でクライアントがすでに送った値が弱い TLS で運ばれたことだけ。
- 例外の範囲は狭くなった：前の形では、静的なページが Worker を通らずに返るので、TLS 1.0 と 1.1 の接続にもページが返ることを例外に含めていた。Worker を先に動かすので、この部分はなくなった。

### 4. レート制限

決定：Workers の Rate Limiting バインディングだけを使う。WAF のレート制限ルールは置かず、その定義も IdP のリポジトリに持たない（決定 ③）。

失うもの：WAF のレート制限ルールは、IdP のパスへの大量の要求を Worker に届く前に止め、1 日のリクエスト上限（アカウント全体で 10 万件）の消費を防げる唯一の仕組みだった。これを外したので、IdP の 2 つの Worker のホスト名への大量の要求は、拒否されても上限に数えられ、A2 では上限を共有するサービスも止める（[無料枠](free-tier.md)の受け入れるリスク）。一方で、Free のルールはホスト名で絞れず、サービスのホスト名の同じパスにも効いていたが、その影響はなくなった。

IdP の Worker の Rate Limiting バインディング：

- IdP の Worker は、ホスト名、スキーム、TLS のバージョンの確認の後、Worker が自分で答えるパス（`/authorize`、`/authorize/resume`、`/token`、`/userinfo`、`/logout`、`/jwks`、discovery、`/webauthn/*`）で、ほかの処理の前に、接続元の IP アドレスをキーにバインディングで数え、上限を超えた要求を 429 で拒否する。期間は 10 秒、上限は仮の値（10 件）にする。実測したら置き換える（[未決事項](open-questions.md)）。
- 静的なページは数えない。書き込みをせず、ページの読み込み 1 回で 4 件の要求になるので、数えると正規の利用を拒否しかねない（[無料枠](free-tier.md)）。
- 1 日のリクエスト上限は守らない（Worker に届いた後なので）。守るのは、D1 の書き込み（認証前のチャレンジの行）と CPU 時間で、ゾーンのプランによらず、同じ形で効く。
- バインディングは近似で、Cloudflare の拠点ごとに別々に数え、結果整合なので、上限を超えることがある（[W3]）。厳密な上限ではなく、単純な大量の要求への備えとして扱う。
- IP アドレスは、バインディングに渡す数え上げのキーとしてだけ使い、ログにも D1 にも書かない（設計原則 7）。接続元の IP アドレスが取れない要求は拒否する。
- バインディングがない、または呼び出しが失敗したら、要求を処理せず拒否する（fail-closed）。上限を確かめられないときに通すと、D1 の書き込みの保護が黙って外れるため。
- Rate Limiting の名前空間の ID はアカウントの中で一意の正の整数（[W3]）で、A2 ではサービスの Worker と同じアカウントに置くので、サービスの名前空間と重なると数えを共有してしまう。そのため名前空間の ID をデプロイごとの入力にし、コードに書かない。
- バインディングが Workers Free で使えるかと料金は、ドキュメントに書かれていない（[W2]、[W3]。未確認）。Worker の設定でバインディングを宣言するので、使えなければ最初のデプロイが失敗して気付く。そのときは、IdP の Worker から D1 の書き込みの保護がなくなることを受け入れるリスクとして記録し直すか、別の方法（Durable Objects による数え上げなど）を検討する。

管理用の Worker にはバインディングを置かない。理由：

- 管理用の Worker が D1 に触れるのは、ゲートを通った許可リストの管理者の要求だけで、ほかの要求は D1 に触れず、CPU もほとんど使わずに拒否される。バインディングが守れるのは D1 の書き込みと CPU 時間だけなので、ゲートの前で数えても守るものがない。1 日の上限は、バインディングでは守れない。
- ゲートの後で数えると、許可リストの管理者の正規の操作（`idpctl` の連続した一覧や更新）を止める害だけが残る。
- 名前空間の ID というデプロイごとの入力が 1 つ増え、サービスと重ならない値を選ぶ手間が増える。

### 5. mTLS の managed CA

- managed CA はアカウント単位で検証し、同じアカウントのどのゾーンで発行したクライアント証明書でも、mTLS を有効にしたホスト名で検証を通る（Cloudflare「Enable mTLS」の「CAs in use」）。A2 では、サービスのアカウントの CA を共有する。サービスが自分のために発行した証明書や、アカウントのどのゾーンでも「SSL and Certificates」の編集の権限を持つ人が発行した証明書は、管理用のホスト名のエッジの検証を通る。
- エッジの mTLS は、証明書を求めて検証し、その結果を `request.cf` で Worker に渡すだけで、要求を止めない（止めていたのは、外した WAF のカスタムルール。[C5]）。証明書のない要求も、検証に失敗した要求も、管理用の Worker に届く。
- 管理者の境界は、今と同じく、管理用の Worker のゲート（検証の結果と失効の確認）と、証明書のフィンガープリントの許可リストにする。許可リストはデプロイの設定ファイルにあり、CI のデプロイでだけ変わるので、証明書を発行できるだけでは管理者になれない（[管理 CLI と管理用の Worker](idpctl.md)）。
- 受け入れるリスク：証明書のない要求も、許可リストにない証明書の要求も、管理用の Worker に届き、1 日のリクエスト上限を使える。管理 API には入れない。

### 6. D1 と API トークン

- D1 の権限（`D1 Read`、`D1 Edit`）と Workers のスクリプトの権限はアカウント単位で、特定のデータベースや Worker に絞れない（[C15]）。ゾーンの権限は特定のゾーンに絞れる（[C16]）が、ホスト名には絞れない。
- そのため、A2 では、サービスのアカウントで D1 の編集か Workers のスクリプトの編集の権限を持つトークンとメンバーは、IdP の D1 を読み書きでき、IdP の Worker を差し替えられる。どちらも IdP の全利用者の全 RP への権限である（[操作とリスク](operations-and-risks.md)の「全ユーザー × 全 RP」）。逆に、IdP のトークンもサービスの D1 と Worker に効く。これは減らせず、受け入れる。サービスの運用者と IdP の管理者が同じであることが、A2 を選ぶ条件である理由。
- IdP のトークンは、Cloudflare が許す範囲で最も狭くする（[デプロイと設定](deployment.md)の API トークン）。
  - サービスのトークンと共有しない。IdP の役割（Terraform 用、デプロイ用、plan 用）ごとに、IdP のためだけのトークンを作る。
  - ゾーンの権限は、すべて IdP のホスト名を持つゾーン 1 つに絞る。
  - Terraform 用のトークンは、クライアント証明書の発行と失効、mTLS のホスト名の割り当てに要る権限（SSL and Certificates の編集）だけにし、WAF とリダイレクトの権限を持たせない。IdP はそれらを持たない（決定 ③）ので、要らない。
  - D1 の権限は、Terraform 用と plan 用のトークンに持たせない（今と同じ）。
  - break-glass の D1 のトークンは、IdP のデータベースに絞れないので、今と同じく前もって作らず、短い有効期限で作って、終わったら失効させる。
- デプロイ用のトークンの、ゾーンの DNS の編集と Workers のルートの編集の権限は、カスタムドメインを付けるために要り、ホスト名に絞れないので、サービスのほかのホスト名のレコードも変えられる。受け入れる。

## 残るリスク

上の抑え方で減らせず、A2 と決定 ③ を採ることで受け入れるもの。

- サービスのアカウントの、Workers と D1 の権限を持つ人とトークンは、IdP の全利用者の全 RP への権限を持つ。アカウントのメンバーを増やすことは、IdP の基盤の権限を配ることになる。
- Workers の 1 日のリクエスト上限（10 万件）と D1 の 1 日の上限は、アカウント全体で数える。サービスの利用やサービスへの攻撃で IdP が止まり、IdP への攻撃でサービスが止まる。
- Worker の前で要求を止める仕組みがないので、IdP の 2 つのホスト名への大量の要求だけで、アカウント全体の 1 日のリクエスト上限を使い切れる（決定 ③ で外した WAF のルールの保護）。
- managed CA を共有するので、サービスのための証明書でも管理用のホスト名のエッジの検証を通る。証明書のない要求も管理用の Worker に届く（境界は管理用の Worker のゲートと許可リスト）。
- mTLS のホスト名の割り当てはゾーンに 1 つで、IdP の Terraform が持つ。サービスが同じゾーンで mTLS を使い始めると取り合いになる。
- TLS の最小バージョンをエッジで 1.2 にするかは、ゾーンの持ち主の設定しだい（RFC 8996 の例外）。
- デプロイ用のトークンは、サービスのほかのホスト名の DNS のレコードも変えられる。

## 経緯：決定の前の提案

以下は、決定の前の提案の内容を、経緯として残したもの。「今の設計」は提案の時点の設計を指す。上の決定と食い違うところは、上の決定を優先する。

### 要件

運用者から次の要件が加わった。

- IdP のドメインは、どのアカウントで管理されていてもよい。issuer のホスト名と管理用のホスト名を持つゾーンは、Workers と別の Cloudflare アカウントにあってもよく、Cloudflare 以外の DNS 事業者にあることもありうる。
- アカウントをまたぐ方法を先に探す。それがなければ、最後の手段として、IdP をドメインを管理するアカウントに置き、IdP 専用アカウントの制約を外してよい（運用者の追加の入力）。
- ここでの移植性は、[デプロイと設定](deployment.md)の「アカウントの移植性」と同じく、fork して自分のアカウントとドメインの情報を入れればデプロイできることを指す。稼働中の IdP をアカウントの間で移すことではない。

検証の構成では、Workers を検証用のアカウントに置き、ドメインは別の Cloudflare アカウントにある。そのドメインのゾーンと DNS のレコードは、別の非公開リポジトリの Terraform で管理されている（`cloudflare_dns_record` でレコードを足す運用）。issuer と管理用のホスト名は、そのドメインのサブドメインにしたい。アカウントの名前とホスト名の実際の値は、[デプロイと設定](deployment.md)の直書きの禁止に従い、ここには書かない。

### 今の設計が成り立たなくなる理由

今の設計は、Workers と同じアカウントにあるゾーンの機能に頼っている。

| 頼っている機能 | 使っている箇所 |
| --- | --- |
| Workers のカスタムドメイン（2 つのホスト名） | IdP の Worker の `cloudflare.config.ts`（`domains`）、管理用の Worker（同じ形の予定） |
| エッジの mTLS（アカウントの managed CA）と、管理用のホスト名の WAF のカスタムルール | `infra/main.tf`（`cloudflare_certificate_authorities_hostname_associations`、`cloudflare_client_certificate`、`cloudflare_ruleset` の `http_request_firewall_custom`） |
| WAF のレート制限ルール | `infra/main.tf`（`http_ratelimit` のフェーズ） |
| Always Use HTTPS と TLS の最小バージョン 1.2 | `infra/main.tf`（`cloudflare_zone_setting`） |
| `workers.dev` とプレビューの URL の無効化 | `cloudflare.config.ts`（`workersDev`、`previewUrls`） |

ドメインが別のアカウントにあると、どれも素直には使えない。

- カスタムドメインは、自分が持つ有効なゾーンにしか作れない（[C1]「You cannot create a Custom Domain … on a zone you do not own」）。
- 別のアカウントのドメインのサブドメインを、自分のアカウントのゾーン（子ゾーン）にする subdomain setup は Enterprise だけ（[C2]）。CNAME による partial setup は Business 以上（[C3]）。Cloudflare 以外の DNS 事業者のドメインでも、サブドメインだけを Free のゾーンにはできない。
- 別の Cloudflare アカウントから proxied の CNAME を向けると、Error 1014（CNAME Cross-User Banned）で拒否される。ドキュメントは、CNAME の向け先の持ち主が Cloudflare for SaaS を使う必要があるとしている（[C4]）。DNS だけの CNAME を `*.workers.dev` に向けても、エッジの証明書と `Host` が `workers.dev` のものにならず、動かない（運用者の検証の結果）。
- Workers のゾーンの機能（WAF、レート制限、mTLS、ゾーンの設定）は、ゾーンに属するので、ゾーンがないアカウントでは使えない。

### 選択肢

選択肢は 4 つある。A はベースライン（ドメインとアカウントの関係を変えない）、B は Cloudflare for SaaS、C は保護を Worker の中に移す形、D はドメインのアカウントに置く転送用の Worker。C は D と組み合わせて使う部品でもある。

評価の観点は、仕組み、fork する人に求めるもの、[セキュリティ要件チェックリスト](security-checklist.md)との関係、無料枠、既存のコードとドキュメントへの影響、残るリスク。

#### A. ベースライン：ゾーンと Workers を同じアカウントに置く

**A1. Workers のアカウントに専用のドメインを置く**

- 仕組み：Workers のアカウントにドメイン（安いもので足りる）を 1 つ追加し、issuer と管理用のホスト名をそのゾーンに置く。今の設計そのもの。
- fork する人に求めるもの：IdP のアカウントにゾーンを 1 つ。ドメインの購入（年に数ドル〜十数ドル）とネームサーバーの切り替え。
- セキュリティ：チェックリストの全項目を今の形で満たす。[デプロイと設定](deployment.md)の「IdP 専用アカウント」（D1 のトークンと managed CA の範囲を IdP に閉じる）もそのまま成り立つ。
- 無料枠：今と同じ。
- 影響：なし。
- 残るリスク：issuer が運用者の主たるドメインの下にならない。要件の「どのアカウントのドメインでも」は満たさず、「IdP のアカウントにドメインを 1 つ用意すること」を fork の前提として明記することになる。

**A2. Workers をドメインのアカウントに置く（運用者が認めた最後の手段。後に採用）**

運用者は、アカウントをまたぐ方法がなければ、IdP をドメインを管理するアカウントに置き、IdP 専用アカウントの制約を外すことを最後の手段として認めた。そのため A2 は退けた案ではなく、採りうる代替案として、何を失うかを正確に書く。

- 仕組み：ドメインを持つアカウントに、IdP の 2 つの Worker と D1 を置き、issuer と管理用のホスト名をそのゾーンのカスタムドメインにする。
- fork する人に求めるもの：ドメインが Cloudflare にあり、そのアカウントに Worker、D1、Terraform の対象の設定をデプロイする権限があること。Cloudflare 以外の DNS 事業者のドメインは、ゾーンごと Cloudflare に移さない限り使えない。
- 失うもの 1（ゾーン全体に効く設定）：今の `infra/` は、次をゾーンの単位で持つ。同じゾーンのほかのホスト名（検証の構成では、ドメインを管理するリポジトリが持つ既存のレコード）にも効く。
  - Always Use HTTPS（`cloudflare_zone_setting`）：ゾーンのすべてのホスト名で平文の HTTP をリダイレクトする（[C8]）。平文の HTTP を要るホスト名があれば壊れる。
  - TLS の最小バージョン 1.2（`cloudflare_zone_setting`）：ゾーンのすべてのホスト名に効く。ホスト名ごとの設定は Advanced Certificate Manager（有料）が要る（[C7]）。
  - WAF のカスタムルールのエントリポイントのルールセット：Free ではカスタムルールは 5 つ、ルールセットは 1 つ（[C9]）。今の Terraform はゾーンのそのフェーズのルールセットを丸ごと持つので、ドメインの持ち主がそのフェーズにルールを置いていれば、片方の apply がもう片方のルールを消す。
  - レート制限ルール：Free ではゾーンに 1 つで、条件にホスト名を使えずパスだけ（[C6]）。IdP のパス（`/authorize`、`/token`、`/webauthn/*`、`/v1/*` など）への 10 秒あたりの上限が、同じパスを持つほかのホスト名にも効く。ゾーンでただ 1 つのルールを IdP が使うので、ドメインの持ち主はほかの用途にレート制限ルールを使えなくなる。
- 失うもの 2（アカウントの共有）：[デプロイと設定](deployment.md)の「IdP 専用アカウント」の理由がそのまま失われる。
  - D1 の API トークンの権限はデータベースに絞れず、アカウントのすべての D1 に効く。同じアカウントのほかのサービスのトークンで IdP の D1 を読み書きでき、IdP の break-glass のトークンもほかのサービスの D1 に効く。
  - managed CA はアカウント単位で検証する（Cloudflare「Enable mTLS」の「CAs in use」）。ほかのゾーンで発行したクライアント証明書でも、管理用のホスト名の mTLS と WAF を通る。管理者になるには許可リストも要るので、管理 API には入れないが、1 日のリクエスト上限を使える。
  - Workers の 1 日のリクエスト上限（10 万件）と D1 の 1 日の上限はアカウント全体で数える。ほかの Worker の利用や、ほかの Worker への攻撃で、IdP も止まる。逆に、IdP への攻撃でほかのサービスも止まる。
  - アカウントのメンバーと API トークンを持つ人は、IdP の基盤の権限（デプロイ、Worker Secret、D1）を持ちうる。[操作とリスク](operations-and-risks.md)の「全ユーザー × 全 RP」の影響を持つ人が増える。
- 抑え方（設計で限れること）：
  - ゾーンの設定を持たない：Always Use HTTPS と TLS の最小バージョンを `cloudflare_zone_setting` で持つのをやめる。HTTPS への誘導は、IdP のホスト名に限ったシングルリダイレクトのルールで行う（[C10]。Free で使えるルールの数はこの調査では確かめていない）。TLS の最小バージョンは、ゾーンの今の値をドメインの持ち主と合意して 1.2 にするか、それができなければ Worker が `request.cf.tlsVersion` で 1.2 未満を拒否する（RFC 8996 の例外として記録する。C を参照）。
  - ルールを IdP のホスト名に絞る：WAF のカスタムルールは、今の管理用のホスト名のルールと同じく `lower(http.host)` で IdP のホスト名に絞れる。レート制限ルールは Free ではホスト名で絞れないので、絞るには Pro 以上が要る（[C6]）。Free のままなら、ゾーンでただ 1 つのレート制限ルールを IdP に使うことを、ドメインの持ち主と合意する。
  - ルールセットを丸ごと持たない：エントリポイントのルールセットはゾーンとフェーズごとに 1 つで、2 つのリポジトリの Terraform が同じ `cloudflare_ruleset` を持つと互いに上書きする。持ち主を 1 つに決める必要がある。案は 2 つ。(a) ドメインを管理するリポジトリがルールセットを持ち、IdP のルール（式とパス）はそのリポジトリへの PR で足す。IdP のリポジトリはルールの式だけを出力として渡す。(b) IdP のリポジトリがそのフェーズを持ち、ドメインの持ち主のルールも IdP のリポジトリに移す。(a) は、ゾーンの持ち主が変わらず、ドメインを管理するリポジトリが今は DNS のレコードしか持っていないので足しやすい。ただし、IdP のルールの変更が IdP のリポジトリのレビューだけでは決まらなくなる。
  - トークンを分ける：IdP のデプロイと Terraform の API トークンは、そのアカウントのほかのサービスのものと分け、ゾーンの権限は IdP のゾーンに絞る。D1 と Workers の権限はアカウント単位でしか絞れない。
  - 移植性：fork する人のドメインが IdP 専用のアカウントにあれば、上の抑え方は何も変えずに今の設計と同じになる。抑え方は「ゾーンをほかの用途と共有するとき」の追加の手順として書き、どちらでも同じコードで動く形にする（ゾーンの設定とルールセットを持つかどうかを、デプロイの入力で選ぶ）。
- 影響：Worker のコードはない。`infra/` は、ゾーンの設定とルールセットを持つかどうかを切り替えられるようにし、HTTPS のリダイレクトのルールを足す。ドメインを管理するリポジトリに、IdP のルールの PR が要る（(a) の場合）。[デプロイと設定](deployment.md)の「IdP 専用アカウント」の決定を、例外として書き換える。
- 残るリスク：上の「失うもの 2」は抑え方で減らせず、受け入れることになる。

#### B. Cloudflare for SaaS（カスタムホスト名）

- 仕組み：IdP のアカウントに自分のゾーン（以下「IdP のゾーン」）を 1 つ置き、Cloudflare for SaaS を有効にする。issuer のホスト名をカスタムホスト名として登録し、ドメインの持ち主は issuer のホスト名から IdP のゾーンの CNAME の向け先へ CNAME を作る。IdP のゾーンのフォールバックオリジンには、オリジンのないレコードと、IdP の Worker のルート（`*/*`）を使う。Worker のルートが当たると、ホスト名ごとのカスタムオリジンは使われない（[S2]）。管理用のホスト名はカスタムホスト名にせず、IdP のゾーンの普通のホスト名にする。
- 事実（すべて公式ドキュメント）：
  - Free で使え、100 ホスト名まで含まれ、超えた分は 1 つ 0.10 ドル。検証中のものも数える。Enterprise 以外は API の `hard_cap` で上限を置ける（[S1]、[S3]）。
  - SaaS を提供する側（IdP のアカウント）に有効なゾーンが要る。フォールバックオリジンは proxied でなければならない（[S4]）。
  - ドメインの持ち主の DNS が Cloudflare 以外でもよい。最低限、CNAME を作れば、リアルタイムのホスト名の検証と、自動の HTTP の DCV で証明書が出る（[S5]、[S6]）。止まる時間を避けるなら、ホスト名の事前検証の TXT（か HTTP のトークン）と、証明書の TXT か Delegated DCV の CNAME も足す（[S7]、[S8]）。ほかの CDN を通したホスト名は使えない（[S5]）。
  - ドメインの持ち主が別の Cloudflare アカウントで CNAME を proxied にすると O2O（Orange-to-Orange）になる。O2O は 2 つのゾーンが別のアカウントのときだけ起き、持ち主のゾーンの設定が先に、IdP のゾーンの設定が後に効く。WAF、レート制限、Access、Workers は両方のゾーンで動き、持ち主のゾーンのものが妨げることがある（[S9]、[S10]）。O2O のカスタムホスト名には事前検証（TXT と HTTP のトークン）を使えない（[S7]）。O2O では、CNAME の向け先のホスト名に別のルートが当たると Worker を迂回し 522 になりうるので、向け先のホスト名のルートも IdP の Worker に向ける（[S2]）。
  - カスタムホスト名の mTLS は Enterprise だけで、Access を通して行う。API Shield の mTLS はカスタムホスト名には使えない（[S1]、[S11]）。一方、ゾーンの普通のホスト名の mTLS（managed CA）は全プランで使える（[C5]）。
  - TLS の最小バージョンは、カスタムホスト名ごとに設定できる（`ssl.settings.min_tls_version`）。設定しなければゾーンの値が効く（[S11]）。
  - Free、Pro、Business のカスタムホスト名には「今のゾーンのプランの WAF ルール」が効き、カスタムホスト名ごとのルールセット（WAF for SaaS、custom metadata）は Enterprise（[S1]、[S12]）。
- fork する人に求めるもの：IdP のアカウントにゾーンを 1 つ（A1 と同じくドメインの購入が要る）。ドメインの持ち主の側に、issuer のホスト名の CNAME（と、止まる時間を避けるなら TXT）を 1 回作る権限。Cloudflare 以外の DNS 事業者でもよい。検証の構成では、ドメインを管理する非公開リポジトリに、DNS だけ（`proxied = false`）の CNAME と TXT の `cloudflare_dns_record` を足す PR になる。
- セキュリティ（チェックリストとの関係）：
  - 管理用の Worker：管理用のホスト名は IdP のゾーンの普通のホスト名なので、エッジの mTLS、WAF のカスタムルール、`workers.dev` とプレビューの URL の無効化、Worker 側の再確認（`gate.ts`）を今のまま持てる。チェックリストの「管理用の Worker（mTLS）」の全項目が変わらない。
  - issuer：Worker の中の確認（issuer のホスト名以外と `https` でないリクエストを 404 で拒否する）は今のまま効き、`*/*` のルートで届くほかのホスト名（フォールバックオリジンのホスト名など）も拒否する。TLS の最小バージョンはカスタムホスト名ごとに 1.2 にできる。
  - DNS だけの CNAME なら O2O にならず、IdP のゾーンの設定だけが効く。proxied にすると、ドメインの持ち主のゾーンの WAF や設定が先に効く。どちらでも、ドメインの持ち主は CNAME を書き換えて issuer を乗っ取れるが、これは今の設計でも同じで（issuer の DNS を握る人は IdP の身元を握る）、新しい信頼の追加ではない。
  - IdP 専用アカウントの性質（D1 と managed CA の範囲）は保たれる。
- 無料枠：issuer の 1 ホスト名は 100 の範囲に収まる。`hard_cap` を 1 か小さい値にして、誤って追加しても課金されないようにできる。Free のレート制限ルールは条件にホスト名を使えない（[C6]）ので、今と同じくパスだけで、IdP のゾーンのすべてのホスト名に効く。
- 既存のコードへの影響：
  - `infra/`：カスタムホスト名、フォールバックオリジン、オリジンのないレコード、カスタムホスト名の TLS の最小バージョンを足す。mTLS、クライアント証明書、WAF のカスタムルール、ゾーンの設定は IdP のゾーンに対してそのまま。provider がカスタムホスト名とフォールバックオリジンを扱えるかは確かめる。
  - IdP の Worker の `cloudflare.config.ts`：issuer のホスト名のカスタムドメインを、IdP のゾーンのルート（`*/*` と CNAME の向け先のホスト名）に変える。ルートは fail closed を設定できる形なので、[未決事項](open-questions.md)の「カスタムドメインの fail closed」はルートの設定として確かめる項目に変わる。
  - 管理用の Worker、`gate.ts`、`idpctl`：変えない。
  - デプロイごとの入力：「ゾーン」は IdP のゾーンを指す。issuer のホスト名はそのゾーンの外でもよくなる。管理用のホスト名は IdP のゾーンの中に限る。issuer をゾーンの中に置くか（A1 と同じ）カスタムホスト名にするかを、issuer のホスト名とゾーンの関係から導くか、明示の入力にするかを決める。
  - ドキュメント：[デプロイと設定](deployment.md)（入力、Cloudflare アカウント、Terraform の分担）、[ブートストラップ](../deployment/bootstrap.md)と[実行手順](../deployment/runbook.md)（ドメインの持ち主の DNS の操作を前提の手作業に足す）、[無料枠](free-tier.md)、[セキュリティ要件チェックリスト](security-checklist.md)（カスタムホスト名の TLS の最小バージョン、フォールバックのホスト名の拒否）、[未決事項](open-questions.md)。
- 残るリスク：
  - ゾーンのカスタムルールの `http.host` が、カスタムホスト名のリクエストに当たるかはドキュメントで確かめられていない（未確認）。今は管理用のホスト名だけを `http.host` で絞っているので、影響するのはこの確認だけ。
  - Always Use HTTPS がカスタムホスト名に効くかは未確認。効かなくても Worker が平文のリクエストを 404 で拒否するので、fail-closed は保たれる。平文のリクエストはエッジでリダイレクトされず Worker に届き、1 日のリクエスト上限を使う。
  - `*/*` のルートが、管理用のホスト名のカスタムドメインより優先されないこと（カスタムドメインがルートより優先されること）は未確認。IdP の Worker は管理用のホスト名へのリクエストを 404 で拒否するので、間違っても管理 API が開くことはないが、管理 API が使えなくなる。
  - IdP のゾーンを手放した後もドメインの持ち主の CNAME が残ると、ぶら下がった CNAME になる。廃止の手順に CNAME の削除を入れる。

#### C. 保護を Worker の中に移し、ゾーンの機能に頼らない

ゾーンを持たずに、すべてを `workers.dev` で動かす形。issuer も `workers.dev` のホスト名になるので、それ単独では要件（ドメインの下に issuer を置く）を満たさない。D の部品、または管理用の Worker だけに使う形として評価する。

- 管理者の認証：エッジの mTLS の代わりに、HTTP Message Signatures（RFC 9421）を使う。`idpctl` が管理者の秘密鍵で要求に署名し、管理用の Worker が許可リストの公開鍵で検証する。
  - 署名の対象は、`@method`、`@authority`、`@path`、`@query`、本文のダイジェスト（RFC 9530 の `Content-Digest`）、`Idempotency-Key` にし、`created`、`expires`、`nonce`、`keyid` を付ける（RFC 9421 §2.3）。リプレイは、`created` からの最大の経過時間の制限と、`nonce` の一意性の確認で防ぐ（RFC 9421 §7.2.2、§3.2.1）。`nonce` は D1 に一意制約で保存し、`expires` を過ぎたものを消す。`@authority` を署名に含めるので、転送の途中でホストを変えると検証に失敗する。
  - アルゴリズムは許可リストで固定し、`alg` のパラメーターを信じない。RFC 9421 は ECDSA P-384 と SHA-384（§3.3.5）と Ed25519（§3.3.6）を定める。今の管理者の鍵は ECDSA P-384 なので、そのまま使えれば鍵の生成スクリプトを変えずに済む。Workers の Web Crypto は Ed25519 の署名と検証に対応している（[W1]）。P-384 の検証に対応していることは、この調査では確かめていない（未確認）。
  - mTLS と比べた利点：Cloudflare の managed CA と「SSL and Certificates Write」の権限が、管理者の信頼の根から外れる（今は証明書の発行と許可リストの両方が要る。これが許可リストだけになる）。ゾーンが要らない。TLS を終端する中継（D の転送用の Worker）があっても、要求の改ざんを検出できる。
  - mTLS と比べた欠点：認証されていないリクエストを Worker に届く前に止められない。Worker に届いたリクエストは 1 日のリクエスト上限に数えられる（[無料枠](free-tier.md)）。署名の検証、`Content-Digest`、`nonce` の保存を自分で実装し、検証の誤りがそのまま管理者の認証の欠陥になる。管理者 1 回の要求ごとに D1 に `nonce` の 1 行を書く。
- レート制限：Workers の Rate Limiting バインディングは 2025-09-19 に GA になった（[W2]）。期間は 10 秒か 60 秒で、拠点（location）ごとに別々に数え、結果整合で、上限を超えることがある。厳密な上限には Durable Objects を勧めている（[W3]）。Free で使えるかと料金は、ドキュメントに書かれていない（未確認）。バインディングは Worker の中で動くので、WAF と違って、止めたリクエストも 1 日のリクエスト上限を使う。
- HTTPS と TLS の最小バージョン：ゾーンがなければ Always Use HTTPS も TLS の最小バージョンも設定できない。Cloudflare の既定の TLS の最小バージョンは 1.0（[C7]）。Worker は `request.cf.tlsVersion` を見て 1.2 未満を拒否できる（[W4]、[W5]）が、ハンドシェイクの後に拒否するので、RFC 8996 §4・§5 の「TLS 1.0 と 1.1 を使ってはならない（MUST NOT）」は満たさない。採るなら例外として記録する必要がある。`workers.dev` が平文の HTTP をどう扱うか（リダイレクトするか）は未確認で、Worker の 404 で拒否する。
- `workers.dev` の制約：`workers.dev` は Free のウェブサイトとして扱われ、本番での利用を勧めていない。Browser Integrity Check を無効にできず、ライブラリの既定の `User-Agent` は Error 1010 で拒否される（[W6]）。RP のサーバーが `/token` を既定の `User-Agent` で呼ぶと拒否されうるので、issuer を `workers.dev` に置くのは RP の互換性の面でも勧めない。`workers.dev` を無効にしても、バージョンとプレビューの URL は無効にならず、`preview_urls = false` で別に無効にする（[W6]、[W7]）。
- Access：Cloudflare Access は Worker の `workers.dev` を守れる（[W8]）。ただし Access の mTLS は Free にない（[管理 CLI と管理用の Worker](idpctl.md)）ので、Free で使えるのはサービストークン（持参人の秘密）で、RFC 9421 より弱い。採らない。
- 影響：`gate.ts` を RFC 9421 の検証に置き換え、`idpctl` に署名を足し、許可リストを証明書のフィンガープリントから公開鍵（の `keyid`）に変える。`infra/` の mTLS、クライアント証明書、WAF、ゾーンの設定を外す。[管理 CLI と管理用の Worker](idpctl.md)、[デプロイと設定](deployment.md)、[ブートストラップ](../deployment/bootstrap.md)、チェックリストの「管理用の Worker（mTLS）」を書き直す。設計原則 1 の「エッジの mTLS で、管理者の証明書を持たないリクエストを Worker に届く前に止める」を変える。
- 残るリスク：証明書のない（署名のない）リクエストで、管理用の Worker を通じて IdP の 1 日のリクエスト上限を使い切れる。今の設計が「Free で可能か確かめる」としてきた性質を、確かめる前に手放すことになる。

#### D. ドメインのアカウントに置く転送用の Worker

- 仕組み：ドメインを持つアカウントに薄い転送用の Worker を置き、issuer のホスト名をそのカスタムドメインにする。転送用の Worker は、IdP のアカウントの IdP の Worker（`workers.dev`）へ要求をそのまま転送する。Service Binding は同じアカウントの中でしか使えないので、アカウントをまたぐ経路は公開の `fetch` になる。
- 信頼：issuer の DNS を握る人は、もともと IdP の身元を握っている（DNS を書き換えれば、別の Worker に issuer のホスト名を向けて、ID トークンを発行できる）。転送用の Worker をドメインの持ち主のアカウントに置いても、信頼の範囲（TCB）は広がらない。ただし、転送用の Worker のデプロイの権限と、そのアカウントの Workers の編集の権限も TCB に入る。DNS の編集権限よりも広く人に配られていることが多いので、ドメインのアカウントでの権限の配り方を確かめる必要がある。
- 直接のアクセスの拒否：IdP の Worker の `workers.dev` は公開されるので、IdP の Worker は、転送用の Worker だけが持つ秘密による証明がないリクエストを拒否する。秘密は、レビュー済みの生成スクリプトで作り、両方のアカウントの Worker Secret に直接渡す。証明は、静的なヘッダーではなく、時刻と要求の内容に対する HMAC（か C の RFC 9421 の署名）にして、漏れたログからの再利用を防ぐ。`workers.dev` では mTLS を使えない（ゾーンがない）。
- アカウントをまたぐ `fetch`：同じゾーンの Worker への `fetch` は Service Binding に限られる（[C1]）が、別のアカウントの `workers.dev` への `fetch` が許されることは、ドキュメントで確かめられていない（未確認）。`workers.dev` の Browser Integrity Check は無効にできないので、転送用の Worker は `User-Agent` を明示する必要がある（[W6]）。
- 利用者の IP：IdP の Worker から見た接続元は転送用の Worker になる。レート制限を IP で数えるなら、転送用の Worker が利用者の IP を証明の対象に含めて渡す必要がある。IdP は IP を記録しない方針（設計原則 7）なので、渡すのはレート制限のためだけにする。
- HTTPS と TLS：利用者の TLS は転送用の Worker のゾーン（ドメインの持ち主のゾーン）で終端する。Always Use HTTPS と TLS の最小バージョンは、そのゾーン全体の設定で、ドメインの持ち主が決める。転送用の Worker が `request.cf.tlsVersion` と URL のスキームを確かめて拒否することはできるが、C と同じく RFC 8996 の例外になる。
- 管理用の Worker：管理用のホスト名は issuer と違い、IdP の身元に関わらないので、ドメインの持ち主のドメインに置く必要はない。D では、管理用の Worker を `workers.dev` に置き、C の RFC 9421 で守るのが自然。転送用の Worker を通して、ドメインの持ち主のゾーンの mTLS を使う形は、管理者の証明書をドメインの持ち主のアカウントの managed CA で発行することになり、IdP 専用アカウントの性質を崩すので採らない。
- fork する人に求めるもの：ドメインが Cloudflare のどこかのアカウントにあること（Cloudflare 以外の DNS 事業者では使えない）。そのアカウントへの Worker のデプロイの権限と、2 つ目のデプロイのパイプライン（API トークン、1Password の Environment、CI）。
- 無料枠：利用者の 1 回のリクエストが、ドメインのアカウントの Workers（転送用）と IdP のアカウントの Workers（IdP）の両方の 1 日のリクエスト上限を使う。ドメインのアカウントのほかの Worker と上限を共有する。IdP の `workers.dev` は WAF で守れないので、直接のリクエストで IdP のアカウントの上限を使い切れる。
- 影響：転送用の Worker（新しいアプリ）と、そのデプロイの設定。IdP の Worker の `cloudflare.config.ts`（カスタムドメインを外し、`workers.dev` を有効にする）と、転送の証明の検証。issuer の確認（issuer のホスト名以外を拒否する）は、`workers.dev` で受けた要求に対して何で行うかを決め直す。管理用の Worker は C の影響をすべて受ける。`infra/` はほぼ空になる。
- 残るリスク：上の上限の消費。2 つのアカウントの間の秘密の管理とローテーション。アカウントをまたぐ `fetch` が許されるかの未確認。転送用の Worker と IdP の Worker の 2 か所にリクエストの境界があり、ヘッダーの扱い（`Host`、`Cookie`、`Sec-Fetch-Site`、`Origin`）の食い違いが、チェックリストの項目（同一オリジンの確認、`__Host-` Cookie）を壊しうる。

#### 比較

| 観点 | A1 専用ドメイン | A2 ドメインのアカウント（最後の手段） | B Cloudflare for SaaS | C `workers.dev` だけ | D 転送用の Worker |
| --- | --- | --- | --- | --- | --- |
| issuer を別のアカウントのドメインに置ける | いいえ | はい（同じアカウントにする） | はい | いいえ | はい |
| Cloudflare 以外の DNS 事業者 | — | — | はい | — | いいえ |
| IdP のアカウントにゾーンが要る | はい | いいえ | はい | いいえ | いいえ |
| 管理用のエッジの mTLS | 今のまま | 今のまま（CA の範囲が広がる） | 今のまま | なし（RFC 9421） | なし（RFC 9421） |
| 認証前のリクエストを Worker の前で止める | はい | はい（ルールを取り合う） | はい | いいえ | 転送側だけ |
| TLS 1.2 の最小をエッジで強制 | はい | ゾーン全体に効く | ホスト名ごとに可能 | いいえ | ドメインの持ち主しだい |
| IdP 専用アカウント | 保つ | 破る | 保つ | 保つ | 保つ（TCB にドメインのアカウントの Workers の権限が入る） |
| コードの変更 | なし | なし | ルートと `infra/` | 管理者の認証を作り直す | 新しい Worker と C の全部 |

### 提案の時点の推奨

アカウントをまたぐ案のうち、実際に使えるものは B だけで、これを第 1 の推奨とする。B が使えないか、IdP のアカウントにゾーンを持つことを受け入れないときは、運用者が認めた最後の手段の A2 を第 2 とする。D と C は勧めない。A1 は B の特別な場合（issuer も IdP のゾーンに置く）として扱う。

| 順位 | 案 | セキュリティ | 移植性（fork して自分のアカウントとドメインを入れる） | 無料枠 |
| --- | --- | --- | --- | --- |
| 1 | B Cloudflare for SaaS | 今の性質をすべて保つ。IdP 専用アカウント、エッジの mTLS、Worker の前の WAF とレート制限、ホスト名ごとの TLS 1.2。ドメインの持ち主は CNAME を握るが、これは今も同じ | どの DNS 事業者のドメインでも、CNAME（と TXT）を 1 回作ればよい。代わりに、IdP のアカウントにゾーン（ドメインの購入）が要る | 1 ホスト名で、無料の 100 に収まる。`hard_cap` で課金を防げる。上限を共有しない |
| 2 | A2 ドメインのアカウント | エッジの保護は保つが、IdP 専用アカウントの性質を失う（D1 のトークン、managed CA、基盤の権限を持つ人の範囲）。ゾーンを共有するなら、ゾーンの設定とルールセットの持ち主を決め直す | ドメインが Cloudflare にあれば、ドメインを買わずに済み、DNS の手作業もない。Cloudflare 以外の DNS 事業者では、ゾーンごと移す必要がある。ゾーンをほかの用途と共有するときは、ドメインを管理する側との合意と PR が要る | 1 日のリクエスト上限と D1 の上限を、アカウントのほかのサービスと共有する。Free のレート制限ルール（ゾーンに 1 つ）をほかの用途と取り合う |
| 3 | D 転送用の Worker | IdP 専用アカウントは保つが、IdP の `workers.dev` が公開され、認証前のリクエストを Worker の前で止められない。管理者の認証を RFC 9421 で作り直し、RFC 8996 の例外を置く。リクエストの境界が 2 か所になる | ドメインが Cloudflare にあることが要る。2 つのアカウントに 2 つのデプロイのパイプラインと、アカウントをまたぐ秘密が要る | 1 回のリクエストが 2 つのアカウントの上限を使う。直接のリクエストで IdP の上限を使い切れる |

- A2 を D より上にする理由：A2 で失うのはアカウントの分離で、運用者が受け入れると明言した。D で失うのは、Worker の前で止める保護と管理者のエッジの mTLS で、受け入れると言われていない。さらに D は、未確認の前提（アカウントをまたぐ `fetch`）と、新しいコードの量が最も多い。
- C は issuer をドメインの下に置けないので、要件を満たさない。

B の詳細：

- 不変条件を「IdP のアカウントは自分のゾーンを 1 つ持ち、管理用のホスト名は必ずそのゾーンに置く。issuer のホスト名は、そのゾーンの中（A1）か、Cloudflare for SaaS のカスタムホスト名として任意のドメイン（B）に置く」とする。
- 理由 1：要件（issuer のドメインがどのアカウントにあっても、Cloudflare 以外の DNS 事業者でもよい）を満たす唯一の選択肢で、ドメインの持ち主に求めるのは CNAME（と TXT）の作成だけ。
- 理由 2：管理用のホスト名を issuer のドメインから切り離せば、管理者のエッジの mTLS、WAF、`gate.ts`、`idpctl` を何も変えずに済む。管理用のホスト名は IdP の身元に関わらないので、issuer と同じドメインである必要はない。
- 理由 3：IdP 専用アカウントの性質（D1 と managed CA の範囲）を保つ。A2 はこれを破る。
- 理由 4：C と D は、ゾーンを買わずに済む代わりに、認証前のリクエストを Worker の前で止める性質と、エッジでの TLS の最小バージョンの強制を手放し、管理者の認証を作り直す。家族規模の IdP で、ドメイン 1 つの費用と引き換えにするほどの利点はない。
- ドメインの持ち主の CNAME は DNS だけ（proxied にしない）を既定にする。O2O を避け、IdP のゾーンの設定だけが効く形にするため。検証の構成では、ドメインを管理するリポジトリに `proxied = false` の CNAME と TXT を足す。
- 実装に入る前に、検証用のアカウントで次を実測で確かめる（どれかが成り立たなければ、この推奨を見直す）。DNS だけの CNAME を別の Cloudflare アカウントから向けたカスタムホスト名が有効になり、O2O にならないこと。`*/*` のルートでカスタムホスト名のリクエストが IdP の Worker に届き、管理用のホスト名のカスタムドメインはルートより優先されること。カスタムホスト名に TLS の最小バージョン 1.2 が効くこと。Terraform の provider でカスタムホスト名とフォールバックオリジンを持てること。

### 運用者の決定

提案は、運用者に、IdP のアカウントにゾーンを持つか（B と A1）、最後の手段の A2 にするか、A2 ならゾーンの設定とルールセットの持ち主をどうするかを決めるよう求めた。運用者は A2 を選んだ。ゾーンの設定とルールセットの扱いは、最初は持ち主を `idp` と `external` で選ぶ形にしたが、その後、運用者が決定 ③（IdP はゾーンのルールセットを持たない）を選んだ。どちらも、この文書の上の「ゾーンをサービスと共有するときの共存の設計」にある。提案の (a)（IdP のルールをゾーンの持ち主のリポジトリに書く）と (b)（IdP がフェーズを持ち、サービスのルールも受け入れる）は、どちらも IdP の保護をゾーンのルールセットに置く形で、③ で要らなくなった。

## 未確認の事項

公式ドキュメントで確かめられなかったもの。推測で埋めない。採った A2 に関わるものは、[未決事項](open-questions.md)に移し、最初のデプロイで確かめる。

A2 に関わるもの：

- Workers の Rate Limiting バインディングが Workers Free で使えるかと、その料金（[W2]、[W3]、Workers の料金と上限のページのどれにも書かれていない）
- `request.cf.tlsVersion` の値の一覧。ドキュメントは例として `TLSv1.3` だけを挙げる（[W4]）。`TLSv1.2` の綴りは、Cloudflare の例（[W5]）の綴りに合わせた
- 管理用のホスト名に mTLS を割り当て、WAF のルールを置かないとき、証明書のない要求が管理用の Worker に届き、`request.cf.tlsClientAuth` の検証の結果が `SUCCESS` 以外（証明書なしの `NONE` など）になること。管理用の Worker は、どの値でも `SUCCESS` でなければ拒否する
- `run_worker_first` を真にしたカスタムドメインの Worker に、平文の HTTP の要求が `http:` の URL のまま届くこと（ゾーンの Always Use HTTPS が無効のとき）と、そのとき `request.cf.tlsVersion` がどの値になるか。ローカルの workerd では、平文の要求が Worker に届き、Worker がリダイレクトすることを e2e で確かめた
- API トークンの権限の正確な名前（クライアント証明書と mTLS のホスト名の割り当て）。権限の一覧のページは 2 つの表で名前が食い違う（[C15]）。トークンを作るときに、最小の組み合わせを確かめて記録する

採らなかった案に関わるもの（経緯として残す）：

- ゾーンの WAF のカスタムルールの `http.host` が、カスタムホスト名のリクエストに当たるか
- Always Use HTTPS がカスタムホスト名に効くか
- 別の Cloudflare アカウントの DNS だけの CNAME で、カスタムホスト名が O2O にならずに有効になるか（ドキュメントは O2O を proxied の場合として説明している）
- Workers のルート（`*/*`）とカスタムドメインの優先順位
- 別のアカウントの `workers.dev` への `fetch` が許されるか
- Workers の Web Crypto で ECDSA P-384 の署名を検証できるか
- `workers.dev` で平文の HTTP がどう扱われるか、Worker の単位で TLS の最小バージョンを設定できるか
- ドメインの持ち主のゾーンのプランが O2O の条件になるか

## 出典

調べた日：2026-11-09。

| 記号 | 出典 |
| --- | --- |
| C1 | Cloudflare Workers「Custom Domains」 https://developers.cloudflare.com/workers/configuration/routing/custom-domains/ |
| C2 | Cloudflare DNS「Subdomain setup」 https://developers.cloudflare.com/dns/zone-setups/subdomain-setup/ |
| C3 | Cloudflare DNS「Partial (CNAME) setup」 https://developers.cloudflare.com/dns/zone-setups/partial-setup/ |
| C4 | Cloudflare「Error 1014」 https://developers.cloudflare.com/support/troubleshooting/http-status-codes/cloudflare-1xxx-errors/error-1014/ |
| C5 | Cloudflare API Shield「mTLS」 https://developers.cloudflare.com/api-shield/security/mtls/ |
| C6 | Cloudflare WAF「Rate limiting rules」 https://developers.cloudflare.com/waf/rate-limiting-rules/ |
| C7 | Cloudflare SSL「Protocols」 https://developers.cloudflare.com/ssl/reference/protocols/ と「Minimum TLS version」 https://developers.cloudflare.com/ssl/edge-certificates/additional-options/minimum-tls/ |
| C8 | Cloudflare SSL「Always Use HTTPS」 https://developers.cloudflare.com/ssl/edge-certificates/additional-options/always-use-https/ |
| C9 | Cloudflare WAF「Custom rules」 https://developers.cloudflare.com/waf/custom-rules/ |
| C10 | Cloudflare Rules「Single Redirects」 https://developers.cloudflare.com/rules/url-forwarding/single-redirects/ |
| C11 | Cloudflare Ruleset Engine「Phases list」 https://developers.cloudflare.com/ruleset-engine/reference/phases-list/ |
| C12 | Cloudflare Ruleset Engine「Rulesets」の「Entry point ruleset」（フェーズごとに、アカウントとゾーンの単位で多くても 1 つ） https://developers.cloudflare.com/ruleset-engine/about/rulesets/ |
| C13 | Cloudflare Rules「URL forwarding」の「Availability」（シングルリダイレクトはすべてのプラン、Free はゾーンあたり 10 ルール、ワイルドカードは可、正規表現は不可） https://developers.cloudflare.com/rules/url-forwarding/ |
| C14 | Cloudflare Rules「Redirect admin area requests to HTTPS」 https://developers.cloudflare.com/rules/url-forwarding/examples/redirect-admin-https/ |
| C15 | Cloudflare Fundamentals「API token permissions」（D1 と Workers のスクリプトはアカウントの権限） https://developers.cloudflare.com/fundamentals/api/reference/permissions/ |
| C16 | Cloudflare Fundamentals「Create API token」（権限を特定のゾーンに絞る） https://developers.cloudflare.com/fundamentals/api/get-started/create-token/ |
| S1 | Cloudflare for SaaS「Plans」 https://developers.cloudflare.com/cloudflare-for-platforms/cloudflare-for-saas/plans/ |
| S2 | Cloudflare for SaaS「Workers as your fallback origin」 https://developers.cloudflare.com/cloudflare-for-platforms/cloudflare-for-saas/start/advanced-settings/worker-as-origin/ |
| S3 | Cloudflare for SaaS「Quotas and billing」 https://developers.cloudflare.com/cloudflare-for-platforms/cloudflare-for-saas/quotas-and-billing/ |
| S4 | Cloudflare for SaaS「Getting started」 https://developers.cloudflare.com/cloudflare-for-platforms/cloudflare-for-saas/start/getting-started/ |
| S5 | Cloudflare for SaaS「Hostname validation」 https://developers.cloudflare.com/cloudflare-for-platforms/cloudflare-for-saas/domain-support/hostname-validation/ |
| S6 | Cloudflare for SaaS「Validate certificates」 https://developers.cloudflare.com/cloudflare-for-platforms/cloudflare-for-saas/security/certificate-management/issue-and-validate/validate-certificates/ |
| S7 | Cloudflare for SaaS「Pre-validation」 https://developers.cloudflare.com/cloudflare-for-platforms/cloudflare-for-saas/domain-support/hostname-validation/pre-validation/ |
| S8 | Cloudflare for SaaS「Delegated DCV」 https://developers.cloudflare.com/cloudflare-for-platforms/cloudflare-for-saas/security/certificate-management/issue-and-validate/validate-certificates/delegated-dcv/ |
| S9 | Cloudflare for SaaS「How O2O works」 https://developers.cloudflare.com/cloudflare-for-platforms/cloudflare-for-saas/saas-customers/how-it-works/ |
| S10 | Cloudflare for SaaS「Product compatibility」 https://developers.cloudflare.com/cloudflare-for-platforms/cloudflare-for-saas/saas-customers/product-compatibility/ |
| S11 | Cloudflare for SaaS「Enforce mTLS」 https://developers.cloudflare.com/cloudflare-for-platforms/cloudflare-for-saas/security/certificate-management/enforce-mtls/ |
| S12 | Cloudflare for SaaS「WAF for SaaS」 https://developers.cloudflare.com/cloudflare-for-platforms/cloudflare-for-saas/security/waf-for-saas/ |
| W1 | Cloudflare Workers「Web Crypto」 https://developers.cloudflare.com/workers/runtime-apis/web-crypto/ |
| W2 | Cloudflare Changelog（2025-09-19、`ratelimit` バインディングの GA） https://developers.cloudflare.com/changelog/post/2025-09-19-ratelimit-workers-ga/ |
| W3 | Cloudflare Workers「Rate Limiting」 https://developers.cloudflare.com/workers/runtime-apis/bindings/rate-limit/ |
| W4 | Cloudflare Workers「Request」（`request.cf`） https://developers.cloudflare.com/workers/runtime-apis/request/ |
| W5 | Cloudflare Workers「Block on TLS」 https://developers.cloudflare.com/workers/examples/block-on-tls/ |
| W6 | Cloudflare Workers「workers.dev」 https://developers.cloudflare.com/workers/configuration/routing/workers-dev/ |
| W7 | Cloudflare Workers「Version URLs」 https://developers.cloudflare.com/workers/versions-and-deployments/version-urls/ |
| W8 | Cloudflare Workers「Cloudflare Access」 https://developers.cloudflare.com/workers/configuration/cloudflare-access/ |
| R1 | RFC 9421「HTTP Message Signatures」 https://www.rfc-editor.org/rfc/rfc9421 |
| R2 | RFC 9530「Digest Fields」 https://www.rfc-editor.org/rfc/rfc9530 |
| R3 | RFC 8996「Deprecating TLS 1.0 and TLS 1.1」 https://www.rfc-editor.org/rfc/rfc8996 |
