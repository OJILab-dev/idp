# 参考資料

**標準規格**

- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)
- [RFC 9700：OAuth 2.0 Security Best Current Practice](https://datatracker.ietf.org/doc/html/rfc9700)
- [RFC 7636：PKCE](https://datatracker.ietf.org/doc/html/rfc7636)
- [RFC 9207：認可レスポンスの iss](https://datatracker.ietf.org/doc/html/rfc9207)
- [RFC 9068：JWT アクセストークン](https://datatracker.ietf.org/doc/html/rfc9068)
- [RFC 8725：JWT Best Current Practices](https://datatracker.ietf.org/doc/html/rfc8725)
- [RFC 8252：OAuth 2.0 for Native Apps](https://www.rfc-editor.org/rfc/rfc8252)
- [RFC 10017：OAuth 2.0 for Browser-Based Applications](https://www.rfc-editor.org/rfc/rfc10017.html)
- [Web Authentication Level 3（W3C）](https://www.w3.org/TR/webauthn-3/)
- [WebAuthn 推奨アルゴリズムの議論（W3C public-webauthn）](https://lists.w3.org/Archives/Public/public-webauthn/2025Mar/0087.html)
- [OpenID Foundation：Self-Certification FAQ](https://openid.net/certification/what-is-self-certification-faq/)
- [Cloudflare Workers：Web Crypto](https://developers.cloudflare.com/workers/runtime-apis/web-crypto/)

**先行事例**

- [Pocket ID のリリース一覧](https://github.com/pocket-id/pocket-id/releases)
- [Pocket ID：v2 への移行ガイド](https://pocket-id.org/docs/setup/major-releases/migrate-v2)
- [Pocket ID：APIs and permissions](https://pocket-id.org/docs/guides/apis)
- [edge-idp（旧 tannerwj/identity）](https://github.com/tannerwj/edge-idp)
- [edge-idp：THREAT\_MODEL.md](https://github.com/tannerwj/edge-idp/blob/master/docs/THREAT_MODEL.md)
- [edge-idp：DEPLOY.md](https://github.com/tannerwj/edge-idp/blob/master/DEPLOY.md)
- [edge-idp：CHANGELOG.md](https://github.com/tannerwj/edge-idp/blob/master/CHANGELOG.md)

**セキュリティ事例（Pocket ID の CVE）**

- [CVE-2026-55834：prompt=none のオープンリダイレクト](https://advisories.gitlab.com/golang/github.com/pocket-id/pocket-id/backend/CVE-2026-55834/)
- [CVE-2026-28513：認可コードのクロスクライアント交換](https://github.com/advisories/GHSA-qh6q-598w-w6m2)
- [CVE-2026-43983：リフレッシュトークンによる失効のすり抜け](https://github.com/pocket-id/pocket-id/security/advisories/GHSA-w6p7-2fxx-4f44)
- [CVE-2026-62662：client credentials での任意 audience](https://cve.threatint.com/CVE/CVE-2026-62662)
- [CVE-2026-115770：メール検証トークンの使い回し](https://github.com/pocket-id/pocket-id/security/advisories/GHSA-rm8c-2cv8-jwf6)

**Cloudflare**

- [Workers の制限](https://developers.cloudflare.com/workers/platform/limits)
- [Workers の料金（上限に数えられるリクエスト）](https://developers.cloudflare.com/workers/platform/pricing/)
- [WAF のレート制限ルール（プラン別の制約）](https://developers.cloudflare.com/waf/rate-limiting-rules/)
- [D1 の料金と無料枠](https://developers.cloudflare.com/d1/platform/pricing/)
- [D1 REST API（raw query）](https://developers.cloudflare.com/api/operations/cloudflare-d1-raw-database-query)

**言語・ライブラリ**

- [MCP 公式 Go SDK](https://github.com/modelcontextprotocol/go-sdk)
- [workers-rs（worker クレート）](https://docs.rs/crate/worker/0.8.3/source/src/lib.rs)
- [rsa クレート（Marvin Attack の注意書き）](https://docs.rs/rsa)
- [Claude Code：permissions](https://code.claude.com/docs/en/permissions?r=0)
