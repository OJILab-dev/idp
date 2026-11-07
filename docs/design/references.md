# 参考資料

**標準規格**

- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)
- [RFC 9700：OAuth 2.0 Security Best Current Practice](https://datatracker.ietf.org/doc/html/rfc9700)
- [RFC 7636：PKCE](https://datatracker.ietf.org/doc/html/rfc7636)
- [RFC 9207：認可レスポンスの iss](https://datatracker.ietf.org/doc/html/rfc9207)
- [RFC 7638：JWK Thumbprint](https://datatracker.ietf.org/doc/html/rfc7638)
- [RFC 9562：UUID](https://datatracker.ietf.org/doc/html/rfc9562)
- [RFC 9068：JWT アクセストークン](https://datatracker.ietf.org/doc/html/rfc9068)
- [RFC 8725：JWT Best Current Practices](https://datatracker.ietf.org/doc/html/rfc8725)
- [RFC 8252：OAuth 2.0 for Native Apps](https://www.rfc-editor.org/rfc/rfc8252)
- [RFC 10017：OAuth 2.0 for Browser-Based Applications](https://www.rfc-editor.org/rfc/rfc10017.html)
- [Web Authentication Level 3（W3C）](https://www.w3.org/TR/webauthn-3/)
- [WebAuthn 推奨アルゴリズムの議論（W3C public-webauthn）](https://lists.w3.org/Archives/Public/public-webauthn/2025Mar/0087.html)
- [NIST SP 800-63B-4：Authentication and Authenticator Management](https://pages.nist.gov/800-63-4/sp800-63b.html)
- [NIST SP 800-57 Part 1 Rev. 5：Recommendation for Key Management（§5.6.1.1 Table 2 のセキュリティ強度）](https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final)
- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
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
- [D1 の Time Travel（常に有効、追加費用なし）](https://developers.cloudflare.com/d1/reference/time-travel/)
- [D1 の制限（Time Travel の保持期間）](https://developers.cloudflare.com/d1/platform/limits/)
- [D1 REST API（raw query）](https://developers.cloudflare.com/api/operations/cloudflare-d1-raw-database-query)
- [Client certificates (mTLS)（managed CA の上限）](https://developers.cloudflare.com/ssl/client-certificates/)
- [Create a client certificate（自分の CSR、プラン別の上限）](https://developers.cloudflare.com/ssl/client-certificates/create-a-client-certificate/)
- [API：Create Client Certificate（`csr` と `validity_days`、必要な権限）](https://developers.cloudflare.com/api/resources/client_certificates/methods/create/)
- [API：Revoke Client Certificate（`pending_revocation`）](https://developers.cloudflare.com/api/resources/client_certificates/methods/delete/)
- [Revoke a client certificate](https://developers.cloudflare.com/ssl/client-certificates/revoke-client-certificate/)
- [Enable mTLS（アカウント単位の CA で検証）](https://developers.cloudflare.com/ssl/client-certificates/enable-mtls/)
- [Bring your own CA for mTLS（Enterprise のみ）](https://developers.cloudflare.com/ssl/client-certificates/byo-ca/)
- [mTLS related features（失効の遮断、WAF のルール）](https://developers.cloudflare.com/learning-paths/mtls/mtls-app-security/related-features/)
- [Rules language：cf.tls\_client\_auth.cert\_verified](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.tls_client_auth.cert_verified/)
- [Client certificate variables（Workers の `request.cf.tlsClientAuth`）](https://developers.cloudflare.com/ssl/client-certificates/client-certificate-variables/)
- [Cloudflare One：Mutual TLS（Access の mTLS、プランと署名アルゴリズム）](https://developers.cloudflare.com/cloudflare-one/access-controls/service-credentials/mutual-tls-authentication/)
- [Cloudflare CLI（`cf`、ベータ）](https://developers.cloudflare.com/cf/)
- [cf for Wrangler users（`cf d1 query` はデータベース ID を取る）](https://developers.cloudflare.com/cf/wrangler/)

**言語・ライブラリ**

- [workers-rs（worker クレート）](https://docs.rs/crate/worker/0.8.3/source/src/lib.rs)
- [rsa クレート（Marvin Attack の注意書き）](https://docs.rs/rsa)
- [Playwright](https://playwright.dev/)
- [Claude Code：Enterprise network configuration（`CLAUDE_CODE_CLIENT_CERT`）](https://code.claude.com/docs/en/network-config.md)
- [Claude Code：Connect Claude Code to tools via MCP（`requiresUserInteraction`）](https://code.claude.com/docs/en/mcp.md)
- [1Password SSH Agent](https://www.1password.dev/ssh/agent/)
