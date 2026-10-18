# Working in Identity Boundary Lab

- Use the maintained standards implementation for issuer/token endpoints. Do not replace OAuth/OIDC behavior with a handwritten imitation or call client credentials browser SSO.
- Keep the first milestone local and synthetic: real HTTP discovery/JWKS, client credentials, audience checks, tenant/RBAC policy, and explicit token-format/revocation tradeoffs. The original client-credentials flow remains separate from the local browser-review issuer. Browser review uses actual Code + PKCE and tested password forms; external SSO/federation, SAML and SCIM remain planned.
- Bind all servers to 127.0.0.1. No existing credentials, cloud accounts, external identity services, paid APIs or public deployment. Generate local signing keys and fixture client secrets at startup; do not persist or log bearer tokens/private keys.
- Fail closed on invalid issuer, audience, algorithm, signature, expiry, tenant, roles and introspection/network failures. Bound input sizes, HTTP waits and response bodies; do not follow issuer redirects or derive trusted URLs from unverified token claims.
- Run real HTTP integration tests against the actual local issuer, plus the documented demo. Preserve standard errors and distinguish opaque-token revocation from stateless JWT behavior. Do not imply two different tokens are the same token.
- Keep dependencies exact and the lockfile committed. Use Node 24 LTS; CI also targets Node 22.
- Preserve true dates and evidence. Disclose AI assistance; automated checks are not owner review, standards certification, penetration testing or production validation.

- The Enterprise AI Lab RAG companion uses a dedicated JWT audience/scope and private JSONL child bridge. Keep access tokens confined to that explicit IPC and Authorization headers; no raw protocol logs, secret export or caller-supplied identity trust.
