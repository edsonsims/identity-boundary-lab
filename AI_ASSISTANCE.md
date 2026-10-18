# Assistance and verification

The implementation, tests, synthetic fixture principals, documentation and SVG
artwork were drafted with OpenAI Codex assistance. Automated agents exercised
actual local HTTP flows and reviewed boundaries. This does not claim owner study
or human review.

Local verification used Node.js 24.19.0, TypeScript 7.0.2 and macOS arm64. A fresh
locked install, strict build, all 67 tests, `npm run demo` and the example client
passed. Tests exercise the actual oidc-provider issuer and jose verifier, tenant/
role/scope policy, revocation, expiry and outage behavior, plus separate negative
claim/signature fixtures and bounded-network cases.

Independent automated review found two defects before publication: inherited
Node environment-proxy mode could bypass the loopback destination restriction,
and a discovery failure during partial startup could leave the resource API
listening. The implementation now rejects all three proxy opt-in forms before
requests and closes both servers after partial startup failure. Regressions for
these cases are retained in `tests/review.test.mjs`; the 67-test run includes
them and the reviewer's additional introspection-claim and key-snapshot checks.

CI is configured for Node 22 and 24. A configured workflow is not evidence of a
successful remote run; check the published revision's actual CI result.

The issuer, tokens and profile data are local synthetic fixtures. Signing keys
and client secrets are generated per process. No existing credentials, employer
code, customer data, real accounts, cloud identity service or paid API is used.
No model inference is involved.

The README artwork is an abstract illustration, not a screenshot or a live UI.
Recorded response excerpts come from the documented local demo and example
client. Upstream OAuth/OIDC support or certification is attributed to the
third-party library, not claimed for this application.

This milestone implements OAuth client credentials and resource authorization.
Browser SSO, authorization code with PKCE, SAML, SCIM, durable issuer storage,
key rotation and production deployment remain unimplemented. The two token
formats in the revocation comparison are separately issued tokens with different
audiences; the documentation retains the provider's structured-JWT limitation.


The RAG connection adds a dedicated audience/scope, analyst fixture profiles and
a bounded private child-process protocol for Enterprise AI Lab. Local Node24.19.0
verification passes **81 tests**, including 14 new actual issuer-process tests.
The Python companion separately exercises real HTTP, signatures, dense embeddings,
vector persistence and tenant/role retrieval; its own CI and recorded observations
are the evidence for that side. This remains automated verification, not owner
study or human review. RAG JWTs retain the same offline revocation/key-snapshot
limitations as other structured access tokens.

The durable-approval companion adds a dedicated JWT audience and role-bounded
request/read/decide scopes, also developed with Codex. Requester, approver and
dual-role service fixtures exercise independent-review and self-approval rules
in the Python/Temporal companion. They do not establish that a human reviewed or
approved a document. New Node tests obtain actual provider-issued tokens, verify
their signatures and check that unpermitted scopes are omitted and that audience swapping fails. Temporal
persistence, worker crash recovery and history replay are verified and recorded
in Enterprise AI Lab, separately from the issuer tests here.

The approval audience extension passed **89 Node 24.19.0 tests** locally. The
provider omits unsupported scopes from issued tokens; the tests check the granted
scopes and the resource independently requires its scope and role. They do not
assume every unsupported scope request produces an OAuth error. The existing
reports/RAG audiences and their validation/revocation behavior remain covered.
