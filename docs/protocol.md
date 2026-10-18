# Protocol choices and limits

## What is implemented

The lab uses the maintained [oidc-provider 9.12.2](https://github.com/panva/node-oidc-provider/tree/v9.12.2)
OAuth/OIDC implementation and [jose 6.2.12](https://github.com/panva/jose/tree/v6.2.12)
for resource-server JWT verification. Packages and integrity values are pinned
in `package-lock.json`; the application does not implement a new OAuth server
or cryptographic primitive.

The milestone implements the application identity portion of OAuth:

- [Client credentials, RFC 6749 §4.4](https://www.rfc-editor.org/rfc/rfc6749#section-4.4)
- [Resource indicators, RFC 8707](https://www.rfc-editor.org/rfc/rfc8707)
- [Bearer token transport, RFC 6750](https://www.rfc-editor.org/rfc/rfc6750)
- [Token introspection, RFC 7662](https://www.rfc-editor.org/rfc/rfc7662)
- [Token revocation, RFC 7009](https://www.rfc-editor.org/rfc/rfc7009)
- [JWT access-token profile, RFC 9068](https://www.rfc-editor.org/rfc/rfc9068)

Library support for OpenID Connect does not make this client-credentials study
browser SSO. There are no end-user sessions, authorization-code redirects, PKCE,
SAML assertions or SCIM provisioning flows in this milestone.

## Two resources and two tokens

The same synthetic client requests:

| Resource audience | Format | Resource-server trust |
| --- | --- | --- |
| `urn:identity-boundary:reports:jwt` | RS256 JWT with `at+jwt` type | Signature from the startup JWKS snapshot plus issuer/audience/time/identity claims |
| `urn:identity-boundary:reports:opaque` | Opaque access token | Active introspection result authenticated with the separate resource-server client |

The audience split stops a token issued for one validation mode from being
silently accepted by the other. Both modes apply the same tenant, role and scope
policy after token validation. Roles and tenant are assigned by the local issuer's
fixture profile; additional request parameters cannot supply them.

## Why the revocation comparison uses paired tokens

This provider deliberately rejects structured-token introspection and revocation;
see its [rejection middleware](https://github.com/panva/node-oidc-provider/blob/v9.12.2/lib/shared/reject_structured_tokens.js)
and [JWT token format](https://github.com/panva/node-oidc-provider/blob/v9.12.2/lib/models/formats/jwt.js).
JWT issuance returns a signed value without retaining a revocable opaque-token
record. Opaque access tokens retain issuer state and can be removed.

The demo first issues both formats, then revokes the opaque token. Its next online
request is denied, while the separate JWT is still accepted by the offline path.
A JWT revocation attempt returns the upstream `unsupported_token_type` error.
This demonstrates token-format and validator tradeoffs; it does not show two
validators disagreeing about one revocable JWT.

A client remains able to obtain new tokens after revoking one token. The lab does
not implement account disablement, push revocation, a JWT denylist or policy
updates during a token's lifetime. Both formats expire within 60 seconds.

## Availability and network budget

The resource API performs one discovery request and one JWKS request at startup.
The internal example client separately discovers the same issuer for token
operations. Each opaque-token API access makes one introspection request, with
no retries or active-result cache. JWT API access makes no issuer request.

Outbound operations accept only HTTP to literal `127.0.0.1`. Discovered endpoints
must share the configured issuer origin, and URLs from unverified token claims
are never fetched. Redirects are refused. Node environment-proxy mode is rejected
before requests, including its environment-variable, CLI and `NODE_OPTIONS` opt-ins. Each call has a default one-second
deadline and 16-KiB JSON-response limit. Tests also exercise stalled bodies,
oversized responses and injected discovery endpoints.

Introspection failure returns 503; an inactive or invalid token returns 401.
Cached-key JWT validation can keep working during issuer outage, but cannot
observe token revocation or new issuer policy. The keyset is a startup snapshot:
unknown/new signing keys are refused until the API is restarted. No rotation,
key-overlap window or remote-JWKS refresh policy is implemented.

## Local state and transport

Every start generates new RSA signing keys, synthetic client secrets and cookie
keys. The provider uses its documented development in-memory adapter. Opaque
records and credentials disappear on restart and are not shared across processes.
Private keys and bearer tokens are not printed or written to disk.

Loopback HTTP keeps this experiment usable without certificates. It is not a
transport-security design for a deployed identity service. There is no TLS,
authenticated user directory, persistent secret store, production rate limiter,
load test, penetration test or compliance/standards certification here.

## Verification and next studies

Integration tests obtain positive tokens through real discovery/token/JWKS/
introspection/revocation HTTP endpoints. Separate negative fixtures use controlled
keys to isolate issuer, audience, signature, algorithm, type and time checks.
This distinguishes protocol integration from direct policy tests.

Useful next milestones are authorization code with PKCE and actual browser
sessions, persistent issuer storage, key rotation and a separately designed
client/policy revocation mechanism. SAML and SCIM require their own implementations
and interoperability tests. They remain planned work.


## Connected RAG audience

The companion Enterprise AI Lab is a separate Python resource server. It accepts
only the dedicated `urn:identity-boundary:rag` JWT audience and `rag:query` scope;
it obtains keys from this actual issuer's discovery/JWKS. The Node fixture adds
reader/analyst principals, while the Python resource applies tenant and document
role permissions before vector top-k. Reports tokens and RAG tokens are not
interchangeable. The private JSONL bridge transports ephemeral access tokens to
the parent process, without exporting client secrets or private keys.
