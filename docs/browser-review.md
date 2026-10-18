# Local browser review identity

This companion is a separate local issuer for the Enterprise AI Lab review UI.
It implements actual browser authentication with **Authorization Code + PKCE
S256**, using `oidc-provider` 9.12.2. It does not turn the existing service
client-credentials fixtures into people.

A user supplies a username and password on the issuer's HTML form. The provider
validates the registered redirect and code challenge; the portal then redeems
the one-use code and independently verifies the ID/access tokens. The portal
must check its own state, nonce, PKCE verifier, issuer/audience and callback.
The provider's signed interaction cookie plus an interaction-specific CSRF token
protect the password form. A cross-origin form submission is rejected.

## Start the private fixture

Build with Node 24 (Node 22 is also tested). Have the portal bind its loopback
port first, then launch this child process:

```sh
npm ci --ignore-scripts
npm run build
node dist/review-bridge.js \
  --redirect-uri http://127.0.0.1:8088/auth/callback \
  --accounts-file /absolute/private/path/accounts.json
```

The account file is a **trusted local fixture**, outside Git: an owned, regular,
non-symlink file with mode `0600`, at most 32 KiB. Its schema is:

```json
{
  "schema_version": 1,
  "accounts": [
    {"username": "reviewer-alpha", "password": "replace-with-a-generated-local-fixture-password"}
  ]
}
```

Do not use an existing password. Passwords must have 16–128 printable ASCII
characters. The fixture reads them only at startup and retains salted scrypt
hashes in memory; it never prints them. Restrict the file to the accounts needed
for the experiment. Roles and tenants cannot be supplied by this file or by the
login form; they come from the registered profiles below.

The child prints a single public `ready` JSON object with issuer/authorization/
token/JWKS URLs, `client_id`, audience, available profiles and token lifetime.
It never sends access tokens or passwords over its JSONL channel. Closing stdin,
SIGTERM, or `{"id":1,"op":"shutdown"}` stops the issuer. Do not expose this
fixture outside loopback.

## Registered client and claims

| Setting | Value |
| --- | --- |
| Client | `review-portal`, public, no client secret |
| Grant | Authorization Code only; no client credentials or refresh token |
| PKCE | S256 mandatory; `plain` is rejected by the provider |
| Redirect | One exact `http://127.0.0.1:<port>/auth/callback` URI, no query/fragment |
| Access-token audience | `urn:identity-boundary:review` |
| Signing/type | RS256 / `at+jwt` |
| Subject | Authenticated fixture username; distinct from `client_id` |
| Extra claims | `tenant_id`, `roles`, `identity_kind: "user"` |
| Lifetime | 300 seconds by default, configurable 1–600 seconds |
| ID token | Client audience, nonce from the authorization request, required `auth_time` |

For the expiry test only, append `--ttl-seconds 3`. This changes **only the review
issuer**. The original report/RAG/approval service tokens still expire within
60 seconds.

Request `openid review:read review:request review:decide` with the review resource.
The issuer grants only the scopes allowed by the authenticated account. A valid
observer token has no review scopes. The portal must check roles **and** granted
scopes, not merely a successful login.

| Account | Tenant | Roles | Review scopes |
| --- | --- | --- | --- |
| `requester-alpha` | alpha | requester, reader | read, request |
| `reviewer-alpha` | alpha | approver, reader | read, decide |
| `analyst-reviewer-alpha` | alpha | approver, reader, analyst | read, decide |
| `requester-beta` | beta | requester, reader | read, request |
| `reviewer-beta` | beta | approver, reader | read, decide |
| `reader-alpha` | alpha | reader | read |
| `observer-alpha` | alpha | observer | none |

The `review:*` prefix is omitted from the last column for readability. The
Enterprise companion must still enforce document tenant and role access before
returning a PDF, a text span, audit data, or accepting a decision. An `approver`
role does not automatically grant `analyst` document access. A batch decision
requires access to every document in that immutable snapshot. Self-approval
remains prohibited by the durable workflow.

## Verification and limits

`tests/review-browser.test.mjs` exercises the real issuer over HTTP, actual
password forms and signed cookies, authorization redirects, PKCE token exchange,
RS256 ID/access verification, user/tenant/role/scope binding, one-use codes,
wrong passwords, CSRF, Origin, wrong verifier, redirect/resource restrictions and
account-file boundaries. These are automated fixture interactions, not a claim
that the owner or another person reviewed a document.

Sessions, grants, signing keys and password hashes use process memory. Restart
requires login and new discovery/key trust; this is not durable identity storage,
key rotation, federation, SAML, SCIM, MFA, production password management or an
external SSO integration. HTTP and fixture credentials are confined to literal
loopback. Five failed form submissions stop that interaction; this is not a
production abuse-prevention system. The local administrator can change the
fixture, replace code or read process memory. A bearer token remains valid until
its expiry when verified offline; logout in the portal does not revoke it.

The API usage follows the maintained provider's
[configuration and interaction documentation](https://github.com/panva/node-oidc-provider/blob/v9.12.2/docs/README.md).
The upstream library's support does not certify this fixture.
