# HTTP contract

The issuer and resource API are separate real HTTP servers, both bound to
`127.0.0.1`. `npm run demo` and `node examples/client.mjs` start isolated instances
on ephemeral ports. `npm start` uses issuer port 9100 and API port 9101 by default.

## Issuer endpoints

Discover the exact endpoints through:

```text
GET /.well-known/openid-configuration
```

The metadata identifies the issuer, token endpoint, `jwks_uri`, introspection
endpoint and revocation endpoint. Clients check the issuer and require every
endpoint to stay on its exact loopback origin. No redirects are followed.

The token endpoint accepts OAuth client authentication using
`client_secret_basic` and an `application/x-www-form-urlencoded` body:

```text
grant_type=client_credentials
scope=reports:read
resource=urn:identity-boundary:reports:jwt
```

Use `urn:identity-boundary:reports:opaque` for the introspected format. Unknown
resources and omitted resource parameters are rejected. Tokens have a maximum
60-second lifetime and carry server-assigned tenant and role claims.

Client IDs are `reader-alpha`, `reader-beta`, `observer-alpha` and the private
resource-server client `resource-api`. Secrets are generated for each process.
The Node example receives them internally; no existing credentials are used or
printed. `resource-api` can introspect opaque tokens but cannot obtain principal
tokens. Other clients cannot introspect a token's active state or revoke tokens
belonging to another client.

## Resource endpoints

```text
GET /offline/v1/tenants/{tenantId}/reports
Authorization: Bearer <JWT for the JWT resource audience>

GET /online/v1/tenants/{tenantId}/reports
Authorization: Bearer <opaque token for the opaque resource audience>
```

An actual response for `reader-alpha` reading `alpha` in offline mode:

```json
{
  "tenantId": "alpha",
  "reports": [{"id": "alpha-demo-report", "text": "Synthetic report for alpha."}],
  "authorization": {"mode": "offline-jwt", "clientId": "reader-alpha"}
}
```

Online mode uses `online-introspection` in the authorization field. No token or
private key appears in the response. Tenant comes from the verified token or
introspection result and is compared with the requested path; a caller header
cannot choose another identity.

| Status | Meaning |
| --- | --- |
| 200 | Authorized synthetic report, or `GET /healthz` readiness |
| 400 | Unsupported query parameters; bearer tokens in URLs are refused |
| 401 | Missing/malformed/invalid/expired/inactive token or wrong token format |
| 403 | Token is valid but tenant, reader role or required scope does not authorize access |
| 404 | Unknown API path |
| 405 | Unsupported HTTP method; API accepts GET |
| 503 | Online introspection could not be completed or authenticated |

Errors have the shape:

```json
{"error":{"code":"forbidden","message":"This principal cannot read this tenant resource."}}
```

There must be exactly one authorization header. Bearer values are bounded to
4,096 characters, and the Node HTTP server additionally bounds headers. Error
messages never echo bearer tokens, client secrets or private keys.

## Revocation behavior

The real provider's revocation endpoint accepts an authenticated client's opaque
access token. A successful 200 makes the next introspection report it inactive.
A different client's revocation request receives the normal response without
revoking another client's token or revealing whether it exists.

Structured JWT requests to this provider's introspection or revocation endpoint
return HTTP 400 with `unsupported_token_type`. Sending a JWT to the online API
therefore returns 401. The offline API checks the JWT's signature and claims
against the startup key snapshot until expiry; it does not consult issuer state.

Revoking the opaque token does not revoke its client's separately issued JWT or
disable the client. The demo reports those separate outcomes explicitly.
