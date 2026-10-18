import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { createLocalJWKSet, jwtVerify, type JSONWebKeySet } from 'jose';
import { close, fetchJson, listen, type NetworkMetrics } from './http.js';
import { JWT_RESOURCE, OPAQUE_RESOURCE, type Credential } from './issuer.js';
import { discover, OAuthClient } from './oauth.js';
import { authorize, BoundaryError, principalFromClaims } from './policy.js';

function reply(response: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}): void {
  response.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...headers });
  response.end(JSON.stringify(body));
}

function bearer(request: IncomingMessage): string {
  const values = request.rawHeaders.filter((_value, index) => index % 2 === 0
    && request.rawHeaders[index]!.toLowerCase() === 'authorization');
  const header = request.headers.authorization;
  if (values.length !== 1 || typeof header !== 'string' || header.length > 4103) {
    throw new BoundaryError(401, 'invalid_token', 'One bounded Bearer authorization header is required.');
  }
  const match = /^Bearer ([A-Za-z0-9._~+/=-]+)$/i.exec(header);
  if (!match) throw new BoundaryError(401, 'invalid_token', 'A Bearer access token is required.');
  return match[1]!;
}

export async function startResourceApi(options: { issuer: string; credential: Credential; port?: number; timeoutMs?: number }) {
  const metrics: NetworkMetrics = { requests: 0 };
  const timeoutMs = options.timeoutMs ?? 1000;
  const metadata = await discover(options.issuer, metrics, timeoutMs);
  const jwks = await fetchJson(metadata.jwks_uri, {}, { timeoutMs, metrics });
  if (jwks.status !== 200 || !Array.isArray(jwks.body.keys)) throw new Error('Issuer JWKS is unavailable.');
  const resolveKey = createLocalJWKSet(jwks.body as unknown as JSONWebKeySet);
  const introspector = new OAuthClient(metadata, options.credential, metrics, timeoutMs);
  const server = createServer({ maxHeaderSize: 8192, requestTimeout: 2000, headersTimeout: 2000 }, (request, response) => {
    void (async () => {
      const url = new URL(request.url ?? '/', 'http://127.0.0.1');
      if (request.method !== 'GET') { reply(response, 405, { error: { code: 'method_not_allowed' } }, { allow: 'GET' }); return; }
      if (url.pathname === '/healthz' && !url.search) { reply(response, 200, { status: 'ok' }); return; }
      if (url.search) throw new BoundaryError(400, 'invalid_request', 'Query parameters are not supported.');
      const route = /^\/(offline|online)\/v1\/tenants\/([a-z][a-z0-9-]{0,63})\/reports$/.exec(url.pathname);
      if (!route) { reply(response, 404, { error: { code: 'not_found' } }); return; }
      const token = bearer(request);
      const mode = route[1]!;
      let claims: Record<string, unknown>;
      if (mode === 'offline') {
        try {
          const verified = await jwtVerify(token, resolveKey, { issuer: metadata.issuer, audience: JWT_RESOURCE,
            algorithms: ['RS256'], typ: 'at+jwt', requiredClaims: ['iss', 'aud', 'exp', 'iat', 'sub', 'client_id', 'jti'], maxTokenAge: 60 });
          if (verified.payload.sub !== verified.payload.client_id) throw new Error('Not a client-credentials identity.');
          claims = verified.payload;
        } catch { throw new BoundaryError(401, 'invalid_token', 'The access token is not valid for this resource.'); }
      } else {
        let result;
        try { result = await introspector.introspect(token); }
        catch { throw new BoundaryError(503, 'issuer_unavailable', 'Online token validation is unavailable.'); }
        if (result.status === 400 && result.body.error === 'unsupported_token_type') {
          throw new BoundaryError(401, 'invalid_token', 'This endpoint requires an opaque access token.');
        }
        if (result.status !== 200) throw new BoundaryError(503, 'issuer_unavailable', 'Online token validation is unavailable.');
        if (result.body.active !== true || result.body.token_type !== 'Bearer') {
          throw new BoundaryError(401, 'invalid_token', 'The access token is not active.');
        }
        claims = result.body;
      }
      const principal = principalFromClaims(claims, metadata.issuer, mode === 'offline' ? JWT_RESOURCE : OPAQUE_RESOURCE);
      const tenant = route[2]!;
      authorize(principal, tenant);
      reply(response, 200, { tenantId: tenant, reports: [{ id: `${tenant}-demo-report`, text: `Synthetic report for ${tenant}.` }],
        authorization: { mode: mode === 'offline' ? 'offline-jwt' : 'online-introspection', clientId: principal.clientId } });
    })().catch(error => {
      const failure = error instanceof BoundaryError ? error : new BoundaryError(500, 'internal_error', 'The request could not be completed.');
      reply(response, failure.status, { error: { code: failure.code, message: failure.message } },
        failure.status === 401 ? { 'www-authenticate': 'Bearer realm="identity-boundary-lab", error="invalid_token"' } : {});
    });
  });
  try {
    const url = await listen(server, options.port);
    return { url, metrics, close: () => close(server) };
  } catch (error) { await close(server); throw error; }
}
