import { randomBytes, randomUUID } from 'node:crypto';
import { createServer } from 'node:http';
import { exportJWK, generateKeyPair, type JWK } from 'jose';
import Provider, { errors, type Configuration } from 'oidc-provider';
import { close, listen } from './http.js';

export const JWT_RESOURCE = 'urn:identity-boundary:reports:jwt';
export const OPAQUE_RESOURCE = 'urn:identity-boundary:reports:opaque';
export const READ_SCOPE = 'reports:read';
export const RAG_RESOURCE = 'urn:identity-boundary:rag';
export const RAG_SCOPE = 'rag:query';
export const TOKEN_TTL_SECONDS = 60;
export const PROFILES = Object.freeze({
  'reader-alpha': Object.freeze({ tenantId: 'alpha', roles: Object.freeze(['reader']) }),
  'reader-beta': Object.freeze({ tenantId: 'beta', roles: Object.freeze(['reader']) }),
  'observer-alpha': Object.freeze({ tenantId: 'alpha', roles: Object.freeze(['observer']) }),
  'analyst-alpha': Object.freeze({ tenantId: 'alpha', roles: Object.freeze(['reader', 'analyst']) }),
  'analyst-beta': Object.freeze({ tenantId: 'beta', roles: Object.freeze(['reader', 'analyst']) }),
});
export type FixtureClientId = keyof typeof PROFILES;
export interface Credential { clientId: string; clientSecret: string }

export async function startIssuer(options: { port?: number; signingJwk?: JWK; ttlSeconds?: number } = {}) {
  let callback: ReturnType<Provider['callback']> | undefined;
  const server = createServer({ maxHeaderSize: 8192, requestTimeout: 2000, headersTimeout: 2000 }, (request, response) => {
    if (!callback) { response.writeHead(503).end(); return; }
    callback(request, response);
  });
  const url = await listen(server, options.port);
  try {
    const privateJwk = options.signingJwk ?? await (async () => {
      const keys = await generateKeyPair('RS256', { modulusLength: 2048, extractable: true });
      return { ...await exportJWK(keys.privateKey), kid: randomUUID(), alg: 'RS256', use: 'sig' };
    })();
    if (privateJwk.kty !== 'RSA' || !privateJwk.d || !privateJwk.kid) throw new Error('Provide a private RSA signing JWK with kid.');
    const ttl = options.ttlSeconds ?? TOKEN_TTL_SECONDS;
    if (!Number.isInteger(ttl) || ttl < 1 || ttl > TOKEN_TTL_SECONDS) throw new Error('Invalid token TTL.');
    const credentials = new Map<string, Credential>();
    for (const clientId of [...Object.keys(PROFILES), 'resource-api']) {
      credentials.set(clientId, { clientId, clientSecret: randomBytes(32).toString('base64url') });
    }
    const configuration: Configuration = {
      clients: [...credentials.values()].map(client => ({
        client_id: client.clientId, client_secret: client.clientSecret,
        grant_types: ['client_credentials'], response_types: [], redirect_uris: [],
        token_endpoint_auth_method: 'client_secret_basic',
      })),
      jwks: { keys: [privateJwk] },
      cookies: { keys: [randomBytes(32).toString('base64url')] },
      clientAuthMethods: ['client_secret_basic'],
      features: {
        devInteractions: { enabled: false },
        clientCredentials: { enabled: true },
        introspection: { enabled: true, allowedPolicy: (_ctx, client, token) =>
          client.clientId === 'resource-api' && 'aud' in token && token.aud === OPAQUE_RESOURCE },
        revocation: { enabled: true, allowedPolicy: (_ctx, client, token) => client.clientId === token.clientId },
        resourceIndicators: {
          enabled: true,
          defaultResource: () => { throw new errors.InvalidTarget('Provide an explicit supported resource.'); },
          getResourceServerInfo: (_ctx, resource, client) => {
            if (!Object.hasOwn(PROFILES, client.clientId) || ![JWT_RESOURCE, OPAQUE_RESOURCE, RAG_RESOURCE].includes(resource)) {
              throw new errors.InvalidTarget('Unsupported resource or client.');
            }
            return { scope: resource === RAG_RESOURCE ? RAG_SCOPE : READ_SCOPE, audience: resource, accessTokenTTL: ttl,
              accessTokenFormat: resource === OPAQUE_RESOURCE ? 'opaque' : 'jwt', jwt: { sign: { alg: 'RS256' } } };
          },
        },
      },
      ttl: { ClientCredentials: ttl },
      extraTokenClaims: (_ctx, token) => {
        const profile = PROFILES[token.clientId as FixtureClientId];
        if (!profile) throw new errors.InvalidClient('No fixture principal is registered.');
        return { tenant_id: profile.tenantId, roles: [...profile.roles] };
      },
      // This milestone never authenticates an end user or follows external URLs.
      fetch: async () => { throw new Error('External issuer requests are disabled.'); },
    };
    const provider = new Provider(url, configuration);
    callback = provider.callback();
    return { url, credentials, provider, close: () => close(server) };
  } catch (error) { await close(server); throw error; }
}
