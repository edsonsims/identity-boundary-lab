import { type JWK } from 'jose';
import { startIssuer, type FixtureClientId } from './issuer.js';
import { discover, OAuthClient } from './oauth.js';
import { startResourceApi } from './resource.js';

export async function startLab(options: { issuerPort?: number; apiPort?: number; signingJwk?: JWK; ttlSeconds?: number; timeoutMs?: number } = {}) {
  const issuer = await startIssuer({ ...(options.issuerPort !== undefined ? { port: options.issuerPort } : {}),
    ...(options.signingJwk ? { signingJwk: options.signingJwk } : {}),
    ...(options.ttlSeconds !== undefined ? { ttlSeconds: options.ttlSeconds } : {}) });
  let startedApi: Awaited<ReturnType<typeof startResourceApi>> | undefined;
  try {
    const api = await startResourceApi({ issuer: issuer.url, credential: issuer.credentials.get('resource-api')!,
      ...(options.apiPort !== undefined ? { port: options.apiPort } : {}),
      ...(options.timeoutMs !== undefined ? { timeoutMs: options.timeoutMs } : {}) });
    startedApi = api;
    const metadata = await discover(issuer.url);
    return {
      issuer, api,
      client(id: FixtureClientId): OAuthClient { return new OAuthClient(metadata, issuer.credentials.get(id)!); },
      async close(): Promise<void> { try { await api.close(); } finally { await issuer.close(); } },
    };
  } catch (error) {
    try { await startedApi?.close(); } finally { await issuer.close(); }
    throw error;
  }
}
