import { fetchJson, loopbackUrl, type JsonResponse, type NetworkMetrics } from './http.js';
import { type Credential, READ_SCOPE } from './issuer.js';

export interface Discovery {
  issuer: string; token_endpoint: string; jwks_uri: string;
  introspection_endpoint: string; revocation_endpoint: string;
}
export interface TokenResponse { access_token: string; token_type: 'Bearer'; expires_in: number; scope?: string }

export async function discover(issuerUrl: string, metrics?: NetworkMetrics, timeoutMs = 1000): Promise<Discovery> {
  const issuer = loopbackUrl(issuerUrl);
  if (issuer.pathname !== '/' || issuer.search) throw new Error('This lab expects an origin-only issuer.');
  const expected = issuer.origin;
  const response = await fetchJson(`${expected}/.well-known/openid-configuration`, {}, { timeoutMs, ...(metrics ? { metrics } : {}) });
  if (response.status !== 200 || response.body.issuer !== expected) throw new Error('Issuer discovery mismatch.');
  const metadata: Record<string, string> = { issuer: expected };
  for (const name of ['token_endpoint', 'jwks_uri', 'introspection_endpoint', 'revocation_endpoint']) {
    const value = response.body[name];
    if (typeof value !== 'string') throw new Error('Missing issuer endpoint.');
    const endpoint = loopbackUrl(value);
    if (endpoint.origin !== expected || endpoint.search) throw new Error('Issuer endpoint origin mismatch.');
    metadata[name] = endpoint.href;
  }
  return metadata as unknown as Discovery;
}

function formPart(value: string): string { return new URLSearchParams({ value }).toString().slice(6); }

export class OAuthClient {
  constructor(readonly discovery: Discovery, private readonly credential: Credential,
    private readonly metrics?: NetworkMetrics, private readonly timeoutMs = 1000) {}

  async post(endpoint: string, values: Record<string, string>, allowEmpty = false): Promise<JsonResponse> {
    const url = loopbackUrl(endpoint);
    if (url.origin !== this.discovery.issuer) throw new Error('Untrusted OAuth endpoint.');
    const basic = Buffer.from(`${formPart(this.credential.clientId)}:${formPart(this.credential.clientSecret)}`).toString('base64');
    return fetchJson(url, { method: 'POST', headers: {
      authorization: `Basic ${basic}`, 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json',
    }, body: new URLSearchParams(values) }, {
      timeoutMs: this.timeoutMs, allowEmpty, ...(this.metrics ? { metrics: this.metrics } : {}),
    });
  }

  async issue(resource: string, scope = READ_SCOPE): Promise<TokenResponse> {
    const response = await this.post(this.discovery.token_endpoint, { grant_type: 'client_credentials', resource, scope });
    const value = response.body;
    if (response.status !== 200 || typeof value.access_token !== 'string' || value.access_token.length > 4096
        || value.token_type !== 'Bearer' || typeof value.expires_in !== 'number' || !Number.isSafeInteger(value.expires_in)
        || value.expires_in < 1 || value.expires_in > 60 || (value.scope !== undefined && typeof value.scope !== 'string')) {
      throw new Error('The local issuer did not return a supported access token.');
    }
    return { access_token: value.access_token, token_type: 'Bearer', expires_in: value.expires_in,
      ...(typeof value.scope === 'string' ? { scope: value.scope } : {}) };
  }

  introspect(token: string): Promise<JsonResponse> {
    return this.post(this.discovery.introspection_endpoint, { token, token_type_hint: 'access_token' });
  }

  revoke(token: string): Promise<JsonResponse> {
    return this.post(this.discovery.revocation_endpoint, { token, token_type_hint: 'access_token' }, true);
  }
}
