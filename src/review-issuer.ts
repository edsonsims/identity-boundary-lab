/** Local end-user sign-in fixture. Never use these accounts as a production IdP. */
import { constants, openSync, fstatSync, readSync, closeSync } from 'node:fs';
import { randomBytes, randomUUID, scryptSync, timingSafeEqual } from 'node:crypto';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { exportJWK, generateKeyPair } from 'jose';
import Provider, { errors, type Configuration } from 'oidc-provider';
import { close, listen, loopbackUrl } from './http.js';

export const REVIEW_RESOURCE = 'urn:identity-boundary:review';
export const REVIEW_CLIENT_ID = 'review-portal';
export const REVIEW_READ = 'review:read';
export const REVIEW_REQUEST = 'review:request';
export const REVIEW_DECIDE = 'review:decide';
export const REVIEW_PROFILES = Object.freeze({
  'requester-alpha': Object.freeze({ tenantId: 'alpha', roles: Object.freeze(['requester', 'reader']) }),
  'reviewer-alpha': Object.freeze({ tenantId: 'alpha', roles: Object.freeze(['approver', 'reader']) }),
  'analyst-reviewer-alpha': Object.freeze({ tenantId: 'alpha', roles: Object.freeze(['approver', 'reader', 'analyst']) }),
  'requester-beta': Object.freeze({ tenantId: 'beta', roles: Object.freeze(['requester', 'reader']) }),
  'reviewer-beta': Object.freeze({ tenantId: 'beta', roles: Object.freeze(['approver', 'reader']) }),
  'reader-alpha': Object.freeze({ tenantId: 'alpha', roles: Object.freeze(['reader']) }),
  'observer-alpha': Object.freeze({ tenantId: 'alpha', roles: Object.freeze(['observer']) }),
});
export type ReviewUsername = keyof typeof REVIEW_PROFILES;
const ALL_SCOPES = [REVIEW_READ, REVIEW_REQUEST, REVIEW_DECIDE];
export function reviewScopes(roles: readonly string[]): string[] {
  return [...(roles.includes('reader') || roles.includes('analyst') ? [REVIEW_READ] : []),
    ...(roles.includes('requester') ? [REVIEW_REQUEST] : []), ...(roles.includes('approver') ? [REVIEW_DECIDE] : [])];
}
interface PasswordRecord { salt: Buffer; hash: Buffer }
function loadAccounts(path: string): Map<ReviewUsername, PasswordRecord> {
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.size > 32768 || (stat.mode & 0o777) !== 0o600
      || (process.getuid && stat.uid !== process.getuid())) throw new Error('Account fixture must be an owned mode-0600 regular file.');
    const buffer = Buffer.alloc(32769);
    let length = 0;
    while (length < buffer.length) { const count = readSync(fd, buffer, length, buffer.length - length, null); if (!count) break; length += count; }
    const bytes = buffer.subarray(0, length);
    if (bytes.byteLength > 32768) throw new Error('Account fixture exceeds its limit.');
    const value: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid accounts.');
    const doc = value as Record<string, unknown>;
    if (Object.keys(doc).sort().join(',') !== 'accounts,schema_version' || doc.schema_version !== 1
      || !Array.isArray(doc.accounts) || doc.accounts.length < 1 || doc.accounts.length > Object.keys(REVIEW_PROFILES).length) throw new Error('Invalid accounts.');
    const records = new Map<ReviewUsername, PasswordRecord>();
    for (const row of doc.accounts) {
      if (!row || typeof row !== 'object' || Array.isArray(row)
        || Object.keys(row).sort().join(',') !== 'password,username'
        || typeof row.username !== 'string' || !Object.hasOwn(REVIEW_PROFILES, row.username)
        || typeof row.password !== 'string' || !/^[\x20-\x7e]{16,128}$/.test(row.password) || records.has(row.username as ReviewUsername)) throw new Error('Invalid account fixture.');
      const salt = randomBytes(16);
      records.set(row.username as ReviewUsername, { salt, hash: scryptSync(row.password, salt, 32) });
    }
    return records;
  } finally { closeSync(fd); }
}
function escape(value: string): string { return value.replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!); }
function headers(response: ServerResponse, status: number, type = 'text/html; charset=utf-8') {
  response.writeHead(status, { 'content-type': type, 'cache-control': 'no-store', 'pragma': 'no-cache',
    'content-security-policy': "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
    'x-content-type-options': 'nosniff', 'referrer-policy': 'no-referrer', 'x-frame-options': 'DENY' });
}
async function body(request: IncomingMessage): Promise<URLSearchParams> {
  if (request.headers['content-type']?.split(';')[0] !== 'application/x-www-form-urlencoded') throw new Error('Invalid form.');
  const chunks: Buffer[] = []; let size = 0;
  for await (const chunk of request) { size += chunk.length; if (size > 4096) throw new Error('Form exceeds limit.'); chunks.push(Buffer.from(chunk)); }
  const params = new URLSearchParams(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)));
  if ([...params.keys()].some(key => !['csrf', 'username', 'password'].includes(key) || params.getAll(key).length !== 1)) throw new Error('Invalid form fields.');
  return params;
}
export async function startReviewIssuer(options: { redirectUri: string; accountsFile: string; port?: number; ttlSeconds?: number }) {
  const redirect = loopbackUrl(options.redirectUri);
  if (!redirect.port || redirect.search || redirect.pathname !== '/auth/callback') throw new Error('Use an exact loopback /auth/callback redirect.');
  const ttl = options.ttlSeconds ?? 300;
  if (!Number.isInteger(ttl) || ttl < 1 || ttl > 600) throw new Error('Invalid token TTL.');
  const accounts = loadAccounts(options.accountsFile);
  const dummy = { salt: randomBytes(16), hash: randomBytes(32) };
  let callback: ReturnType<Provider['callback']> | undefined, issuerUrl = '';
  let provider: Provider;
  const forms = new Map<string, { csrf: string; deadline: number; attempts: number }>();
  const server = createServer({ maxHeaderSize: 8192, requestTimeout: 3000, headersTimeout: 3000 }, (request, response) => {
    void (async () => {
      if (!callback || request.headers.host !== new URL(issuerUrl).host
        || Object.keys(request.headers).some(key => key === 'forwarded' || key.startsWith('x-forwarded-'))) { headers(response, 400); response.end('Invalid local request.'); return; }
      const pathname = new URL(request.url ?? '/', issuerUrl).pathname;
      const match = /^\/interaction\/([A-Za-z0-9_-]{1,128})$/.exec(pathname);
      if (!match) { callback(request, response); return; }
      if (request.url !== pathname || !['GET', 'POST'].includes(request.method ?? '')) { headers(response, 400); response.end('Invalid interaction.'); return; }
      const details = await provider.interactionDetails(request, response);
      if (details.uid !== match[1] || details.params.client_id !== REVIEW_CLIENT_ID
        || !['login', 'consent'].includes(details.prompt.name)) throw new Error('Invalid interaction.');
      const uid = details.uid;
      for (const [key, value] of forms) if (value.deadline < Date.now()) forms.delete(key);
      let form = forms.get(uid);
      if (request.method === 'GET') {
        if (!form) { if (forms.size >= 256) { headers(response, 503); response.end('Try again later.'); return; }
          form = { csrf: randomBytes(32).toString('base64url'), deadline: Date.now() + 300000, attempts: 0 }; forms.set(uid, form); }
        headers(response, 200);
        const consent = details.prompt.name === 'consent';
        response.end(`<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Identity Boundary · local sign-in</title><style>body{font:17px system-ui;background:#ece8ff;color:#1c1730;max-width:420px;margin:8vh auto;padding:24px}main{background:white;border:2px solid;padding:28px;box-shadow:7px 7px #7354ce}h1{font-size:28px}label{display:block;margin:18px 0}input,button{box-sizing:border-box;width:100%;padding:12px;font:inherit;border:1px solid}button{background:#7354ce;color:white;cursor:pointer}small{display:block;line-height:1.6}</style><main><small>IDENTITY BOUNDARY LAB · LOCAL FIXTURE</small><h1>${consent ? 'Continue to review' : 'Sign in to review'}</h1><p>Local study accounts only. Use the generated fixture credentials.</p><form method="post" action="/interaction/${escape(uid)}"><input type="hidden" name="csrf" value="${form.csrf}">${consent ? '' : '<label>Username<input name="username" autocomplete="username" required maxlength="96"></label><label>Password<input name="password" type="password" autocomplete="current-password" required maxlength="128"></label>'}<button type="submit">${consent ? 'Continue' : 'Sign in'}</button></form><p><small>Authorization Code + PKCE. No external identity service. This fixture is not production authentication.</small></p></main></html>`); return;
      }
      if (request.headers.origin !== issuerUrl || !form || form.deadline < Date.now()) { headers(response, 403); response.end('Invalid sign-in form.'); return; }
      const fields = await body(request);
      const csrf = fields.get('csrf') ?? '';
      if (csrf.length !== form.csrf.length || !timingSafeEqual(Buffer.from(csrf), Buffer.from(form.csrf))) { headers(response, 403); response.end('Invalid sign-in form.'); return; }
      if (++form.attempts > 5) { headers(response, 429); response.end('Start a new sign-in attempt.'); return; }
      let accountId: string | undefined;
      if (details.prompt.name === 'login') {
        const username = fields.get('username') ?? '', password = fields.get('password') ?? '';
        const record = accounts.get(username as ReviewUsername) ?? dummy;
        const valid = /^[\x20-\x7e]{16,128}$/.test(password) && timingSafeEqual(scryptSync(password, record.salt, 32), record.hash);
        if (!valid || !accounts.has(username as ReviewUsername)) { headers(response, 401); response.end('Sign-in failed. Return to the sign-in form and try again.'); return; }
        accountId = username;
      } else accountId = details.session?.accountId;
      if (!accountId || !accounts.has(accountId as ReviewUsername)) throw new Error('Invalid account.');
      const profile = REVIEW_PROFILES[accountId as ReviewUsername];
      const requested = String(details.params.scope ?? '').split(' ');
      const permitted = reviewScopes(profile.roles);
      const grant = new provider.Grant({ accountId, clientId: REVIEW_CLIENT_ID });
      if (requested.includes('openid')) grant.addOIDCScope('openid');
      grant.addResourceScope(REVIEW_RESOURCE, requested.filter(scope => permitted.includes(scope)));
      grant.rejectResourceScope(REVIEW_RESOURCE, requested.filter(scope => ALL_SCOPES.includes(scope) && !permitted.includes(scope)));
      const grantId = await grant.save();
      forms.delete(uid);
      await provider.interactionFinished(request, response, { ...(details.prompt.name === 'login' ? { login: { accountId } } : {}), consent: { grantId } }, { mergeWithLastSubmission: false });
    })().catch(() => { if (!response.headersSent) headers(response, 400); response.end('Invalid local sign-in request.'); });
  });
  issuerUrl = await listen(server, options.port);
  try {
    const keys = await generateKeyPair('RS256', { modulusLength: 2048, extractable: true });
    const privateJwk = { ...await exportJWK(keys.privateKey), kid: randomUUID(), alg: 'RS256', use: 'sig' };
    const configuration: Configuration = {
      clients: [{ client_id: REVIEW_CLIENT_ID, grant_types: ['authorization_code'], response_types: ['code'],
        redirect_uris: [redirect.href], token_endpoint_auth_method: 'none', id_token_signed_response_alg: 'RS256', require_auth_time: true }],
      clientAuthMethods: ['none'], jwks: { keys: [privateJwk] },
      cookies: { keys: [randomBytes(32).toString('base64url')], short: { httpOnly: true, sameSite: 'lax' }, long: { httpOnly: true, sameSite: 'lax' } },
      scopes: ['openid'], claims: { openid: ['sub'] }, pkce: { required: () => true },
      interactions: { url: (_ctx, interaction) => `/interaction/${interaction.uid}` },
      features: { devInteractions: { enabled: false }, userinfo: { enabled: false }, resourceIndicators: {
        enabled: true, defaultResource: () => { throw new errors.InvalidTarget('Select the review resource.'); },
        getResourceServerInfo: (_ctx, resource, client) => {
          if (resource !== REVIEW_RESOURCE || client.clientId !== REVIEW_CLIENT_ID) throw new errors.InvalidTarget('Unsupported resource.');
          return { scope: ALL_SCOPES.join(' '), audience: REVIEW_RESOURCE, accessTokenTTL: ttl,
            accessTokenFormat: 'jwt', jwt: { sign: { alg: 'RS256' } } };
        },
      } },
      ttl: { AccessToken: ttl, IdToken: ttl, AuthorizationCode: 60, Interaction: 300, Session: 900, Grant: 900 },
      findAccount: (_ctx, id) => accounts.has(id as ReviewUsername) ? { accountId: id, claims: () => ({ sub: id }) } : undefined,
      extraTokenClaims: (_ctx, token) => {
        if (!('accountId' in token) || !token.accountId || !accounts.has(token.accountId as ReviewUsername)) throw new errors.InvalidGrant('No fixture user.');
        const profile = REVIEW_PROFILES[token.accountId as ReviewUsername];
        return { tenant_id: profile.tenantId, roles: [...profile.roles], identity_kind: 'user' };
      },
      fetch: async () => { throw new Error('External issuer requests are disabled.'); },
    };
    provider = new Provider(issuerUrl, configuration);
    callback = provider.callback();
    return { url: issuerUrl, provider, clientId: REVIEW_CLIENT_ID, redirectUri: redirect.href,
      profiles: [...accounts.keys()].map(username => ({ username, ...REVIEW_PROFILES[username] })), close: () => close(server) };
  } catch (error) { await close(server); throw error; }
}
