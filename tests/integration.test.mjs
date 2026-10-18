import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { request as httpRequest } from 'node:http';
import { randomUUID } from 'node:crypto';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import { startLab } from '../dist/lab.js';
import { JWT_RESOURCE, OPAQUE_RESOURCE, READ_SCOPE, PROFILES } from '../dist/issuer.js';
import { OAuthClient } from '../dist/oauth.js';

let lab, keys, jwk;
before(async () => {
  keys = await generateKeyPair('RS256', { extractable: true });
  jwk = { ...await exportJWK(keys.privateKey), kid: randomUUID(), alg: 'RS256', use: 'sig' };
  lab = await startLab({ signingJwk: jwk });
});
after(async () => { if (lab) await lab.close(); });

async function api(mode, token, tenant = 'alpha', extra = '') {
  const response = await fetch(`${lab.api.url}/${mode}/v1/tenants/${tenant}/reports${extra}`, {
    headers: token === undefined ? {} : { authorization: `Bearer ${token}` }, signal: AbortSignal.timeout(2000),
  });
  return { status: response.status, body: await response.json(), headers: response.headers };
}
async function signed(overrides = {}, header = {}) {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({ iss: lab.issuer.url, aud: JWT_RESOURCE, iat: now, exp: now + 30,
    sub: 'reader-alpha', client_id: 'reader-alpha', jti: randomUUID(),
    tenant_id: 'alpha', roles: ['reader'], scope: READ_SCOPE, ...overrides })
    .setProtectedHeader({ alg: 'RS256', kid: jwk.kid, typ: 'at+jwt', ...header }).sign(keys.privateKey);
}

test('real discovery and JWKS describe the local issuer and actual public key only', async () => {
  const response = await fetch(`${lab.issuer.url}/.well-known/openid-configuration`);
  assert.equal(response.status, 200);
  const metadata = await response.json();
  assert.equal(metadata.issuer, lab.issuer.url);
  assert.ok(metadata.grant_types_supported.includes('client_credentials'));
  assert.deepEqual(metadata.token_endpoint_auth_methods_supported, ['client_secret_basic']);
  for (const name of ['token_endpoint', 'jwks_uri', 'introspection_endpoint', 'revocation_endpoint']) {
    assert.equal(new URL(metadata[name]).origin, lab.issuer.url);
  }
  const published = await (await fetch(metadata.jwks_uri)).json();
  const publicKey = published.keys.find(key => key.kid === jwk.kid);
  assert.equal(publicKey.kty, 'RSA');
  assert.equal(publicKey.d, undefined);
  assert.equal(publicKey.p, undefined);
});

for (const [mode, resource] of [['offline', JWT_RESOURCE], ['online', OPAQUE_RESOURCE]]) {
  test(`${mode}: actual client-credentials token authorizes its own tenant`, async () => {
    const token = await lab.client('reader-alpha').issue(resource);
    const beforeCalls = lab.api.metrics.requests;
    const result = await api(mode, token.access_token);
    assert.equal(result.status, 200);
    assert.equal(result.body.tenantId, 'alpha');
    assert.equal(result.body.authorization.clientId, 'reader-alpha');
    assert.equal(lab.api.metrics.requests - beforeCalls, mode === 'offline' ? 0 : 1);
    assert.equal(result.body.reports.length, 1);
    assert.ok(!JSON.stringify(result.body).includes(token.access_token));
  });
  test(`${mode}: signed/introspected tenant is compared against the requested resource`, async () => {
    const token = await lab.client('reader-alpha').issue(resource);
    const result = await api(mode, token.access_token, 'beta');
    assert.equal(result.status, 403);
    assert.equal(result.body.error.code, 'forbidden');
    assert.ok(!JSON.stringify(result.body).includes('beta-demo-report'));
  });
  test(`${mode}: role checks remain necessary even with a valid token and correct scope`, async () => {
    const token = await lab.client('observer-alpha').issue(resource);
    assert.equal(token.scope, READ_SCOPE);
    assert.equal((await api(mode, token.access_token)).status, 403);
  });
  test(`${mode}: a valid role without the required scope cannot read reports`, async () => {
    const token = await lab.client('reader-alpha').issue(resource, '');
    assert.equal((await api(mode, token.access_token)).status, 403);
  });
}

test('actual issuer revokes only the opaque token; paired JWT is a different token/audience', async () => {
  const client = lab.client('reader-alpha');
  const jwt = await client.issue(JWT_RESOURCE), opaque = await client.issue(OPAQUE_RESOURCE);
  assert.equal((await api('offline', jwt.access_token)).status, 200);
  assert.equal((await api('online', opaque.access_token)).status, 200);
  assert.equal((await client.revoke(opaque.access_token)).status, 200);
  assert.equal((await api('online', opaque.access_token)).status, 401);
  assert.equal((await api('offline', jwt.access_token)).status, 200);
  const unsupportedRevoke = await client.revoke(jwt.access_token);
  const unsupportedIntrospection = await lab.client('reader-alpha').introspect(jwt.access_token);
  assert.equal(unsupportedRevoke.status, 400);
  assert.equal(unsupportedRevoke.body.error, 'unsupported_token_type');
  assert.equal(unsupportedIntrospection.status, 400);
  assert.equal(unsupportedIntrospection.body.error, 'unsupported_token_type');
});

test('another authenticated client cannot revoke a principal token', async () => {
  const token = await lab.client('reader-alpha').issue(OPAQUE_RESOURCE);
  const response = await lab.client('reader-beta').revoke(token.access_token);
  assert.equal(response.status, 200); // RFC revocation response does not reveal token existence.
  assert.equal((await api('online', token.access_token)).status, 200);
});

test('only the registered resource server can introspect opaque principal tokens', async () => {
  const token = await lab.client('reader-alpha').issue(OPAQUE_RESOURCE);
  const result = await lab.client('reader-alpha').introspect(token.access_token);
  assert.equal(result.status, 200);
  assert.deepEqual(result.body, { active: false });
  assert.equal((await api('online', token.access_token)).status, 200);
});

test('token format and audience boundaries reject swapping opaque and JWT tokens', async () => {
  const client = lab.client('reader-alpha');
  const jwt = await client.issue(JWT_RESOURCE), opaque = await client.issue(OPAQUE_RESOURCE);
  assert.equal((await api('offline', opaque.access_token)).status, 401);
  assert.equal((await api('online', jwt.access_token)).status, 401);
});

test('unknown resources and missing resource parameters are rejected by the issuer', async () => {
  const client = lab.client('reader-alpha');
  for (const fields of [
    { grant_type: 'client_credentials', scope: READ_SCOPE, resource: 'urn:unregistered' },
    { grant_type: 'client_credentials', scope: READ_SCOPE },
  ]) {
    const result = await client.post(client.discovery.token_endpoint, fields);
    assert.equal(result.status, 400);
    assert.equal(result.body.error, 'invalid_target');
  }
});

test('actual OAuth client authentication rejects a wrong client secret', async () => {
  const metadata = lab.client('reader-alpha').discovery;
  const wrong = new OAuthClient(metadata, { clientId: 'reader-alpha', clientSecret: 'incorrect-fixture-secret' });
  const result = await wrong.post(metadata.token_endpoint, { grant_type: 'client_credentials', scope: READ_SCOPE, resource: JWT_RESOURCE });
  assert.equal(result.status, 401);
  assert.equal(result.body.error, 'invalid_client');
});

test('submitted tenant and role parameters cannot replace server-assigned principal claims', async () => {
  const client = lab.client('observer-alpha');
  const result = await client.post(client.discovery.token_endpoint, { grant_type: 'client_credentials', scope: READ_SCOPE,
    resource: JWT_RESOURCE, tenant_id: 'beta', roles: 'reader' });
  assert.equal(result.status, 200);
  assert.equal((await api('offline', result.body.access_token)).status, 403);
});

for (const [label, overrides] of [
  ['wrong issuer', { iss: 'http://127.0.0.1:1' }], ['wrong audience', { aud: OPAQUE_RESOURCE }],
  ['expired', { iat: 1, exp: 2 }], ['future issued-at', { iat: Math.floor(Date.now() / 1000) + 120, exp: Math.floor(Date.now() / 1000) + 150 }],
  ['excess lifetime', { exp: Math.floor(Date.now() / 1000) + 1000 }],
  ['malformed role claim', { roles: 'reader' }], ['missing tenant', { tenant_id: undefined }],
  ['wrong subject identity', { sub: 'another-principal' }], ['missing expiry', { exp: undefined }],
]) {
  test(`offline verification rejects ${label} despite a valid fixture signing key`, async () => {
    const result = await api('offline', await signed(overrides));
    assert.equal(result.status, 401);
    assert.equal(result.body.error.code, 'invalid_token');
  });
}

test('offline verification rejects a forged signature with the trusted kid', async () => {
  const other = await generateKeyPair('RS256');
  const token = await new SignJWT({}).setProtectedHeader({ alg: 'RS256', kid: jwk.kid, typ: 'at+jwt' }).sign(other.privateKey);
  assert.equal((await api('offline', token)).status, 401);
});

test('offline verification rejects HMAC algorithm substitution', async () => {
  const token = await new SignJWT({}).setProtectedHeader({ alg: 'HS256', kid: jwk.kid, typ: 'at+jwt' }).sign(new Uint8Array(32));
  assert.equal((await api('offline', token)).status, 401);
});

test('offline verification rejects unsigned tokens and wrong JWT type', async () => {
  const token = Buffer.from(JSON.stringify({ alg: 'none', typ: 'at+jwt' })).toString('base64url') + '.'
    + Buffer.from('{}').toString('base64url') + '.';
  assert.equal((await api('offline', token)).status, 401);
  assert.equal((await api('offline', await signed({}, { typ: 'JWT' }))).status, 401);
});

test('missing, malformed, duplicate and oversized bearer headers fail closed', async () => {
  assert.equal((await api('offline', undefined)).status, 401);
  const malformed = await fetch(`${lab.api.url}/offline/v1/tenants/alpha/reports`, { headers: { authorization: 'Basic not-a-bearer' } });
  assert.equal(malformed.status, 401); await malformed.arrayBuffer();
  assert.equal((await api('offline', 'x'.repeat(4097))).status, 401);
  const token = (await lab.client('reader-alpha').issue(JWT_RESOURCE)).access_token;
  const duplicateStatus = await new Promise((resolve, reject) => {
    const req = httpRequest(`${lab.api.url}/offline/v1/tenants/alpha/reports`, {
      headers: ['Host', new URL(lab.api.url).host, 'Authorization', `Bearer ${token}`, 'Authorization', `Bearer ${token}`],
    }, response => { response.resume(); response.on('end', () => resolve(response.statusCode)); });
    req.once('error', reject); req.end();
  });
  assert.equal(duplicateStatus, 401);
});

test('query token transport is refused without echoing the bearer', async () => {
  const token = (await lab.client('reader-alpha').issue(JWT_RESOURCE)).access_token;
  const result = await api('offline', token, 'alpha', '?access_token=' + token);
  assert.equal(result.status, 400);
  assert.ok(!JSON.stringify(result.body).includes(token));
});

test('fixture role configuration is immutable at runtime', () => {
  assert.throws(() => PROFILES['observer-alpha'].roles.push('reader'), TypeError);
});

test('real provider tokens expire in both validation modes', async () => {
  const short = await startLab({ ttlSeconds: 1 });
  try {
    const client = short.client('reader-alpha');
    const jwt = await client.issue(JWT_RESOURCE), opaque = await client.issue(OPAQUE_RESOURCE);
    await new Promise(resolve => setTimeout(resolve, 1100));
    for (const [mode, token] of [['offline', jwt.access_token], ['online', opaque.access_token]]) {
      const response = await fetch(`${short.api.url}/${mode}/v1/tenants/alpha/reports`, { headers: { authorization: `Bearer ${token}` } });
      assert.equal(response.status, 401); await response.arrayBuffer();
    }
  } finally { await short.close(); }
});

test('issuer outage denies online access while the separately issued JWT verifies from cached keys', async () => {
  const isolated = await startLab({ timeoutMs: 100 });
  try {
    const client = isolated.client('reader-alpha');
    const jwt = await client.issue(JWT_RESOURCE), opaque = await client.issue(OPAQUE_RESOURCE);
    await isolated.issuer.close();
    const offline = await fetch(`${isolated.api.url}/offline/v1/tenants/alpha/reports`, { headers: { authorization: `Bearer ${jwt.access_token}` } });
    assert.equal(offline.status, 200); await offline.arrayBuffer();
    const started = performance.now();
    const online = await fetch(`${isolated.api.url}/online/v1/tenants/alpha/reports`, { headers: { authorization: `Bearer ${opaque.access_token}` } });
    assert.equal(online.status, 503);
    assert.equal((await online.json()).error.code, 'issuer_unavailable');
    assert.ok(performance.now() - started < 1500);
  } finally { await isolated.close(); }
});
