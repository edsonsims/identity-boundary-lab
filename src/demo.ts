import assert from 'node:assert/strict';
import { startLab } from './lab.js';
import { JWT_RESOURCE, OPAQUE_RESOURCE } from './issuer.js';

const lab = await startLab();
try {
  const client = lab.client('reader-alpha');
  const jwt = await client.issue(JWT_RESOURCE);
  const opaque = await client.issue(OPAQUE_RESOURCE);
  const observer = lab.client('observer-alpha');
  const observerJwt = await observer.issue(JWT_RESOURCE);
  const observerOpaque = await observer.issue(OPAQUE_RESOURCE);
  async function status(mode: string, tenant: string, token: string): Promise<number> {
    const response = await fetch(`${lab.api.url}/${mode}/v1/tenants/${tenant}/reports`,
      { headers: { authorization: `Bearer ${token}` }, signal: AbortSignal.timeout(2000) });
    await response.arrayBuffer();
    return response.status;
  }
  let before = lab.api.metrics.requests;
  const offline = await status('offline', 'alpha', jwt.access_token);
  const offlineCalls = lab.api.metrics.requests - before;
  before = lab.api.metrics.requests;
  const online = await status('online', 'alpha', opaque.access_token);
  const onlineCalls = lab.api.metrics.requests - before;
  const crossTenant = { offlineJwt: await status('offline', 'beta', jwt.access_token),
    onlineOpaque: await status('online', 'beta', opaque.access_token) };
  const wrongRole = { offlineJwt: await status('offline', 'alpha', observerJwt.access_token),
    onlineOpaque: await status('online', 'alpha', observerOpaque.access_token) };
  const revoked = await client.revoke(opaque.access_token);
  const jwtRevocation = await client.revoke(jwt.access_token);
  const after = { offlineJwt: await status('offline', 'alpha', jwt.access_token),
    onlineOpaque: await status('online', 'alpha', opaque.access_token) };
  assert.deepEqual([offline, online, offlineCalls, onlineCalls], [200, 200, 0, 1]);
  assert.deepEqual(crossTenant, { offlineJwt: 403, onlineOpaque: 403 });
  assert.deepEqual(wrongRole, { offlineJwt: 403, onlineOpaque: 403 });
  assert.equal(revoked.status, 200);
  assert.equal(jwtRevocation.status, 400);
  assert.equal(jwtRevocation.body.error, 'unsupported_token_type');
  assert.deepEqual(after, { offlineJwt: 200, onlineOpaque: 401 });
  console.log(JSON.stringify({
    experiment: 'paired tokens for one synthetic client; different resource audiences',
    discoveryAndJwks: 'real local oidc-provider endpoints',
    beforeRevocation: { offlineJwt: offline, onlineOpaque: online },
    issuerCallsPerAuthorizedRequest: { offlineJwt: offlineCalls, onlineOpaque: onlineCalls },
    crossTenant, wrongRole,
    opaqueRevocation: { status: revoked.status },
    jwtRevocation: { status: jwtRevocation.status, error: jwtRevocation.body.error },
    afterOpaqueRevocation: after,
    jwtLifetimeSeconds: jwt.expires_in,
    browserSso: 'planned; not implemented',
  }, null, 2));
} finally { await lab.close(); }
