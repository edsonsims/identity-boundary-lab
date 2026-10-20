import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { createInterface } from 'node:readline';
import { after, before, test } from 'node:test';
import { createLocalJWKSet, jwtVerify } from 'jose';
import * as policy from '../dist/issuer.js';
import { discover, OAuthClient } from '../dist/oauth.js';

const RESOURCE = 'urn:identity-boundary:privacy';
const REDACT = 'privacy:redact', RESTORE = 'privacy:restore';
const BOTH = `${REDACT} ${RESTORE}`;
const profiles = [
  ['privacy-alpha', 'alpha', ['redactor', 'restorer'], BOTH],
  ['privacy-beta', 'beta', ['redactor', 'restorer'], BOTH],
  ['privacy-other-alpha', 'alpha', ['redactor', 'restorer'], BOTH],
  ['privacy-redactor-alpha', 'alpha', ['redactor'], REDACT],
];
let issuer, metadata, keys;
before(async () => {
  issuer = await policy.startIssuer();
  metadata = await discover(issuer.url);
  keys = createLocalJWKSet(await (await fetch(metadata.jwks_uri)).json());
});
after(async () => { if (issuer) await issuer.close(); });
function client(id) {
  const credential = issuer.credentials.get(id);
  assert.ok(credential, `Registered local fixture client ${id}`);
  return new OAuthClient(metadata, credential);
}
const verify = token => jwtVerify(token, keys, {
  issuer: issuer.url, audience: RESOURCE, algorithms: ['RS256'], typ: 'at+jwt',
});
const scopes = value => typeof value === 'string' ? value.split(' ').filter(Boolean) : [];

test('privacy resource and scopes are explicit, deterministic and role bounded', () => {
  assert.equal(policy.PRIVACY_RESOURCE, RESOURCE);
  assert.equal(policy.PRIVACY_REDACT, REDACT);
  assert.equal(policy.PRIVACY_RESTORE, RESTORE);
  assert.equal(typeof policy.privacyScopes, 'function');
  assert.equal(policy.privacyScopes(['restorer', 'redactor', 'restorer']), BOTH);
  assert.equal(policy.privacyScopes(['redactor']), REDACT);
  assert.equal(policy.privacyScopes(['restorer']), RESTORE);
  assert.equal(policy.privacyScopes(['observer', 'reader', 'approver']), '');
});

for (const [id, tenant, roles, granted] of profiles) {
  test(`actual privacy JWT binds server-authored identity and least scopes for ${id}`, async () => {
    const issued = await client(id).issue(RESOURCE, BOTH);
    const { payload } = await verify(issued.access_token);
    assert.equal(payload.aud, RESOURCE);
    assert.equal(payload.iss, issuer.url);
    assert.equal(payload.client_id, id);
    assert.equal(payload.sub, id);
    assert.equal(payload.tenant_id, tenant);
    assert.deepEqual(payload.roles, roles);
    assert.equal(payload.scope, granted);
    assert.equal(issued.scope, granted);
    assert.equal(issued.expires_in, 60);
    assert.equal(payload.exp - payload.iat, 60);
    assert.ok(Object.isFrozen(policy.PROFILES[id]));
    assert.ok(Object.isFrozen(policy.PROFILES[id].roles));
    assert.throws(() => policy.PROFILES[id].roles.push('reader'), TypeError);
  });
}

test('scope escalation is measured from both actual response and signed token', async () => {
  for (const id of ['privacy-redactor-alpha', 'observer-alpha']) {
    const issued = await client(id).issue(RESOURCE, `${BOTH} rag:query approval:decide reports:read`);
    const { payload } = await verify(issued.access_token);
    const expected = id === 'privacy-redactor-alpha' ? [REDACT] : [];
    assert.deepEqual(scopes(issued.scope), expected);
    assert.deepEqual(scopes(payload.scope), expected);
    assert.equal(payload.tenant_id, 'alpha');
  }
  const noScope = await client('privacy-alpha').issue(RESOURCE, '');
  assert.deepEqual(scopes(noScope.scope), []);
  assert.deepEqual(scopes((await verify(noScope.access_token)).payload.scope), []);
});

test('request parameters cannot replace the provider privacy tenant, roles or client identity', async () => {
  const response = await client('privacy-redactor-alpha').post(metadata.token_endpoint, {
    grant_type: 'client_credentials', resource: RESOURCE, scope: BOTH,
    tenant_id: 'beta', roles: 'redactor restorer',
  });
  assert.equal(response.status, 200);
  const { payload } = await verify(response.body.access_token);
  assert.equal(payload.tenant_id, 'alpha');
  assert.equal(payload.client_id, 'privacy-redactor-alpha');
  assert.equal(payload.sub, 'privacy-redactor-alpha');
  assert.deepEqual(payload.roles, ['redactor']);
  assert.equal(payload.scope, REDACT);
  const conflict = await client('privacy-redactor-alpha').post(metadata.token_endpoint, {
    grant_type: 'client_credentials', resource: RESOURCE, scope: BOTH, client_id: 'privacy-beta',
  });
  assert.equal(conflict.status, 400);
  assert.equal(typeof conflict.body.error, 'string');
  assert.equal(conflict.body.access_token, undefined);
});

test('privacy tokens and all existing JWT resource audiences cannot be swapped', async () => {
  const privacy = await client('privacy-alpha').issue(RESOURCE, BOTH);
  for (const [id, resource, scope] of [
    ['analyst-alpha', policy.RAG_RESOURCE, policy.RAG_SCOPE],
    ['approver-alpha', policy.APPROVAL_RESOURCE, policy.APPROVAL_DECIDE],
    ['reader-alpha', policy.JWT_RESOURCE, policy.READ_SCOPE],
  ]) {
    const other = await client(id).issue(resource, scope);
    await assert.rejects(verify(other.access_token), error => error.code === 'ERR_JWT_CLAIM_VALIDATION_FAILED');
    await assert.rejects(jwtVerify(privacy.access_token, keys, {
      issuer: issuer.url, audience: resource, algorithms: ['RS256'], typ: 'at+jwt',
    }), error => error.code === 'ERR_JWT_CLAIM_VALIDATION_FAILED');
    const crossed = await client('privacy-alpha').issue(resource, BOTH);
    assert.deepEqual(scopes(crossed.scope), []);
  }
});

test('privacy fixture secrets are generated independently for each client and issuer', async () => {
  const another = await policy.startIssuer();
  try {
    const observed = new Set();
    for (const [id] of profiles) {
      const secret = issuer.credentials.get(id)?.clientSecret;
      assert.equal(typeof secret, 'string');
      assert.equal(secret.length, 43);
      assert.ok(!observed.has(secret));
      observed.add(secret);
      assert.notEqual(secret, another.credentials.get(id)?.clientSecret);
    }
  } finally { await another.close(); }
});

test('privacy tokens honor the actual provider short TTL and reject a TTL above 60 seconds', async () => {
  await assert.rejects(policy.startIssuer({ ttlSeconds: 61 }), /Invalid token TTL/);
  const short = await policy.startIssuer({ ttlSeconds: 1 });
  try {
    const config = await discover(short.url);
    const keyset = createLocalJWKSet(await (await fetch(config.jwks_uri)).json());
    const issued = await new OAuthClient(config, short.credentials.get('privacy-alpha')).issue(RESOURCE, BOTH);
    assert.equal(issued.expires_in, 1);
    await new Promise(resolve => setTimeout(resolve, 1100));
    await assert.rejects(jwtVerify(issued.access_token, keyset, {
      issuer: short.url, audience: RESOURCE, algorithms: ['RS256'], typ: 'at+jwt',
    }), error => error.code === 'ERR_JWT_EXPIRED');
  } finally { await short.close(); }
});

test('private JSONL bridge preserves RAG defaults while privacy scope defaults follow roles', async t => {
  const child = spawn(process.execPath, ['dist/bridge.js'], {
    cwd: new URL('..', import.meta.url), stdio: ['pipe', 'pipe', 'pipe'], env: process.env,
  });
  const reader = createInterface({ input: child.stdout });
  const waiting = [], buffered = [];
  let stderr = '', exited = false;
  child.stderr.on('data', chunk => { stderr += chunk.toString(); });
  const exit = once(child, 'exit').then(value => { exited = true; return value; });
  reader.on('line', line => {
    if (waiting.length) waiting.shift()(line); else buffered.push(line);
  });
  const next = async () => {
    let timeout;
    try {
      const raw = await Promise.race([
        new Promise(resolve => buffered.length ? resolve(buffered.shift()) : waiting.push(resolve)),
        new Promise((_resolve, reject) => { timeout = setTimeout(() => reject(new Error('Bridge response deadline.')), 5000); }),
      ]);
      return JSON.parse(raw);
    } finally { clearTimeout(timeout); }
  };
  const finish = async () => {
    let timeout;
    try {
      return await Promise.race([exit, new Promise((_resolve, reject) => {
        timeout = setTimeout(() => reject(new Error('Bridge exit deadline.')), 5000);
      })]);
    } finally { clearTimeout(timeout); }
  };
  t.after(async () => {
    child.stdin.end();
    try { await finish(); } finally { if (!exited) child.kill('SIGKILL'); reader.close(); }
  });
  const ready = await next();
  assert.deepEqual(Object.keys(ready).sort(), ['audience', 'event', 'issuer', 'profiles', 'protocol', 'scope']);
  assert.equal(ready.audience, policy.RAG_RESOURCE);
  assert.equal(ready.scope, policy.RAG_SCOPE);
  const config = await discover(ready.issuer);
  const keyset = createLocalJWKSet(await (await fetch(config.jwks_uri)).json());
  let sequence = 0;
  async function issue(command) {
    const id = ++sequence;
    child.stdin.write(JSON.stringify({ id, op: 'issue', ...command }) + '\n');
    const response = await next();
    assert.equal(response.id, id);
    return response;
  }
  for (const [clientId, tenantId, roles, scope] of profiles) {
    assert.deepEqual(ready.profiles.find(p => p.clientId === clientId), { clientId, tenantId, roles });
    const response = await issue({ clientId, resource: RESOURCE });
    assert.equal(response.ok, true);
    const { payload } = await jwtVerify(response.token.access_token, keyset, {
      issuer: ready.issuer, audience: RESOURCE, algorithms: ['RS256'], typ: 'at+jwt',
    });
    assert.equal(payload.scope, scope);
    assert.equal(payload.client_id, clientId);
    assert.equal(payload.tenant_id, tenantId);
    assert.deepEqual(payload.roles, roles);
  }
  const observer = await issue({ clientId: 'observer-alpha', resource: RESOURCE });
  assert.equal(observer.ok, true);
  assert.deepEqual(scopes(observer.token.scope), []);
  const defaultRag = await issue({ clientId: 'privacy-alpha' });
  assert.equal(defaultRag.ok, true);
  assert.equal((await jwtVerify(defaultRag.token.access_token, keyset, {
    issuer: ready.issuer, audience: policy.RAG_RESOURCE, algorithms: ['RS256'], typ: 'at+jwt',
  })).payload.scope, policy.RAG_SCOPE);
  for (const injected of [{ tenantId: 'beta' }, { roles: ['restorer'] }, { resource: 'urn:identity-boundary:privacy:other' }]) {
    assert.equal((await issue({ clientId: 'privacy-redactor-alpha', resource: RESOURCE, ...injected })).error, 'invalid_command');
  }
  const empty = await issue({ clientId: 'privacy-redactor-alpha', resource: RESOURCE, scope: RESTORE });
  assert.equal(empty.ok, true);
  assert.deepEqual(scopes(empty.token.scope), []);
  child.stdin.write(JSON.stringify({ id: ++sequence, op: 'shutdown' }) + '\n');
  assert.deepEqual(await next(), { id: sequence, ok: true });
  assert.equal((await finish())[0], 0);
  assert.ok(!stderr.includes('client_secret'));
});
