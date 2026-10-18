import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { test } from 'node:test';
import { createLocalJWKSet, jwtVerify } from 'jose';
import { JWT_RESOURCE, OPAQUE_RESOURCE, RAG_RESOURCE, RAG_SCOPE } from '../dist/issuer.js';

async function fixture(t, env = {}, expectReady = true) {
  const child = spawn(process.execPath, ['dist/bridge.js'], {
    cwd: new URL('..', import.meta.url), stdio: ['pipe', 'pipe', 'pipe'], env: { ...process.env, ...env },
  });
  const lines = [], waiters = [];
  let stderr = '', exited;
  child.stderr.on('data', chunk => { stderr += chunk.toString(); });
  const finished = new Promise(resolve => child.once('exit', (code, signal) => { exited = { code, signal }; resolve(exited); }));
  const reader = createInterface({ input: child.stdout });
  reader.on('line', line => {
    const waiter = waiters.shift();
    if (waiter) waiter(line); else lines.push(line);
  });
  async function next() {
    let timer;
    try {
      const line = await Promise.race([
        new Promise(resolve => { if (lines.length) resolve(lines.shift()); else waiters.push(resolve); }),
        new Promise((_resolve, reject) => { timer = setTimeout(() => reject(new Error('No bounded fixture response.')), 5000); }),
      ]);
      return JSON.parse(line);
    } finally { clearTimeout(timer); }
  }
  async function waitExit() {
    let timer;
    try {
      return await Promise.race([finished, new Promise((_resolve, reject) => {
        timer = setTimeout(() => reject(new Error('Fixture did not exit.')), 5000);
      })]);
    } finally { clearTimeout(timer); }
  }
  t.after(async () => {
    child.stdin.end();
    try { await waitExit(); } finally { if (!exited) child.kill('SIGKILL'); reader.close(); }
  });
  let sequence = 0;
  const ready = expectReady ? await next() : undefined;
  return { child, ready, next, waitExit, get stderr() { return stderr; },
    async command(value) {
      const id = ++sequence;
      child.stdin.write(JSON.stringify({ id, ...value }) + '\n');
      const result = await next();
      assert.equal(result.id, id);
      return result;
    },
  };
}

async function verifier(ready) {
  const metadata = await (await fetch(ready.issuer + '/.well-known/openid-configuration')).json();
  const keys = await (await fetch(metadata.jwks_uri)).json();
  assert.ok(keys.keys.every(key => key.d === undefined));
  return token => jwtVerify(token, createLocalJWKSet(keys), {
    issuer: ready.issuer, audience: RAG_RESOURCE, algorithms: ['RS256'], typ: 'at+jwt',
  });
}

test('private fixture bridge exposes bounded metadata and issues real RAG JWTs with server-owned roles', async t => {
  const bridge = await fixture(t);
  assert.equal(bridge.ready.event, 'ready');
  assert.equal(bridge.ready.protocol, 1);
  assert.equal(new URL(bridge.ready.issuer).hostname, '127.0.0.1');
  assert.equal(bridge.ready.audience, RAG_RESOURCE);
  assert.equal(bridge.ready.scope, RAG_SCOPE);
  assert.deepEqual(Object.keys(bridge.ready).sort(), ['audience', 'event', 'issuer', 'profiles', 'protocol', 'scope']);
  const verify = await verifier(bridge.ready);
  for (const [clientId, tenant, roles] of [
    ['reader-alpha', 'alpha', ['reader']], ['reader-beta', 'beta', ['reader']],
    ['analyst-alpha', 'alpha', ['reader', 'analyst']], ['analyst-beta', 'beta', ['reader', 'analyst']],
    ['observer-alpha', 'alpha', ['observer']],
  ]) {
    const issued = await bridge.command({ op: 'issue', clientId });
    assert.equal(issued.ok, true);
    const { payload } = await verify(issued.token.access_token);
    assert.equal(payload.tenant_id, tenant);
    assert.deepEqual(payload.roles, roles);
    assert.equal(payload.scope, RAG_SCOPE);
    assert.equal(payload.client_id, clientId);
    assert.equal(payload.sub, clientId);
    assert.equal(payload.exp - payload.iat, 60);
  }
  assert.equal((await bridge.command({ op: 'issue', clientId: 'reader-alpha', roles: ['analyst'] })).error, 'invalid_command');
  assert.equal((await bridge.command({ op: 'shutdown' })).ok, true);
  assert.equal((await bridge.waitExit()).code, 0);
  assert.ok(!bridge.stderr.includes('client_secret'));
});

test('RAG and reports resources have distinct audiences and scope boundaries', async t => {
  const bridge = await fixture(t), verify = await verifier(bridge.ready);
  const report = await bridge.command({ op: 'issue', clientId: 'reader-alpha', resource: JWT_RESOURCE });
  assert.equal(report.ok, true);
  await assert.rejects(verify(report.token.access_token), error => error.code === 'ERR_JWT_CLAIM_VALIDATION_FAILED');
  const noScope = await bridge.command({ op: 'issue', clientId: 'reader-alpha', scope: '' });
  const { payload } = await verify(noScope.token.access_token);
  assert.equal(payload.scope, undefined);
  const wrongScope = await bridge.command({ op: 'issue', clientId: 'reader-alpha', scope: 'reports:read' });
  assert.equal(wrongScope.ok, true);
  assert.equal((await verify(wrongScope.token.access_token)).payload.scope, undefined);
});

test('opaque reports revocation remains real while RAG JWT revocation is explicitly unsupported', async t => {
  const bridge = await fixture(t);
  const opaque = await bridge.command({ op: 'issue', clientId: 'reader-alpha', resource: OPAQUE_RESOURCE });
  assert.equal(opaque.ok, true);
  const revoked = await bridge.command({ op: 'revoke', clientId: 'reader-alpha', token: opaque.token.access_token });
  assert.equal(revoked.result.status, 200);
  const jwt = await bridge.command({ op: 'issue', clientId: 'reader-alpha' });
  const unsupported = await bridge.command({ op: 'revoke', clientId: 'reader-alpha', token: jwt.token.access_token });
  assert.equal(unsupported.result.status, 400);
  assert.equal(unsupported.result.body.error, 'unsupported_token_type');
  const verify = await verifier(bridge.ready);
  assert.equal((await verify(jwt.token.access_token)).payload.aud, RAG_RESOURCE);
});

test('malformed IPC commands cannot inject a principal or leak issuer internals', async t => {
  const bridge = await fixture(t);
  for (const command of [
    { op: 'issue', clientId: 'unregistered' }, { op: 'issue', clientId: 'reader-alpha', resource: 'https://example.org/' },
    { op: 'issue', clientId: 'reader-alpha', scope: ['rag:query'] },
    { op: 'issue', clientId: 'reader-alpha', scope: 'x'.repeat(257) },
    { op: 'issue', clientId: 'reader-alpha', tenant: 'beta' }, { op: 'revoke', clientId: 'reader-alpha', token: '' },
    { op: 'shutdown', unexpected: true }, { op: 'unknown' },
  ]) {
    const result = await bridge.command(command);
    assert.deepEqual(Object.keys(result).sort(), ['error', 'id', 'ok']);
    assert.equal(result.error, 'invalid_command');
  }
  for (const line of ['{broken', '[]', '{"id":-1,"op":"shutdown"}', '{"id":"ok","op":"issue","clientId":"reader-alpha","scope":"\\ud800"}',
    JSON.stringify({ id: 'deep', op: 'issue', clientId: 'reader-alpha', extra: Array.from({ length: 18 }).reduce(value => [value], null) })]) {
    bridge.child.stdin.write(line + '\n');
    const result = await bridge.next();
    assert.equal(result.ok, false);
    assert.equal(result.error, 'invalid_command');
  }
  assert.equal((await bridge.command({ op: 'issue', clientId: 'reader-alpha' })).ok, true);
});

test('EOF closes the real loopback issuer even after a truncated final command', async t => {
  const bridge = await fixture(t);
  assert.equal((await fetch(bridge.ready.issuer + '/.well-known/openid-configuration')).status, 200);
  bridge.child.stdin.end('{"id":4,"op":"issue"');
  assert.equal((await bridge.waitExit()).code, 0);
  await assert.rejects(fetch(bridge.ready.issuer + '/.well-known/openid-configuration'));
});

test('oversized IPC lines terminate the fixture without reflecting input', async t => {
  const bridge = await fixture(t);
  bridge.child.stdin.write('sensitive-sentinel-' + 'x'.repeat(8192));
  assert.equal((await bridge.waitExit()).code, 1);
  assert.ok(!bridge.stderr.includes('sensitive-sentinel'));
  assert.match(bridge.stderr, /IPC bounds/);
});

test('explicit issuer outage fails further issuance with a sanitized response', async t => {
  const bridge = await fixture(t);
  assert.equal((await bridge.command({ op: 'stopIssuer' })).ok, true);
  const result = await bridge.command({ op: 'issue', clientId: 'reader-alpha' });
  assert.equal(result.ok, false);
  assert.equal(result.error, 'issuer_unavailable');
  assert.deepEqual(Object.keys(result).sort(), ['error', 'id', 'ok']);
});

test('configured short TTL causes actual provider JWT expiry', async t => {
  const bridge = await fixture(t, { BRIDGE_TTL_SECONDS: '1' }), verify = await verifier(bridge.ready);
  const result = await bridge.command({ op: 'issue', clientId: 'reader-alpha' });
  assert.equal(result.token.expires_in, 1);
  await new Promise(resolve => setTimeout(resolve, 1100));
  await assert.rejects(verify(result.token.access_token), error => error.code === 'ERR_JWT_EXPIRED');
});

for (const value of ['0', '61', 'abc', '', '1.5', '01']) {
  test(`invalid fixture TTL ${JSON.stringify(value)} fails startup without exposing configuration`, async t => {
    const bridge = await fixture(t, { BRIDGE_TTL_SECONDS: value }, false);
    assert.equal((await bridge.waitExit()).code, 1);
    assert.match(bridge.stderr, /^Identity fixture bridge stopped;/);
  });
}
