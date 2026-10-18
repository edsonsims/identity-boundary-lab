// Independent boundary tests. Fixture issuers below are test doubles, not
// standards/conformance evidence; integration.test.mjs uses the real provider.
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { createServer, Server } from 'node:http';
import { test } from 'node:test';
import { promisify } from 'node:util';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import { close, listen } from '../dist/http.js';
import { JWT_RESOURCE, OPAQUE_RESOURCE, READ_SCOPE } from '../dist/issuer.js';
import { startLab } from '../dist/lab.js';
import { startResourceApi } from '../dist/resource.js';

const execute = promisify(execFile);

for (const mode of ['environment', 'command-line', 'NODE_OPTIONS']) {
  test(`loopback transport refuses inherited proxy mode via ${mode}`, async t => {
    if (mode !== 'environment' && !process.allowedNodeEnvironmentFlags.has('--use-env-proxy')) {
      t.skip('This Node release does not implement the proxy startup flag.');
      return;
    }
    let proxyHits = 0;
    const target = createServer((_request, response) => response.writeHead(200, { 'content-type': 'application/json' }).end('{}'));
    const proxy = createServer((_request, response) => { proxyHits += 1; response.writeHead(502).end(); });
    proxy.on('connect', (_request, socket) => {
      proxyHits += 1;
      socket.end('HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n');
    });
    const targetUrl = await listen(target), proxyUrl = await listen(proxy);
    try {
      const env = { ...process.env, NODE_USE_ENV_PROXY: mode === 'environment' ? '1' : '0',
        NODE_OPTIONS: mode === 'NODE_OPTIONS' ? '--use-env-proxy' : '',
        HTTP_PROXY: proxyUrl, HTTPS_PROXY: proxyUrl, http_proxy: proxyUrl, https_proxy: proxyUrl,
        NO_PROXY: '', no_proxy: '' };
      const source = `import {fetchJson} from './dist/http.js';
        try {await fetchJson(${JSON.stringify(targetUrl)});process.stdout.write('direct')}
        catch {process.stdout.write('blocked')}`;
      const flags = mode === 'command-line' ? ['--use-env-proxy'] : [];
      const result = await execute(process.execPath, [...flags, '--input-type=module', '-e', source],
        { cwd: new URL('..', import.meta.url), env, timeout: 3000 });
      assert.ok(['direct', 'blocked'].includes(result.stdout));
      assert.equal(proxyHits, 0, 'A validated loopback URL must not contact an inherited proxy.');
    } finally {
      proxy.closeAllConnections(); target.closeAllConnections();
      await close(proxy); await close(target);
    }
  });
}

test('online boundary validates active introspection claims and keeps a one-call budget', async t => {
  const keys = await generateKeyPair('RS256', { extractable: true });
  const publicJwk = { ...await exportJWK(keys.publicKey), kid: 'review-key', alg: 'RS256', use: 'sig' };
  let issuerUrl, responseBody, introspections = 0;
  const issuer = createServer((request, response) => {
    let body;
    if (request.url === '/.well-known/openid-configuration') {
      body = { issuer: issuerUrl, token_endpoint: issuerUrl + '/token', jwks_uri: issuerUrl + '/jwks',
        introspection_endpoint: issuerUrl + '/introspect', revocation_endpoint: issuerUrl + '/revoke' };
    } else if (request.url === '/jwks') body = { keys: [publicJwk] };
    else if (request.url === '/introspect') { introspections += 1; body = responseBody; }
    else { response.writeHead(404).end(); return; }
    request.resume();
    response.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify(body));
  });
  issuerUrl = await listen(issuer);
  let resource;
  try {
    resource = await startResourceApi({ issuer: issuerUrl,
      credential: { clientId: 'resource-api', clientSecret: 'synthetic-review-secret' } });
    const now = Math.floor(Date.now() / 1000);
    const valid = { active: true, token_type: 'Bearer', iss: issuerUrl, aud: OPAQUE_RESOURCE,
      iat: now, exp: now + 30, client_id: 'reader-alpha', tenant_id: 'alpha',
      roles: ['reader'], scope: READ_SCOPE };
    for (const [name, changes, expected] of [
      ['valid fixture claims', {}, 200], ['string active', { active: 'true' }, 401],
      ['inactive', { active: false }, 401], ['wrong type', { token_type: 'JWT' }, 401],
      ['wrong issuer', { iss: issuerUrl + '/different' }, 401],
      ['wrong audience', { aud: JWT_RESOURCE }, 401], ['mixed audience types', { aud: [OPAQUE_RESOURCE, 5] }, 401],
      ['expired', { iat: 1, exp: 2 }, 401], ['string expiry', { exp: String(now + 30) }, 401],
      ['future issued-at', { iat: now + 10, exp: now + 30 }, 401],
      ['excess lifetime', { exp: now + 61 }, 401],
      ['malformed roles', { roles: 'reader' }, 401], ['duplicate roles', { roles: ['reader', 'reader'] }, 401],
      ['missing tenant', { tenant_id: undefined }, 401], ['malformed scope', { scope: [READ_SCOPE] }, 401],
      ['another tenant', { tenant_id: 'beta' }, 403], ['wrong role', { roles: ['observer'] }, 403],
      ['missing scope', { scope: '' }, 403],
    ]) {
      await t.test(name, async () => {
        responseBody = { ...valid, ...changes };
        const before = introspections;
        const result = await fetch(resource.url + '/online/v1/tenants/alpha/reports', {
          headers: { authorization: 'Bearer synthetic-opaque-token' }, signal: AbortSignal.timeout(1500),
        });
        assert.equal(result.status, expected);
        const body = await result.json();
        assert.equal(introspections - before, 1);
        if (expected !== 200) assert.equal(body.reports, undefined);
        assert.ok(!JSON.stringify(body).includes('synthetic-opaque-token'));
        assert.ok(!JSON.stringify(body).includes('synthetic-review-secret'));
      });
    }
  } finally { if (resource) await resource.close(); await close(issuer); }
});

test('unknown JWT key URLs are not fetched and cannot refresh the frozen key snapshot', async () => {
  const keys = await generateKeyPair('RS256', { extractable: true });
  const privateJwk = { ...await exportJWK(keys.privateKey), kid: randomUUID(), alg: 'RS256', use: 'sig' };
  let keyUrlHits = 0;
  const tripwire = createServer((_request, response) => {
    keyUrlHits += 1;
    response.writeHead(200, { 'content-type': 'application/jwk-set+json' }).end('{"keys":[]}');
  });
  const keyUrl = await listen(tripwire);
  let lab;
  try {
    lab = await startLab({ signingJwk: privateJwk });
    const now = Math.floor(Date.now() / 1000);
    const token = await new SignJWT({ iss: lab.issuer.url, aud: JWT_RESOURCE, iat: now, exp: now + 30,
      sub: 'reader-alpha', client_id: 'reader-alpha', jti: randomUUID(),
      tenant_id: 'alpha', roles: ['reader'], scope: READ_SCOPE })
      .setProtectedHeader({ alg: 'RS256', typ: 'at+jwt', kid: 'unpublished-review-key', jku: keyUrl, x5u: keyUrl })
      .sign(keys.privateKey);
    const calls = lab.api.metrics.requests;
    const result = await fetch(lab.api.url + '/offline/v1/tenants/alpha/reports', {
      headers: { authorization: `Bearer ${token}` }, signal: AbortSignal.timeout(1500),
    });
    assert.equal(result.status, 401);
    assert.equal((await result.json()).error.code, 'invalid_token');
    assert.equal(lab.api.metrics.requests, calls);
    assert.equal(keyUrlHits, 0);
  } finally { if (lab) await lab.close(); await close(tripwire); }
});

test('partial lab startup closes both real servers if final discovery fails', async t => {
  const servers = [];
  const originalListen = Server.prototype.listen;
  t.mock.method(Server.prototype, 'listen', function (...args) {
    servers.push(this);
    return originalListen.apply(this, args);
  });
  const originalFetch = globalThis.fetch;
  let discoveries = 0;
  t.mock.method(globalThis, 'fetch', async (url, init) => {
    if (new URL(url).pathname === '/.well-known/openid-configuration' && ++discoveries === 2) {
      throw new Error('Injected final discovery failure.');
    }
    return originalFetch(url, init);
  });
  try {
    await assert.rejects(startLab(), /Injected final discovery failure/);
    assert.equal(discoveries, 2);
    assert.equal(servers.length, 2, 'The real issuer and API both started before the injected failure.');
    assert.ok(servers.every(server => !server.listening), 'Partial startup must not leave a listener behind.');
  } finally {
    for (const server of servers) { server.closeAllConnections(); await close(server); }
  }
});
