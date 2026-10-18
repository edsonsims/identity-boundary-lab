import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { test } from 'node:test';
import { close, fetchJson, listen, loopbackUrl } from '../dist/http.js';
import { discover } from '../dist/oauth.js';

for (const value of ['https://127.0.0.1', 'http://localhost', 'http://example.com',
  'http://user:secret@127.0.0.1', 'http://127.0.0.1/#fragment']) {
  test(`outbound HTTP policy rejects ${value.replace('user:secret@', '')} before fetch`, () => {
    assert.throws(() => loopbackUrl(value));
  });
}

test('bounded HTTP refuses redirects without following a second endpoint', async () => {
  let followed = 0;
  const server = createServer((request, response) => {
    if (request.url === '/target') { followed += 1; response.writeHead(200, { 'content-type': 'application/json' }).end('{}'); }
    else { response.writeHead(302, { location: '/target' }).end(); }
  });
  const url = await listen(server);
  try { await assert.rejects(fetchJson(url)); assert.equal(followed, 0); }
  finally { await close(server); }
});

test('bounded HTTP rejects an oversized JSON response before parsing it', async () => {
  const server = createServer((_request, response) => {
    response.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ text: 'x'.repeat(2000) }));
  });
  const url = await listen(server);
  try { await assert.rejects(fetchJson(url, {}, { maxBytes: 128 }), /byte limit/); }
  finally { await close(server); }
});

test('bounded HTTP deadline covers a stalled response body', async () => {
  const server = createServer((_request, response) => {
    response.writeHead(200, { 'content-type': 'application/json' });
    response.write('{'); // Never finish; caller must cancel rather than wait indefinitely.
  });
  const url = await listen(server);
  const started = performance.now();
  try {
    await assert.rejects(fetchJson(url, {}, { timeoutMs: 50 }));
    assert.ok(performance.now() - started < 1500);
  } finally { server.closeAllConnections(); await close(server); }
});

test('discovery refuses a wrong issuer and does not fetch keys', async () => {
  let requests = 0;
  const server = createServer((_request, response) => {
    requests += 1;
    response.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ issuer: 'http://127.0.0.1:1' }));
  });
  const url = await listen(server);
  try { await assert.rejects(discover(url), /mismatch/); assert.equal(requests, 1); }
  finally { await close(server); }
});

test('discovery rejects cross-origin endpoint injection before sending any credential', async () => {
  let requests = 0;
  let url;
  const server = createServer((_request, response) => {
    requests += 1;
    response.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ issuer: url,
      token_endpoint: 'http://127.0.0.1:1/token', jwks_uri: url + '/jwks',
      introspection_endpoint: url + '/introspection', revocation_endpoint: url + '/revocation' }));
  });
  url = await listen(server);
  try { await assert.rejects(discover(url), /origin mismatch/); assert.equal(requests, 1); }
  finally { await close(server); }
});
