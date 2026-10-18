// Run `npm run build` first, then `node examples/client.mjs`.
// Real local issuer and API; no tokens, credentials or private keys are printed.
import { startLab } from '../dist/lab.js';
import { JWT_RESOURCE, OPAQUE_RESOURCE } from '../dist/issuer.js';

const lab = await startLab();
try {
  const client = lab.client('reader-alpha');
  for (const [mode, resource] of [['offline', JWT_RESOURCE], ['online', OPAQUE_RESOURCE]]) {
    const token = await client.issue(resource);
    const response = await fetch(`${lab.api.url}/${mode}/v1/tenants/alpha/reports`, {
      headers: { authorization: `Bearer ${token.access_token}` }, signal: AbortSignal.timeout(2000),
    });
    console.log(JSON.stringify({ mode, status: response.status, body: await response.json() }, null, 2));
    if (response.status !== 200) throw new Error('Example request was not authorized.');
  }
} finally { await lab.close(); }
