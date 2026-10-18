/** Private process lifecycle bridge. It never issues or prints browser tokens/passwords. */
import { startReviewIssuer, REVIEW_CLIENT_ID, REVIEW_RESOURCE, REVIEW_READ, REVIEW_REQUEST, REVIEW_DECIDE } from './review-issuer.js';

async function main() {
  const args = process.argv.slice(2);
  if (![4,6].includes(args.length) || args[0] !== '--redirect-uri' || args[2] !== '--accounts-file' || (args.length === 6 && (args[4] !== '--ttl-seconds' || !/^[1-9][0-9]{0,2}$/.test(args[5]!)))) throw new Error('Invalid bridge arguments.');
  const issuer = await startReviewIssuer({ redirectUri: args[1]!, accountsFile: args[3]!, ttlSeconds: args.length === 6 ? Number(args[5]) : 300 });
  let closing = false;
  const stop = async () => { if (!closing) { closing = true; process.stdin.destroy(); await issuer.close(); } };
  process.once('SIGINT', () => { void stop(); }); process.once('SIGTERM', () => { void stop(); });
  try {
    process.stdout.write(JSON.stringify({ event: 'ready', protocol: 1, issuer: issuer.url,
      authorization_endpoint: issuer.url + '/auth', token_endpoint: issuer.url + '/token', jwks_uri: issuer.url + '/jwks',
      client_id: REVIEW_CLIENT_ID, ttl_seconds: args.length === 6 ? Number(args[5]) : 300, audience: REVIEW_RESOURCE, scopes: ['openid', REVIEW_READ, REVIEW_REQUEST, REVIEW_DECIDE],
      profiles: issuer.profiles }) + '\n');
    let pending = Buffer.alloc(0);
    for await (const chunk of process.stdin) {
      pending = Buffer.concat([pending, Buffer.from(chunk)]);
      if (pending.length > 1024) throw new Error('Bridge command limit.');
      const newline = pending.indexOf(10);
      if (newline === -1) continue;
      const command: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(pending.subarray(0, newline)));
      if (!command || typeof command !== 'object' || Array.isArray(command)
        || Object.keys(command).sort().join(',') !== 'id,op'
        || (command as {op: unknown}).op !== 'shutdown'
        || !Number.isSafeInteger((command as {id: unknown}).id)) throw new Error('Invalid bridge command.');
      process.stdout.write(JSON.stringify({ id: (command as {id:number}).id, ok: true }) + '\n'); return;
    }
  } finally { await stop(); }
}
try { await main(); } catch { console.error('Local browser identity fixture stopped; check its configuration.'); process.exitCode = 1; }
