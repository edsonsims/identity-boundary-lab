import { startLab } from './lab.js';

function port(name: string, fallback: number): number {
  const value = Number(process.env[name] ?? fallback);
  if (!Number.isInteger(value) || value < 0 || value > 65535) throw new Error('Invalid loopback port.');
  return value;
}
try {
  const lab = await startLab({ issuerPort: port('ISSUER_PORT', 9100), apiPort: port('API_PORT', 9101) });
  console.log(JSON.stringify({ issuer: lab.issuer.url, api: lab.api.url,
    discovery: `${lab.issuer.url}/.well-known/openid-configuration`,
    note: 'Ephemeral synthetic clients. Run npm run demo for the complete token flow; no credentials are printed.' }));
  let stopping = false;
  const stop = async () => { if (stopping) return; stopping = true; await lab.close(); };
  process.once('SIGINT', () => { void stop(); });
  process.once('SIGTERM', () => { void stop(); });
} catch { console.error('Local identity lab could not start; check runtime and loopback ports.'); process.exitCode = 1; }
