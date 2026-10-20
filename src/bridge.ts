/** Private child-process fixture for Enterprise AI Lab; stdout is a JSONL IPC channel. */
import { once } from 'node:events';
import { JWT_RESOURCE, OPAQUE_RESOURCE, PROFILES, RAG_RESOURCE, RAG_SCOPE, READ_SCOPE, APPROVAL_RESOURCE, approvalScopes,
  PRIVACY_RESOURCE, privacyScopes,
  startIssuer, type FixtureClientId } from './issuer.js';
import { discover, OAuthClient } from './oauth.js';

const MAX_LINE_BYTES = 8192;
type RequestId = string | number;
type Command = Record<string, unknown> & { id: RequestId; op: string };

function validId(value: unknown): value is RequestId {
  return (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && value <= 1_000_000_000)
    || (typeof value === 'string' && /^[A-Za-z0-9_-]{1,64}$/.test(value));
}

function boundedTree(value: unknown, depth = 0): boolean {
  if (depth > 16) return false;
  if (typeof value === 'string') {
    try { return new TextDecoder('utf-8', { fatal: true }).decode(new TextEncoder().encode(value)) === value; }
    catch { return false; }
  }
  if (Array.isArray(value)) return value.every(item => boundedTree(item, depth + 1));
  if (value !== null && typeof value === 'object') {
    return Object.entries(value).every(([key, item]) => boundedTree(key, depth + 1) && boundedTree(item, depth + 1));
  }
  return typeof value !== 'number' || Number.isFinite(value);
}

function parse(line: Buffer): Command | undefined {
  try {
    const value: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(line));
    if (!boundedTree(value) || value === null || typeof value !== 'object' || Array.isArray(value)) return;
    const command = value as Record<string, unknown>;
    if (!validId(command.id) || typeof command.op !== 'string') return;
    return command as Command;
  } catch { return; }
}

function exactKeys(command: Command, allowed: readonly string[]): boolean {
  return Object.keys(command).every(key => allowed.includes(key));
}

async function emit(value: unknown): Promise<void> {
  if (!process.stdout.write(JSON.stringify(value) + '\n')) await once(process.stdout, 'drain');
}

async function main(): Promise<void> {
  const value = process.env.BRIDGE_TTL_SECONDS ?? '60';
  if (!/^[1-9]\d?$/.test(value) || Number(value) > 60) throw new Error('Invalid fixture TTL.');
  const issuer = await startIssuer({ ttlSeconds: Number(value) });
  let closed = false;
  const closeIssuer = async () => { if (!closed) { closed = true; await issuer.close(); } };
  const stop = () => { process.stdin.destroy(); void closeIssuer(); };
  process.once('SIGINT', stop);
  process.once('SIGTERM', stop);
  try {
    const metadata = await discover(issuer.url);
    const client = (id: FixtureClientId) => new OAuthClient(metadata, issuer.credentials.get(id)!);
    await emit({ event: 'ready', protocol: 1, issuer: issuer.url, audience: RAG_RESOURCE, scope: RAG_SCOPE,
      profiles: Object.entries(PROFILES).map(([clientId, profile]) => ({ clientId, tenantId: profile.tenantId, roles: [...profile.roles] })) });

    async function execute(line: Buffer): Promise<boolean> {
      const command = parse(line);
      const id = command?.id ?? null;
      const invalid = async () => { await emit({ id, ok: false, error: 'invalid_command' }); return false; };
      if (!command) return invalid();
      if (command.op === 'shutdown' && exactKeys(command, ['id', 'op'])) {
        await emit({ id, ok: true }); return true;
      }
      if (command.op === 'stopIssuer' && exactKeys(command, ['id', 'op'])) {
        await closeIssuer(); await emit({ id, ok: true }); return false;
      }
      if (!['issue', 'revoke'].includes(command.op) || typeof command.clientId !== 'string'
          || !Object.hasOwn(PROFILES, command.clientId)) return invalid();
      try {
        const principal = client(command.clientId as FixtureClientId);
        if (command.op === 'issue') {
          const resource = command.resource ?? RAG_RESOURCE;
          if (!exactKeys(command, ['id', 'op', 'clientId', 'resource', 'scope'])
              || typeof resource !== 'string' || ![JWT_RESOURCE, OPAQUE_RESOURCE, RAG_RESOURCE, APPROVAL_RESOURCE, PRIVACY_RESOURCE].includes(resource)
              || (command.scope !== undefined && (typeof command.scope !== 'string' || command.scope.length > 256))) return invalid();
          const scope = typeof command.scope === 'string' ? command.scope : (resource === PRIVACY_RESOURCE
            ? privacyScopes(PROFILES[command.clientId as FixtureClientId].roles) : resource === APPROVAL_RESOURCE
            ? approvalScopes(PROFILES[command.clientId as FixtureClientId].roles) : resource === RAG_RESOURCE ? RAG_SCOPE : READ_SCOPE);
          const token = await principal.issue(resource, scope);
          await emit({ id, ok: true, token });
        } else {
          if (!exactKeys(command, ['id', 'op', 'clientId', 'token']) || typeof command.token !== 'string'
              || !/^[A-Za-z0-9._~+/=-]{1,4096}$/.test(command.token)) return invalid();
          const result = await principal.revoke(command.token);
          await emit({ id, ok: true, result });
        }
      } catch { await emit({ id, ok: false, error: 'issuer_unavailable' }); }
      return false;
    }

    let pending = Buffer.alloc(0);
    for await (const chunk of process.stdin) {
      pending = Buffer.concat([pending, Buffer.from(chunk)]);
      let newline: number;
      while ((newline = pending.indexOf(10)) !== -1) {
        if (newline > MAX_LINE_BYTES) throw new Error('IPC line exceeds its limit.');
        const line = pending.subarray(0, newline);
        pending = pending.subarray(newline + 1);
        if (await execute(line)) return;
      }
      if (pending.length > MAX_LINE_BYTES) throw new Error('IPC line exceeds its limit.');
    }
    // A truncated final command has no effect. EOF still closes the issuer.
  } finally {
    process.off('SIGINT', stop);
    process.off('SIGTERM', stop);
    await closeIssuer();
  }
}

try { await main(); }
catch { console.error('Identity fixture bridge stopped; check local runtime, configuration or IPC bounds.'); process.exitCode = 1; }
