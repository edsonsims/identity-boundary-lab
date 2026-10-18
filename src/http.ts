import { type Server } from 'node:http';

export function loopbackUrl(value: string | URL): URL {
  const url = new URL(value);
  if (url.protocol !== 'http:' || url.hostname !== '127.0.0.1' || url.username || url.password || url.hash) {
    throw new Error('Only credential-free http://127.0.0.1 URLs are permitted.');
  }
  return url;
}

export interface JsonResponse { status: number; body: Record<string, unknown> }
export interface NetworkMetrics { requests: number }

export async function fetchJson(url: string | URL, init: RequestInit = {}, options: {
  timeoutMs?: number; maxBytes?: number; metrics?: NetworkMetrics; allowEmpty?: boolean;
} = {}): Promise<JsonResponse> {
  // Node can route even literal loopback fetches through an inherited proxy.
  // Refuse every supported opt-in form before credentials or tokens are sent.
  if (process.env.NODE_USE_ENV_PROXY === '1'
      || process.execArgv.some(argument => argument.includes('--use-env-proxy'))
      || process.env.NODE_OPTIONS?.includes('--use-env-proxy')) {
    throw new Error('Node environment-proxy mode is unsupported by this loopback-only lab.');
  }
  const target = loopbackUrl(url);
  const timeoutMs = options.timeoutMs ?? 1000;
  const maxBytes = options.maxBytes ?? 16384;
  if (!Number.isInteger(timeoutMs) || timeoutMs < 10 || timeoutMs > 5000
      || !Number.isInteger(maxBytes) || maxBytes < 1 || maxBytes > 65536) throw new Error('Invalid HTTP bounds.');
  if (options.metrics) options.metrics.requests += 1;
  const response = await fetch(target, { ...init, redirect: 'error', signal: AbortSignal.timeout(timeoutMs) });
  const reader = response.body?.getReader();
  if (!reader) throw new Error('Missing JSON response body.');
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const result = await reader.read();
      if (result.done) break;
      size += result.value.byteLength;
      if (size > maxBytes) throw new Error('JSON response exceeds its byte limit.');
      chunks.push(result.value);
    }
  } finally { await reader.cancel().catch(() => {}); }
  if (size === 0 && options.allowEmpty) return { status: response.status, body: {} };
  const type = response.headers.get('content-type')?.split(';')[0]?.trim();
  if (type !== 'application/json' && type !== 'application/jwk-set+json') throw new Error('Expected JSON response.');
  const body: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)));
  if (body === null || typeof body !== 'object' || Array.isArray(body)) throw new Error('Expected JSON object.');
  return { status: response.status, body: body as Record<string, unknown> };
}

export async function listen(server: Server, port = 0): Promise<string> {
  if (!Number.isInteger(port) || port < 0 || port > 65535) throw new Error('Invalid port.');
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', () => { server.off('error', reject); resolve(); });
  });
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('Missing TCP address.');
  return `http://127.0.0.1:${address.port}`;
}

export async function close(server: Server): Promise<void> {
  if (!server.listening) return;
  await new Promise<void>((resolve, reject) => {
    server.close(error => error ? reject(error) : resolve());
    server.closeIdleConnections();
  });
}
