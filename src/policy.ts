import { READ_SCOPE } from './issuer.js';

export interface Principal { clientId: string; tenantId: string; roles: readonly string[]; scopes: readonly string[] }
const name = /^[a-z][a-z0-9:_-]{0,63}$/;

export class BoundaryError extends Error {
  constructor(readonly status: number, readonly code: string, message: string) { super(message); }
}

export function principalFromClaims(claims: Record<string, unknown>, issuer: string, audience: string, now = Math.floor(Date.now() / 1000)): Principal {
  const audiences = typeof claims.aud === 'string' ? [claims.aud] : claims.aud;
  if (claims.iss !== issuer || !Array.isArray(audiences) || !audiences.length
      || !audiences.every(value => typeof value === 'string') || !audiences.includes(audience)
      || typeof claims.exp !== 'number' || !Number.isSafeInteger(claims.exp) || claims.exp <= now
      || typeof claims.iat !== 'number' || !Number.isSafeInteger(claims.iat) || claims.iat > now
      || claims.exp <= claims.iat || claims.exp - claims.iat > 60
      || typeof claims.client_id !== 'string' || !name.test(claims.client_id)
      || typeof claims.tenant_id !== 'string' || !name.test(claims.tenant_id)
      || !Array.isArray(claims.roles) || claims.roles.length > 8 || !claims.roles.length
      || !claims.roles.every(value => typeof value === 'string' && name.test(value))
      || new Set(claims.roles).size !== claims.roles.length
      || (claims.scope !== undefined && typeof claims.scope !== 'string')) {
    throw new BoundaryError(401, 'invalid_token', 'The access token is not valid for this resource.');
  }
  const scopes = typeof claims.scope === 'string' ? claims.scope.split(' ').filter(Boolean) : [];
  return { clientId: claims.client_id, tenantId: claims.tenant_id, roles: [...claims.roles] as string[], scopes };
}

export function authorize(principal: Principal, tenantId: string): void {
  if (principal.tenantId !== tenantId || !principal.roles.includes('reader') || !principal.scopes.includes(READ_SCOPE)) {
    throw new BoundaryError(403, 'forbidden', 'This principal cannot read this tenant resource.');
  }
}
