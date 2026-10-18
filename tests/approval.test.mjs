import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { createLocalJWKSet, jwtVerify } from 'jose';
import { startIssuer, APPROVAL_RESOURCE, APPROVAL_READ, APPROVAL_REQUEST, APPROVAL_DECIDE, RAG_RESOURCE, RAG_SCOPE } from '../dist/issuer.js';
import { discover, OAuthClient } from '../dist/oauth.js';

let issuer, metadata, keys;
before(async () => {
  issuer = await startIssuer(); metadata = await discover(issuer.url);
  keys = createLocalJWKSet(await (await fetch(metadata.jwks_uri)).json());
});
after(async () => { if (issuer) await issuer.close(); });
const client = id => new OAuthClient(metadata, issuer.credentials.get(id));
const verify = token => jwtVerify(token, keys, {issuer:issuer.url,audience:APPROVAL_RESOURCE,algorithms:['RS256'],typ:'at+jwt'});
for (const [id,tenant,roles,scope] of [
  ['requester-alpha','alpha',['requester'],`${APPROVAL_READ} ${APPROVAL_REQUEST}`],
  ['requester-beta','beta',['requester'],`${APPROVAL_READ} ${APPROVAL_REQUEST}`],
  ['approver-alpha','alpha',['approver'],`${APPROVAL_READ} ${APPROVAL_DECIDE}`],
  ['approver-beta','beta',['approver'],`${APPROVAL_READ} ${APPROVAL_DECIDE}`],
  ['dual-alpha','alpha',['requester','approver'],`${APPROVAL_READ} ${APPROVAL_REQUEST} ${APPROVAL_DECIDE}`],
]) {
  test(`approval provider assigns immutable tenant, roles and bounded audience scope for ${id}`,async()=>{
    const issued=await client(id).issue(APPROVAL_RESOURCE,scope);
    const {payload}=await verify(issued.access_token);
    assert.equal(payload.tenant_id,tenant); assert.deepEqual(payload.roles,roles);
    assert.equal(payload.scope,scope);assert.equal(payload.client_id,id);assert.equal(payload.sub,id);
    assert.equal(payload.exp-payload.iat,60);
  });
}
test('requester cannot obtain approval:decide through scope escalation',async()=>{
  const issued=await client('requester-alpha').issue(APPROVAL_RESOURCE,APPROVAL_DECIDE);
  const {payload}=await verify(issued.access_token);
  assert.ok(!payload.scope?.split(' ').includes(APPROVAL_DECIDE));
});
test('approver cannot obtain approval:request through scope escalation',async()=>{
  const issued=await client('approver-alpha').issue(APPROVAL_RESOURCE,APPROVAL_REQUEST);
  const {payload}=await verify(issued.access_token);
  assert.ok(!payload.scope?.split(' ').includes(APPROVAL_REQUEST));
});
test('RAG and approval resources reject swapped audiences and scopes',async()=>{
  const rag=await client('analyst-alpha').issue(RAG_RESOURCE,RAG_SCOPE);
  const approval=await client('approver-alpha').issue(APPROVAL_RESOURCE,APPROVAL_DECIDE);
  await assert.rejects(verify(rag.access_token));
  await assert.rejects(jwtVerify(approval.access_token,keys,{issuer:issuer.url,audience:RAG_RESOURCE,algorithms:['RS256'],typ:'at+jwt'}));
  const crossedRag=await client('approver-alpha').issue(RAG_RESOURCE,APPROVAL_DECIDE);
  const crossedApproval=await client('approver-alpha').issue(APPROVAL_RESOURCE,RAG_SCOPE);
  assert.ok(!crossedRag.scope?.split(' ').includes(APPROVAL_DECIDE));
  assert.ok(!crossedApproval.scope?.split(' ').includes(RAG_SCOPE));
});
