import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { mkdtemp, writeFile, chmod, rm, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { createLocalJWKSet, jwtVerify } from 'jose';
import { startReviewIssuer, REVIEW_RESOURCE, REVIEW_CLIENT_ID } from '../dist/review-issuer.js';

const password = 'local-study-password-only';
async function fixture(t, names = ['requester-alpha','reviewer-alpha','analyst-reviewer-alpha','reviewer-beta','observer-alpha']) {
  const directory = await mkdtemp(join(tmpdir(), 'identity-browser-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const path = join(directory, 'accounts.json');
  await writeFile(path, JSON.stringify({ schema_version:1, accounts:names.map(username => ({ username, password })) }), { mode:0o600 });
  const issuer = await startReviewIssuer({ redirectUri:'http://127.0.0.1:48171/auth/callback', accountsFile:path });
  t.after(() => issuer.close());
  return { issuer, path, directory };
}
class Browser {
  cookies = new Map();
  async request(url, init = {}) {
    const headers = { ...init.headers, ...(this.cookies.size ? {cookie:[...this.cookies].map(([a,b])=>`${a}=${b}`).join('; ')} : {}) };
    const response = await fetch(url, { ...init, headers, redirect:'manual', signal:AbortSignal.timeout(3000) });
    for (const raw of response.headers.getSetCookie()) {
      const part = raw.split(';')[0], separator = part.indexOf('=');
      this.cookies.set(part.slice(0, separator), part.slice(separator+1));
    }
    return response;
  }
}
async function begin(issuer, options = {}) {
  const browser = new Browser(), verifier = randomBytes(32).toString('base64url');
  const params = new URLSearchParams({ client_id:REVIEW_CLIENT_ID, response_type:'code', redirect_uri:issuer.redirectUri,
    scope:'openid review:read review:request review:decide', state:'test-state-123456', nonce:'test-nonce-123456',
    resource:REVIEW_RESOURCE, code_challenge:createHash('sha256').update(verifier).digest('base64url'), code_challenge_method:'S256', ...options });
  const response = await browser.request(issuer.url + '/auth?' + params);
  return { browser, verifier, response };
}
async function login(issuer, username, suppliedPassword = password) {
  const flow = await begin(issuer);
  assert.equal(flow.response.status, 303);
  const interaction = new URL(flow.response.headers.get('location'), issuer.url).href;
  const page = await flow.browser.request(interaction);
  assert.equal(page.status, 200);
  const html = await page.text(), csrf = /name="csrf" value="([^"]+)"/.exec(html)[1];
  const response = await flow.browser.request(interaction, {method:'POST', headers:{origin:issuer.url,'content-type':'application/x-www-form-urlencoded'},
    body:new URLSearchParams({csrf,username,password:suppliedPassword})});
  return {...flow,response,interaction,csrf};
}
async function complete(issuer, username) {
  const flow = await login(issuer, username);
  assert.equal(flow.response.status, 303);
  let response = flow.response;
  for(let i=0;i<5;i++) {
    const target = new URL(response.headers.get('location'), issuer.url);
    if(target.origin !== issuer.url) return {...flow,code:target.searchParams.get('code'), callback:target};
    response = await flow.browser.request(target);
    assert.equal(response.status,303, await response.text());
  }
  throw new Error('Redirect loop');
}
async function redeem(issuer, code, verifier, extra = {}) {
  return fetch(issuer.url+'/token',{method:'POST', headers:{'content-type':'application/x-www-form-urlencoded'},redirect:'manual',
    body:new URLSearchParams({grant_type:'authorization_code',client_id:REVIEW_CLIENT_ID,redirect_uri:issuer.redirectUri,resource:REVIEW_RESOURCE,
      code,code_verifier:verifier,...extra}),signal:AbortSignal.timeout(3000)});
}

test('actual code+PKCE login binds human subject, tenant, role and granted scopes', async t => {
  const {issuer} = await fixture(t);
  const jwks = createLocalJWKSet(await (await fetch(issuer.url+'/jwks')).json());
  for(const [username,tenant,roles,scopes] of [
    ['requester-alpha','alpha',['requester','reader'],['review:read','review:request']],
    ['reviewer-alpha','alpha',['approver','reader'],['review:read','review:decide']],
    ['analyst-reviewer-alpha','alpha',['approver','reader','analyst'],['review:read','review:decide']],
    ['reviewer-beta','beta',['approver','reader'],['review:read','review:decide']],
    ['observer-alpha','alpha',['observer'],[]],
  ]) await t.test(username,async()=>{
    const flow = await complete(issuer,username);
    assert.equal(flow.callback.searchParams.get('state'),'test-state-123456');
    assert.ok(flow.code);
    const response = await redeem(issuer,flow.code,flow.verifier);
    assert.equal(response.status,200,await response.clone().text());
    const token = await response.json();
    assert.equal(token.token_type,'Bearer');
    assert.equal(token.expires_in,300);
    const {payload,protectedHeader} = await jwtVerify(token.access_token,jwks,{issuer:issuer.url,audience:REVIEW_RESOURCE,algorithms:['RS256']});
    assert.equal(protectedHeader.typ,'at+jwt');
    assert.equal(payload.sub,username); assert.equal(payload.client_id,REVIEW_CLIENT_ID); assert.notEqual(payload.sub,payload.client_id);
    assert.equal(payload.identity_kind,'user'); assert.equal(payload.tenant_id,tenant); assert.deepEqual(payload.roles,roles);
    assert.deepEqual(new Set((payload.scope ?? '').split(' ').filter(Boolean)),new Set(scopes));
    const id = await jwtVerify(token.id_token,jwks,{issuer:issuer.url,audience:REVIEW_CLIENT_ID,algorithms:['RS256']});
    assert.equal(id.payload.nonce,'test-nonce-123456'); assert.equal(id.payload.sub,username);
    assert.ok(Number.isInteger(id.payload.auth_time)); assert.ok(Math.abs(id.payload.auth_time-Math.floor(Date.now()/1000)) <= 3);
    assert.equal((await redeem(issuer,flow.code,flow.verifier)).status,400,'Authorization codes are single-use');
  });
});

test('wrong passwords and forged interaction CSRF cannot sign in or mint tokens',async t=>{
  const {issuer}=await fixture(t);
  const wrong=await login(issuer,'reviewer-alpha','incorrect-password-long');
  assert.equal(wrong.response.status,401);
  const response=await wrong.browser.request(wrong.interaction,{method:'POST',headers:{origin:issuer.url,'content-type':'application/x-www-form-urlencoded'},
    body:new URLSearchParams({csrf:'X'.repeat(43),username:'reviewer-alpha',password})});
  assert.equal(response.status,403);
  const origin=await wrong.browser.request(wrong.interaction,{method:'POST',headers:{origin:'http://127.0.0.1:12345','content-type':'application/x-www-form-urlencoded'},
    body:new URLSearchParams({csrf:wrong.csrf,username:'reviewer-alpha',password})});
  assert.equal(origin.status,403);
  const other=new Browser();
  const cookie=await other.request(wrong.interaction,{method:'POST',headers:{origin:issuer.url,'content-type':'application/x-www-form-urlencoded'},
    body:new URLSearchParams({csrf:wrong.csrf,username:'reviewer-alpha',password})});
  assert.equal(cookie.status,400,'Interaction requires signed provider cookie');
});

test('PKCE, exact redirect and registered resource are enforced by actual provider',async t=>{
  const {issuer}=await fixture(t);
  const wrong=await complete(issuer,'reviewer-alpha');
  assert.equal((await redeem(issuer,wrong.code,'a'.repeat(43))).status,400);
  for(const changes of [ {code_challenge:'',code_challenge_method:''}, {code_challenge_method:'plain'},
    {redirect_uri:'http://127.0.0.1:48171/other'}, {resource:'urn:identity-boundary:rag'} ]) {
    const flow=await begin(issuer,changes);
    assert.ok([303,400].includes(flow.response.status));
    const location=flow.response.headers.get('location');
    if(location) assert.ok(new URL(location,issuer.url).searchParams.has('error'));
  }
  assert.equal((await fetch(issuer.url+'/token',{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},
    body:new URLSearchParams({grant_type:'client_credentials',client_id:REVIEW_CLIENT_ID,resource:REVIEW_RESOURCE})})).status,400);
});

test('account fixture permissions, names, schema, symlinks and redirect are bounded',async t=>{
  const {issuer,path,directory}=await fixture(t);
  await issuer.close();
  await chmod(path,0o644);
  await assert.rejects(startReviewIssuer({redirectUri:'http://127.0.0.1:48171/auth/callback',accountsFile:path}));
  await chmod(path,0o600);
  const link=join(directory,'link.json'); await symlink(path,link);
  await assert.rejects(startReviewIssuer({redirectUri:'http://127.0.0.1:48171/auth/callback',accountsFile:link}));
  await assert.rejects(startReviewIssuer({redirectUri:'https://example.com/auth/callback',accountsFile:path}));
  await writeFile(path,JSON.stringify({schema_version:1,accounts:[{username:'reviewer-alpha',password,roles:['admin']}]}));
  await assert.rejects(startReviewIssuer({redirectUri:'http://127.0.0.1:48171/auth/callback',accountsFile:path}));
});

test('configured human token TTL expires against actual provider signature validation',async t=>{
  const fixtureValue=await fixture(t,['reviewer-alpha']);
  await fixtureValue.issuer.close();
  const issuer=await startReviewIssuer({redirectUri:'http://127.0.0.1:48171/auth/callback',accountsFile:fixtureValue.path,ttlSeconds:1});
  t.after(()=>issuer.close());
  const flow=await complete(issuer,'reviewer-alpha');
  const response=await redeem(issuer,flow.code,flow.verifier);
  assert.equal(response.status,200);
  const token=await response.json();
  assert.equal(token.expires_in,1);
  const jwks=createLocalJWKSet(await(await fetch(issuer.url+'/jwks')).json());
  await jwtVerify(token.access_token,jwks,{issuer:issuer.url,audience:REVIEW_RESOURCE});
  await new Promise(resolve=>setTimeout(resolve,1100));
  await assert.rejects(jwtVerify(token.access_token,jwks,{issuer:issuer.url,audience:REVIEW_RESOURCE}),error=>error.code==='ERR_JWT_EXPIRED');
});

test('private browser bridge prints public metadata only and EOF closes actual listener',async t=>{
  const {spawn}=await import('node:child_process');
  const {once}=await import('node:events');
  const {issuer,path}=await fixture(t,['reviewer-alpha']);
  await issuer.close();
  const child=spawn(process.execPath,['dist/review-bridge.js','--redirect-uri','http://127.0.0.1:48171/auth/callback','--accounts-file',path,'--ttl-seconds','3'],
    {cwd:new URL('..',import.meta.url),stdio:['pipe','pipe','pipe']});
  t.after(()=>child.kill('SIGTERM'));
  child.stderr.resume();
  let output='';
  const ready=await new Promise((resolve,reject)=>{
    const timer=setTimeout(()=>reject(new Error('Bridge startup timeout.')),5000);
    child.stdout.on('data',chunk=>{output+=chunk; if(output.length>8192){clearTimeout(timer);reject(new Error('Metadata limit'));}
      else if(output.includes('\n')) {clearTimeout(timer);resolve(JSON.parse(output.split('\n')[0]));}});
    child.once('error',reject);
  });
  assert.equal(ready.event,'ready'); assert.equal(ready.client_id,REVIEW_CLIENT_ID); assert.equal(ready.ttl_seconds,3);
  assert.ok(!output.includes(password)); assert.ok(!/access_token|client_secret|private_key/.test(output));
  assert.equal((await fetch(ready.issuer+'/.well-known/openid-configuration')).status,200);
  const finished=once(child,'exit'); child.stdin.end();
  assert.equal((await finished)[0],0);
  await assert.rejects(fetch(ready.issuer+'/.well-known/openid-configuration',{signal:AbortSignal.timeout(500)}));
});
