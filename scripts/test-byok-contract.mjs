// scripts/test-byok-contract.mjs — BYOK (bring your own key) contract.
//
// Pins the guarantees published in docs/BYOK-SECURITY.md to the code:
// encryption envelope, uid/provider binding, rotation, SSRF guard, header-only
// validation, zero-credit funding decision, request-scoped client resolution,
// server-only Firestore rule, and the absence of any plain-key persistence.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import {
  BYOK_COLLECTION,
  ByokError,
  decryptSecret,
  encryptSecret,
  isPrivateAddress,
  loadDecryptedKeys,
  loadMasterKeys,
  normalizeModelName,
  normalizeSecret,
  publicKeyMetadata,
  saveProviderKey,
  validateCustomBaseUrl,
  validateProviderKey,
} from '../lib/byok-vault.js';
import {
  activeByokProviders,
  byokKeyFor,
  decideFundingSource,
  runWithByokContext,
} from '../lib/byok-context.js';
import { byokApiKey, byokClient, isServedByUserKey, withModelOverride } from '../lib/byok-clients.js';

const k1 = Buffer.alloc(32, 1).toString('base64');
const k2 = Buffer.alloc(32, 2).toString('base64');
const masterA = loadMasterKeys({ BYOK_MASTER_KEY: k1 });
const masterB = loadMasterKeys({ BYOK_MASTER_KEY: k2, BYOK_MASTER_KEY_PREVIOUS: k1 });
const masterC = loadMasterKeys({ BYOK_MASTER_KEY: k2 });

// ─── Envelope ───────────────────────────────────────────────────────────────
{
  const rec = encryptSecret('sk-live-abcdef123456', { uid: 'u1', provider: 'openai' }, masterA);
  assert.equal(rec.v, 1);
  assert.ok(!JSON.stringify(rec).includes('sk-live'), 'ciphertext must not contain the plain key');
  assert.equal(decryptSecret(rec, { uid: 'u1', provider: 'openai' }, masterA), 'sk-live-abcdef123456');
  assert.throws(() => decryptSecret(rec, { uid: 'u2', provider: 'openai' }, masterA), /BYOK_RECORD_UNREADABLE/, 'bound to uid');
  assert.throws(() => decryptSecret(rec, { uid: 'u1', provider: 'anthropic' }, masterA), /BYOK_RECORD_UNREADABLE/, 'bound to provider');
  const tampered = { ...rec, ct: Buffer.from(Buffer.from(rec.ct, 'base64').map((b, i) => (i === 0 ? b ^ 1 : b))).toString('base64') };
  assert.throws(() => decryptSecret(tampered, { uid: 'u1', provider: 'openai' }, masterA), /BYOK_RECORD_UNREADABLE/, 'auth tag detects tampering');
  // Rotation: new current key + previous key still decrypts old records.
  assert.equal(decryptSecret(rec, { uid: 'u1', provider: 'openai' }, masterB), 'sk-live-abcdef123456');
  assert.throws(() => decryptSecret(rec, { uid: 'u1', provider: 'openai' }, masterC), /BYOK_MASTER_KEY_UNKNOWN/, 'record names its key id');
  const rec2 = encryptSecret('sk-live-abcdef123456', { uid: 'u1', provider: 'openai' }, masterA);
  assert.notEqual(rec.iv, rec2.iv, 'fresh nonce per write');
  assert.throws(() => loadMasterKeys({ BYOK_MASTER_KEY: 'short' }), /INVALID_LENGTH/);
  assert.throws(() => loadMasterKeys({}), /BYOK_NOT_CONFIGURED/);
}

// ─── Input validation ───────────────────────────────────────────────────────
{
  assert.equal(normalizeSecret('  sk-abc12345  '), 'sk-abc12345');
  assert.throws(() => normalizeSecret('sk 123456789'), /BYOK_KEY_FORMAT_INVALID/);
  assert.throws(() => normalizeSecret('short'), /BYOK_KEY_FORMAT_INVALID/);
  assert.throws(() => normalizeSecret('x'.repeat(513)), /BYOK_KEY_FORMAT_INVALID/);
  assert.equal(normalizeModelName('llama-3.3-70b/instruct:latest'), 'llama-3.3-70b/instruct:latest');
  assert.throws(() => normalizeModelName('bad model'), /BYOK_MODEL_NAME_INVALID/);
  assert.throws(() => normalizeModelName(''), /BYOK_MODEL_NAME_INVALID/);
}

// ─── SSRF guard ─────────────────────────────────────────────────────────────
{
  const pub = { resolve: async () => [{ address: '93.184.216.34' }] };
  assert.equal(await validateCustomBaseUrl('https://api.example.com/v1/', pub), 'https://api.example.com/v1');
  for (const [url, code] of [
    ['http://api.example.com/v1', 'BYOK_BASE_URL_HTTPS_REQUIRED'],
    ['https://localhost/v1', 'BYOK_BASE_URL_HOST_BLOCKED'],
    ['https://127.0.0.1/v1', 'BYOK_BASE_URL_HOST_BLOCKED'],
    ['https://10.1.2.3/v1', 'BYOK_BASE_URL_HOST_BLOCKED'],
    ['https://169.254.169.254/latest', 'BYOK_BASE_URL_HOST_BLOCKED'],
    ['https://[::1]/v1', 'BYOK_BASE_URL_HOST_BLOCKED'],
    ['https://www.asksary.com/api', 'BYOK_BASE_URL_HOST_BLOCKED'],
    ['https://sary-os.com/api', 'BYOK_BASE_URL_HOST_BLOCKED'],
    ['https://www.sary-os.com/api', 'BYOK_BASE_URL_HOST_BLOCKED'],
    ['https://WWW.Sary-OS.com/api', 'BYOK_BASE_URL_HOST_BLOCKED'],
    ['https://foo.vercel.app/v1', 'BYOK_BASE_URL_HOST_BLOCKED'],
    ['https://user:pw@api.example.com/v1', 'BYOK_BASE_URL_INVALID'],
    ['https://api.example.com/v1?x=1', 'BYOK_BASE_URL_INVALID'],
    ['not a url', 'BYOK_BASE_URL_INVALID'],
  ]) {
    await assert.rejects(validateCustomBaseUrl(url, pub), new RegExp(code), url);
  }
  // A public hostname that resolves to a private address is still blocked.
  await assert.rejects(validateCustomBaseUrl('https://evil.example.com/v1', { resolve: async () => [{ address: '10.0.0.5' }] }), /HOST_BLOCKED/);
  await assert.rejects(validateCustomBaseUrl('https://nx.example.com/v1', { resolve: async () => { throw new Error('ENOTFOUND'); } }), /UNRESOLVABLE/);
  assert.equal(isPrivateAddress('::ffff:192.168.1.1'), true);
  assert.equal(isPrivateAddress('8.8.8.8'), false);
}

// ─── Provider validation: header-only, status mapping ───────────────────────
{
  const calls = [];
  const fetchImpl = async (url, init) => { calls.push({ url, init }); return { ok: true, status: 200 }; };
  await validateProviderKey({ provider: 'gemini', secret: 'AIza-secret-key-123', fetchImpl });
  assert.ok(!calls[0].url.includes('AIza'), 'gemini key must not be placed in the URL');
  assert.equal(calls[0].init.headers['x-goog-api-key'], 'AIza-secret-key-123');
  assert.equal(calls[0].init.redirect, 'error', 'no redirects: a key must not follow a Location header elsewhere');
  await validateProviderKey({ provider: 'anthropic', secret: 'sk-ant-12345678', fetchImpl });
  assert.equal(calls[1].init.headers['x-api-key'], 'sk-ant-12345678');
  await validateProviderKey({ provider: 'custom', secret: 'tok-12345678', baseUrl: 'https://api.example.com/v1', fetchImpl });
  assert.equal(calls[2].url, 'https://api.example.com/v1/models');
  await assert.rejects(validateProviderKey({ provider: 'openai', secret: 'sk-bad-12345678', fetchImpl: async () => ({ ok: false, status: 401 }) }), /BYOK_KEY_REJECTED/);
  await assert.rejects(validateProviderKey({ provider: 'openai', secret: 'sk-bad-12345678', fetchImpl: async () => ({ ok: false, status: 500 }) }), /BYOK_PROVIDER_ERROR/);
  await assert.rejects(validateProviderKey({ provider: 'openai', secret: 'sk-bad-12345678', fetchImpl: async () => { throw new Error('boom'); } }), /BYOK_PROVIDER_UNREACHABLE/);
}

// ─── Storage: nothing plain is persisted; listing never returns the key ─────
class FakeDb {
  constructor() { this.docs = new Map(); }
  collection(name) {
    assert.equal(name, BYOK_COLLECTION);
    const db = this;
    return {
      doc(id) {
        return {
          async set(data, opts) {
            assert.equal(opts?.merge, true);
            const prev = db.docs.get(id) || {};
            const next = { ...prev };
            for (const [k, v] of Object.entries(data)) {
              if (v && typeof v === 'object' && v.constructor?.name === 'DeleteTransform') delete next[k];
              else if (v && typeof v === 'object' && v.constructor?.name === 'ServerTimestampTransform') next[k] = 'server-ts';
              else next[k] = v;
            }
            db.docs.set(id, next);
          },
          async get() { const data = db.docs.get(id); return { exists: Boolean(data), data: () => data }; },
        };
      },
    };
  }
}
{
  const db = new FakeDb();
  const fetchImpl = async () => ({ ok: true, status: 200 });
  const meta = await saveProviderKey({ uid: 'u1', provider: 'openai', secret: 'sk-live-abcdef123456', label: 'Work', db, masterKeys: masterA, fetchImpl });
  assert.deepEqual(Object.keys(meta).sort(), ['addedAt', 'baseUrl', 'label', 'last4', 'model', 'provider', 'validatedAt']);
  assert.equal(meta.last4, '3456');
  const stored = JSON.stringify(db.docs.get('u1'));
  assert.ok(!stored.includes('sk-live-abcdef'), 'plain key must not be persisted');
  assert.ok(stored.includes('"cipher"'));
  assert.equal(publicKeyMetadata('openai', db.docs.get('u1').openai).last4, '3456');
  assert.equal(JSON.stringify(publicKeyMetadata('openai', db.docs.get('u1').openai)).includes('cipher'), false);

  await saveProviderKey({ uid: 'u1', provider: 'custom', secret: 'tok-abcdef123456', baseUrl: 'https://api.example.com/v1', model: 'llama-3.3-70b', db, masterKeys: masterA, fetchImpl, resolveHost: async () => [{ address: '93.184.216.34' }] });
  const keys = await loadDecryptedKeys({ uid: 'u1', db, masterKeys: masterA });
  assert.equal(keys.openai.secret, 'sk-live-abcdef123456');
  assert.deepEqual(keys.custom, { secret: 'tok-abcdef123456', baseUrl: 'https://api.example.com/v1', model: 'llama-3.3-70b' });
  assert.deepEqual(await loadDecryptedKeys({ uid: 'guest_abc', db, masterKeys: masterA }), {}, 'guests never load keys');
  // Unreadable record degrades to platform funding, never throws.
  const unreadable = [];
  assert.equal((await loadDecryptedKeys({ uid: 'u1', db, masterKeys: masterC, onUnreadable: (p, c) => unreadable.push([p, c]) })).openai, undefined);
  assert.deepEqual(unreadable.map(([p]) => p).sort(), ['custom', 'openai']);
  // Missing master key → empty set, no throw.
  const saved = process.env.BYOK_MASTER_KEY; delete process.env.BYOK_MASTER_KEY;
  assert.deepEqual(await loadDecryptedKeys({ uid: 'u1', db }), {});
  if (saved) process.env.BYOK_MASTER_KEY = saved;
  await assert.rejects(saveProviderKey({ uid: 'u1', provider: 'replicate', secret: 'r8_abcdef123456', db, masterKeys: masterA, fetchImpl }), /BYOK_PROVIDER_UNSUPPORTED/);
  await assert.rejects(saveProviderKey({ uid: 'u1', provider: 'custom', secret: 'tok-abcdef123456', baseUrl: 'https://api.example.com/v1', db, masterKeys: masterA, fetchImpl, resolveHost: async () => [{ address: '93.184.216.34' }] }), /BYOK_MODEL_NAME_INVALID/);
  assert.ok(new ByokError('X', 418) instanceof Error);
}

// ─── Funding decision and request-scoped clients ────────────────────────────
{
  assert.equal(decideFundingSource('OpenAI'), 'platform', 'no context → platform');
  const keys = { gemini: { secret: 'g-1' }, openai: { secret: 'o-1' } };
  await runWithByokContext(keys, async () => {
    assert.equal(decideFundingSource('Google'), 'user_key');
    assert.equal(decideFundingSource('OpenAI'), 'user_key');
    assert.equal(decideFundingSource('Anthropic'), 'platform');
    assert.equal(decideFundingSource('Replicate'), 'platform', 'non-BYOK providers are never user funded');
    assert.equal(decideFundingSource('OpenAI', { explicit: 'platform' }), 'platform', 'explicit override wins');
    assert.deepEqual(activeByokProviders(), ['openai', 'gemini']);
    assert.equal(byokKeyFor('gemini').secret, 'g-1');
    assert.equal(byokApiKey('gemini', 'platform-g'), 'g-1');
    assert.equal(byokApiKey('anthropic', 'platform-a'), 'platform-a');
    assert.equal(isServedByUserKey('openai'), true);
    // Context is isolated per run.
    await runWithByokContext({}, async () => {
      assert.equal(decideFundingSource('OpenAI'), 'platform');
      assert.deepEqual(activeByokProviders(), []);
    });
  });
  assert.equal(decideFundingSource('OpenAI', { keys: { openai: { secret: 'x' } } }), 'user_key');

  const platform = { id: 'platform', chat: { completions: { create: params => ({ who: 'platform', params }) } } };
  const built = [];
  const client = byokClient('openai', platform, entry => {
    const c = { id: `user:${entry.secret}`, chat: { completions: { create: params => ({ who: `user:${entry.secret}`, params }) } } };
    built.push(c);
    return c;
  }, { fallback: 'custom' });
  assert.equal(client.id, 'platform');
  await runWithByokContext({ openai: { secret: 'o-2' } }, async () => {
    assert.equal(client.id, 'user:o-2');
    assert.equal(client.chat.completions.create({ model: 'm' }).who, 'user:o-2');
    assert.equal(client.id, 'user:o-2');
    assert.equal(built.length, 1, 'one client per request, reused within it');
  });
  await runWithByokContext({ openai: { secret: 'o-3' } }, async () => assert.equal(client.id, 'user:o-3'));
  assert.equal(built.length, 2, 'never cached across requests');
  assert.equal(client.id, 'platform');
  await runWithByokContext({ custom: { secret: 'c-1', baseUrl: 'https://api.example.com/v1', model: 'my-model' } }, async () => {
    assert.equal(client.id, 'user:c-1', 'custom stands in for OpenAI when no OpenAI key is stored');
  });
  await runWithByokContext({ openai: { secret: 'o-4' }, custom: { secret: 'c-2' } }, async () => {
    assert.equal(client.id, 'user:o-4', 'OpenAI key wins over custom');
  });

  const wrapped = withModelOverride({
    chat: { completions: { create: p => p, list: () => 'list' } },
    responses: { create: p => p },
    files: { create: p => p },
  }, 'llama-3.3-70b');
  assert.equal(wrapped.chat.completions.create({ model: 'gpt-6.1-terra', messages: [] }).model, 'llama-3.3-70b');
  assert.equal(wrapped.responses.create({ model: 'gpt-6.1-terra' }).model, 'llama-3.3-70b');
  assert.equal(wrapped.chat.completions.list(), 'list');
  assert.equal(wrapped.files.create({ model: 'x' }).model, 'x', 'only chat/responses are rewritten');
}

// ─── Static contract: rules, billing, chat wiring, docs ─────────────────────
{
  const rules = await readFile(new URL('../firestore.rules', import.meta.url), 'utf8');
  assert.match(rules, /match \/userProviderKeys\/\{userId\} \{\s*allow read, write: if false;\s*\}/, 'userProviderKeys must be server-only');

  const billing = await readFile(new URL('../lib/billing-authority.js', import.meta.url), 'utf8');
  assert.match(billing, /decideFundingSource\(price\.provider/, 'reservation reads the request context');
  assert.match(billing, /fundingSource: funding/, 'operation records its funding source');
  assert.match(billing, /if \(op\.fundingSource === 'user_key'\) actual = 0;/, 'settlement clamps user-key operations to zero');
  assert.match(billing, /const holdCredits = userFunded \? 0/, 'no wallet hold for user-key operations');

  const ops = await readFile(new URL('../lib/ops-control.js', import.meta.url), 'utf8');
  assert.match(ops, /operation\?\.fundingSource === 'user_key'/, 'free-generation pause does not apply to user-key calls');

  const chat = await readFile(new URL('../api/web-chat.js', import.meta.url), 'utf8');
  assert.match(chat, /runWithByokContext\(keys, \(\) => webChatHandler\(req, res\)\)/, 'handler runs inside the key context');
  for (const name of ['anthropic', 'openai', 'grok', 'gemini']) {
    assert.match(chat, new RegExp(`byokClient\\(\\s*'${name}'`), `${name} client is request-aware`);
  }
  const rawGemini = chat.match(/process\.env\.GEMINI_API_KEY/g) || [];
  const wrappedGemini = chat.match(/byokApiKey\('gemini', process\.env\.GEMINI_API_KEY\)/g) || [];
  assert.equal(rawGemini.length - wrappedGemini.length, 2, 'only the platform client construction and the startup config check read the raw Gemini key');
  assert.match(chat, /byokRejectionMessage\(err\)/, 'rejected user keys get a user-facing message');

  const vault = await readFile(new URL('../lib/byok-vault.js', import.meta.url), 'utf8');
  assert.ok(!/console\.(log|error|warn)/.test(vault), 'the vault never logs');
  const api = await readFile(new URL('../api/web-byok.js', import.meta.url), 'utf8');
  assert.ok(!/body\.key/.test(api.split('saveProviderKey')[1] || ''), 'the raw key is passed once and never referenced after save');
  assert.ok(!/console\.(log|error)\([^\n]*(secret|body\.key)/.test(api), 'the endpoint never logs the key');
  assert.match(api, /Cache-Control', 'no-store'/);

  const settings = await readFile(new URL('../public/byok-settings.js', import.meta.url), 'utf8');
  assert.ok(!/localStorage|sessionStorage|indexedDB/i.test(settings), 'the panel never touches browser storage');
  assert.match(settings, /keyField\.value = ''/, 'the field is cleared before the request');

  const app = await readFile(new URL('../public/app.html', import.meta.url), 'utf8');
  // BYOK is LiveLoop-only, for paid LiveLoop plans (owner, 2026-09-26): the
  // panel opens from LiveLoop → Projects, not from Settings.
  assert.doesNotMatch(app, /data-tab="apikeys"/, 'no API Keys tab in Settings');
  assert.match(app, /id="liveloop-files-byok"/, 'the panel opens from LiveLoop');
  assert.match(app, /id="tab-panel-apikeys"/);
  const client = await readFile(new URL('../public/script.js', import.meta.url), 'utf8');
  assert.doesNotMatch(client, /data-suite="apikeys"/, 'no API Keys suite outside LiveLoop');
  assert.match(client, /if \(extraParams\?\.toolId === 'tool-liveloop'\) fetchOptions\.headers\['X-AskSary-Surface'\] = 'liveloop';/);
  // Site-wide since 2026-10-01 (owner: "byok on pro and max works anywhere"):
  // "your key" shows wherever keys are in force, not only in LiveLoop.
  assert.match(settings, /if \(!\(window\.liveLoopByokInForce \|\| window\.liveLoopByokEligible\)\?\.\(\)\) return null;/, 'no "your key" unless keys are in force');
  const chatSource = await readFile(new URL('../api/web-chat.js', import.meta.url), 'utf8');
  assert.match(chatSource, /if \(!\(await liveLoopByokAllowed\(\{ db, decoded \}\)\)\) return \{\};/, 'chat loads keys only for Pro, Max and the trial BYOK week, on any surface');
  assert.match(chatSource, /BYOK_SURFACE_MISMATCH/, 'a request labelled LiveLoop that is not LiveLoop is refused');
  assert.ok(chatSource.indexOf('BYOK_SURFACE_MISMATCH') < chatSource.indexOf("const isLiveLoopTurn = fields.toolId === 'tool-liveloop';"), 'refused before any turn runs');
  const assistant = await readFile(new URL('../api/code-assistant.js', import.meta.url), 'utf8');
  assert.match(assistant, /allow: \(\{ decoded, db \}\) => liveLoopByokAllowed\(\{ db, decoded \}\)/, 'Code Lab, Project Lab and LiveLoop share one gate');
  assert.match(app, /byok-settings\.js/);
  assert.match(app, /href="\/byok-security"/);

  const doc = await readFile(new URL('../docs/BYOK-SECURITY.md', import.meta.url), 'utf8');
  const page = await readFile(new URL('../public/byok-security.html', import.meta.url), 'utf8');
  for (const claim of ['AES‑256‑GCM', 'userProviderKeys', 'allow read, write: if false', 'BYOK_MASTER_KEY', 'zero credits']) {
    assert.ok(doc.includes(claim), `doc states: ${claim}`);
    assert.ok(page.includes(claim), `page states: ${claim}`);
  }
  // The product name is Sary-OS (commit 5686cf2, 2026-09-27; formerly AskSary).
  // The doc and the page both state the threat under that name.
  assert.ok(doc.includes('compromised Sary-OS server'), 'doc states: compromised Sary-OS server');
  assert.ok(page.includes('compromised Sary-OS server'), 'page states: compromised Sary-OS server');
}

// ── The gate, run for real ─────────────────────────────────────────────────
{
  const { withByokRequest } = await import('../lib/byok-request.js');
  const { activeByokProviders } = await import('../lib/byok-context.js');
  const { paidLiveLoopPlan, byokAllowedForPlan } = await import('../lib/byok-liveloop-gate.js');
  // Every LiveLoop plan (owner, 2026-10-30: "all plan users can use bring your own keys").
  for (const plan of ['liveloop_lite', 'liveloop_pro', 'liveloop_max']) {
    assert.equal(byokAllowedForPlan({ source: 'subscription', plan, byok: { active: false } }), true, `${plan} has BYOK`);
  }
  assert.equal(byokAllowedForPlan({ source: 'subscription', byok: { active: false } }), false, 'a subscription naming no plan gets no BYOK');
  assert.equal(byokAllowedForPlan({ source: 'owner' }), true);
  for (const source of ['locked', 'none', undefined]) assert.equal(byokAllowedForPlan({ source, byok: { active: false } }), false, `${source} gets no BYOK`);
  // paidLiveLoopPlan stays Pro and Max: Flow's waves read it, not BYOK.
  assert.equal(paidLiveLoopPlan({ source: 'subscription', plan: 'liveloop_pro' }), true);
  assert.equal(paidLiveLoopPlan({ source: 'subscription', plan: 'liveloop_max' }), true);
  assert.equal(paidLiveLoopPlan({ source: 'subscription', plan: 'liveloop_lite' }), false, 'Lite has no waves');
  assert.equal(paidLiveLoopPlan({ source: 'owner' }), true);
  // The Sary-OS trial's BYOK week (owner, 2026-10-01), and nothing else.
  assert.equal(byokAllowedForPlan({ source: 'trial', byok: { active: true } }), true, 'the trial BYOK week');
  assert.equal(byokAllowedForPlan({ source: 'trial', byok: { active: false, available: true } }), false, 'not before a key is connected');
  assert.equal(byokAllowedForPlan({ source: 'locked', byok: { active: false } }), false, 'not after the window');
  const services = () => ({ auth: { verifyIdToken: async () => ({ uid: 'u1', firebase: { sign_in_provider: 'password' } }) }, db: {} });
  let seen = null;
  const refused = withByokRequest(async () => { seen = activeByokProviders(); }, services, { allow: async () => false });
  await refused({ headers: { authorization: 'Bearer t' } }, {});
  assert.deepEqual(seen, [], 'a request the gate refuses runs with no user keys');
}

console.log('byok contract: ok');
