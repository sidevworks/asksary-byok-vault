// lib/byok-vault.js — encrypted at-rest storage for user provider keys.
//
// Every guarantee below is stated publicly in docs/BYOK-SECURITY.md. Change the
// document when you change the code.
//
//  * AES-256-GCM, a fresh random 96-bit IV per write, 128-bit auth tag.
//  * Additional authenticated data binds the ciphertext to (uid, provider), so a
//    record copied between users or providers fails to decrypt.
//  * The master key lives only in the server environment (BYOK_MASTER_KEY). A
//    previous key (BYOK_MASTER_KEY_PREVIOUS) is accepted for decrypt-only so
//    rotation never locks users out; records carry the key id they were
//    written with.
//  * Firestore collection `userProviderKeys` is server-only (rules deny all
//    client access). Documents hold ciphertext and non-secret metadata only.
//  * Reads return the secret to the calling request; listing returns metadata
//    (provider, last four characters, timestamps, custom host) and never the key.
//  * Deleting removes the field immediately. There is no soft delete and no
//    backup copy written by this module.
import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';
import { isIP } from 'node:net';
import dns from 'node:dns/promises';
import { getFirestore, FieldValue } from 'firebase-admin/firestore';
import { BYOK_PROVIDERS } from './byok-context.js';

export const BYOK_COLLECTION = 'userProviderKeys';
export const BYOK_RECORD_VERSION = 1;
const AAD_PREFIX = 'asksary-byok-v1';

export class ByokError extends Error {
  constructor(code, status = 400, details = null) {
    super(code);
    this.code = code;
    this.status = status;
    this.details = details;
  }
}

// ─── Master key ─────────────────────────────────────────────────────────────
function parseMasterKey(raw, label) {
  if (!raw) return null;
  const buf = Buffer.from(String(raw).trim(), 'base64');
  if (buf.length !== 32) throw new ByokError(`${label}_INVALID_LENGTH`, 500);
  return buf;
}

function keyId(buf) {
  return createHash('sha256').update(buf).digest('hex').slice(0, 12);
}

export function loadMasterKeys(env = process.env) {
  const current = parseMasterKey(env.BYOK_MASTER_KEY, 'BYOK_MASTER_KEY');
  if (!current) throw new ByokError('BYOK_NOT_CONFIGURED', 503);
  const previous = parseMasterKey(env.BYOK_MASTER_KEY_PREVIOUS, 'BYOK_MASTER_KEY_PREVIOUS');
  const byId = new Map([[keyId(current), current]]);
  if (previous) byId.set(keyId(previous), previous);
  return { current, currentId: keyId(current), byId };
}

export function isByokConfigured(env = process.env) {
  try { loadMasterKeys(env); return true; } catch { return false; }
}

// ─── Envelope ───────────────────────────────────────────────────────────────
function aad(uid, provider) {
  return Buffer.from(`${AAD_PREFIX}:${uid}:${provider}`, 'utf8');
}

export function encryptSecret(secret, { uid, provider }, masterKeys = loadMasterKeys()) {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', masterKeys.current, iv);
  cipher.setAAD(aad(uid, provider));
  const ct = Buffer.concat([cipher.update(String(secret), 'utf8'), cipher.final()]);
  return {
    v: BYOK_RECORD_VERSION,
    kid: masterKeys.currentId,
    iv: iv.toString('base64'),
    tag: cipher.getAuthTag().toString('base64'),
    ct: ct.toString('base64'),
  };
}

export function decryptSecret(record, { uid, provider }, masterKeys = loadMasterKeys()) {
  if (!record || record.v !== BYOK_RECORD_VERSION) throw new ByokError('BYOK_RECORD_UNREADABLE', 500);
  const key = masterKeys.byId.get(record.kid);
  if (!key) throw new ByokError('BYOK_MASTER_KEY_UNKNOWN', 500);
  try {
    const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(record.iv, 'base64'));
    decipher.setAAD(aad(uid, provider));
    decipher.setAuthTag(Buffer.from(record.tag, 'base64'));
    return Buffer.concat([decipher.update(Buffer.from(record.ct, 'base64')), decipher.final()]).toString('utf8');
  } catch {
    // Wrong key, wrong uid/provider binding, or tampered ciphertext all land
    // here. Never include the record in the error.
    throw new ByokError('BYOK_RECORD_UNREADABLE', 500);
  }
}

// ─── Input validation ───────────────────────────────────────────────────────
export function normalizeProvider(value) {
  const provider = String(value || '').trim().toLowerCase();
  if (!BYOK_PROVIDERS.includes(provider)) throw new ByokError('BYOK_PROVIDER_UNSUPPORTED', 400);
  return provider;
}

export function normalizeSecret(value) {
  const secret = String(value || '').trim();
  if (secret.length < 8 || secret.length > 512) throw new ByokError('BYOK_KEY_FORMAT_INVALID', 400);
  // Printable ASCII only: keys are opaque tokens, never contain whitespace or
  // control characters, and anything else is almost certainly a paste error.
  if (!/^[\x21-\x7e]+$/.test(secret)) throw new ByokError('BYOK_KEY_FORMAT_INVALID', 400);
  return secret;
}

export function normalizeModelName(value) {
  const model = String(value || '').trim();
  if (!/^[A-Za-z0-9._:/-]{1,120}$/.test(model)) throw new ByokError('BYOK_MODEL_NAME_INVALID', 400);
  return model;
}

const PRIVATE_V4 = [
  /^10\./, /^127\./, /^0\./, /^169\.254\./, /^192\.168\./, /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./,
  /^172\.(1[6-9]|2\d|3[01])\./, /^22[4-9]\./, /^2[3-5]\d\./,
];
export function isPrivateAddress(address) {
  const ip = String(address || '').toLowerCase();
  const family = isIP(ip);
  if (family === 4) return PRIVATE_V4.some(re => re.test(ip));
  if (family === 6) {
    if (ip === '::1' || ip === '::') return true;
    if (ip.startsWith('fc') || ip.startsWith('fd') || ip.startsWith('fe80')) return true;
    if (ip.startsWith('::ffff:')) return isPrivateAddress(ip.slice(7));
    return false;
  }
  return true; // not an IP literal: caller must resolve first
}

const BLOCKED_HOST_SUFFIXES = ['.asksary.com', '.vercel.app', '.internal', '.local', '.localhost', '.googleapis.com', '.firebaseio.com'];

/**
 * A custom base URL must be a public HTTPS origin. Loopback, private ranges,
 * link-local, metadata hosts and AskSary's own hosts are rejected so a stored
 * URL can never turn the server into a proxy into its own network (SSRF).
 */
export async function validateCustomBaseUrl(value, { resolve = host => dns.lookup(host, { all: true }) } = {}) {
  let url;
  try { url = new URL(String(value || '').trim()); } catch { throw new ByokError('BYOK_BASE_URL_INVALID', 400); }
  if (url.protocol !== 'https:') throw new ByokError('BYOK_BASE_URL_HTTPS_REQUIRED', 400);
  if (url.username || url.password || url.search || url.hash) throw new ByokError('BYOK_BASE_URL_INVALID', 400);
  // URL keeps IPv6 literals bracketed ([::1]); strip so isIP() sees the address.
  const host = url.hostname.toLowerCase().replace(/^\[(.*)\]$/, '$1');
  if (host === 'localhost' || host === 'asksary.com' || BLOCKED_HOST_SUFFIXES.some(s => host.endsWith(s))) {
    throw new ByokError('BYOK_BASE_URL_HOST_BLOCKED', 400);
  }
  if (isIP(host)) {
    if (isPrivateAddress(host)) throw new ByokError('BYOK_BASE_URL_HOST_BLOCKED', 400);
  } else {
    let addresses;
    try { addresses = await resolve(host); } catch { throw new ByokError('BYOK_BASE_URL_UNRESOLVABLE', 400); }
    const list = (Array.isArray(addresses) ? addresses : [addresses]).map(a => (typeof a === 'string' ? a : a?.address));
    if (!list.length || list.some(a => isPrivateAddress(a))) throw new ByokError('BYOK_BASE_URL_HOST_BLOCKED', 400);
  }
  // Normalise: no trailing slash, path preserved (e.g. https://host/v1).
  return `${url.origin}${url.pathname.replace(/\/+$/, '')}`;
}

// ─── Live validation against the provider ───────────────────────────────────
const VALIDATION_TIMEOUT_MS = 12_000;

function validationRequest(provider, secret, baseUrl) {
  switch (provider) {
    case 'openai': return { url: 'https://api.openai.com/v1/models', headers: { authorization: `Bearer ${secret}` } };
    case 'grok': return { url: 'https://api.x.ai/v1/models', headers: { authorization: `Bearer ${secret}` } };
    case 'anthropic': return { url: 'https://api.anthropic.com/v1/models', headers: { 'x-api-key': secret, 'anthropic-version': '2023-06-01' } };
    // Header, not query string, so the key never appears in a URL or access log.
    case 'gemini': return { url: 'https://generativelanguage.googleapis.com/v1beta/models?pageSize=1', headers: { 'x-goog-api-key': secret } };
    case 'custom': return { url: `${baseUrl}/models`, headers: { authorization: `Bearer ${secret}` } };
    default: throw new ByokError('BYOK_PROVIDER_UNSUPPORTED', 400);
  }
}

/**
 * Confirms the key is accepted by the provider before it is stored. Uses the
 * cheapest read-only endpoint each provider offers. Nothing about the key is
 * logged on failure; only the upstream HTTP status is surfaced.
 */
export async function validateProviderKey({ provider, secret, baseUrl = null, fetchImpl = globalThis.fetch }) {
  const { url, headers } = validationRequest(provider, secret, baseUrl);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), VALIDATION_TIMEOUT_MS);
  let response;
  try {
    response = await fetchImpl(url, { method: 'GET', headers: { accept: 'application/json', ...headers }, signal: controller.signal, redirect: 'error' });
  } catch {
    throw new ByokError('BYOK_PROVIDER_UNREACHABLE', 502);
  } finally {
    clearTimeout(timer);
  }
  if (response.status === 401 || response.status === 403) {
    // A scoped key (for example an OpenAI project key created without
    // "Models: read") authenticates but may not list models. The provider
    // says so in the body; that key is valid for chat and must be accepted.
    let body = '';
    try { body = String(await response.text()).slice(0, 2_000).toLowerCase(); } catch { body = ''; }
    const scopedButValid = /insufficient[_ ]permissions?|missing scopes?|permission denied for|not authorized to (list|access) models|does not have (the )?permission/.test(body)
      && !/invalid[_ ]api[_ ]key|incorrect api key|api key not valid|invalid x-api-key|authentication_error|invalid authentication|revoked|expired/.test(body);
    if (scopedButValid) return { ok: true, scoped: true, upstreamStatus: response.status };
    throw new ByokError('BYOK_KEY_REJECTED', 400, { upstreamStatus: response.status });
  }
  if (!response.ok) throw new ByokError('BYOK_PROVIDER_ERROR', 502, { upstreamStatus: response.status });
  return { ok: true, scoped: false, upstreamStatus: response.status };
}

// ─── Storage ────────────────────────────────────────────────────────────────
function docRef(db, uid) {
  return db.collection(BYOK_COLLECTION).doc(uid);
}

const isoOrNull = value => value?.toDate?.().toISOString?.() || (typeof value === 'string' ? value : null);

export function publicKeyMetadata(provider, entry) {
  if (!entry || !entry.cipher) return null;
  return {
    provider,
    last4: entry.last4 || null,
    label: entry.label || null,
    baseUrl: provider === 'custom' ? entry.baseUrl || null : null,
    model: provider === 'custom' ? entry.model || null : null,
    addedAt: isoOrNull(entry.addedAt),
    validatedAt: isoOrNull(entry.validatedAt),
  };
}

export async function saveProviderKey({ uid, provider, secret, baseUrl = null, model = null, label = null, db = getFirestore(), masterKeys = loadMasterKeys(), fetchImpl, resolveHost }) {
  const cleanProvider = normalizeProvider(provider);
  const cleanSecret = normalizeSecret(secret);
  const cleanBase = cleanProvider === 'custom' ? await validateCustomBaseUrl(baseUrl, resolveHost ? { resolve: resolveHost } : {}) : null;
  const cleanModel = cleanProvider === 'custom' ? normalizeModelName(model) : null;
  const validation = await validateProviderKey({ provider: cleanProvider, secret: cleanSecret, baseUrl: cleanBase, fetchImpl });
  const entry = {
    v: BYOK_RECORD_VERSION,
    cipher: encryptSecret(cleanSecret, { uid, provider: cleanProvider }, masterKeys),
    last4: cleanSecret.slice(-4),
    label: label ? String(label).trim().slice(0, 60) : null,
    baseUrl: cleanBase,
    model: cleanModel,
    scopedKey: validation?.scoped === true,
    addedAt: FieldValue.serverTimestamp(),
    validatedAt: FieldValue.serverTimestamp(),
  };
  await docRef(db, uid).set({ [cleanProvider]: entry, updatedAt: FieldValue.serverTimestamp() }, { merge: true });
  const now = new Date().toISOString();
  return publicKeyMetadata(cleanProvider, { ...entry, addedAt: now, validatedAt: now });
}

export async function deleteProviderKey({ uid, provider, db = getFirestore() }) {
  const cleanProvider = normalizeProvider(provider);
  await docRef(db, uid).set({ [cleanProvider]: FieldValue.delete(), updatedAt: FieldValue.serverTimestamp() }, { merge: true });
  return { provider: cleanProvider, deleted: true };
}

/** Current-month usage tally written by settlement; numbers only, never the key. */
export function publicUsage(usageByMonth, month = new Date().toISOString().slice(0, 7)) {
  const u = usageByMonth?.[month];
  if (!u) return null;
  const n = v => (Number.isFinite(Number(v)) ? Number(v) : 0);
  return {
    month,
    requests: n(u.requests),
    inputTokens: n(u.inputTokens),
    outputTokens: n(u.outputTokens),
    catalogCredits: n(u.catalogCredits),
    providerUsd: Math.round(n(u.providerUsd) * 10_000) / 10_000,
    lastAt: isoOrNull(u.lastAt),
  };
}

export async function listProviderKeys({ uid, db = getFirestore() }) {
  const snap = await docRef(db, uid).get();
  const data = snap.exists ? snap.data() : {};
  return BYOK_PROVIDERS
    .map(p => publicKeyMetadata(p, data[p]))
    .filter(Boolean)
    .map(item => ({ ...item, usage: publicUsage(data.usage?.[item.provider]) }));
}

/**
 * Decrypts every stored key for a request. Returns { provider: { secret, baseUrl } }.
 * Anonymous guests never reach this; the caller gates on a registered uid.
 * A record that fails to decrypt is skipped and reported, never thrown, so a
 * rotation mistake degrades to platform funding instead of breaking chat.
 */
export async function loadDecryptedKeys({ uid, db = getFirestore(), masterKeys = null, onUnreadable = () => {} }) {
  if (!uid || String(uid).startsWith('guest_')) return {};
  let keys;
  try { keys = masterKeys || loadMasterKeys(); } catch { return {}; }
  const snap = await docRef(db, uid).get();
  if (!snap.exists) return {};
  const data = snap.data() || {};
  const out = {};
  for (const provider of BYOK_PROVIDERS) {
    const entry = data[provider];
    if (!entry?.cipher) continue;
    try {
      out[provider] = { secret: decryptSecret(entry.cipher, { uid, provider }, keys), baseUrl: entry.baseUrl || null, model: entry.model || null };
    } catch (error) {
      onUnreadable(provider, error?.code || 'BYOK_RECORD_UNREADABLE');
    }
  }
  return out;
}
