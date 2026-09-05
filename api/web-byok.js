// /api/web-byok.js — manage the signed-in user's own provider keys (BYOK).
//
// GET    → metadata for stored keys (provider, last4, label, custom host/model, timestamps). Never the key.
// PUT    → { provider, key, baseUrl?, model?, label? } validate against the provider, encrypt, store.
// DELETE → { provider } remove immediately.
//
// Registered accounts only. Anonymous guests and the frozen iOS product never
// reach this surface. Public contract: docs/BYOK-SECURITY.md.
import { getFirebaseAdminServices } from '../lib/firebase-admin.js';
import { isAnonymousGuestIdentity } from '../lib/guest-access-policy.js';
import { BYOK_PROVIDERS } from '../lib/byok-context.js';
import {
  ByokError,
  deleteProviderKey,
  isByokConfigured,
  listProviderKeys,
  saveProviderKey,
} from '../lib/byok-vault.js';

const ALLOWED_ORIGINS = ['capacitor://localhost', 'http://localhost:3000'];

function readJsonBody(req) {
  if (req.body && typeof req.body === 'object') return req.body;
  if (typeof req.body === 'string' && req.body) {
    try { return JSON.parse(req.body); } catch { return null; }
  }
  return {};
}

export default async function handler(req, res) {
  const { db, auth, error: adminInitError } = getFirebaseAdminServices();

  const origin = req.headers.origin;
  if (origin && (origin.startsWith('capacitor://') || ALLOWED_ORIGINS.includes(origin))) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  } else {
    res.setHeader('Access-Control-Allow-Origin', '*');
  }
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Methods', 'GET, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type');
  // A response carrying key metadata must never be cached by a shared proxy.
  res.setHeader('Cache-Control', 'no-store');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (!['GET', 'PUT', 'DELETE'].includes(req.method)) return res.status(405).json({ error: 'Method not allowed' });
  if (adminInitError || !db || !auth) return res.status(503).json({ error: 'Firebase admin is not configured on server' });

  const token = req.headers.authorization?.split('Bearer ')[1];
  if (!token) return res.status(401).json({ error: 'authentication_required' });
  let decoded;
  try {
    decoded = await auth.verifyIdToken(token);
  } catch {
    return res.status(401).json({ error: 'invalid_auth_token' });
  }
  if (isAnonymousGuestIdentity(decoded) || decoded.firebase?.sign_in_provider === 'anonymous') {
    return res.status(403).json({ error: 'registration_required' });
  }
  const uid = decoded.uid;
  let body = null;

  try {
    if (req.method === 'GET') {
      return res.status(200).json({
        configured: isByokConfigured(),
        providers: BYOK_PROVIDERS,
        keys: isByokConfigured() ? await listProviderKeys({ uid, db }) : [],
      });
    }
    if (!isByokConfigured()) return res.status(503).json({ error: 'BYOK_NOT_CONFIGURED' });

    body = readJsonBody(req);
    if (!body) return res.status(400).json({ error: 'INVALID_JSON' });

    if (req.method === 'DELETE') {
      const result = await deleteProviderKey({ uid, provider: body.provider, db });
      console.log(JSON.stringify({ evt: 'byok_key_deleted', uid, provider: result.provider }));
      return res.status(200).json(result);
    }

    // PUT — the raw key exists only in this request: it is validated, encrypted
    // and discarded. It is never logged, never written to any other store, and
    // never echoed back.
    const saved = await saveProviderKey({
      uid,
      provider: body.provider,
      secret: body.key,
      baseUrl: body.baseUrl ?? null,
      model: body.model ?? null,
      label: body.label ?? null,
      db,
    });
    console.log(JSON.stringify({ evt: 'byok_key_saved', uid, provider: saved.provider, last4: saved.last4 }));
    return res.status(200).json(saved);
  } catch (error) {
    if (error instanceof ByokError) {
      // Provider name and upstream status only; never the key or the body.
      console.warn(JSON.stringify({ evt: 'byok_key_refused', uid, method: req.method, provider: String(body?.provider || '').slice(0, 20), code: error.code, ...(error.details || {}) }));
      return res.status(error.status).json({ error: error.code, ...(error.details || {}) });
    }
    // Deliberately do not log the error object: a provider SDK error can
    // include request headers. Log the class of failure only.
    console.error(JSON.stringify({ evt: 'byok_request_failed', uid, method: req.method, code: error?.code || 'unknown' }));
    return res.status(500).json({ error: 'BYOK_INTERNAL_ERROR' });
  }
}
