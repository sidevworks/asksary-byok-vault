// lib/byok-context.js — per-request "bring your own key" context.
//
// One AsyncLocalStorage store carries the caller's decrypted provider keys for
// exactly the lifetime of a single request. Both the provider client proxies
// (lib/byok-clients.js) and the billing authority (lib/billing-authority.js)
// read the SAME store, so the key that serves a call and the decision to charge
// zero credits for it can never disagree. There is no second code path.
//
// Public security contract: docs/BYOK-SECURITY.md. Keep this file consistent
// with that document; it is published.
import { AsyncLocalStorage } from 'node:async_hooks';

export const BYOK_PROVIDERS = Object.freeze(['openai', 'anthropic', 'gemini', 'grok', 'custom']);

// Billing catalogue provider labels (lib/billing-catalog.js) → BYOK provider ids.
const CATALOG_PROVIDER_TO_BYOK = Object.freeze({
  openai: 'openai',
  anthropic: 'anthropic',
  google: 'gemini',
  xai: 'grok',
});

const storage = new AsyncLocalStorage();

export function runWithByokContext(keys, fn) {
  const frozen = Object.freeze({ keys: Object.freeze({ ...(keys || {}) }) });
  return storage.run(frozen, fn);
}

export function getByokContext() {
  return storage.getStore() || null;
}

/** The decrypted entry ({ secret, baseUrl }) for a provider in this request, or null. */
export function byokKeyFor(provider) {
  const ctx = getByokContext();
  const entry = ctx?.keys?.[String(provider || '').toLowerCase()];
  return entry && typeof entry.secret === 'string' && entry.secret ? entry : null;
}

export function byokProviderForCatalogProvider(catalogProvider) {
  return CATALOG_PROVIDER_TO_BYOK[String(catalogProvider || '').trim().toLowerCase()] || null;
}

/**
 * Decide who pays for a catalogued provider operation in the current request.
 * 'user_key' means the request executes on the user's own key and zero credits
 * are reserved. 'platform' is today's behaviour. An explicit value wins so a
 * caller that deliberately uses the platform key (e.g. a shared index build)
 * can say so.
 */
export function decideFundingSource(catalogProvider, { explicit = null, keys = null } = {}) {
  if (explicit === 'platform' || explicit === 'user_key') return explicit;
  const byokProvider = byokProviderForCatalogProvider(catalogProvider);
  if (!byokProvider) return 'platform';
  const source = keys ? { keys } : getByokContext();
  const entry = source?.keys?.[byokProvider];
  return entry && typeof entry.secret === 'string' && entry.secret ? 'user_key' : 'platform';
}

/** Provider ids the current request can serve on the user's own key. */
export function activeByokProviders() {
  const ctx = getByokContext();
  return BYOK_PROVIDERS.filter(p => ctx?.keys?.[p]?.secret);
}
