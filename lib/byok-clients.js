// lib/byok-clients.js — request-aware provider clients.
//
// `byokClient(name, platformClient, factory, options)` returns a Proxy. Every
// property access resolves against the client for the CURRENT request: a
// client built from the user's own key when lib/byok-context.js holds one for
// that provider, otherwise the platform client. Per-request clients are built
// fresh and never cached across requests, so a key is only ever attached to
// SDK instances that live inside the request that decrypted it.
//
// `options.fallback` names a second provider entry to use when the primary
// one is absent. The OpenAI client uses fallback: 'custom' so an
// OpenAI-compatible endpoint (base URL + key + model) can stand in for OpenAI.
import { byokKeyFor } from './byok-context.js';

const cacheKey = Symbol('byok-request-client');

function requestClient(name, factory, fallback) {
  const entry = byokKeyFor(name) || (fallback ? byokKeyFor(fallback) : null);
  if (!entry) return null;
  // Cache on the context entry itself so a long streaming request reuses one
  // SDK instance; the entry dies with the request context.
  if (!entry[cacheKey]) {
    Object.defineProperty(entry, cacheKey, { value: factory(entry), enumerable: false });
  }
  return entry[cacheKey];
}

export function byokClient(name, platformClient, factory, { fallback = null } = {}) {
  const resolve = () => requestClient(name, factory, fallback) || platformClient;
  return new Proxy(platformClient, {
    get(_, prop) {
      const target = resolve();
      const value = target[prop];
      return typeof value === 'function' ? value.bind(target) : value;
    },
    has(_, prop) { return prop in resolve(); },
  });
}

/**
 * Wraps an OpenAI-SDK-shaped client so every chat/responses call is sent with
 * the user's configured model instead of AskSary's catalogue model id. Used
 * for custom OpenAI-compatible endpoints, which do not know AskSary's ids.
 */
export function withModelOverride(client, model) {
  if (!model) return client;
  const rewrite = fn => (params, ...rest) => fn({ ...params, model }, ...rest);
  const chat = client.chat;
  const completions = chat?.completions;
  const responses = client.responses;
  return new Proxy(client, {
    get(target, prop) {
      if (prop === 'chat' && completions) {
        return { ...chat, completions: new Proxy(completions, {
          get(c, p) { const v = c[p]; return p === 'create' ? rewrite(v.bind(c)) : (typeof v === 'function' ? v.bind(c) : v); },
        }) };
      }
      if (prop === 'responses' && responses) {
        return new Proxy(responses, {
          get(r, p) { const v = r[p]; return p === 'create' ? rewrite(v.bind(r)) : (typeof v === 'function' ? v.bind(r) : v); },
        });
      }
      const value = target[prop];
      return typeof value === 'function' ? value.bind(target) : value;
    },
  });
}

/** The API key string to use for a raw-fetch provider call in this request. */
export function byokApiKey(name, platformKey) {
  return byokKeyFor(name)?.secret || platformKey;
}

/** True when this request's call to `name` runs on the user's own key. */
export function isServedByUserKey(name) {
  return Boolean(byokKeyFor(name));
}
