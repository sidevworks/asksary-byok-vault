// lib/byok-seal.js — cryptographic commitment over the BYOK key-handling code.
//
// SEALED. This file is itself part of the sealed set it describes. The hash
// function, the domain-separation tags, the canonical JSON form and the sealed
// file list are part of the seal's identity: changing any of them produces a
// different manifest hash and therefore a new, separately announced seal.
//
// Model: docs/BYOK-SEALED-VAULT.md (public). A verifier that a member of the
// public runs is scripts/byok-verify.mjs; it is deliberately self-contained
// and does not import this file, so the two implementations cross-check each
// other in scripts/test-byok-seal.mjs.
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import path from 'node:path';

export const SEAL_VERSION = 1;

/** Domain separation. Fixed forever for seal version 1. */
export const SealDomain = Object.freeze({
  File: 'asksary-byok-seal/v1/file',
  RuleBlock: 'asksary-byok-seal/v1/rule-block',
  Manifest: 'asksary-byok-seal/v1/manifest',
});

/**
 * The sealed set. Paths are repository-relative and sorted. Every file that
 * can see a plain user key, plus the seal machinery itself.
 */
export const SEALED_FILES = Object.freeze([
  'api/web-byok-seal.js',
  'api/web-byok.js',
  'lib/byok-clients.js',
  'lib/byok-context.js',
  'lib/byok-seal.js',
  'lib/byok-vault.js',
  'scripts/byok-verify.mjs',
]);

/** The exact Firestore rule text that must appear verbatim in firestore.rules. */
export const SEALED_RULE_BLOCK = 'match /userProviderKeys/{userId} {\n      allow read, write: if false;\n    }';

export function sha256Hex(domain, input) {
  return createHash('sha256').update(`${domain}\n`, 'utf8').update(input).digest('hex');
}

/** Deterministic JSON: sorted keys, no whitespace, arrays in given order. */
export function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map(k => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

/** Normalise line endings so a checkout on any OS hashes identically. */
export function normalizeSource(buffer) {
  return Buffer.from(buffer.toString('utf8').replace(/\r\n/g, '\n'), 'utf8');
}

export async function digestFile(root, relativePath) {
  const bytes = normalizeSource(await readFile(path.join(root, relativePath)));
  return { path: relativePath, sha256: sha256Hex(SealDomain.File, bytes), bytes: bytes.length };
}

export function ruleBlockDigest() {
  return sha256Hex(SealDomain.RuleBlock, Buffer.from(SEALED_RULE_BLOCK, 'utf8'));
}

/** The fields the manifest hash covers, in canonical form. */
export function manifestCommitment(manifest) {
  return canonicalJson({
    sealVersion: manifest.sealVersion,
    files: manifest.files.map(f => ({ path: f.path, sha256: f.sha256, bytes: f.bytes })),
    ruleBlock: { text: manifest.ruleBlock.text, sha256: manifest.ruleBlock.sha256 },
    sealedAt: manifest.sealedAt,
    sourceCommit: manifest.sourceCommit,
    reason: manifest.reason,
    note: manifest.note,
    previousManifestHash: manifest.previousManifestHash,
  });
}

export function manifestHash(manifest) {
  return sha256Hex(SealDomain.Manifest, Buffer.from(manifestCommitment(manifest), 'utf8'));
}

export async function buildManifest(root, { sealedAt = new Date().toISOString(), sourceCommit = 'local-uncommitted', reason, note, previousManifestHash = null }) {
  if (!['initial', 'upgrade', 'maintenance'].includes(reason)) throw new Error('SEAL_REASON_INVALID');
  if (!note || String(note).trim().length < 8) throw new Error('SEAL_NOTE_REQUIRED');
  const files = [];
  for (const rel of SEALED_FILES) files.push(await digestFile(root, rel));
  const manifest = {
    sealVersion: SEAL_VERSION,
    files,
    ruleBlock: { text: SEALED_RULE_BLOCK, sha256: ruleBlockDigest() },
    sealedAt,
    sourceCommit,
    reason,
    note: String(note).trim(),
    previousManifestHash,
  };
  return { ...manifest, manifestHash: manifestHash(manifest) };
}

/**
 * Verify a checkout against a manifest. Reads only. Returns a report; never
 * repairs anything. `expectedAnchor` is the published hash a member of the
 * public compares against; without it a self-consistent forgery still passes.
 */
export async function verifyManifest(root, manifest, { expectedAnchor = null, rulesPath = 'firestore.rules' } = {}) {
  const problems = [];
  if (manifest?.sealVersion !== SEAL_VERSION) problems.push(`sealVersion ${manifest?.sealVersion} is not ${SEAL_VERSION}`);
  const recomputed = manifestHash(manifest);
  if (recomputed !== manifest.manifestHash) problems.push(`manifestHash mismatch: file says ${manifest.manifestHash}, recomputed ${recomputed}`);
  if (expectedAnchor && recomputed !== expectedAnchor) problems.push(`anchor mismatch: expected ${expectedAnchor}, manifest is ${recomputed}`);
  const listed = manifest.files.map(f => f.path);
  if (canonicalJson(listed) !== canonicalJson([...SEALED_FILES])) problems.push('sealed file list differs from SEALED_FILES');
  const fileResults = [];
  for (const entry of manifest.files) {
    let actual;
    try { actual = await digestFile(root, entry.path); } catch (error) { problems.push(`${entry.path}: unreadable (${error.code || error.message})`); continue; }
    const ok = actual.sha256 === entry.sha256 && actual.bytes === entry.bytes;
    if (!ok) problems.push(`${entry.path}: modified (expected ${entry.sha256.slice(0, 16)}…, got ${actual.sha256.slice(0, 16)}…)`);
    fileResults.push({ path: entry.path, ok, sha256: actual.sha256 });
  }
  let rules = '';
  try { rules = (await readFile(path.join(root, rulesPath), 'utf8')).replace(/\r\n/g, '\n'); } catch { problems.push(`${rulesPath}: unreadable`); }
  if (rules && !rules.includes(manifest.ruleBlock.text)) problems.push('firestore.rules no longer contains the sealed userProviderKeys deny-all block');
  if (manifest.ruleBlock.sha256 !== ruleBlockDigest() || manifest.ruleBlock.text !== SEALED_RULE_BLOCK) problems.push('manifest rule block differs from SEALED_RULE_BLOCK');
  return { ok: problems.length === 0, manifestHash: recomputed, sealedAt: manifest.sealedAt, sourceCommit: manifest.sourceCommit, reason: manifest.reason, files: fileResults, problems };
}
