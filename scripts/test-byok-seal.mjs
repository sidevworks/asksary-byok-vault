// scripts/test-byok-seal.mjs — the BYOK seal is real, deterministic, and
// tamper-evident, and the public verifier agrees with the sealing library.
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { cp, mkdir, mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import { SEALED_FILES, SEALED_RULE_BLOCK, buildManifest, canonicalJson, manifestHash, verifyManifest } from '../lib/byok-seal.js';
import { verify as publicVerify } from './byok-verify.mjs';

const run = promisify(execFile);
const ROOT = path.resolve(new URL('..', import.meta.url).pathname);
const MANIFEST = path.join(ROOT, 'byok-seal', 'manifest.json');
const VERIFIER = path.join(ROOT, 'scripts', 'byok-verify.mjs');

// ─── Canonical JSON and determinism ─────────────────────────────────────────
assert.equal(canonicalJson({ b: 1, a: [3, { z: null, y: 'x' }] }), '{"a":[3,{"y":"x","z":null}],"b":1}');
const meta = { sealedAt: '2026-09-05T00:00:00.000Z', sourceCommit: 'test', reason: 'initial', note: 'determinism check', previousManifestHash: null };
const m1 = await buildManifest(ROOT, meta);
const m2 = await buildManifest(ROOT, meta);
assert.equal(m1.manifestHash, m2.manifestHash, 'same inputs → same manifest hash');
assert.notEqual((await buildManifest(ROOT, { ...meta, note: 'a different note' })).manifestHash, m1.manifestHash, 'metadata is committed');
assert.deepEqual(m1.files.map(f => f.path), [...SEALED_FILES]);
await assert.rejects(buildManifest(ROOT, { ...meta, reason: 'whim' }), /SEAL_REASON_INVALID/);
await assert.rejects(buildManifest(ROOT, { ...meta, note: 'short' }), /SEAL_NOTE_REQUIRED/);

// ─── The published manifest verifies against this checkout ──────────────────
const published = JSON.parse(await readFile(MANIFEST, 'utf8'));
const libReport = await verifyManifest(ROOT, published, { expectedAnchor: published.manifestHash });
assert.ok(libReport.ok, `published seal must verify against the working tree:\n${libReport.problems.join('\n')}`);
const pubReport = await publicVerify({ root: ROOT, manifestPath: MANIFEST, anchor: published.manifestHash });
assert.ok(pubReport.ok, `public verifier must agree:\n${pubReport.problems.join('\n')}`);
assert.equal(pubReport.manifestHash, libReport.manifestHash, 'both implementations compute the same manifest hash');
assert.equal(manifestHash(published), published.manifestHash);

// The history names the published seal.
const anchors = await readFile(path.join(ROOT, 'byok-seal', 'ANCHORS.md'), 'utf8');
assert.ok(anchors.includes(published.manifestHash), 'ANCHORS.md must list the current manifest hash');
if (published.previousManifestHash) assert.ok(anchors.includes(published.previousManifestHash), 'ANCHORS.md must keep the previous seal');

// ─── Tamper evidence in an isolated copy ────────────────────────────────────
async function copyTree() {
  const dir = await mkdtemp(path.join(tmpdir(), 'byok-seal-'));
  for (const rel of [...SEALED_FILES, 'firestore.rules', 'byok-seal/manifest.json']) {
    await mkdir(path.dirname(path.join(dir, rel)), { recursive: true });
    await cp(path.join(ROOT, rel), path.join(dir, rel));
  }
  return dir;
}
{
  const dir = await copyTree();
  assert.ok((await publicVerify({ root: dir, manifestPath: path.join(dir, 'byok-seal/manifest.json'), anchor: published.manifestHash })).ok, 'clean copy verifies');
  // One byte in the vault.
  const vault = path.join(dir, 'lib/byok-vault.js');
  await writeFile(vault, (await readFile(vault, 'utf8')) + '\n// stolen\n');
  const tampered = await publicVerify({ root: dir, manifestPath: path.join(dir, 'byok-seal/manifest.json'), anchor: published.manifestHash });
  assert.equal(tampered.ok, false);
  assert.ok(tampered.problems.some(p => p.startsWith('lib/byok-vault.js: modified')), tampered.problems.join('\n'));
  assert.equal((await verifyManifest(dir, published)).ok, false, 'library verifier agrees');
}
{
  const dir = await copyTree();
  // CRLF line endings must not count as tampering.
  const ctx = path.join(dir, 'lib/byok-context.js');
  await writeFile(ctx, (await readFile(ctx, 'utf8')).replace(/\n/g, '\r\n'));
  assert.ok((await publicVerify({ root: dir, manifestPath: path.join(dir, 'byok-seal/manifest.json'), anchor: published.manifestHash })).ok, 'CRLF checkout still verifies');
  // Weakening the rule is detected even though the file is not in the sealed list.
  const rules = path.join(dir, 'firestore.rules');
  await writeFile(rules, (await readFile(rules, 'utf8')).replace(SEALED_RULE_BLOCK, 'match /userProviderKeys/{userId} {\n      allow read: if request.auth != null;\n    }'));
  const weakened = await publicVerify({ root: dir, manifestPath: path.join(dir, 'byok-seal/manifest.json'), anchor: published.manifestHash });
  assert.equal(weakened.ok, false);
  assert.ok(weakened.problems.some(p => p.includes('deny-all block')));
}
{
  const dir = await copyTree();
  // A forged manifest that matches forged code is self-consistent but fails the anchor.
  const forged = await buildManifest(dir, { ...meta, note: 'forged reseal by attacker' });
  await writeFile(path.join(dir, 'byok-seal/manifest.json'), JSON.stringify(forged));
  assert.ok((await publicVerify({ root: dir, manifestPath: path.join(dir, 'byok-seal/manifest.json'), anchor: null })).ok, 'without an anchor a forgery is self-consistent (documented limit)');
  const anchored = await publicVerify({ root: dir, manifestPath: path.join(dir, 'byok-seal/manifest.json'), anchor: published.manifestHash });
  assert.equal(anchored.ok, false);
  assert.ok(anchored.problems.some(p => p.startsWith('anchor mismatch')));
}

// ─── CLI exit codes ─────────────────────────────────────────────────────────
async function cli(args) {
  try { const { stdout } = await run(process.execPath, [VERIFIER, ...args], { cwd: ROOT }); return { code: 0, stdout }; }
  catch (error) { return { code: error.code, stdout: error.stdout || '', stderr: error.stderr || '' }; }
}
assert.equal((await cli(['--anchor', published.manifestHash])).code, 0);
assert.match((await cli(['--anchor', published.manifestHash])).stdout, /BYOK SEAL VERIFIED/);
assert.equal((await cli(['--anchor', 'deadbeef'])).code, 1);
assert.equal((await cli(['--bogus'])).code, 2);
assert.equal(JSON.parse((await cli(['--json'])).stdout).ok, true);

// ─── Static: docs and pages describe the same sealed set ────────────────────
const sealedDoc = await readFile(path.join(ROOT, 'docs/BYOK-SEALED-VAULT.md'), 'utf8');
for (const rel of SEALED_FILES) assert.ok(sealedDoc.includes(`\`${rel}\``), `sealed doc lists ${rel}`);
assert.ok(sealedDoc.includes('does not prove'), 'sealed doc states its limits');
const verifierSource = await readFile(VERIFIER, 'utf8');
assert.ok(!/^import .* from '\.\.?\//m.test(verifierSource), 'public verifier imports nothing from the repository');
for (const rel of SEALED_FILES) assert.ok(verifierSource.includes(`'${rel}'`), `verifier hard-codes ${rel}`);
const secDoc = await readFile(path.join(ROOT, 'docs/BYOK-SECURITY.md'), 'utf8');
const secPage = await readFile(path.join(ROOT, 'public/byok-security.html'), 'utf8');
assert.ok(secDoc.includes('BYOK-SEALED-VAULT.md'));
assert.ok(secPage.includes('byok-verify.mjs') && secPage.includes('/api/web-byok-seal'));
assert.ok(secPage.includes(published.manifestHash), 'security page publishes the current anchor');

console.log(`byok seal: ok (${published.manifestHash.slice(0, 16)}…, ${published.reason})`);
