#!/usr/bin/env node
// byok-verify — the command a member of the public runs to check that the
// AskSary BYOK key-handling code matches its published seal.
//
// SELF-CONTAINED ON PURPOSE. This file imports nothing from the repository so
// it can be copied anywhere, read in full in a few minutes, and run against
// any checkout. It reads. It cannot repair or rewrite anything.
//
// Usage:
//   node scripts/byok-verify.mjs [--root <dir>] [--manifest <file>] [--anchor <hash>] [--json]
//
// Exit codes: 0 verified, 1 verification failed, 2 usage error. The exit code
// matters: this is meant to run in someone else's CI, not just be read.
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import path from 'node:path';

const SEAL_VERSION = 1;
const DOMAIN_FILE = 'asksary-byok-seal/v1/file';
const DOMAIN_RULE = 'asksary-byok-seal/v1/rule-block';
const DOMAIN_MANIFEST = 'asksary-byok-seal/v1/manifest';
const SEALED_FILES = [
  'api/web-byok-seal.js',
  'api/web-byok.js',
  'lib/byok-clients.js',
  'lib/byok-context.js',
  'lib/byok-seal.js',
  'lib/byok-vault.js',
  'scripts/byok-verify.mjs',
];
const SEALED_RULE_BLOCK = 'match /userProviderKeys/{userId} {\n      allow read, write: if false;\n    }';

const sha256 = (domain, bytes) => createHash('sha256').update(`${domain}\n`, 'utf8').update(bytes).digest('hex');
const canonical = v => Array.isArray(v) ? `[${v.map(canonical).join(',')}]`
  : v && typeof v === 'object' ? `{${Object.keys(v).sort().map(k => `${JSON.stringify(k)}:${canonical(v[k])}`).join(',')}}`
  : JSON.stringify(v);
const normalize = buf => Buffer.from(buf.toString('utf8').replace(/\r\n/g, '\n'), 'utf8');

function manifestHash(m) {
  const commitment = canonical({
    sealVersion: m.sealVersion,
    files: m.files.map(f => ({ path: f.path, sha256: f.sha256, bytes: f.bytes })),
    ruleBlock: { text: m.ruleBlock.text, sha256: m.ruleBlock.sha256 },
    sealedAt: m.sealedAt,
    sourceCommit: m.sourceCommit,
    reason: m.reason,
    note: m.note,
    previousManifestHash: m.previousManifestHash,
  });
  return sha256(DOMAIN_MANIFEST, Buffer.from(commitment, 'utf8'));
}

function parseArgs(argv) {
  const out = { root: process.cwd(), manifest: null, anchor: null, json: false };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--root') out.root = argv[++i];
    else if (arg === '--manifest') out.manifest = argv[++i];
    else if (arg === '--anchor') out.anchor = argv[++i];
    else if (arg === '--json') out.json = true;
    else if (arg === '--help' || arg === '-h') return { help: true };
    else return { error: `unknown argument: ${arg}` };
    if (out.root === undefined || out.manifest === undefined || out.anchor === undefined) return { error: `${arg} requires a value` };
  }
  if (!out.manifest) out.manifest = path.join(out.root, 'byok-seal', 'manifest.json');
  return out;
}

const USAGE = `byok-verify — verify the AskSary BYOK key-handling code against its seal

Usage:
  node scripts/byok-verify.mjs [options]

Options:
  --root <dir>        Repository checkout to verify (default: current directory)
  --manifest <file>   Manifest to verify against (default: <root>/byok-seal/manifest.json)
  --anchor <hash>     Compare the manifest hash against the published anchor.
                      Without this, a self-consistent forgery (new code + new
                      manifest) still verifies. Always pass the anchor you got
                      from a source you trust.
  --json              Emit the report as JSON

Exit codes: 0 verified, 1 verification failed, 2 usage error.`;

export async function verify({ root, manifestPath, anchor }) {
  const problems = [];
  let manifest;
  try { manifest = JSON.parse(await readFile(manifestPath, 'utf8')); } catch (error) { return { ok: false, problems: [`manifest unreadable: ${error.message}`] }; }
  if (manifest.sealVersion !== SEAL_VERSION) problems.push(`sealVersion ${manifest.sealVersion} is not ${SEAL_VERSION}`);
  const recomputed = manifestHash(manifest);
  if (recomputed !== manifest.manifestHash) problems.push(`manifestHash mismatch: file says ${manifest.manifestHash}, recomputed ${recomputed}`);
  if (anchor && recomputed !== anchor) problems.push(`anchor mismatch: expected ${anchor}, manifest is ${recomputed}`);
  if (canonical(manifest.files.map(f => f.path)) !== canonical(SEALED_FILES)) problems.push('sealed file list differs from the verifier\'s SEALED_FILES');
  const files = [];
  for (const entry of manifest.files) {
    let bytes;
    try { bytes = normalize(await readFile(path.join(root, entry.path))); } catch (error) { problems.push(`${entry.path}: unreadable (${error.code || error.message})`); continue; }
    const actual = sha256(DOMAIN_FILE, bytes);
    const ok = actual === entry.sha256 && bytes.length === entry.bytes;
    if (!ok) problems.push(`${entry.path}: modified (expected ${entry.sha256.slice(0, 16)}…, got ${actual.slice(0, 16)}…)`);
    files.push({ path: entry.path, ok, sha256: actual });
  }
  let rules = '';
  try { rules = (await readFile(path.join(root, 'firestore.rules'), 'utf8')).replace(/\r\n/g, '\n'); } catch { problems.push('firestore.rules: unreadable'); }
  if (rules && !rules.includes(SEALED_RULE_BLOCK)) problems.push('firestore.rules no longer contains the sealed userProviderKeys deny-all block');
  if (manifest.ruleBlock?.text !== SEALED_RULE_BLOCK || manifest.ruleBlock?.sha256 !== sha256(DOMAIN_RULE, Buffer.from(SEALED_RULE_BLOCK, 'utf8'))) problems.push('manifest rule block differs from the sealed rule text');
  return { ok: problems.length === 0, manifestHash: recomputed, anchorChecked: Boolean(anchor), sealedAt: manifest.sealedAt, sourceCommit: manifest.sourceCommit, reason: manifest.reason, note: manifest.note, previousManifestHash: manifest.previousManifestHash, files, problems };
}

function format(report) {
  const lines = [];
  lines.push(report.ok ? 'BYOK SEAL VERIFIED' : 'BYOK SEAL VERIFICATION FAILED');
  if (report.manifestHash) lines.push(`manifest hash:   ${report.manifestHash}${report.anchorChecked ? '  (matches anchor)' : '  (no --anchor given: not compared to a published value)'}`);
  if (report.sealedAt) lines.push(`sealed at:       ${report.sealedAt}`);
  if (report.sourceCommit) lines.push(`source commit:   ${report.sourceCommit}`);
  if (report.reason) lines.push(`reason:          ${report.reason} — ${report.note || ''}`);
  if (report.previousManifestHash) lines.push(`previous seal:   ${report.previousManifestHash}`);
  for (const f of report.files || []) lines.push(`  ${f.ok ? 'ok      ' : 'MODIFIED'} ${f.path}`);
  for (const p of report.problems) lines.push(`  ! ${p}`);
  return lines.join('\n');
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) { console.log(USAGE); return 0; }
  if (args.error) { console.error(`${args.error}\n\n${USAGE}`); return 2; }
  const report = await verify({ root: path.resolve(args.root), manifestPath: path.resolve(args.manifest), anchor: args.anchor });
  console.log(args.json ? JSON.stringify(report, null, 2) : format(report));
  return report.ok ? 0 : 1;
}

if (process.argv[1] && path.resolve(process.argv[1]) === new URL(import.meta.url).pathname) {
  main().then(code => process.exit(code), error => { console.error(error); process.exit(2); });
}
