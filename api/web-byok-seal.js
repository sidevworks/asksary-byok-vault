// /api/web-byok-seal.js — live self-report of the BYOK seal from the running
// deployment. Unauthenticated, read-only, cacheable for a minute.
//
// SEALED. What this returns:
//   deployed.manifestHash  — recomputed right now from the files on this server
//   published.manifestHash — the manifest that shipped with this build
//   match                  — whether the running code equals the shipped manifest
//   sourceCommit           — the git commit Vercel built this deployment from
//
// Honesty note (also in docs/BYOK-SEALED-VAULT.md): this is the server
// describing itself. A server that had been altered to steal keys could also be
// altered to lie here. The strong check is the public source anchor verified
// with scripts/byok-verify.mjs on a checkout; this endpoint exists so that an
// honest deployment can be cross-checked against that anchor by commit.
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { SEALED_FILES, buildManifest, manifestHash } from '../lib/byok-seal.js';

const ROOT = path.resolve(process.cwd());

async function readPublishedManifest() {
  try { return JSON.parse(await readFile(path.join(ROOT, 'byok-seal', 'manifest.json'), 'utf8')); } catch { return null; }
}

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Cache-Control', 'public, max-age=60');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });
  try {
    const published = await readPublishedManifest();
    if (!published) return res.status(503).json({ error: 'SEAL_MANIFEST_MISSING' });
    // Recompute from the deployed files using the published manifest's own
    // metadata, so the only thing that can differ is the file contents.
    const live = await buildManifest(ROOT, {
      sealedAt: published.sealedAt,
      sourceCommit: published.sourceCommit,
      reason: published.reason,
      note: published.note,
      previousManifestHash: published.previousManifestHash,
    });
    const publishedHash = manifestHash(published);
    return res.status(200).json({
      sealVersion: published.sealVersion,
      match: live.manifestHash === publishedHash && publishedHash === published.manifestHash,
      deployed: { manifestHash: live.manifestHash, files: live.files.map(f => ({ path: f.path, sha256: f.sha256 })) },
      published: { manifestHash: published.manifestHash, recomputed: publishedHash, sealedAt: published.sealedAt, reason: published.reason, note: published.note },
      sourceCommit: process.env.VERCEL_GIT_COMMIT_SHA || null,
      sealedFiles: SEALED_FILES,
      verifyWith: 'node scripts/byok-verify.mjs --anchor <published manifest hash>',
    });
  } catch (error) {
    return res.status(500).json({ error: 'SEAL_SELF_REPORT_FAILED', code: error?.code || null });
  }
}
