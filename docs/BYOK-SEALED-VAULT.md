# The BYOK sealed vault

This document defines what AskSary may claim about the code that touches your
API key, and how you check that claim yourself. It follows the same discipline
as the After Genesis sealed‑experiment protocol: a valid hash proves that a
record has not changed. It does not, by itself, prove anything else, and we say
so below.

## Public claim

The files that can see a user's plain API key are a fixed, small set. Their
exact contents are committed to by a SHA‑256 manifest whose hash is published.
That code is not edited casually. It changes only for an upgrade or for
maintenance, and every such change is a new, announced seal that names the seal
it replaced and the reason. Anyone can recompute the hashes from the public
source and compare them with the published anchor, and can ask the running
deployment which seal it reports.

## What is sealed

The sealed set, in fixed order:

| File | Role |
|---|---|
| `lib/byok-vault.js` | encryption, decryption, validation, storage, deletion |
| `lib/byok-context.js` | request‑scoped context that holds decrypted keys |
| `lib/byok-clients.js` | request‑aware provider clients built from that context |
| `lib/byok-seal.js` | the seal itself: hash domains, sealed list, manifest, verifier |
| `api/web-byok.js` | the endpoint that receives, validates, stores and deletes keys |
| `api/web-byok-seal.js` | the live self‑report endpoint |
| `scripts/byok-verify.mjs` | the public verifier |

Plus one rule block that must appear verbatim in `firestore.rules`:

```
match /userProviderKeys/{userId} {
  allow read, write: if false;
}
```

## How the seal is computed

Everything uses SHA‑256 with domain separation, so a value hashed as a file can
never be confused with a value hashed as a manifest:

- file digest: `SHA-256("asksary-byok-seal/v1/file\n" + bytes)` with CRLF normalised to LF;
- rule digest: `SHA-256("asksary-byok-seal/v1/rule-block\n" + text)`;
- manifest hash: `SHA-256("asksary-byok-seal/v1/manifest\n" + canonical JSON)`.

Canonical JSON sorts object keys and contains no whitespace, so key order never
matters. The manifest commits to: seal version, each file's path, digest and
byte length, the rule block, the seal time, the source commit, the reason
(`initial`, `upgrade` or `maintenance`), a human note, and the hash of the
previous manifest. Changing any of these produces a different manifest hash.

The manifest lives at `byok-seal/manifest.json`. The history of every seal ever
published lives at `byok-seal/ANCHORS.md`, oldest first. Because each manifest
carries `previousManifestHash`, a removed or rewritten history row is itself
detectable.

## Verifying it yourself

1. Get the anchor from a source you trust: `byok-seal/ANCHORS.md` in the
   public repository, or the security page at https://www.asksary.com/byok-security.
2. Clone the public repository https://github.com/sidevworks/asksary-byok-vault and run:

   ```
   node scripts/byok-verify.mjs --anchor <manifest hash>
   ```

   Exit code 0: every sealed file matches the anchor. Exit code 1: something
   differs, and the report names the file. The verifier is a single file with
   no dependencies. Read it first; it is short.
3. Ask the live deployment which seal it is running:

   ```
   curl https://www.asksary.com/api/web-byok-seal
   ```

   `deployed.manifestHash` is recomputed from the files on the server at that
   moment. `sourceCommit` is the commit the deployment was built from. Compare
   both with the anchor and the public repository.

Always pass `--anchor`. Without it, new code shipped with a freshly generated
manifest still verifies as self‑consistent. The anchor is what ties the check
to a value you obtained independently.

## What a valid seal proves

- The seven sealed files in the checkout you verified are byte‑for‑byte the
  files that were hashed when the anchor was published.
- The Firestore rule that denies all client access to stored keys is present in
  the rules file you verified.
- The seal history is intact back to the initial seal.

## What a valid seal does not prove

- **That the deployed server runs the verified code.** The self‑report endpoint
  is the server describing itself. A server altered to steal keys could be
  altered to lie there too. The endpoint exists so an honest deployment can be
  cross‑checked by commit; it is not proof on its own. Stronger deployment
  attestation would require build provenance from the hosting platform, which
  AskSary does not have today.
- **That code outside the sealed set is harmless.** The chat handler that calls
  these files is large and changes often, so it is not sealed. It receives
  decrypted keys through the sealed context for the life of one request. The
  sealed set is designed so that the handler never needs to touch a key
  directly, only an SDK client built from it, but the handler is not itself
  committed to by the seal.
- **That the operator cannot read keys.** Whoever holds the master key and can
  run code on the server can decrypt records. That is inherent to server‑side
  BYOK. The seal makes silent changes to the key‑handling code detectable; it
  does not make them impossible.
- **Anything about a checkout without a matching anchor.** A manifest hash you
  did not obtain independently proves only internal consistency.

## Reseal policy

The sealed set is changed only when one of these is true:

- **upgrade**: a new provider, a new protection, or a security fix;
- **maintenance**: a dependency, runtime or platform change requires it.

Every reseal appends one row to `ANCHORS.md` with the time, the new hash, the
reason, the source commit and a note, and the new manifest names the previous
hash. Reseals are announced on the security page. A reseal without a row in
the public history is a broken promise, and the history is designed so that you
can tell.

## Reporting a discrepancy

If the verifier fails against a published anchor, or the live endpoint reports a
hash that is not in the public history, email security@asksary.com with the
verifier output. Do not include any API key.
