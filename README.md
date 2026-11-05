# Sary-OS BYOK vault (sealed)

This repository is the public, verifiable copy of the code that handles a
user's own API key inside [Sary-OS](https://www.sary-os.com).

> **Formerly AskSary.** Sary-OS was previously called AskSary. You will still
> see the old name in a few places on purpose: inside the sealed source files
> (editing them would change their hashes and break every published seal), in
> the seal's fixed hashing tags (`asksary-byok-seal/v1/…`), and in the
> historical seal notes. These are the same product.

- **What it protects and how:** [docs/BYOK-SECURITY.md](docs/BYOK-SECURITY.md)
- **What the seal proves and what it does not:** [docs/BYOK-SEALED-VAULT.md](docs/BYOK-SEALED-VAULT.md)
- **Every seal ever published:** [byok-seal/ANCHORS.md](byok-seal/ANCHORS.md)

## Verify it yourself

Requires Node.js 18 or newer. No install step: the verifier has no dependencies.

```
node scripts/byok-verify.mjs --anchor <manifest hash from ANCHORS.md>
```

Exit code 0 means every sealed file in this checkout matches the published
seal. Exit code 1 means something was changed. Then compare the same anchor
with the live deployment: `https://www.sary-os.com/api/web-byok-seal`.
