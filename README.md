# AskSary BYOK vault (sealed)

This repository is the public, verifiable copy of the code that handles a
user's own API key inside [AskSary](https://www.asksary.com).

- **What it protects and how:** [docs/BYOK-SECURITY.md](docs/BYOK-SECURITY.md)
- **What the seal proves and what it does not:** [docs/BYOK-SEALED-VAULT.md](docs/BYOK-SEALED-VAULT.md)
- **Every seal ever published:** [byok-seal/ANCHORS.md](byok-seal/ANCHORS.md)

## Verify it yourself

```
node scripts/byok-verify.mjs --anchor <manifest hash from ANCHORS.md>
```

Exit code 0 means every sealed file in this checkout matches the published
seal. Exit code 1 means something was changed. Then compare the same anchor
with the live deployment: `https://www.asksary.com/api/web-byok-seal`.
