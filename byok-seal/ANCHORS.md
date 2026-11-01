# BYOK seal anchors

Every seal ever published, oldest first. Each manifest names the one before it. Verify any row with:

```
node scripts/byok-verify.mjs --anchor <manifest hash>
```

| Sealed at | Manifest hash | Reason | Source commit | Note |
|---|---|---|---|---|
| 2026-09-05T13:31:44.063Z | `af5fd7638d16d4d68309484512fcb1b75ef4380fda7739b596878f8510b4ae07` | initial | b3cd7644945c08f9fecaeb321770b6863cd7356e+uncommitted-sealed-files | Initial seal of the BYOK key-handling code: AES-256-GCM vault, request context, provider clients, endpoint, verifier. |
| 2026-09-05T14:36:50.930Z | `3ba84e6068cd9d67fd46ed77f4f6f2583e92b6ec6f0535228e4cdd5b02f2c560` | maintenance | 98181a85c39b01f52ea9cd4da56e2c8a931e944b | Record clean source commit 98181a8 after the initial commit; no code change to the sealed set. |
| 2026-09-05T19:44:15.839Z | `b1db19b3ea3440e535f3e685a5f6c04c4481cc2379f8ae8d6a892324d06b2463` | upgrade | bc282177c995248f1fa31abae208a0c3db0a3038 | Accept permission-scoped provider keys during validation; log refusals with provider and upstream status; no change to encryption or storage. |
| 2026-09-05T19:46:40.616Z | `fa576a1bd588605108f7fed43368f2b61f04511126899edea828e439e37114e1` | upgrade | 83c49282bfbb48cc48c9245eace09c8edd4a0593 | Key listing includes a per-month usage tally written by settlement; no change to encryption, validation or storage of the key itself. |
| 2026-09-14T23:41:33.041Z | `c0ff66db3bf25e3e2f2668ba93c81a46f0aff6801a28ab6d8b1f89db2ff8942f` | maintenance | f0441fd67dec963ff2a7cee8f7ac97289663b9e5+uncommitted-sealed-files | iOS retirement: capacitor://localhost and the capacitor:// origin prefix removed from web-byok CORS. No other sealed file changed. |
| 2026-09-19T22:31:21.353Z | `c9a3a6984190bfda646549c836c813dd254e352743fce00cf8098bc542b8d597` | maintenance | local-uncommitted | Project agent gains a Grok mode on the xAI base URL (owner, 2026-09-20); LiveLoop attachment and refund fixes. |
| 2026-10-02T01:51:43.572Z | `353d158e8da7c4a2125aa94d12d7868504f4c80f566628f3e514ffe1af88164a` | maintenance | 1aa8abeafbd76e91109dd679d7f433200e8c7a53 | Keyless Firebase Admin (primeFirebaseAdmin) added to web-byok.js; no change to key handling |
| 2026-11-01T09:13:38.791Z | `8ed4b4d21012e26cfde77b149521c674e893572b8dc71b0f4a60691e89faf8f8` | upgrade | 662b362430428f1f63205fd90f3982a0e8bdc568 | New provider: Meta (api.meta.ai, Muse models). byok-context adds 'meta' to BYOK_PROVIDERS and the Meta catalogue mapping; byok-vault validates a Meta key with GET https://api.meta.ai/v1/models. No change to encryption or storage. |
| 2026-11-01T09:39:09.903Z | `d66e72d5e52a59e75fb4533372f65e4d739eb0daa132baad379cfc7dbced3d4c` | upgrade | a4bdfb3ad82ea89b4b3d8c80d685661471611c72 | A custom endpoint is its own model and never stands in for OpenAI. byok-context maps the 'Custom' catalogue provider to the stored 'custom' key, so a custom-endpoint turn is funded by that key; byok-clients comment updated. No change to encryption, validation or storage. |
