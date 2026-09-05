# BYOK seal anchors

Every seal ever published, oldest first. Each manifest names the one before it. Verify any row with:

```
node scripts/byok-verify.mjs --anchor <manifest hash>
```

| Sealed at | Manifest hash | Reason | Source commit | Note |
|---|---|---|---|---|
| 2026-09-05T13:31:44.063Z | `af5fd7638d16d4d68309484512fcb1b75ef4380fda7739b596878f8510b4ae07` | initial | b3cd7644945c08f9fecaeb321770b6863cd7356e+uncommitted-sealed-files | Initial seal of the BYOK key-handling code: AES-256-GCM vault, request context, provider clients, endpoint, verifier. |
| 2026-09-05T14:36:50.930Z | `3ba84e6068cd9d67fd46ed77f4f6f2583e92b6ec6f0535228e4cdd5b02f2c560` | maintenance | 98181a85c39b01f52ea9cd4da56e2c8a931e944b | Record clean source commit 98181a8 after the initial commit; no code change to the sealed set. |
