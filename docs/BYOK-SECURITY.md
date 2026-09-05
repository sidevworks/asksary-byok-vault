# How AskSary protects your API keys

**Status:** published contract. The code that implements this document lives in
`lib/byok-vault.js`, `lib/byok-context.js`, `lib/byok-clients.js`,
`api/web-byok.js` and `firestore.rules`. When the code changes, this document
changes in the same commit. If you find a difference, that is a bug and we want
to hear about it: security@asksary.com.

AskSary lets you use your own OpenAI, Anthropic, Google Gemini or xAI key, or
any OpenAI‑compatible endpoint. Requests served on your key cost you zero
AskSary credits. This page describes exactly what happens to that key.

## The short version

- Your key is validated against the provider, encrypted, and stored. The plain
  key is never written to disk, never logged, and never sent back to you.
- Only AskSary's server can read the encrypted record. Browsers, mobile apps
  and other users cannot, even if they know your user id.
- The key is decrypted only inside the request that needs it and is discarded
  when that request ends. It is never cached across requests.
- Deleting a key removes it immediately. There is no soft delete.
- We will never use your key for anything other than the request you sent.

## What happens when you save a key

1. Your browser sends the key over HTTPS to `PUT /api/web-byok` with your
   signed‑in Firebase identity. Anonymous guests cannot store keys.
2. The server checks the key is a plausible token (printable ASCII, no spaces,
   8 to 512 characters). A custom endpoint URL must be `https://`, must resolve
   to a public address, and may not point at AskSary's own hosts, private
   networks, loopback, link‑local or cloud metadata addresses. This is the
   server‑side request forgery (SSRF) guard.
3. The server makes one read‑only call to the provider (its "list models"
   endpoint) using your key. If the provider answers 401 or 403 the key is
   rejected and nothing is stored. The key is sent in a header, never in a URL,
   so it cannot appear in an access log.
4. The key is encrypted with AES‑256‑GCM:
   - a fresh random 96‑bit nonce for every write;
   - a 128‑bit authentication tag, so a modified record fails to decrypt;
   - additional authenticated data binding the ciphertext to your user id and
     the provider name, so a record copied to another user or provider slot
     fails to decrypt.
5. The ciphertext, the last four characters of the key, an optional label,
   and timestamps are written to the Firestore document
   `userProviderKeys/{your uid}`. No other field of the key is stored.
6. The plain key is discarded. The response contains only the provider name and
   the last four characters.

## Where the encryption key lives

The master key (`BYOK_MASTER_KEY`, 256 bits) exists only as an environment
variable on AskSary's server functions. It is not in the repository, not in the
database, and not reachable from the client. A second variable
(`BYOK_MASTER_KEY_PREVIOUS`) is accepted for decryption only so the key can be
rotated without locking anyone out. Each record carries the id of the master
key that wrote it.

## Who can read the record

Firestore security rules deny **all** client access to `userProviderKeys`:

```
match /userProviderKeys/{userId} {
  allow read, write: if false;
}
```

Only server code running with the Firebase Admin SDK can read or write it, and
that code decrypts a record only for the user whose signed identity is on the
request.

## What happens when you send a message

1. Your request arrives with your signed identity. The server loads your
   encrypted records, decrypts them, and places them in a request‑scoped
   context (Node's `AsyncLocalStorage`). That context lives exactly as long as
   the request.
2. Every provider client in the chat handler is a proxy that reads that
   context. If you have a key for the provider being called, a fresh SDK
   client is built with your key for this request. Otherwise AskSary's own
   client is used.
3. The billing layer reads the **same** context. If the call is going out on
   your key, the operation is recorded with `fundingSource: "user_key"`, zero
   credits are reserved, and settlement writes zero. The audit row still
   exists so you and we can see what ran. Because one context drives both
   decisions, "used your key" and "charged you nothing" cannot disagree.
4. When the request ends the context is gone. Nothing about the key is written
   to logs. The only key‑related log lines are `byok_key_saved`,
   `byok_key_deleted` (provider name and last four characters) and
   `byok_key_unreadable` (provider name and an error code).

If the provider rejects your key during a chat (401 or 403), you see a message
telling you which provider refused it and how to fix it. It is not treated as
an AskSary outage and is not sent to our error tracker.

## What still costs credits

Only calls that go to a provider you have a key for run at zero credits.
Everything else is unchanged: image, video, music and 3D generation on
AskSary's own provider accounts, and any text call to a provider you have not
added a key for. Rate limits and abuse controls apply to every request
regardless of who pays the provider.

## Custom endpoints

A custom entry is an OpenAI‑compatible base URL, a key, and the model name your
endpoint expects. It stands in for OpenAI when you have not stored an OpenAI
key. Features that require OpenAI‑only APIs (file search, code interpreter,
the Responses API) may not work on endpoints that do not implement them.

## Deleting a key

`DELETE /api/web-byok` removes the provider's field from your document in a
single write. There is no retention window, no backup written by this feature,
and no copy anywhere else. Firestore's own point‑in‑time recovery, if enabled
on the project, retains history for at most seven days and is accessible only
to project administrators.

## What this does not protect against

We would rather say this plainly than let you assume otherwise.

- **A compromised AskSary server.** Server code that holds the master key can
  decrypt records. That is inherent to any server‑side BYOK design. We limit
  the blast radius by keeping the key decrypted only for the life of a
  request and never logging it, but we cannot make the server unable to read
  what it must use.
- **Your provider account.** We validate that a key works; we do not know or
  control what it is allowed to spend. Create a dedicated key with a spending
  limit at your provider, and rotate it whenever you like.
- **Your own device and browser.** The key is typed into a password field and
  cleared from the field before the network call. We do not store it in
  browser storage. Anything that can read your screen or keyboard is outside
  our control.

## Verify the code yourself

The files that can see a plain key are sealed: their exact contents are
committed to by a SHA‑256 manifest whose hash is published, and they change
only for an upgrade or maintenance, each time as a new announced seal that
names the previous one. The protocol, including what a valid seal does and does
not prove, is in [BYOK-SEALED-VAULT.md](BYOK-SEALED-VAULT.md). The sealed source, the
verifier and the history of every seal are public at https://github.com/sidevworks/asksary-byok-vault
(mirrored here in [`byok-seal/ANCHORS.md`](../byok-seal/ANCHORS.md)).

```
node scripts/byok-verify.mjs --anchor <manifest hash from ANCHORS.md>
curl https://www.asksary.com/api/web-byok-seal
```

## Reporting a problem

Email security@asksary.com. Please do not include your API key in the report.
