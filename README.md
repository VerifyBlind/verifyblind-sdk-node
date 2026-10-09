# VerifyBlind Node.js Server Library

> **Kimliğinizi Kanıtlayın, Gizliliğinizi Koruyun** · _Prove Your Identity, Protect Your Privacy_

**[🇹🇷 Türkçe](#türkçe) · [🇬🇧 English](#english)**

---

## Türkçe

VerifyBlind doğrulama sonucunu **kendi sunucunuzda** birkaç satırla doğrulamak için resmi Node.js kütüphanesi.
Node.js 18+, TypeScript tipleriyle gelir, çalışma zamanında hiçbir bağımlılığı yoktur (`node:crypto` ve
yerleşik `fetch`). ESM ve CommonJS ile çalışır; Express, Next.js, Fastify ve benzerlerinde kullanılabilir.

## Ne yapar

```
[Web widget / mobil SDK]  ── onSuccess → token ──►  [Sizin sunucunuz]
                                                        │  verifier.verifyAndConsume(token, nonceTüket)
                                                        │   1. Enclave imzası (RSA-PSS SHA-256, salt 32)
                                                        │   2. Nonce'u bir kez tüketir (tekrar oynatma koruması)
                                                        │   3. Sonucu SİZİN sorduğunuz koşula göre okur
                                                        ▼
                                                  { ok: true, validations: { age, user_id, ... } }
```

- Enclave anahtarını `GET /api/public/enclave-key` adresinden alır, 60 sn önbellekte tutar; imza tutmazsa
  anahtarı **bir kez** tazeleyip yeniden dener (enclave yeniden başlayınca anahtar değişir).
- Webhook (callback ve revoke) imzasını doğrular, callback'te `encrypted_response`'u çözer (desen B).
- İsteğe bağlı: PCR0 yetkilendirme imzasını doğrular.
- Hiçbir şey loglamaz. Hata mesajlarında `user_id`, `nsbd_id`, `doc_id` geçmez.

## Kurulum

```bash
npm install @verifyblind/server
```

## Hızlı Başlangıç: Express

```js
import express from 'express';
import Redis from 'ioredis';
import { createVerifier } from '@verifyblind/server';

const app = express();
const redis = new Redis(process.env.REDIS_URL);
const verifier = createVerifier();

app.post('/api/verifyblind/verify', express.json(), async (req, res) => {
  const r = await verifier.verifyAndConsume(req.body?.token, (nonce) => redis.getdel(`vb:nonce:${nonce}`));
  if (!r.ok) return res.status(r.error.code === 'KEY_FETCH_FAILED' ? 503 : 401).json({ error: r.error.code });
  if (r.isTest && process.env.NODE_ENV === 'production') return res.status(403).json({ error: 'TEST_RESULT' });
  await saveVerification(req.user.id, r.validations); // user_id / nsbd_id / doc_id → veritabanına, LOGA DEĞİL
  res.json({ ok: true, age: r.validations.age });
});
```

## Hızlı Başlangıç: Next.js (App Router)

```ts
// app/api/verifyblind/verify/route.ts
import { NextResponse } from 'next/server';
import { createVerifier } from '@verifyblind/server';
import { redis } from '@/lib/redis';

export const runtime = 'nodejs'; // node:crypto gerekir; Edge runtime desteklenmez
const verifier = createVerifier();

export async function POST(req: Request) {
  const { token } = await req.json();
  const r = await verifier.verifyAndConsume(token, (nonce) => redis.getdel(`vb:nonce:${nonce}`));
  if (!r.ok) {
    return NextResponse.json({ error: r.error.code }, { status: r.error.code === 'KEY_FETCH_FAILED' ? 503 : 401 });
  }
  // r.validations.age === true → kişi SİZİN sorduğunuz koşulu sağlıyor
  return NextResponse.json({ ok: true, age: r.validations.age });
}
```

## Nonce kuralı

Generate vekilinizde (`POST /api/pop/generate`) dönen `nonce`'u, **sorduğunuz validations ile birlikte**
saklayın (TTL **960 sn**):

```js
const VALIDATIONS = { age: '18+', user_id: true };        // tarayıcının gönderdiği DEĞİL, sunucunuzun ayarı
// ... VerifyBlind'dan { nonce } döndükten sonra:
await redis.set(`vb:nonce:${nonce}`, JSON.stringify(VALIDATIONS), 'EX', 960);
```

`verifyAndConsume`'a verdiğiniz fonksiyon nonce'u **al-ve-sil** şeklinde tüketmelidir (Redis `GETDEL`,
veritabanında `DELETE ... RETURNING`). Bilinmeyen, süresi dolmuş ya da kullanılmış nonce için `null`
döndürün; sonuç `NONCE_NOT_FOUND` olur. Aynı token ikinci kez gelirse reddedilir.

Kütüphane, imza geçersizse nonce deposuna hiç dokunmaz.

## Sorulan doğrulamalar kuralı

Sonucu **tarayıcının söylediğine göre değil, sizin sakladığınıza göre** okuyun. `checkAsked` (ve
`verifyAndConsume`) şunları denetler:

| Siz sordunuz | İmzalı sonuçta olması gereken |
|---|---|
| `age: '18+'` | `validations.age` boolean **ve** `validations.age_condition === '18+'` (yoksa ya da farklıysa red) |
| `age` sormadınız | `validations.age` **olmamalı** |
| `user_id: true` | `validations.user_id` dolu olmalı |

Neden: tarayıcı isteği DevTools'ta değiştirilebilir. Ziyaretçi `"18+"`'yı `"1+"` yapar ve gerçekten imzalı bir
`age: true` alır, ama `age_condition: "1+"` olarak imzalanır. Bu satır o sonucu yakalar.

`validations.age === false` geçerli bir cevaptır (kişi koşulu sağlamıyor); `ok: true` döner, kararı siz verirsiniz.

## Kimlik kodlarını asla loglamayın

`user_id`, `nsbd_id`, `doc_id` takma adlı kişisel veridir. Veritabanına kullanıcı verisi gibi kaydedin;
`console.log`, istek logları, hata izleme (Sentry vb.) ya da analitiğe **yazmayın**. Bu kütüphane hiçbir şey
loglamaz ve hata mesajlarına bu kodları koymaz. `r` nesnesinin tamamını loglamayın.

Demo kartı sonuçları `validations.is_test: true` taşır (`r.isTest`) ve kodları `TEST_` ile başlar;
üretim kararlarından ayrı tutun.

## API

| Fonksiyon | Açıklama |
|---|---|
| `createVerifier(options?)` | Verifier oluşturur. Seçenekler: `apiBaseUrl` (varsayılan `https://api.verifyblind.com`), `keyCacheMs` (60 000), `webhookKeyCacheMs` (3 600 000), `webhookToleranceSec` (300), `fetch`, `now` |
| `verifier.verifyAndConsume(token, consumeNonce)` | İmza → nonce tüketme → sorulan koşul. `{ ok: true, nonce, validations, asked, isTest, payload }` ya da `{ ok: false, error }`. Doğrulama hatasında fırlatmaz |
| `verifier.verifyToken(token)` | Yalnız imza. `VerifiedResult` döner ya da `VerifyBlindError` fırlatır. Nonce'u siz tüketmelisiniz |
| `verifier.verifySigned({ payload, signature })` | `verifyToken`'ın çözülmüş hâli |
| `verifier.consumeAndCheck(verified, consumeNonce)` | İmzası doğrulanmış sonuç için nonce + koşul |
| `checkAsked(asked, validations)` | Red nedeni (string) ya da `null` |
| `verifier.verifyWebhook({ rawBody, signature, timestamp })` | `X-Webhook-Signature` / `X-Webhook-Timestamp` doğrular (±300 sn), JSON gövdeyi döner |
| `verifier.verifyRevoke(...)` | Revoke webhook'u (aynı imza). Yalnız `nonce`'a göre işlem yapın |
| `verifier.verifyCallback(input, privateKey)` | Desen B: webhook + `encrypted_response` çözme + enclave imzası. `status: 'completed' \| 'cancelled'` |
| `decryptCallbackResponse(encrypted, privateKey)` | Yalnız çözme (RSA-OAEP-SHA256 + AES-256-GCM) |
| `verifier.verifyPcr0Signature(pcr0Hex, sigB64)` | İsteğe bağlı enclave kontrolü (PKCS#1 v1.5). Sonra PCR0'ı Enclave reposunun `expected_pcr.json` dosyasıyla kendiniz karşılaştırın |

### Hata kodları (`VerifyBlindError.code`)

| Kod | Anlamı | Önerilen HTTP |
|---|---|---|
| `BAD_TOKEN` | Token, `{ payload, signature }` JSON'unun base64'ü değil | 400 |
| `BAD_SIGNATURE` | Enclave imzası tutmuyor (anahtar bir kez tazelendikten sonra da) | 401 |
| `KEY_FETCH_FAILED` | VerifyBlind açık anahtarı alınamadı (geçici) | 503 |
| `BAD_PAYLOAD` | İmza geçerli ama gövde beklenen biçimde değil | 400 |
| `NONCE_NOT_FOUND` | Nonce bilinmiyor, süresi dolmuş ya da kullanılmış | 401 |
| `ASKED_MISMATCH` | Sonuç sizin sorduğunuzla eşleşmiyor | 401 |
| `BAD_WEBHOOK_TIMESTAMP` / `BAD_WEBHOOK_SIGNATURE` | Webhook reddedildi | 401 |
| `DECRYPT_FAILED` | `encrypted_response` çözülemedi | 400 |

## Revoke webhook'u (Express)

Ham gövdeye ihtiyaç var, `express.json()` **kullanmayın**:

```js
app.post('/api/verifyblind/revoke', express.raw({ type: '*/*' }), async (req, res) => {
  try {
    const body = await verifier.verifyRevoke({
      rawBody: req.body,
      signature: req.get('X-Webhook-Signature'),
      timestamp: req.get('X-Webhook-Timestamp'),
    });
    await deleteVerificationByNonce(body.nonce); // bu nonce'a bağlı veriyi silin ya da işaretleyin
    res.sendStatus(200);
  } catch {
    res.sendStatus(401);
  }
});
```

## Desen B (callback)

```js
app.post('/api/callback', express.raw({ type: '*/*' }), async (req, res) => {
  try {
    const r = await verifier.verifyCallback(
      { rawBody: req.body, signature: req.get('X-Webhook-Signature'), timestamp: req.get('X-Webhook-Timestamp') },
      process.env.CALLBACK_PRIVATE_KEY, // PEM, git'e girmez
    );
    if (r.status === 'cancelled') await saveStatus(r.nonce, { status: 'cancelled', reason: r.reason });
    else {
      const checked = await verifier.consumeAndCheck(r, (nonce) => redis.getdel(`vb:nonce:${nonce}`));
      if (checked.ok) await saveStatus(r.nonce, { status: 'completed', validations: checked.validations });
    }
  } catch { /* imza/çözme hatası: sonucu saklamayın */ }
  res.sendStatus(200);
});
```

## Güvenlik Notları

- API anahtarı (`VERIFYBLIND_API_KEY`) yalnız sunucuda durur. Bu kütüphane API anahtarı istemez; yalnız açık
  uç noktalardan açık anahtarları okur.
- Sorulacak `validations`'ı generate vekilinizde sunucu ayarından koyun; tarayıcının gönderdiğini yok sayın.
- Kurallar ve tüm akış: https://verifyblind.com/ai-integration.md · https://verifyblind.com/tr/developers

## Sürüm Geçmişi

| Sürüm | Açıklama |
|---------|-------------|
| 0.1.0 | İlk sürüm (yayımlanmadı): token doğrulama, nonce + sorulan koşul, webhook, callback çözme, PCR0 |

---

## English

The official Node.js library for verifying a VerifyBlind result **on your own server** in a few lines.
Node.js 18+, TypeScript types included, zero runtime dependencies (`node:crypto` and the built-in `fetch`).
Works with ESM and CommonJS, in Express, Next.js, Fastify and the like.

### What it does

```
[Web widget / mobile SDK]  ── onSuccess → token ──►  [Your server]
                                                        │  verifier.verifyAndConsume(token, consumeNonce)
                                                        │   1. Enclave signature (RSA-PSS SHA-256, salt 32)
                                                        │   2. Consumes the nonce exactly once (replay protection)
                                                        │   3. Reads the result against what YOU asked
                                                        ▼
                                                  { ok: true, validations: { age, user_id, ... } }
```

- Fetches the enclave key from `GET /api/public/enclave-key`, caches it for 60 s, and on a failed signature
  refreshes it **once** and retries (the key rotates when the enclave restarts).
- Verifies webhook signatures (callback and revoke) and decrypts the callback `encrypted_response` (pattern B).
- Optional: verifies the PCR0 authorization signature.
- Logs nothing. Error messages never contain `user_id`, `nsbd_id` or `doc_id`.

### Installation

```bash
npm install @verifyblind/server
```

### Quick Start: Express

```js
import express from 'express';
import Redis from 'ioredis';
import { createVerifier } from '@verifyblind/server';

const app = express();
const redis = new Redis(process.env.REDIS_URL);
const verifier = createVerifier();

app.post('/api/verifyblind/verify', express.json(), async (req, res) => {
  const r = await verifier.verifyAndConsume(req.body?.token, (nonce) => redis.getdel(`vb:nonce:${nonce}`));
  if (!r.ok) return res.status(r.error.code === 'KEY_FETCH_FAILED' ? 503 : 401).json({ error: r.error.code });
  if (r.isTest && process.env.NODE_ENV === 'production') return res.status(403).json({ error: 'TEST_RESULT' });
  await saveVerification(req.user.id, r.validations); // user_id / nsbd_id / doc_id → database, NOT logs
  res.json({ ok: true, age: r.validations.age });
});
```

### Quick Start: Next.js (App Router)

```ts
// app/api/verifyblind/verify/route.ts
import { NextResponse } from 'next/server';
import { createVerifier } from '@verifyblind/server';
import { redis } from '@/lib/redis';

export const runtime = 'nodejs'; // needs node:crypto; the Edge runtime is not supported
const verifier = createVerifier();

export async function POST(req: Request) {
  const { token } = await req.json();
  const r = await verifier.verifyAndConsume(token, (nonce) => redis.getdel(`vb:nonce:${nonce}`));
  if (!r.ok) {
    return NextResponse.json({ error: r.error.code }, { status: r.error.code === 'KEY_FETCH_FAILED' ? 503 : 401 });
  }
  // r.validations.age === true → the person meets the condition YOU asked
  return NextResponse.json({ ok: true, age: r.validations.age });
}
```

### The nonce rule

In your generate proxy (`POST /api/pop/generate`), store the returned `nonce` **together with the validations
you asked** (TTL **960 s**):

```js
const VALIDATIONS = { age: '18+', user_id: true };        // your server's setting, NOT what the browser sent
// ... after VerifyBlind returns { nonce }:
await redis.set(`vb:nonce:${nonce}`, JSON.stringify(VALIDATIONS), 'EX', 960);
```

The function you pass to `verifyAndConsume` must **get-and-delete** the nonce (Redis `GETDEL`, SQL
`DELETE ... RETURNING`). Return `null` for an unknown, expired or used nonce; the result is then
`NONCE_NOT_FOUND`. The same token presented twice is rejected.

The library does not touch your nonce store when the signature is invalid.

### The asked-validations rule

Read the result against **what you stored, not what the browser says**. `checkAsked` (and `verifyAndConsume`)
enforce:

| You asked | The signed result must have |
|---|---|
| `age: '18+'` | `validations.age` boolean **and** `validations.age_condition === '18+'` (missing or different → reject) |
| no `age` | **no** `validations.age` |
| `user_id: true` | a non-empty `validations.user_id` |

Why: the browser request can be edited in DevTools. A visitor changes `"18+"` to `"1+"` and receives a genuinely
signed `age: true`, but it is signed with `age_condition: "1+"`. This rule catches it.

`validations.age === false` is a valid answer (the person does not meet the condition): you get `ok: true` and
make the decision yourself.

### Never log identity codes

`user_id`, `nsbd_id` and `doc_id` are pseudonymous personal data. Store them like other user data; **never**
write them to `console.log`, request logs, error tracking (Sentry etc.) or analytics. This library logs nothing
and keeps them out of error messages. Do not log the whole `r` object.

Demo-card results carry `validations.is_test: true` (`r.isTest`) and codes prefixed `TEST_`; keep them out of
production decisions.

### API

| Function | Description |
|---|---|
| `createVerifier(options?)` | Creates a verifier. Options: `apiBaseUrl` (default `https://api.verifyblind.com`), `keyCacheMs` (60 000), `webhookKeyCacheMs` (3 600 000), `webhookToleranceSec` (300), `fetch`, `now` |
| `verifier.verifyAndConsume(token, consumeNonce)` | Signature → nonce consume → asked check. `{ ok: true, nonce, validations, asked, isTest, payload }` or `{ ok: false, error }`. Does not throw for verification failures |
| `verifier.verifyToken(token)` | Signature only. Returns `VerifiedResult` or throws `VerifyBlindError`. You must consume the nonce |
| `verifier.verifySigned({ payload, signature })` | `verifyToken` for an already-decoded token |
| `verifier.consumeAndCheck(verified, consumeNonce)` | Nonce + asked check for a result whose signature is already verified |
| `checkAsked(asked, validations)` | A rejection reason (string) or `null` |
| `verifier.verifyWebhook({ rawBody, signature, timestamp })` | Verifies `X-Webhook-Signature` / `X-Webhook-Timestamp` (±300 s), returns the JSON body |
| `verifier.verifyRevoke(...)` | Revoke webhook (same signature). Act on `nonce` only |
| `verifier.verifyCallback(input, privateKey)` | Pattern B: webhook + `encrypted_response` decrypt + enclave signature. `status: 'completed' \| 'cancelled'` |
| `decryptCallbackResponse(encrypted, privateKey)` | Decrypt only (RSA-OAEP-SHA256 + AES-256-GCM) |
| `verifier.verifyPcr0Signature(pcr0Hex, sigB64)` | Optional enclave check (PKCS#1 v1.5). Then compare the PCR0 with `expected_pcr.json` from the Enclave repo yourself |

#### Error codes (`VerifyBlindError.code`)

| Code | Meaning | Suggested HTTP |
|---|---|---|
| `BAD_TOKEN` | The token is not base64 of JSON `{ payload, signature }` | 400 |
| `BAD_SIGNATURE` | The enclave signature does not verify (also after one key refresh) | 401 |
| `KEY_FETCH_FAILED` | A VerifyBlind public key could not be fetched (temporary) | 503 |
| `BAD_PAYLOAD` | Valid signature, but the body is not in the expected shape | 400 |
| `NONCE_NOT_FOUND` | Nonce unknown, expired or already used | 401 |
| `ASKED_MISMATCH` | The result does not match what you asked | 401 |
| `BAD_WEBHOOK_TIMESTAMP` / `BAD_WEBHOOK_SIGNATURE` | Webhook rejected | 401 |
| `DECRYPT_FAILED` | `encrypted_response` could not be decrypted | 400 |

### Revoke webhook (Express)

You need the raw body; do **not** use `express.json()` on this route:

```js
app.post('/api/verifyblind/revoke', express.raw({ type: '*/*' }), async (req, res) => {
  try {
    const body = await verifier.verifyRevoke({
      rawBody: req.body,
      signature: req.get('X-Webhook-Signature'),
      timestamp: req.get('X-Webhook-Timestamp'),
    });
    await deleteVerificationByNonce(body.nonce); // delete or mark the data tied to this nonce
    res.sendStatus(200);
  } catch {
    res.sendStatus(401);
  }
});
```

### Pattern B (callback)

```js
app.post('/api/callback', express.raw({ type: '*/*' }), async (req, res) => {
  try {
    const r = await verifier.verifyCallback(
      { rawBody: req.body, signature: req.get('X-Webhook-Signature'), timestamp: req.get('X-Webhook-Timestamp') },
      process.env.CALLBACK_PRIVATE_KEY, // PEM, never in git
    );
    if (r.status === 'cancelled') await saveStatus(r.nonce, { status: 'cancelled', reason: r.reason });
    else {
      const checked = await verifier.consumeAndCheck(r, (nonce) => redis.getdel(`vb:nonce:${nonce}`));
      if (checked.ok) await saveStatus(r.nonce, { status: 'completed', validations: checked.validations });
    }
  } catch { /* signature/decrypt error: do not store a result */ }
  res.sendStatus(200);
});
```

### Security Notes

- The API key (`VERIFYBLIND_API_KEY`) stays on the server. This library does not need the API key; it only
  reads public keys from public endpoints.
- Set the `validations` to ask in your generate proxy from server configuration; ignore what the browser sent.
- Rules and the full flow: https://verifyblind.com/ai-integration.md · https://verifyblind.com/en/developers

### Version History

| Version | Description |
|---------|-------------|
| 0.1.0 | First version (unpublished): token verify, nonce + asked check, webhook, callback decrypt, PCR0 |

---

## Lisans · License

Apache License 2.0 — bkz. / see [LICENSE](LICENSE).
