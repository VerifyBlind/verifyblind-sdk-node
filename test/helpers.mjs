import crypto from 'node:crypto';

export function rsaKeyPair() {
  return crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
}

/** base64 SPKI text, as `GET /api/public/enclave-key` returns it. */
export function spkiBase64(publicKey) {
  return publicKey.export({ format: 'der', type: 'spki' }).toString('base64');
}

export function pemJson(publicKey) {
  return JSON.stringify({ algorithm: 'x', public_key: publicKey.export({ format: 'pem', type: 'spki' }) });
}

export function pssSign(privateKey, data, saltLength = 32) {
  return crypto
    .sign('sha256', Buffer.from(data), { key: privateKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength })
    .toString('base64');
}

/** Builds a token exactly like the widget / SDK: base64(JSON { payload, signature }). */
export function makeToken(privateKey, payloadObj, { saltLength = 32 } = {}) {
  const payload = typeof payloadObj === 'string' ? payloadObj : JSON.stringify(payloadObj);
  const signature = pssSign(privateKey, payload, saltLength);
  return Buffer.from(JSON.stringify({ payload, signature })).toString('base64');
}

/** Fake fetch: `routes[path]` is a function returning { status, body } (may change between calls). */
export function fakeFetch(routes) {
  const calls = [];
  const fn = async (url, init) => {
    const path = new URL(url).pathname;
    calls.push({ path, init });
    const route = routes[path];
    if (!route) return { ok: false, status: 404, text: async () => 'not found' };
    const { status = 200, body = '' } = await route();
    return { ok: status >= 200 && status < 300, status, text: async () => body };
  };
  fn.calls = calls;
  fn.count = (path) => calls.filter((c) => c.path === path).length;
  return fn;
}

/** Encrypts like the enclave for pattern B: AES-256-GCM blob + OAEP-SHA256-wrapped base64 AES key. */
export function encryptForCallback(partnerPublicKey, innerObj) {
  const aesKey = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, iv);
  const ct = Buffer.concat([cipher.update(JSON.stringify(innerObj), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  const encKey = crypto.publicEncrypt(
    { key: partnerPublicKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
    Buffer.from(aesKey.toString('base64'), 'utf8'),
  );
  return { enc_key: encKey.toString('base64'), blob: Buffer.concat([iv, ct, tag]).toString('base64') };
}

/** A Map-backed get-and-delete nonce store. */
export function memoryStore(entries = {}) {
  const map = new Map(Object.entries(entries));
  const consume = async (nonce) => {
    consume.calls.push(nonce);
    const v = map.get(nonce);
    map.delete(nonce);
    return v ?? null;
  };
  consume.calls = [];
  return consume;
}
