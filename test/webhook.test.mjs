import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { createRequire } from 'node:module';
import { createVerifier, decryptCallbackResponse, VerifyBlindError } from '../dist/index.js';
import { rsaKeyPair, spkiBase64, pemJson, pssSign, fakeFetch, encryptForCallback } from './helpers.mjs';

const WEBHOOK_PATH = '/api/public/webhook-signing-key';
const enclave = rsaKeyPair();
const webhookA = rsaKeyPair();
const webhookB = rsaKeyPair();
const developer = rsaKeyPair();
const partner = rsaKeyPair(); // the partner's fixed callback key pair (pattern B)

const NOW_MS = 1_800_000_000_000;
const nowSec = String(NOW_MS / 1000);

function setup({ webhookKeys = [webhookA.publicKey] } = {}) {
  let i = 0;
  const fetch = fakeFetch({
    '/api/public/enclave-key': () => ({ body: spkiBase64(enclave.publicKey) }),
    [WEBHOOK_PATH]: () => ({ body: pemJson(webhookKeys[Math.min(i++, webhookKeys.length - 1)]) }),
    '/api/public/developer-key': () => ({ body: pemJson(developer.publicKey) }),
  });
  return { verifier: createVerifier({ fetch, now: () => NOW_MS }), fetch };
}

function signedWebhook(bodyObj, { key = webhookA.privateKey, ts = nowSec } = {}) {
  const rawBody = JSON.stringify(bodyObj);
  return { rawBody, timestamp: ts, signature: pssSign(key, `${ts}.${rawBody}`) };
}

async function rejectsWith(promise, code) {
  await assert.rejects(promise, (e) => {
    assert.ok(e instanceof VerifyBlindError, `expected VerifyBlindError, got ${e}`);
    assert.equal(e.code, code);
    return true;
  });
}

describe('verifyWebhook / verifyRevoke', () => {
  test('valid revoke webhook returns the body', async () => {
    const { verifier } = setup();
    const body = await verifier.verifyRevoke(signedWebhook({ nonce: 'n-9', event_type: 'CONSENT_WITHDRAWN' }));
    assert.equal(body.nonce, 'n-9');
    assert.equal(body.event_type, 'CONSENT_WITHDRAWN');
  });

  test('raw body as bytes works the same', async () => {
    const { verifier } = setup();
    const w = signedWebhook({ nonce: 'n-9' });
    const body = await verifier.verifyWebhook({ ...w, rawBody: Buffer.from(w.rawBody) });
    assert.equal(body.nonce, 'n-9');
  });

  test('tampered body is BAD_WEBHOOK_SIGNATURE', async () => {
    const { verifier } = setup();
    const w = signedWebhook({ nonce: 'n-9' });
    await rejectsWith(verifier.verifyWebhook({ ...w, rawBody: w.rawBody.replace('n-9', 'n-8') }), 'BAD_WEBHOOK_SIGNATURE');
  });

  test('signature over a different timestamp is rejected', async () => {
    const { verifier } = setup();
    const w = signedWebhook({ nonce: 'n-9' });
    await rejectsWith(verifier.verifyWebhook({ ...w, timestamp: String(Number(nowSec) - 1) }), 'BAD_WEBHOOK_SIGNATURE');
  });

  test('timestamp outside ±300 s, missing or non-numeric is BAD_WEBHOOK_TIMESTAMP', async () => {
    const { verifier } = setup();
    for (const ts of [String(Number(nowSec) - 301), String(Number(nowSec) + 301), '', '17e8', '-5']) {
      await rejectsWith(verifier.verifyWebhook(signedWebhook({ nonce: 'n' }, { ts })), 'BAD_WEBHOOK_TIMESTAMP');
    }
    for (const ts of [undefined, null]) {
      await rejectsWith(verifier.verifyWebhook({ ...signedWebhook({ nonce: 'n' }), timestamp: ts }), 'BAD_WEBHOOK_TIMESTAMP');
    }
    // edge of the window is accepted
    await verifier.verifyWebhook(signedWebhook({ nonce: 'n' }, { ts: String(Number(nowSec) - 300) }));
  });

  test('missing signature is BAD_WEBHOOK_SIGNATURE', async () => {
    const { verifier } = setup();
    await rejectsWith(verifier.verifyWebhook({ ...signedWebhook({ nonce: 'n' }), signature: null }), 'BAD_WEBHOOK_SIGNATURE');
  });

  test('webhook key rotation refreshes once', async () => {
    const { verifier, fetch } = setup({ webhookKeys: [webhookA.publicKey, webhookB.publicKey] });
    await verifier.verifyWebhook(signedWebhook({ nonce: 'a' }));
    await verifier.verifyWebhook(signedWebhook({ nonce: 'b' }, { key: webhookB.privateKey }));
    assert.equal(fetch.count(WEBHOOK_PATH), 2);
  });

  test('body without nonce is BAD_PAYLOAD', async () => {
    const { verifier } = setup();
    await rejectsWith(verifier.verifyWebhook(signedWebhook({ event_type: 'X' })), 'BAD_PAYLOAD');
  });
});

describe('verifyCallback (pattern B)', () => {
  const partnerPem = partner.privateKey.export({ format: 'pem', type: 'pkcs8' });

  function completedBody(nonce, signedNonce = nonce) {
    const payload = JSON.stringify({ nonce: signedNonce, validations: { age: true, age_condition: '18+' } });
    const signature = pssSign(enclave.privateKey, payload);
    return { nonce, encrypted_response: encryptForCallback(partner.publicKey, { payload, signature }) };
  }

  test('completed callback decrypts and verifies the enclave signature', async () => {
    const { verifier } = setup();
    const r = await verifier.verifyCallback(signedWebhook(completedBody('n-5')), partnerPem);
    assert.equal(r.status, 'completed');
    assert.equal(r.nonce, 'n-5');
    assert.equal(r.validations.age_condition, '18+');
    const checked = await verifier.consumeAndCheck(r, async () => ({ age: '18+' }));
    assert.equal(checked.ok, true);
  });

  test('cancelled callback returns the reason', async () => {
    const { verifier } = setup();
    const r = await verifier.verifyCallback(signedWebhook({ nonce: 'n-6', status: 'cancelled', reason: 'user_declined' }), partnerPem);
    assert.deepEqual([r.status, r.nonce, r.reason], ['cancelled', 'n-6', 'user_declined']);
  });

  test('signed nonce different from webhook nonce is BAD_PAYLOAD', async () => {
    const { verifier } = setup();
    await rejectsWith(verifier.verifyCallback(signedWebhook(completedBody('n-7', 'other')), partnerPem), 'BAD_PAYLOAD');
  });

  test('wrong private key is DECRYPT_FAILED', async () => {
    const { verifier } = setup();
    const other = rsaKeyPair().privateKey;
    await rejectsWith(verifier.verifyCallback(signedWebhook(completedBody('n-8')), other), 'DECRYPT_FAILED');
  });

  test('decryptCallbackResponse rejects a tampered blob', () => {
    const enc = encryptForCallback(partner.publicKey, { payload: 'p', signature: 's' });
    assert.deepEqual(decryptCallbackResponse(enc, partner.privateKey), { payload: 'p', signature: 's' });
    const blob = Buffer.from(enc.blob, 'base64');
    blob[14] ^= 1;
    assert.throws(() => decryptCallbackResponse({ ...enc, blob: blob.toString('base64') }, partner.privateKey), (e) => e.code === 'DECRYPT_FAILED');
  });
});

describe('verifyPcr0Signature', () => {
  const pcr0 = 'ab'.repeat(48);
  test('PKCS#1 v1.5 signature verifies; PSS signature does not', async () => {
    const { verifier } = setup();
    const pkcs1 = crypto.sign('sha256', Buffer.from(pcr0), { key: developer.privateKey, padding: crypto.constants.RSA_PKCS1_PADDING }).toString('base64');
    assert.equal(await verifier.verifyPcr0Signature(pcr0, pkcs1), true);
    assert.equal(await verifier.verifyPcr0Signature(pcr0, pssSign(developer.privateKey, pcr0)), false);
    assert.equal(await verifier.verifyPcr0Signature('cd'.repeat(48), pkcs1), false);
  });
});

describe('packaging', () => {
  test('CommonJS build exposes the same API', () => {
    const require = createRequire(import.meta.url);
    const cjs = require('../dist/index.cjs');
    for (const name of ['createVerifier', 'checkAsked', 'decryptCallbackResponse', 'VerifyBlindError', 'isVerifyBlindError']) {
      assert.equal(typeof cjs[name], 'function', name);
    }
  });
});
