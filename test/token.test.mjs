import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { createVerifier, VerifyBlindError, checkAsked } from '../dist/index.js';
import { rsaKeyPair, spkiBase64, makeToken, fakeFetch, memoryStore } from './helpers.mjs';

const KEY_PATH = '/api/public/enclave-key';
const enclaveA = rsaKeyPair();
const enclaveB = rsaKeyPair();

const SECRET_UID = 'UID_SECRET_7f3a';
const goodPayload = {
  nonce: 'n-1',
  validations: { age: true, age_condition: '18+', user_id: SECRET_UID, nsbd_id: 'NSBD_SECRET', doc_id: 'DOC_SECRET' },
};

function setup({ keys = [enclaveA.publicKey], status = 200, now, allowTestCards } = {}) {
  let i = 0;
  const fetch = fakeFetch({
    [KEY_PATH]: () => {
      const k = keys[Math.min(i, keys.length - 1)];
      i++;
      return { status, body: typeof k === 'string' ? k : spkiBase64(k) };
    },
  });
  const verifier = createVerifier({ fetch, now, allowTestCards });
  return { verifier, fetch };
}

async function rejectsWith(promise, code) {
  await assert.rejects(promise, (e) => {
    assert.ok(e instanceof VerifyBlindError, `expected VerifyBlindError, got ${e}`);
    assert.equal(e.code, code);
    return true;
  });
}

describe('verifyToken', () => {
  test('valid token verifies and returns the parsed payload', async () => {
    const { verifier, fetch } = setup();
    const r = await verifier.verifyToken(makeToken(enclaveA.privateKey, goodPayload));
    assert.equal(r.nonce, 'n-1');
    assert.equal(r.validations.age, true);
    assert.equal(r.validations.user_id, SECRET_UID);
    assert.equal(r.isTest, false);
    assert.equal(r.rawPayload, JSON.stringify(goodPayload));
    assert.equal(fetch.count(KEY_PATH), 1);
    assert.equal(fetch.calls[0].init.cache, 'no-store');
  });

  test('uses https://api.verifyblind.com by default and honours apiBaseUrl', async () => {
    const urls = [];
    const f = async (url) => {
      urls.push(url);
      return { ok: true, status: 200, text: async () => spkiBase64(enclaveA.publicKey) };
    };
    await createVerifier({ fetch: f }).verifyToken(makeToken(enclaveA.privateKey, goodPayload));
    await createVerifier({ fetch: f, apiBaseUrl: 'https://example.test/' }).verifyToken(
      makeToken(enclaveA.privateKey, goodPayload),
    );
    assert.deepEqual(urls, ['https://api.verifyblind.com/api/public/enclave-key', 'https://example.test/api/public/enclave-key']);
  });

  test('is_test marks demo-card results', async () => {
    const { verifier } = setup();
    const r = await verifier.verifyToken(
      makeToken(enclaveA.privateKey, { nonce: 'n', validations: { user_id: 'TEST_x', is_test: true } }),
    );
    assert.equal(r.isTest, true);
  });

  test('tampered payload is rejected with BAD_SIGNATURE', async () => {
    const { verifier } = setup();
    const token = makeToken(enclaveA.privateKey, goodPayload);
    const decoded = JSON.parse(Buffer.from(token, 'base64').toString());
    decoded.payload = decoded.payload.replace('"18+"', '"1+"');
    await rejectsWith(verifier.verifyToken(Buffer.from(JSON.stringify(decoded)).toString('base64')), 'BAD_SIGNATURE');
  });

  test('signature with a different salt length (20) is rejected', async () => {
    const { verifier } = setup();
    await rejectsWith(verifier.verifyToken(makeToken(enclaveA.privateKey, goodPayload, { saltLength: 20 })), 'BAD_SIGNATURE');
  });

  test('signature from another key is rejected', async () => {
    const { verifier } = setup();
    await rejectsWith(verifier.verifyToken(makeToken(enclaveB.privateKey, goodPayload)), 'BAD_SIGNATURE');
  });

  test('malformed tokens are rejected with BAD_TOKEN', async () => {
    const { verifier, fetch } = setup();
    for (const t of ['', '   ', 'not-base64-json', Buffer.from('{"payload":1}').toString('base64'), 42, null]) {
      await rejectsWith(verifier.verifyToken(t), 'BAD_TOKEN');
    }
    assert.equal(fetch.count(KEY_PATH), 0, 'no key fetch for malformed tokens');
  });

  test('valid signature over a payload without nonce is BAD_PAYLOAD', async () => {
    const { verifier } = setup();
    await rejectsWith(verifier.verifyToken(makeToken(enclaveA.privateKey, { validations: {} })), 'BAD_PAYLOAD');
    await rejectsWith(verifier.verifyToken(makeToken(enclaveA.privateKey, 'not json')), 'BAD_PAYLOAD');
  });
});

describe('enclave key cache', () => {
  test('key rotation: cached key fails, refreshes once, succeeds', async () => {
    const { verifier, fetch } = setup({ keys: [enclaveA.publicKey, enclaveB.publicKey] });
    await verifier.verifyToken(makeToken(enclaveA.privateKey, goodPayload)); // caches A
    const r = await verifier.verifyToken(makeToken(enclaveB.privateKey, goodPayload)); // enclave restarted → B
    assert.equal(r.nonce, 'n-1');
    assert.equal(fetch.count(KEY_PATH), 2);
  });

  test('refresh happens only once per bad token', async () => {
    const { verifier, fetch } = setup({ keys: [enclaveA.publicKey] });
    await verifier.verifyToken(makeToken(enclaveA.privateKey, goodPayload)); // 1 fetch
    await rejectsWith(verifier.verifyToken(makeToken(enclaveB.privateKey, goodPayload)), 'BAD_SIGNATURE');
    assert.equal(fetch.count(KEY_PATH), 2, 'one refresh, no loop');
  });

  test('a key fetched for this call is not fetched again on failure', async () => {
    const { verifier, fetch } = setup();
    await rejectsWith(verifier.verifyToken(makeToken(enclaveB.privateKey, goodPayload)), 'BAD_SIGNATURE');
    assert.equal(fetch.count(KEY_PATH), 1);
  });

  test('key is cached for 60 s by default', async () => {
    let t = 1_000_000;
    const { verifier, fetch } = setup({ now: () => t });
    const token = makeToken(enclaveA.privateKey, goodPayload);
    await verifier.verifyToken(token);
    t += 59_000;
    await verifier.verifyToken(token);
    assert.equal(fetch.count(KEY_PATH), 1);
    t += 2_000;
    await verifier.verifyToken(token);
    assert.equal(fetch.count(KEY_PATH), 2);
  });

  test('concurrent first calls share one key request', async () => {
    const { verifier, fetch } = setup();
    const token = makeToken(enclaveA.privateKey, goodPayload);
    await Promise.all([verifier.verifyToken(token), verifier.verifyToken(token), verifier.verifyToken(token)]);
    assert.equal(fetch.count(KEY_PATH), 1);
  });

  test('HTTP error and unusable key are KEY_FETCH_FAILED', async () => {
    await rejectsWith(setup({ status: 503 }).verifier.verifyToken(makeToken(enclaveA.privateKey, goodPayload)), 'KEY_FETCH_FAILED');
    await rejectsWith(setup({ keys: ['%%%not a key%%%'] }).verifier.verifyToken(makeToken(enclaveA.privateKey, goodPayload)), 'KEY_FETCH_FAILED');
    await rejectsWith(setup({ keys: ['QUJD'] }).verifier.verifyToken(makeToken(enclaveA.privateKey, goodPayload)), 'KEY_FETCH_FAILED');
    const throwing = createVerifier({ fetch: async () => { throw new Error('ECONNREFUSED'); } });
    await rejectsWith(throwing.verifyToken(makeToken(enclaveA.privateKey, goodPayload)), 'KEY_FETCH_FAILED');
  });
});

describe('checkAsked', () => {
  const cases = [
    ['age asked, matching condition', { age: '18+' }, { age: true, age_condition: '18+' }, true],
    ['age asked, answer false is still a valid answer', { age: '18+' }, { age: false, age_condition: '18+' }, true],
    ['age asked, age_condition missing', { age: '18+' }, { age: true }, false],
    ['age asked, age_condition mismatched (1+ attack)', { age: '18+' }, { age: true, age_condition: '1+' }, false],
    ['age asked, age missing', { age: '18+' }, { age_condition: '18+' }, false],
    ['age asked, age not boolean', { age: '18+' }, { age: 'true', age_condition: '18+' }, false],
    ['age not asked but age present', { user_id: true }, { age: true, age_condition: '1+', user_id: 'u' }, false],
    ['age not asked, age absent', { user_id: true }, { user_id: 'u' }, true],
    ['age not asked but age_condition present', { user_id: true }, { age_condition: '18+', user_id: 'u' }, false],
    ['user_id asked but missing', { user_id: true }, {}, false],
    ['user_id asked but empty', { user_id: true }, { user_id: '' }, false],
    ['both asked, both present', { age: '18+', user_id: true }, { age: true, age_condition: '18+', user_id: 'u' }, true],
    ['nothing asked, nothing answered', {}, {}, true],
    ['nothing asked, validations undefined', {}, undefined, true],
    ['age asked, validations undefined', { age: '18+' }, undefined, false],
  ];
  for (const [name, asked, validations, pass] of cases) {
    test(name, () => {
      const r = checkAsked(asked, validations);
      if (pass) assert.equal(r, null);
      else assert.equal(typeof r, 'string');
      assert.equal(createVerifier({ fetch: async () => { throw new Error('unused'); } }).checkAsked(asked, validations), r);
    });
  }
});

describe('demo cards', () => {
  const demo = { nonce: 'n-1', validations: { age: true, age_condition: '18+', user_id: 'TEST_abc', is_test: true } };
  const prefixOnly = { nonce: 'n-1', validations: { age: true, age_condition: '18+', nsbd_id: 'TEST_def' } };

  test('rejected by default with TEST_CARD (is_test flag)', async () => {
    const { verifier } = setup();
    const r = await verifier.verifyAndConsume(makeToken(enclaveA.privateKey, demo), memoryStore({ 'n-1': { age: '18+', user_id: true } }));
    assert.equal(r.ok, false);
    assert.equal(r.error.code, 'TEST_CARD');
  });

  test('rejected by default with TEST_CARD (TEST_ prefix only)', async () => {
    const { verifier } = setup();
    const r = await verifier.verifyAndConsume(makeToken(enclaveA.privateKey, prefixOnly), memoryStore({ 'n-1': { age: '18+' } }));
    assert.equal(r.error?.code, 'TEST_CARD');
  });

  test('accepted with allowTestCards', async () => {
    const { verifier } = setup({ allowTestCards: true });
    const r = await verifier.verifyAndConsume(makeToken(enclaveA.privateKey, demo), memoryStore({ 'n-1': { age: '18+', user_id: true } }));
    assert.equal(r.ok, true);
    assert.equal(r.isTest, true);
  });
});

describe('verifyAndConsume', () => {
  test('happy path returns ok with validations and asked', async () => {
    const { verifier } = setup();
    const consume = memoryStore({ 'n-1': { age: '18+', user_id: true } });
    const r = await verifier.verifyAndConsume(makeToken(enclaveA.privateKey, goodPayload), consume);
    assert.equal(r.ok, true);
    assert.deepEqual(r.asked, { age: '18+', user_id: true });
    assert.equal(r.validations.user_id, SECRET_UID);
    assert.deepEqual(consume.calls, ['n-1']);
  });

  test('accepts the asked validations as the stored JSON string', async () => {
    const { verifier } = setup();
    const consume = memoryStore({ 'n-1': JSON.stringify({ age: '18+', user_id: true }) });
    const r = await verifier.verifyAndConsume(makeToken(enclaveA.privateKey, goodPayload), consume);
    assert.equal(r.ok, true);
  });

  test('replay: second use of the same token is NONCE_NOT_FOUND', async () => {
    const { verifier } = setup();
    const consume = memoryStore({ 'n-1': { age: '18+', user_id: true } });
    const token = makeToken(enclaveA.privateKey, goodPayload);
    assert.equal((await verifier.verifyAndConsume(token, consume)).ok, true);
    const second = await verifier.verifyAndConsume(token, consume);
    assert.equal(second.ok, false);
    assert.equal(second.error.code, 'NONCE_NOT_FOUND');
  });

  test('result not matching what was asked is ASKED_MISMATCH', async () => {
    const { verifier } = setup();
    const consume = memoryStore({ 'n-1': { age: '21+' } });
    const r = await verifier.verifyAndConsume(makeToken(enclaveA.privateKey, goodPayload), consume);
    assert.equal(r.ok, false);
    assert.equal(r.error.code, 'ASKED_MISMATCH');
  });

  test('unreadable stored value fails closed', async () => {
    const { verifier } = setup();
    const r = await verifier.verifyAndConsume(makeToken(enclaveA.privateKey, goodPayload), memoryStore({ 'n-1': '{oops' }));
    assert.equal(r.ok, false);
    assert.equal(r.error.code, 'ASKED_MISMATCH');
  });

  test('bad signature never touches the nonce store', async () => {
    const { verifier } = setup();
    const consume = memoryStore({ 'n-1': { age: '18+' } });
    const r = await verifier.verifyAndConsume(makeToken(enclaveB.privateKey, goodPayload), consume);
    assert.equal(r.ok, false);
    assert.equal(r.error.code, 'BAD_SIGNATURE');
    assert.deepEqual(consume.calls, []);
  });

  test('errors from your store propagate (they are yours, not a verification result)', async () => {
    const { verifier } = setup();
    await assert.rejects(
      verifier.verifyAndConsume(makeToken(enclaveA.privateKey, goodPayload), async () => { throw new Error('redis down'); }),
      /redis down/,
    );
  });

  test('no error message contains identity codes', async () => {
    const { verifier } = setup();
    const messages = [];
    const token = makeToken(enclaveA.privateKey, goodPayload);
    for (const stored of [null, { age: '21+' }, { age: '18+', user_id: true, extra: 1 }, '{oops', {}]) {
      const r = await verifier.verifyAndConsume(token, async () => stored);
      if (!r.ok) messages.push(r.error.message, String(r.error.cause ?? ''));
    }
    const bad = await verifier.verifyAndConsume(makeToken(enclaveB.privateKey, goodPayload), async () => null);
    messages.push(bad.error.message);
    const truncated = Buffer.from(token, 'base64').toString().slice(0, 60);
    const badTok = await verifier.verifyAndConsume(Buffer.from(truncated).toString('base64'), async () => null);
    messages.push(badTok.error.message);
    assert.ok(messages.length >= 4);
    for (const m of messages) {
      for (const secret of [SECRET_UID, 'NSBD_SECRET', 'DOC_SECRET']) assert.ok(!m.includes(secret), m);
    }
  });
});
