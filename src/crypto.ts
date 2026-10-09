import {
  constants,
  createDecipheriv,
  createPublicKey,
  privateDecrypt,
  verify,
  type KeyLike,
  type KeyObject,
} from 'node:crypto';
import { VerifyBlindError } from './errors.js';
import type { EncryptedResponse } from './types.js';

/** Enclave result signature and webhook signature: RSA-PSS, SHA-256, MGF1-SHA-256, salt length 32. */
export const PSS_SALT_LENGTH = 32;

/** `GET /api/public/enclave-key` returns base64 SPKI as plain text. */
export function parseSpkiBase64(text: string): KeyObject {
  const b64 = text.trim();
  if (!b64 || !/^[A-Za-z0-9+/=\s]+$/.test(b64)) throw new Error('enclave key is not base64');
  return createPublicKey({ key: Buffer.from(b64, 'base64'), format: 'der', type: 'spki' });
}

/** `GET /api/public/webhook-signing-key` and `/developer-key` return JSON `{ public_key: "<PEM>" }`. */
export function parsePemFromJson(text: string): KeyObject {
  const json = safeJsonParse(text);
  const pem = json && typeof json === 'object' ? (json as { public_key?: unknown }).public_key : undefined;
  if (typeof pem !== 'string' || !pem.includes('BEGIN PUBLIC KEY')) throw new Error('public_key missing');
  return createPublicKey(pem);
}

export function verifyPss(data: Buffer, signatureB64: string, key: KeyObject): boolean {
  try {
    return verify(
      'sha256',
      data,
      { key, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: PSS_SALT_LENGTH },
      Buffer.from(signatureB64, 'base64'),
    );
  } catch {
    return false;
  }
}

/** PCR0 authorization signature: RSA PKCS#1 v1.5 (NOT PSS), SHA-256, over the PCR0 hex string. */
export function verifyPkcs1(data: Buffer, signatureB64: string, key: KeyObject): boolean {
  try {
    return verify('sha256', data, { key, padding: constants.RSA_PKCS1_PADDING }, Buffer.from(signatureB64, 'base64'));
  } catch {
    return false;
  }
}

/**
 * Decrypts a pattern B (callback) `encrypted_response` with your fixed callback private key.
 *
 * - `enc_key`: RSA-OAEP-SHA256. The decrypted bytes are a base64 STRING; base64-decode it again to get
 *   the 32-byte AES key.
 * - `blob`: IV (12 bytes) + ciphertext + tag (16 bytes), AES-256-GCM.
 *
 * Returns the enclave-signed `{ payload, signature }`. The signature is NOT checked here; pass the
 * result to `verifier.verifySigned` (or use `verifier.verifyCallback`, which does both).
 */
export function decryptCallbackResponse(
  encrypted: EncryptedResponse,
  privateKey: KeyLike,
): { payload: string; signature: string } {
  try {
    if (!encrypted || typeof encrypted.enc_key !== 'string' || typeof encrypted.blob !== 'string') {
      throw new Error('encrypted_response must have enc_key and blob strings');
    }
    const aesKeyB64 = privateDecrypt(
      { key: privateKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
      Buffer.from(encrypted.enc_key, 'base64'),
    ).toString('utf8');
    const aesKey = Buffer.from(aesKeyB64, 'base64');
    if (aesKey.length !== 32) throw new Error('unwrapped AES key is not 32 bytes');

    const blob = Buffer.from(encrypted.blob, 'base64');
    if (blob.length < 12 + 16) throw new Error('blob too short');
    const iv = blob.subarray(0, 12);
    const tag = blob.subarray(blob.length - 16);
    const cipherText = blob.subarray(12, blob.length - 16);

    const decipher = createDecipheriv('aes-256-gcm', aesKey, iv);
    decipher.setAuthTag(tag);
    const plain = Buffer.concat([decipher.update(cipherText), decipher.final()]).toString('utf8');

    // safeJsonParse: a JSON.parse error message quotes the input, which may hold identity codes.
    const inner = safeJsonParse(plain);
    const { payload, signature } = (inner ?? {}) as { payload?: unknown; signature?: unknown };
    if (typeof payload !== 'string' || typeof signature !== 'string') {
      throw new Error('decrypted body is not { payload, signature }');
    }
    return { payload, signature };
  } catch (e) {
    const reason = e instanceof Error ? `: ${e.message}` : '';
    throw new VerifyBlindError('DECRYPT_FAILED', `could not decrypt encrypted_response${reason}`);
  }
}

/**
 * JSON.parse that returns `undefined` instead of throwing. Node's JSON.parse error messages quote
 * part of the input; the input here can contain `user_id` / `nsbd_id` / `doc_id`, so the original
 * error must never reach an error message or a log.
 */
export function safeJsonParse(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}
