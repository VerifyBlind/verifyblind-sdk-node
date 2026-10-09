/**
 * Every failure this library reports is a `VerifyBlindError` with a stable `code`.
 * Branch on `code`, not on `message` (messages may change).
 *
 * Messages never contain `user_id`, `nsbd_id` or `doc_id`.
 */
export type VerifyBlindErrorCode =
  /** The token is not base64 of JSON `{ payload, signature }`. */
  | 'BAD_TOKEN'
  /** The enclave signature does not verify (also after one key refresh). */
  | 'BAD_SIGNATURE'
  /** A VerifyBlind public key could not be fetched or parsed. Usually temporary: answer 503. */
  | 'KEY_FETCH_FAILED'
  /** The signature is valid but the payload is not a JSON object with a `nonce` string. */
  | 'BAD_PAYLOAD'
  /** The nonce is unknown to your store: expired or already used (replay). */
  | 'NONCE_NOT_FOUND'
  /** The signed result does not match what your server asked for this nonce. */
  | 'ASKED_MISMATCH'
  /** Webhook timestamp header missing, not a number, or outside the allowed window. */
  | 'BAD_WEBHOOK_TIMESTAMP'
  /** Webhook signature header missing or not valid (also after one key refresh). */
  | 'BAD_WEBHOOK_SIGNATURE'
  /** The callback `encrypted_response` could not be decrypted with your private key. */
  | 'DECRYPT_FAILED'
  /** A demo-card result while `allowTestCards` is off. */
  | 'TEST_CARD';

export class VerifyBlindError extends Error {
  readonly code: VerifyBlindErrorCode;

  constructor(code: VerifyBlindErrorCode, message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = 'VerifyBlindError';
    this.code = code;
  }
}

export function isVerifyBlindError(e: unknown): e is VerifyBlindError {
  return e instanceof VerifyBlindError;
}
