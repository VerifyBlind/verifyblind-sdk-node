/**
 * @verifyblind/server — verify VerifyBlind results on your own server.
 *
 * Contract: https://verifyblind.com/ai-integration.md
 * This library never logs anything, and its error messages never contain user_id / nsbd_id / doc_id.
 */
export { createVerifier, DEFAULT_API_BASE_URL } from './verifier.js';
export type { Verifier, ConsumeNonce, WebhookBody, CallbackResult } from './verifier.js';
export { checkAsked } from './asked.js';
export { decryptCallbackResponse } from './crypto.js';
export { VerifyBlindError, isVerifyBlindError } from './errors.js';
export type { VerifyBlindErrorCode } from './errors.js';
export type {
  Asked,
  Validations,
  SignedPayload,
  VerifiedResult,
  VerifyOutcome,
  VerifierOptions,
  FetchLike,
  EncryptedResponse,
  WebhookInput,
} from './types.js';
