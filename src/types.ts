/**
 * What YOUR server asked VerifyBlind at generate time (the `validations` you sent to
 * `POST /api/pop/generate`). Store it together with the returned nonce.
 *
 * Example: `{ age: '18+', user_id: true }`.
 */
export interface Asked {
  /** Age condition, e.g. `"18+"`, `"16-"`, `"18-65"`, `"24"`. Omit when age was not asked. */
  age?: string;
  /** `true` when you asked for the pseudonymous codes. */
  user_id?: boolean;
}

/**
 * The `validations` object inside the enclave-signed payload.
 *
 * `user_id`, `nsbd_id` and `doc_id` are pseudonymous personal data: store them like other user
 * data and NEVER write them to logs.
 */
export interface Validations {
  /** Answer to the asked age condition. */
  age?: boolean;
  /** The condition the enclave answered. Must equal what you asked (checked by `checkAsked`). */
  age_condition?: string;
  /** Stable pseudonymous code for this person, unique to your partner account. */
  user_id?: string;
  nsbd_id?: string;
  doc_id?: string;
  /** `true` for demo-card results (test partners only). Codes then start with `TEST_`. */
  is_test?: boolean;
  [key: string]: unknown;
}

/** The parsed enclave-signed payload. */
export interface SignedPayload {
  nonce: string;
  validations?: Validations;
  additional_data?: unknown;
  [key: string]: unknown;
}

/** Result of a successful signature check (`verifyToken` / `verifySigned`). */
export interface VerifiedResult {
  /** The signed nonce. Consume it exactly once in your store before trusting the result. */
  nonce: string;
  /** `payload.validations` (an empty object when absent). */
  validations: Validations;
  /** The whole parsed payload. */
  payload: SignedPayload;
  /** The exact signed payload string. */
  rawPayload: string;
  /** `true` for demo-card results. Keep them out of production decisions. */
  isTest: boolean;
}

/** Result of `verifyAndConsume`. It never throws for verification failures. */
export type VerifyOutcome =
  | (VerifiedResult & { ok: true; asked: Asked })
  | { ok: false; error: import('./errors.js').VerifyBlindError };

export type FetchLike = (input: string, init?: { method?: string; headers?: Record<string, string>; cache?: string }) => Promise<{
  ok: boolean;
  status: number;
  text(): Promise<string>;
}>;

export interface VerifierOptions {
  /** Default `https://api.verifyblind.com`. */
  apiBaseUrl?: string;
  /** How long the enclave public key is cached. Default 60 000 ms (the key rotates on enclave restart). */
  keyCacheMs?: number;
  /** How long the webhook-signing and developer public keys are cached. Default 3 600 000 ms. */
  webhookKeyCacheMs?: number;
  /** Allowed clock difference for webhook timestamps, in seconds. Default 300. */
  webhookToleranceSec?: number;
  /** `fetch` replacement (tests, proxies). Default: global `fetch`. */
  fetch?: FetchLike;
  /** Clock replacement for tests. Returns milliseconds since epoch. Default `Date.now`. */
  now?: () => number;
}

/** The `encrypted_response` object of a pattern B (callback) webhook body. */
export interface EncryptedResponse {
  enc_key: string;
  blob: string;
}

export interface WebhookInput {
  /** The request body EXACTLY as received (string or bytes), before any JSON parsing. */
  rawBody: string | Uint8Array;
  /** `X-Webhook-Signature` header. */
  signature: string | null | undefined;
  /** `X-Webhook-Timestamp` header (Unix seconds). */
  timestamp: string | null | undefined;
}
