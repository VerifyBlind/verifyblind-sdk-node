import type { KeyLike, KeyObject } from 'node:crypto';
import { checkAsked, normalizeAsked } from './asked.js';
import {
  decryptCallbackResponse,
  parsePemFromJson,
  parseSpkiBase64,
  safeJsonParse,
  verifyPkcs1,
  verifyPss,
} from './crypto.js';
import { VerifyBlindError } from './errors.js';
import type {
  Asked,
  EncryptedResponse,
  FetchLike,
  SignedPayload,
  Validations,
  VerifiedResult,
  VerifierOptions,
  VerifyOutcome,
  WebhookInput,
} from './types.js';

export const DEFAULT_API_BASE_URL = 'https://api.verifyblind.com';

/** Your nonce store: get-and-delete. Return what you asked (object or the stored JSON string), or null. */
export type ConsumeNonce = (nonce: string) => Promise<Asked | string | null | undefined>;

/** A verified webhook body. Only `nonce` is guaranteed; other fields vary by event. */
export interface WebhookBody {
  nonce: string;
  [key: string]: unknown;
}

export type CallbackResult =
  | { status: 'cancelled'; nonce: string; reason: string; body: WebhookBody }
  | (VerifiedResult & { status: 'completed'; body: WebhookBody });

export interface Verifier {
  /** Verifies the enclave signature of a result token (web widget `onSuccess` token, mobile SDK `token`). */
  verifyToken(token: string): Promise<VerifiedResult>;
  /** Same as `verifyToken` for an already-decoded `{ payload, signature }`. */
  verifySigned(signed: { payload: string; signature: string }): Promise<VerifiedResult>;
  /** Signature → nonce consume → asked check, in that order. Never throws for verification failures. */
  verifyAndConsume(token: string, consumeNonce: ConsumeNonce): Promise<VerifyOutcome>;
  /** Nonce consume → asked check for a result whose signature is already verified (e.g. from `verifyCallback`). */
  consumeAndCheck(verified: VerifiedResult, consumeNonce: ConsumeNonce): Promise<VerifyOutcome>;
  /** See `checkAsked` (exported standalone too). */
  checkAsked(asked: Asked | null | undefined, validations: Validations | null | undefined): string | null;
  /** Verifies a webhook (callback or revoke): timestamp window + RSA-PSS over `"{timestamp}.{rawBody}"`. */
  verifyWebhook(input: WebhookInput): Promise<WebhookBody>;
  /** Revoke webhook: same signature as the callback. Key on `nonce` only; other fields vary by event. */
  verifyRevoke(input: WebhookInput): Promise<WebhookBody>;
  /**
   * Pattern B callback: verifies the webhook, then (unless cancelled) decrypts `encrypted_response`
   * with your callback private key and verifies the enclave signature. You still consume the nonce
   * and check the asked validations (`consumeAndCheck`).
   */
  verifyCallback(input: WebhookInput, privateKey: KeyLike): Promise<CallbackResult>;
  /**
   * Optional enclave check: PCR0 authorization signature (RSA PKCS#1 v1.5, SHA-256, over the PCR0 hex
   * string) against `GET /api/public/developer-key`. Then compare the PCR0 with `expected_pcr.json` of
   * https://github.com/VerifyBlind/VerifyBlind-Enclave/releases/latest yourself.
   * Returns false for a bad signature; throws KEY_FETCH_FAILED when the key cannot be fetched.
   */
  verifyPcr0Signature(pcr0Hex: string, pcr0SignatureB64: string): Promise<boolean>;
  /** Drops all cached keys. */
  clearKeyCache(): void;
}

/** Caches one public key with a TTL and shares a single in-flight request between concurrent callers. */
class KeyCache {
  private key: KeyObject | null = null;
  private fetchedAt = 0;
  private inflight: Promise<KeyObject> | null = null;

  constructor(
    private readonly load: () => Promise<KeyObject>,
    private readonly ttlMs: number,
    private readonly now: () => number,
  ) {}

  /** `fresh` is true when the key was fetched for this call (a retry with a refresh is then useless). */
  async get(forceRefresh = false): Promise<{ key: KeyObject; fresh: boolean }> {
    if (!forceRefresh && this.key && this.now() - this.fetchedAt < this.ttlMs) {
      return { key: this.key, fresh: false };
    }
    if (!this.inflight) {
      this.inflight = this.load()
        .then((k) => {
          this.key = k;
          this.fetchedAt = this.now();
          return k;
        })
        .finally(() => {
          this.inflight = null;
        });
    }
    return { key: await this.inflight, fresh: true };
  }

  clear(): void {
    this.key = null;
    this.fetchedAt = 0;
  }
}

/** A demo-card result (test partners only): `is_test: true` or identity codes with the `TEST_` prefix. */
function isTestResult(v: Validations): boolean {
  if (v.is_test === true) return true;
  return [v.user_id, v.nsbd_id, v.doc_id].some((c) => typeof c === 'string' && c.startsWith('TEST_'));
}

export function createVerifier(options: VerifierOptions = {}): Verifier {
  const baseUrl = (options.apiBaseUrl ?? DEFAULT_API_BASE_URL).replace(/\/+$/, '');
  const now = options.now ?? Date.now;
  const toleranceSec = options.webhookToleranceSec ?? 300;

  const doFetch: FetchLike = (url, init) => {
    const f = options.fetch ?? (globalThis.fetch as unknown as FetchLike | undefined);
    if (!f) throw new Error('global fetch is not available (Node 18+ required) — pass options.fetch');
    return f(url, init);
  };

  async function fetchText(path: string): Promise<string> {
    let res: Awaited<ReturnType<FetchLike>>;
    try {
      // cache: 'no-store' — Next.js patches fetch and would otherwise cache this GET.
      res = await doFetch(`${baseUrl}${path}`, { method: 'GET', cache: 'no-store' });
    } catch (e) {
      throw new VerifyBlindError('KEY_FETCH_FAILED', `GET ${path} failed`, { cause: e });
    }
    if (!res.ok) throw new VerifyBlindError('KEY_FETCH_FAILED', `GET ${path} returned HTTP ${res.status}`);
    return res.text();
  }

  function keyLoader(path: string, parse: (text: string) => KeyObject): () => Promise<KeyObject> {
    return async () => {
      const text = await fetchText(path);
      try {
        return parse(text);
      } catch (e) {
        throw new VerifyBlindError('KEY_FETCH_FAILED', `GET ${path} returned an unusable key`, { cause: e });
      }
    };
  }

  const enclaveKey = new KeyCache(
    keyLoader('/api/public/enclave-key', parseSpkiBase64),
    options.keyCacheMs ?? 60_000,
    now,
  );
  const longTtl = options.webhookKeyCacheMs ?? 3_600_000;
  const webhookKey = new KeyCache(keyLoader('/api/public/webhook-signing-key', parsePemFromJson), longTtl, now);
  const developerKey = new KeyCache(keyLoader('/api/public/developer-key', parsePemFromJson), longTtl, now);

  /** Verify with the cached key; on failure refresh once (the key rotates on enclave restart) and retry. */
  async function verifyWithRefresh(cache: KeyCache, check: (key: KeyObject) => boolean): Promise<boolean> {
    const first = await cache.get();
    if (check(first.key)) return true;
    if (first.fresh) return false;
    const second = await cache.get(true);
    return check(second.key);
  }

  async function verifySigned(signed: { payload: string; signature: string }): Promise<VerifiedResult> {
    const { payload, signature } = signed ?? ({} as never);
    if (typeof payload !== 'string' || typeof signature !== 'string' || !payload || !signature) {
      throw new VerifyBlindError('BAD_TOKEN', 'payload and signature must be non-empty strings');
    }
    const data = Buffer.from(payload, 'utf8');
    const ok = await verifyWithRefresh(enclaveKey, (key) => verifyPss(data, signature, key));
    if (!ok) throw new VerifyBlindError('BAD_SIGNATURE', 'enclave signature is not valid');

    const parsed = safeJsonParse(payload);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new VerifyBlindError('BAD_PAYLOAD', 'signed payload is not a JSON object');
    }
    const p = parsed as SignedPayload;
    if (typeof p.nonce !== 'string' || !p.nonce) {
      throw new VerifyBlindError('BAD_PAYLOAD', 'signed payload has no nonce');
    }
    const validations: Validations =
      p.validations && typeof p.validations === 'object' && !Array.isArray(p.validations) ? p.validations : {};
    return { nonce: p.nonce, validations, payload: p, rawPayload: payload, isTest: isTestResult(validations) };
  }

  async function verifyToken(token: string): Promise<VerifiedResult> {
    if (typeof token !== 'string' || !token.trim()) {
      throw new VerifyBlindError('BAD_TOKEN', 'token must be a non-empty string');
    }
    const decoded = safeJsonParse(Buffer.from(token.trim(), 'base64').toString('utf8'));
    if (!decoded || typeof decoded !== 'object') {
      throw new VerifyBlindError('BAD_TOKEN', 'token is not base64 of JSON { payload, signature }');
    }
    const { payload, signature } = decoded as { payload?: unknown; signature?: unknown };
    if (typeof payload !== 'string' || typeof signature !== 'string') {
      throw new VerifyBlindError('BAD_TOKEN', 'token is not base64 of JSON { payload, signature }');
    }
    return verifySigned({ payload, signature });
  }

  async function consumeAndCheck(verified: VerifiedResult, consumeNonce: ConsumeNonce): Promise<VerifyOutcome> {
    const stored = await consumeNonce(verified.nonce);
    if (stored === null || stored === undefined || stored === '') {
      return {
        ok: false,
        error: new VerifyBlindError('NONCE_NOT_FOUND', 'nonce is unknown, expired or already used'),
      };
    }
    if (verified.isTest && options.allowTestCards !== true) {
      return { ok: false, error: new VerifyBlindError('TEST_CARD', 'demo-card result; set allowTestCards on test setups only') };
    }
    const asked = normalizeAsked(stored);
    if (!asked) {
      // Fail closed: if we cannot read what we asked, we cannot read the answer.
      return { ok: false, error: new VerifyBlindError('ASKED_MISMATCH', 'stored asked validations are unreadable') };
    }
    const mismatch = checkAsked(asked, verified.validations);
    if (mismatch) return { ok: false, error: new VerifyBlindError('ASKED_MISMATCH', mismatch) };
    return { ok: true, ...verified, asked };
  }

  async function verifyAndConsume(token: string, consumeNonce: ConsumeNonce): Promise<VerifyOutcome> {
    let verified: VerifiedResult;
    try {
      verified = await verifyToken(token);
    } catch (e) {
      if (e instanceof VerifyBlindError) return { ok: false, error: e };
      throw e;
    }
    return consumeAndCheck(verified, consumeNonce);
  }

  async function verifyWebhook(input: WebhookInput): Promise<WebhookBody> {
    const { rawBody, signature, timestamp } = input ?? ({} as never);
    const ts = typeof timestamp === 'string' ? timestamp.trim() : '';
    if (!/^\d{1,15}$/.test(ts)) {
      throw new VerifyBlindError('BAD_WEBHOOK_TIMESTAMP', 'X-Webhook-Timestamp missing or not Unix seconds');
    }
    if (Math.abs(Math.floor(now() / 1000) - Number(ts)) > toleranceSec) {
      throw new VerifyBlindError('BAD_WEBHOOK_TIMESTAMP', `X-Webhook-Timestamp is outside ±${toleranceSec} s`);
    }
    if (typeof signature !== 'string' || !signature.trim()) {
      throw new VerifyBlindError('BAD_WEBHOOK_SIGNATURE', 'X-Webhook-Signature missing');
    }
    if (typeof rawBody !== 'string' && !(rawBody instanceof Uint8Array)) {
      throw new VerifyBlindError('BAD_PAYLOAD', 'rawBody must be the raw request body (string or bytes)');
    }
    const bodyBytes = typeof rawBody === 'string' ? Buffer.from(rawBody, 'utf8') : Buffer.from(rawBody);
    const signedBytes = Buffer.concat([Buffer.from(`${ts}.`, 'utf8'), bodyBytes]);
    const ok = await verifyWithRefresh(webhookKey, (key) => verifyPss(signedBytes, signature.trim(), key));
    if (!ok) throw new VerifyBlindError('BAD_WEBHOOK_SIGNATURE', 'webhook signature is not valid');

    const body = safeJsonParse(bodyBytes.toString('utf8'));
    if (!body || typeof body !== 'object' || Array.isArray(body)) {
      throw new VerifyBlindError('BAD_PAYLOAD', 'webhook body is not a JSON object');
    }
    const b = body as WebhookBody;
    if (typeof b.nonce !== 'string' || !b.nonce) throw new VerifyBlindError('BAD_PAYLOAD', 'webhook body has no nonce');
    return b;
  }

  async function verifyCallback(input: WebhookInput, privateKey: KeyLike): Promise<CallbackResult> {
    const body = await verifyWebhook(input);
    if (body.status === 'cancelled') {
      const reason = typeof body.reason === 'string' && body.reason ? body.reason : 'user_cancelled';
      return { status: 'cancelled', nonce: body.nonce, reason, body };
    }
    const inner = decryptCallbackResponse(body.encrypted_response as EncryptedResponse, privateKey);
    const verified = await verifySigned(inner);
    if (verified.nonce !== body.nonce) {
      throw new VerifyBlindError('BAD_PAYLOAD', 'signed nonce does not match the webhook nonce');
    }
    return { ...verified, status: 'completed', body };
  }

  async function verifyPcr0Signature(pcr0Hex: string, pcr0SignatureB64: string): Promise<boolean> {
    if (typeof pcr0Hex !== 'string' || typeof pcr0SignatureB64 !== 'string' || !pcr0Hex || !pcr0SignatureB64) {
      return false;
    }
    const data = Buffer.from(pcr0Hex, 'utf8');
    return verifyWithRefresh(developerKey, (key) => verifyPkcs1(data, pcr0SignatureB64, key));
  }

  return {
    verifyToken,
    verifySigned,
    verifyAndConsume,
    consumeAndCheck,
    checkAsked,
    verifyWebhook,
    verifyRevoke: verifyWebhook,
    verifyCallback,
    verifyPcr0Signature,
    clearKeyCache() {
      enclaveKey.clear();
      webhookKey.clear();
      developerKey.clear();
    },
  };
}
