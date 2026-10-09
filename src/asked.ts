import type { Asked, Validations } from './types.js';

/**
 * Checks the signed `validations` against what YOUR server asked for this nonce.
 * Returns a reason string when the result must be rejected, or `null` when it matches.
 *
 * Rules (https://verifyblind.com/ai-integration.md, step 4.5):
 * - Age asked: `validations.age` must be a boolean AND `validations.age_condition` must be present
 *   and equal the asked condition. The enclave always signs the condition it answered, so a visitor
 *   who changed `"18+"` to `"1+"` in the browser is caught here.
 * - Age not asked: no `age` answer and no `age_condition` are allowed.
 * - `user_id` asked: `validations.user_id` must be present.
 *
 * The returned reason never contains identity codes.
 */
export function checkAsked(asked: Asked | null | undefined, validations: Validations | null | undefined): string | null {
  const a = asked ?? {};
  const v: Validations = validations && typeof validations === 'object' ? validations : {};

  if (a.age === undefined || a.age === null) {
    if (v.age !== undefined) return 'age result present although age was not asked';
    if (v.age_condition !== undefined) return 'age_condition present although age was not asked';
  } else {
    if (typeof v.age !== 'boolean') return 'age result missing';
    if (typeof v.age_condition !== 'string') return `age_condition missing (expected ${a.age})`;
    if (v.age_condition !== a.age) {
      return `age_condition does not match the asked condition (expected ${a.age}, got ${v.age_condition})`;
    }
  }

  if (a.user_id === true && (typeof v.user_id !== 'string' || v.user_id.length === 0)) {
    return 'user_id missing although it was asked';
  }

  return null;
}

/** Accepts the asked validations as an object or as the JSON string you stored. */
export function normalizeAsked(stored: Asked | string): Asked | null {
  if (typeof stored === 'string') {
    try {
      const parsed: unknown = JSON.parse(stored);
      return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? (parsed as Asked) : null;
    } catch {
      return null;
    }
  }
  return stored && typeof stored === 'object' ? stored : null;
}
