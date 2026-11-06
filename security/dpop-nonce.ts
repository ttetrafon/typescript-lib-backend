import { DPOP_NONCE_TTL_S } from "../constants";
import { bytesToBase64, hmacSha256 } from "./conversions";

/** RFC 9449 §8 error code, and the header the nonce travels in. */
export const USE_DPOP_NONCE = "use_dpop_nonce";
export const DPOP_NONCE_HEADER = "DPoP-Nonce";

const encoder = new TextEncoder();

async function mac(secret: string, issuedAt: string): Promise<string> {
  // The prefix keeps this MAC separate from anything else signed with the same secret.
  return bytesToBase64(new Uint8Array(await hmacSha256(encoder.encode(secret), `dpop-nonce:${issuedAt}`)));
}

function safeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/**
 * A stateless server nonce: `<issued-at, base36>.<HMAC>`. Nothing is stored; validity is the signature plus the age.
 * Requiring it in a proof means a proof cannot be signed ahead of time, since the nonce is only valid for DPOP_NONCE_TTL_S.
 */
export async function createDpopNonce(secret: string, nowMs: number = Date.now()): Promise<string> {
  const issuedAt = Math.floor(nowMs / 1000).toString(36);
  return `${issuedAt}.${await mac(secret, issuedAt)}`;
}

export async function verifyDpopNonce(nonce: string | undefined, secret: string, nowMs: number = Date.now()): Promise<boolean> {
  if (!nonce) return false;
  const parts = nonce.split(".");
  if (parts.length !== 2) return false;
  const [issuedAt, signature] = parts as [string, string];

  const issued = parseInt(issuedAt, 36);
  if (!Number.isFinite(issued)) return false;
  const age = nowMs / 1000 - issued;
  if (age < -DPOP_NONCE_TTL_S || age > DPOP_NONCE_TTL_S) return false;

  return safeEqual(signature, await mac(secret, issuedAt));
}
