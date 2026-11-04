import { ParsedRefreshToken } from "../types/user";
import { bytesToBase64 } from "./conversions";

export function randomToken(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return bytesToBase64(bytes);
}

/**
 * The refresh credential handed to clients: `<userId>.<sid>.<secret>`.
 * On a cold start (page reload) the client has no access token, so the credential itself must say which
 * user's Durable Object and which session to look in. userId and sid are not secret; only `secret` is,
 * and only its hash is stored.
 */
export function formatRefreshToken(userId: number, sid: string, secret: string): string {
  return `${userId}.${sid}.${secret}`;
}

export function parseRefreshToken(token: string | null | undefined): ParsedRefreshToken | null {
  if (!token || token.length > 512) return null;
  const parts = token.split(".");
  if (parts.length !== 3) return null;

  const [id, sid, secret] = parts;
  if (!id || !sid || !secret || !/^\d+$/.test(id)) return null;

  const userId = Number(id);
  if (!Number.isSafeInteger(userId)) return null;

  return { userId, sid, secret };
}
