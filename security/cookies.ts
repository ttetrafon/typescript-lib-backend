import { JWTPayload } from "library/lib/types";
import { SESSION_COOKIE_NAME, SESSION_DURATION_MS } from "../constants";
import { base64urlToStr } from "./conversions";

/**
 * Create a Set-Cookie header value for the session
 */
export function createSessionCookie(token: string, secure: boolean = true): string {
  const maxAge = Math.floor(SESSION_DURATION_MS / 1000);
  const parts = [
    `${SESSION_COOKIE_NAME}=${token}`,
    `Max-Age=${maxAge}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
  ];
  if (secure) {
    parts.push('Secure');
  }
  return parts.join('; ');
}

/**
 * Create a Set-Cookie header to clear the session cookie
 */
export function clearSessionCookie(): string {
  return `${SESSION_COOKIE_NAME}=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax`;
}

/**
 * Extract session token from cookie header
 */
export function getSessionFromCookie(cookieHeader: string | null): string | null {
  console.log(`---> getSessionFromCookie(${cookieHeader})`);
  if (!cookieHeader) return null;

  const cookies = cookieHeader.split(';').map((c) => c.trim());
  console.log("... cookies:", cookies);
  for (const cookie of cookies) {
    const [name, ...valueParts] = cookie.split('=');
    if (name === SESSION_COOKIE_NAME) {
      return valueParts.join('=') || null;
    }
  }
  return null;
}

export function getPayloadFromCookie<T extends JWTPayload>(cookieHeader: string | null): T | null {
  const token = getSessionFromCookie(cookieHeader);
  if (!token) return null;

  const parts = token.split('.');
  if (parts.length !== 3) return null;

  const [, body] = parts;
  if (!body) return null;
  try {
    return JSON.parse(base64urlToStr(body)) as T;
  } catch {
    return null;
  }
}
