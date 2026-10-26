import { JWTPayload } from "library/lib/types";
import { JWT_DURATION_S, JWT_COOKIE_NAME } from "../constants";
import { strToBase64url, bytesToBase64url, base64urlToStr } from "./conversions";
import { signToken } from "./sessions";

/**
 * Create a signed JWT containing user info
 */
export async function createJWT<T extends JWTPayload>(
  payload: Omit<T, 'iat' | 'exp'>,
  secret: string
): Promise<string> {
  const header = strToBase64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const now = Math.floor(Date.now() / 1000);
  const body = strToBase64url(
    JSON.stringify({ ...payload, iat: now, exp: now + JWT_DURATION_S })
  );
  const data = `${header}.${body}`;
  const sigHex = await signToken(data, secret);
  const sigBytes = new Uint8Array(sigHex.match(/.{2}/g)!.map((b) => parseInt(b, 16)));
  return `${data}.${bytesToBase64url(sigBytes)}`;
}

/**
 * Verify a JWT and return its payload, or null if invalid/expired
 * // TODO: add error handling and just return null if something happens?
 */
export async function verifyJWT<T extends JWTPayload>(token: string, secret: string): Promise<T | null> {
  const parts = token.split('.');
  if (parts.length !== 3) return null;

  const [header, body, sig] = parts;
  const data = `${header}.${body}`;

  const expectedHex = await signToken(data, secret);
  const expectedBytes = new Uint8Array(expectedHex.match(/.{2}/g)!.map((b) => parseInt(b, 16)));
  const expectedSig = bytesToBase64url(expectedBytes);

  // Constant-time comparison
  if (!sig || !body) return null;
  if (sig.length !== expectedSig.length) return null;
  let diff = 0;
  for (let i = 0; i < sig.length; i++) {
    diff |= sig.charCodeAt(i) ^ expectedSig.charCodeAt(i);
  }
  if (diff !== 0) return null;

  const decoded = JSON.parse(base64urlToStr(body)) as T;
  if (Date.now() / 1000 > decoded.exp) return null;

  return decoded;
}

/**
 * Create a Set-Cookie header value for the JWT
 */
export function createJWTCookie(token: string, secure = true): string {
  const parts = [
    `${JWT_COOKIE_NAME}=${token}`,
    `Max-Age=${JWT_DURATION_S}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
  ];
  if (secure) parts.push('Secure');
  return parts.join('; ');
}

/**
 * Create a Set-Cookie header to clear the JWT cookie
 */
export function clearJWTCookie(): string {
  return `${JWT_COOKIE_NAME}=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax`;
}

/**
 * Extract JWT from cookie header
 */
export function getJWTFromCookie(cookieHeader: string | null): string | null {
  if (!cookieHeader) return null;
  const cookies = cookieHeader.split(';').map((c) => c.trim());
  for (const cookie of cookies) {
    const [name, ...valueParts] = cookie.split('=');
    if (name === JWT_COOKIE_NAME) {
      return valueParts.join('=') || null;
    }
  }
  return null;
}
