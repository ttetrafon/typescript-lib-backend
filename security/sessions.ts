import { SessionData } from "lib/lib/types";
import { SESSION_DURATION_MS, SESSION_PREFIX } from "../constants";

/**
 * Generate a cryptographically secure random session ID
 */
export function generateSessionId(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Create an HMAC signature for a session token
 */
export async function signToken(data: string, secret: string): Promise<string> {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(data));
  return Array.from(new Uint8Array(signature), (b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Verify an HMAC signature
 */
export async function verifySignature(data: string, signature: string, secret: string): Promise<boolean> {
  console.log(`---> verifySignature(data=${data}, signature=${signature}, secret=${secret})`);
  const expectedSignature = await signToken(data, secret);
  console.log("... expectedSignature:", expectedSignature);
  // Constant-time comparison
  if (signature.length !== expectedSignature.length) return false;
  let result = 0;
  for (let i = 0; i < signature.length; i++) {
    result |= signature.charCodeAt(i) ^ expectedSignature.charCodeAt(i);
  }
  return result === 0;
}

/**
 * Create a new session and return the session token
 */
export async function createSession(setSessionSecretCb: Function, secret: string): Promise<string> {
  const sessionId = generateSessionId();
  const expiresAt = Date.now() + SESSION_DURATION_MS;

  // Store session in KV with TTL
  await setSessionSecretCb(
    `${SESSION_PREFIX}${sessionId}`,
    JSON.stringify({ createdAt: Date.now() }),
    { expirationTtl: Math.floor(SESSION_DURATION_MS / 1000) }
  );
  // await kv.put(
  //   `${SESSION_PREFIX}${sessionId}`,
  //   JSON.stringify({ createdAt: Date.now() }),
  //   { expirationTtl: Math.floor(SESSION_DURATION_MS / 1000) }
  // );

  // Create signed token: sessionId.expiresAt.signature
  const data = `${sessionId}.${expiresAt}`;
  const signature = await signToken(data, secret);

  return `${data}.${signature}`;
}

/**
 * Verify a session token and return session data if valid
 */
export async function verifySession(
  token: string,
  getSessionDataCb: Function | null,
  secret: string
): Promise<SessionData | null> {
  console.log(`---> verifySession(token=${token}, secret=${secret})`);
  const parts = token.split('.');
  console.log("... parts:", parts);
  if (parts.length !== 3) return null;

  const [sessionId, expiresAtStr, signature] = parts;
  if (!sessionId || !expiresAtStr || !signature) return null;

  const data = `${sessionId}.${expiresAtStr}`;
  console.log("... data:", data);

  // Verify signature
  const isValid = await verifySignature(data, signature, secret);
  console.log("... isValid:", isValid);
  if (!isValid) return null;

  // Check expiration
  const expiresAt = parseInt(expiresAtStr, 10);
  if (isNaN(expiresAt) || Date.now() > expiresAt) return null;

  // Check if session is not revoked
  if (getSessionDataCb != null) {
    const sessionData = await getSessionDataCb(`${SESSION_PREFIX}${sessionId}`);
    // const sessionData = await kv.get(`${SESSION_PREFIX}${sessionId}`);
    if (!sessionData) return null;
  }

  return { sessionId, expiresAt };
}

/**
 * Invalidate a session (logout)
 */
export async function invalidateSession(token: string, secret: string, getSessionDataCb: Function, deleteSessionCb: Function): Promise<void> {
  const session = await verifySession(token, getSessionDataCb, secret);
  if (session) {
    await deleteSessionCb(`${SESSION_PREFIX}${session.sessionId}`);
  }
}
