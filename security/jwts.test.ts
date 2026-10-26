import { JWTPayload } from "lib/lib/types";
import { describe, expect, it } from "vitest";
import { createJWT, verifyJWT, getJWTFromCookie } from "./jwts";

describe('JWT Utilities', () => {
  const secret = 'test-secret';
  const payload: JWTPayload = {
    sub: 125,
    username: 'test-user',
    iat: 0,
    exp: 0
  };

  it('should create a valid JWT', async () => {
    const token = await createJWT(payload, secret);

    expect(typeof token).toBe('string');
    expect(token.length).toBeGreaterThan(0);
  });

  it('should verify a valid JWT', async () => {
    const token = await createJWT(payload, secret);
    const verified = await verifyJWT<typeof payload>(token, secret);

    expect(verified).not.toBeNull();
    if (verified) {
      expect(verified.sub).toBe(125);
      expect(verified.username).toBe('test-user');
    }
  });

  it('should reject an invalid JWT', async () => {
    const verified = await verifyJWT<JWTPayload>('invalid-token', secret);

    expect(verified).toBeNull();
  });

  it('should extract JWT from cookie header', () => {
    const cookieHeader = 'token=abc123; other=value';
    const token = getJWTFromCookie(cookieHeader);

    expect(token).toBe('abc123');
  });

  it('should return null when no token found in cookie', () => {
    const cookieHeader = 'other=value; another=test';
    const token = getJWTFromCookie(cookieHeader);

    expect(token).toBeNull();
  });
});
