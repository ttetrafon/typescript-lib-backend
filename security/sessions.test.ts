import { describe, expect, it } from "vitest";
import { generateSessionId, signToken, verifySignature } from "./sessions";

describe('Session Utilities', () => {
  const secret = 'test-secret';
  const tokenDuration = 7 * 24 * 60 * 60 * 1000;

  describe('generateSessionId', () => {
    it('should generate a valid session id', async () => {
      const sessionId = generateSessionId();

      expect(sessionId.length).toBeGreaterThan(0);
    });
  });

  describe('signToken', () => {
    it('should generate a valid signature', async () => {
      const sessionId = generateSessionId();
      const expiresAt = Date.now() + tokenDuration;
      const data = `${sessionId}.${expiresAt}`;
      const signature = await signToken(data, secret);
      console.log("signature", signature);

      expect(signature.length).greaterThan(0);
    });
  });

  describe('verifySignature', () => {
    it('should verify a signed token', async () => {
      const sessionId = generateSessionId();
      const expiresAt = Date.now() + tokenDuration;
      const data = `${sessionId}.${expiresAt}`;
      const signature = await signToken(data, secret);

      const verificationResult = verifySignature(data, signature, secret);

      expect(verificationResult).toBeTruthy();
    });

    it('should not verify a modified token', async () => {
      const sessionId = generateSessionId();
      const expiresAt = Date.now() + tokenDuration;
      const data = `${sessionId}.${expiresAt}`;
      const signature = await signToken(data, secret);

      const dataModified = `${sessionId}.${expiresAt + 1000}`;
      const verificationResult = await verifySignature(dataModified, signature, secret);

      expect(verificationResult).toBeFalsy();
    });
  });

  describe('createSession', () => {
    it('', async () => {
      // TODO...
    });
  });

  describe('verifySession', () => {
    it('', async () => {
      // TODO...
    });
  });
});
