import { describe, expect, it, vi } from "vitest";
import { getStoredPasswordHash, hashPassword, setPasswordHash, verifyPassword } from "./passwords";

describe('Password Utilities', () => {
  describe('hashPassword', () => {
    it('should hash a password correctly', async () => {
      const password = 'testPassword123';
      const hash = await hashPassword(password);

      expect(typeof hash).toBe('string');
      expect(hash.length).toBeGreaterThan(0);
    });

    it('should produce different hashes for different passwords', async () => {
      const hash1 = await hashPassword('password1');
      const hash2 = await hashPassword('password2');

      expect(hash1).not.toBe(hash2);
    });
  });

  describe('verifyPassword', () => {
    it('should verify a correct password', async () => {
      const password = 'testPassword123';
      const hash = await hashPassword(password);
      const result = await verifyPassword(password, hash);

      expect(result).toBe(true);
    });

    it('should reject an incorrect password', async () => {
      const password = 'testPassword123';
      const hash = await hashPassword(password);
      const result = await verifyPassword('wrongPassword', hash);

      expect(result).toBe(false);
    });

    it('should handle invalid hash gracefully', async () => {
      const result = await verifyPassword('password', 'invalid-hash');

      expect(result).toBe(false);
    });
  });

  describe('getStoredPasswordHash and setPasswordHash', () => {
    it('should get password hash through callback', async () => {
      const mockCb = vi.fn().mockResolvedValue('mock-hash');
      const result = await getStoredPasswordHash(mockCb);

      expect(result).toBe('mock-hash');
      expect(mockCb).toHaveBeenCalled();
    });

    it('should set password hash through callback', async () => {
      const mockCb = vi.fn();
      await setPasswordHash(mockCb, 'test-hash');

      expect(mockCb).toHaveBeenCalledWith('test-hash');
    });
  });
});
