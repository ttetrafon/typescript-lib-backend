import { describe, it, expect } from 'vitest'
import { hmacSha256, sha256Hex } from './conversions'

describe('Conversions', () => {
  describe('hmacSha256', () => {
    it('should generate a valid HMAC-SHA256 hash', async () => {
      const key = new TextEncoder().encode('secret-key');
      const data = 'test data';

      const result = await hmacSha256(key, data);

      expect(result).toBeInstanceOf(ArrayBuffer);
      expect(result.byteLength).toBe(32);
    });

    it('should generate consistent results for the same input', async () => {
      const key = new TextEncoder().encode('secret-key');
      const data = 'test data';

      const result1 = await hmacSha256(key, data);
      const result2 = await hmacSha256(key, data);

      expect(result1).toEqual(result2);
    });

    it('should generate different results for different data', async () => {
      const key = new TextEncoder().encode('secret-key');

      const result1 = await hmacSha256(key, 'data1');
      const result2 = await hmacSha256(key, 'data2');

      expect(result1 === result2).toBeFalsy();
    });

    it('should handle empty data correctly', async () => {
      const key = new TextEncoder().encode('secret-key');
      const data = ''

      const result = await hmacSha256(key, data);

      expect(result).toBeInstanceOf(ArrayBuffer);
    });
  });

  describe('sha256Hex', () => {
    it('should generate a valid SHA256 hex string', async () => {
      const data = 'test data';

      const result = await sha256Hex(data);

      expect(result).toBeTypeOf('string');
      expect(result).toHaveLength(64); // SHA-256 produces 64-character hex string
      expect(/^[a-f0-9]+$/.test(result)).toBe(true); // Should only contain hex characters
    });

    it('should generate consistent results for the same input', async () => {
      const data = 'test data';

      const result1 = await sha256Hex(data);
      const result2 = await sha256Hex(data);

      expect(result1).toBe(result2);
    });

    it('should generate different results for different data', async () => {
      const result1 = await sha256Hex('data1');
      const result2 = await sha256Hex('data2');

      expect(result1).not.toBe(result2);
    });

    it('should handle empty data correctly', async () => {
      const data = '';

      const result = await sha256Hex(data);

      expect(result).toBeTypeOf('string');
      expect(result).toHaveLength(64);
    });
  });
});
