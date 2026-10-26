/**
 * Hash a password for storage using Web Crypto API
 */
export async function hashPassword(password: string): Promise<string> {
  // Convert password to bytes
  const encoder = new TextEncoder();
  const data = encoder.encode(password);

  // Generate salt (32 bytes)
  const salt = new Uint8Array(32);
  crypto.getRandomValues(salt);

  // Use PBKDF2 with SHA-256 for password hashing directly
  const key = await crypto.subtle.importKey(
    'raw',
    data,
    { name: 'PBKDF2' },
    false,
    ['deriveBits']
  );

  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: 100000,
      hash: 'SHA-256'
    },
    key,
    256 // 256 bits for AES-256
  );

  // Combine salt and derived bits for storage
  const combined = new Uint8Array(salt.length + derivedBits.byteLength);
  combined.set(salt, 0);
  combined.set(new Uint8Array(derivedBits), salt.length);

  // Convert to base64 string for storage
  return btoa(String.fromCharCode(...combined));
}

/**
 * Verify a password against a stored hash using Web Crypto API
 */
export async function verifyPassword(password: string, hash: string): Promise<boolean> {
  try {
    // Decode the stored hash
    const decoded = new Uint8Array(atob(hash).split('').map(c => c.charCodeAt(0)));

    // Extract salt (first 32 bytes) and hash (remaining bytes)
    const salt = decoded.slice(0, 32);
    const expectedHash = decoded.slice(32);

    // Hash the provided password with the same salt
    const encoder = new TextEncoder();
    const data = encoder.encode(password);

    // Use PBKDF2 with SHA-256 for password verification directly
    const key = await crypto.subtle.importKey(
      'raw',
      data,
      { name: 'PBKDF2' },
      false,
      ['deriveBits']
    );

    const derivedBits = await crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt: salt,
        iterations: 100000,
        hash: 'SHA-256'
      },
      key,
      256 // 256 bits for AES-256
    );

    // Compare hashes
    const actualHash = new Uint8Array(derivedBits);
    if (actualHash.length !== expectedHash.length) {
      return false;
    }

    for (let i = 0; i < actualHash.length; i++) {
      if (actualHash[i] !== expectedHash[i]) {
        return false;
      }
    }

    return true;
  } catch (error) {
    // If there's any error in verification, return false
    return false;
  }
}

/**
 * Get the stored password hash from KV
 */
export async function getStoredPasswordHash(passwordHashCb: Function): Promise<string | null> {
  return passwordHashCb();
  // return kv.get(PASSWORD_HASH_KEY);
}

/**
 * Set the password hash in KV (for initial setup or password change)
 */
export async function setPasswordHash(setPasswordHashCb: Function, hash: string): Promise<void> {
  await setPasswordHashCb(hash);
  // await kv.put(PASSWORD_HASH_KEY, hash);
}

/**
 * Check if a password has been set up
 */
export async function isPasswordConfigured(passwordHashCb: Function): Promise<boolean> {
  const hash = await getStoredPasswordHash(passwordHashCb);
  return hash !== null;
}
