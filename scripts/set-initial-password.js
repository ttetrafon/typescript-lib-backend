import * as readline from 'readline';

async function promptPassword() {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  return new Promise((resolve) => {
    rl.question('Enter password to set: ', (answer) => {
      rl.close();
      resolve(answer);
    });
  });
}

async function main() {
  const args = process.argv.slice(2);
  const password = args.find((arg) => !arg.startsWith('--')) || (await promptPassword());

  if (!password) {
    console.error('Error: Password is required');
    process.exit(1);
  }

  console.log(`Hashing password...`);

  // Use Web Crypto API for password hashing
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
  const hash = btoa(String.fromCharCode(...combined));
  console.log(`hash is: ${hash}`);
}

main();
