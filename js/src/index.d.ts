export const VERSION: string;

/** Thrown for malformed input, wrong password, or failed authentication. */
export class VornError extends Error {
  constructor(message: string);
}

/** First 32 fractional bits of sqrt(p) for the first 20 primes p. */
export const ROUND_CONSTANTS: number[];

/** Vorn-P: permutes a 64-byte state in place. */
export function permute(state: Uint8Array, rounds?: number): void;

/** Low-level AEAD. Returns ciphertext || 16-byte tag. Never reuse a (key, nonce) pair. */
export function seal(key: Uint8Array, nonce: Uint8Array, plaintext: Uint8Array | string, aad?: Uint8Array | string): Uint8Array;

/** Inverse of seal(). Throws VornError if authentication fails. */
export function unseal(key: Uint8Array, nonce: Uint8Array, sealed: Uint8Array, aad?: Uint8Array | string): Uint8Array;

export interface EncryptOptions {
  /** Extra authenticated (not encrypted) data. */
  aad?: Uint8Array | string;
  /** log2 of the scrypt cost parameter n. Default 16. */
  logN?: number;
  r?: number;
  p?: number;
  /** Return a base64url string instead of bytes. */
  armor?: boolean;
}

export function encrypt(data: Uint8Array | string, password: Uint8Array | string, options: EncryptOptions & { armor: true }): string;
export function encrypt(data: Uint8Array | string, password: Uint8Array | string, options?: EncryptOptions & { armor?: false }): Uint8Array;

export function decrypt(blob: Uint8Array | string, password: Uint8Array | string, options?: { aad?: Uint8Array | string }): Uint8Array;
