/**
 * Vorn-2: an experimental duplex-sponge AEAD built on a 512-bit ARX permutation.
 *
 * EXPERIMENTAL. Not reviewed by third parties. Do not use it to protect real secrets.
 * Specification: https://github.com/LowLeery/vorn/blob/main/SPEC.md
 */
import { randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';

export const VERSION = '0.2.1';

const ROUNDS = 20;
const RATE = 32;
const STATE_LEN = 64;
const KEY_LEN = 32;
const NONCE_LEN = 16;
const TAG_LEN = 16;
const SALT_LEN = 16;
const DEFAULT_LOG_N = 16;
const MAX_SCRYPT_BYTES = 1 << 29; // refuse scrypt settings needing more than 512 MiB

const enc = new TextEncoder();
const LABEL = enc.encode('Vorn-2 AEAD v0.2');
const MAGIC = enc.encode('VRN2');
const HEADER_LEN = MAGIC.length + 3 + SALT_LEN + NONCE_LEN;

export class VornError extends Error {
  constructor(message) {
    super(message);
    this.name = 'VornError';
  }
}

// ---------------------------------------------------------------- constants
function firstPrimes(count) {
  const primes = [];
  for (let n = 2; primes.length < count; n++) {
    if (primes.every((p) => p * p > n || n % p !== 0)) primes.push(n);
  }
  return primes;
}

function isqrt(n) {
  if (n < 2n) return n;
  let x = 1n << BigInt((n.toString(2).length + 1) >> 1);
  for (;;) {
    const y = (x + n / x) >> 1n;
    if (y >= x) return x;
    x = y;
  }
}

const PRIMES = firstPrimes(ROUNDS);
// first 32 fractional bits of sqrt(prime); same construction as the SHA-256 initial words
export const ROUND_CONSTANTS = PRIMES.map((p) => Number(isqrt(BigInt(p) << 64n) & 0xffffffffn));
// "prime hopping": the lane receiving round constant r is (prime_r mod 16)
const LANE = PRIMES.map((p) => p % 16);

const COLUMNS = [[0, 4, 8, 12], [1, 5, 9, 13], [2, 6, 10, 14], [3, 7, 11, 15]];
const DIAGONALS = [[0, 5, 10, 15], [1, 6, 11, 12], [2, 7, 8, 13], [3, 4, 9, 14]];

// ---------------------------------------------------------------- permutation
/** Vorn-P applied in place to a 64-byte state (16 little-endian 32-bit words). */
export function permute(state, rounds = ROUNDS) {
  if (!(state instanceof Uint8Array) || state.length !== STATE_LEN) throw new RangeError('state must be 64 bytes');
  if (!Number.isInteger(rounds) || rounds < 1 || rounds > ROUNDS) throw new RangeError('rounds out of range');
  const dv = new DataView(state.buffer, state.byteOffset, STATE_LEN);
  const s = new Uint32Array(16);
  for (let i = 0; i < 16; i++) s[i] = dv.getUint32(i * 4, true);
  for (let r = 0; r < rounds; r++) {
    s[LANE[r]] ^= ROUND_CONSTANTS[r];
    const quads = r & 1 ? DIAGONALS : COLUMNS;
    for (let q = 0; q < 4; q++) {
      const [a, b, c, d] = quads[q];
      let x = s[a], y = s[b], z = s[c], w = s[d];
      x = (x + y) >>> 0; w ^= x; w = ((w << 16) | (w >>> 16)) >>> 0;
      z = (z + w) >>> 0; y ^= z; y = ((y << 12) | (y >>> 20)) >>> 0;
      x = (x + y) >>> 0; w ^= x; w = ((w << 8) | (w >>> 24)) >>> 0;
      z = (z + w) >>> 0; y ^= z; y = ((y << 7) | (y >>> 25)) >>> 0;
      s[a] = x; s[b] = y; s[c] = z; s[d] = w;
    }
  }
  for (let i = 0; i < 16; i++) dv.setUint32(i * 4, s[i], true);
}

// ---------------------------------------------------------------- duplex AEAD
function run(key, nonce, aad, data, decrypting) {
  const st = new Uint8Array(STATE_LEN);
  st.set(LABEL, 0);
  st.set(nonce, 16);
  st.set(key, 32);
  permute(st);

  // associated data, always followed by one padded block (pad10*)
  let i = 0;
  while (aad.length - i >= RATE) {
    for (let j = 0; j < RATE; j++) st[j] ^= aad[i + j];
    permute(st);
    i += RATE;
  }
  const rem = aad.length - i;
  for (let j = 0; j < rem; j++) st[j] ^= aad[i + j];
  st[rem] ^= 0x80;
  permute(st);

  st[STATE_LEN - 1] ^= 0x01; // domain separation: associated data -> message

  const out = new Uint8Array(data.length);
  i = 0;
  while (data.length - i >= RATE) {
    for (let j = 0; j < RATE; j++) {
      const b = data[i + j];
      const o = b ^ st[j];
      st[j] = decrypting ? b : o; // the rate is overwritten with ciphertext
      out[i + j] = o;
    }
    permute(st);
    i += RATE;
  }
  const m = data.length - i;
  for (let j = 0; j < m; j++) {
    const b = data[i + j];
    const o = b ^ st[j];
    st[j] = decrypting ? b : o;
    out[i + j] = o;
  }
  st[m] ^= 0x80;

  // finalisation: the key goes into the capacity again, the tag is read from the last 16 bytes
  for (let j = 0; j < KEY_LEN; j++) st[RATE + j] ^= key[j];
  permute(st);
  const tag = new Uint8Array(TAG_LEN);
  for (let j = 0; j < TAG_LEN; j++) tag[j] = st[48 + j] ^ key[16 + j];
  return [out, tag];
}

function asBytes(value, name) {
  if (typeof value === 'string') return enc.encode(value);
  if (value instanceof Uint8Array) return value; // includes Buffer
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  throw new VornError(`${name} must be a string or Uint8Array.`);
}

function checkKeyNonce(key, nonce) {
  if (!(key instanceof Uint8Array) || key.length !== KEY_LEN) throw new VornError('Key must be exactly 32 bytes.');
  if (!(nonce instanceof Uint8Array) || nonce.length !== NONCE_LEN) throw new VornError('Nonce must be exactly 16 bytes.');
}

/** Low-level AEAD. Returns ciphertext || 16-byte tag. Never reuse a (key, nonce) pair. */
export function seal(key, nonce, plaintext, aad = new Uint8Array(0)) {
  checkKeyNonce(key, nonce);
  const [ct, tag] = run(key, nonce, asBytes(aad, 'aad'), asBytes(plaintext, 'plaintext'), false);
  const out = new Uint8Array(ct.length + TAG_LEN);
  out.set(ct, 0);
  out.set(tag, ct.length);
  return out;
}

/** Inverse of seal(). Throws VornError if authentication fails. */
export function unseal(key, nonce, sealed, aad = new Uint8Array(0)) {
  checkKeyNonce(key, nonce);
  sealed = asBytes(sealed, 'sealed');
  if (sealed.length < TAG_LEN) throw new VornError('Malformed ciphertext.');
  const ct = sealed.subarray(0, sealed.length - TAG_LEN);
  const tag = sealed.subarray(sealed.length - TAG_LEN);
  const [pt, expected] = run(key, nonce, asBytes(aad, 'aad'), ct, true);
  if (!timingSafeEqual(tag, expected)) {
    throw new VornError('Authentication failed: wrong password or modified data.');
  }
  return pt;
}

// ---------------------------------------------------------------- password API
function checkScryptParams(logN, r, p) {
  const ok = Number.isInteger(logN) && Number.isInteger(r) && Number.isInteger(p);
  if (!ok || logN < 1 || logN > 24 || r < 1 || r > 32 || p < 1 || p > 16) {
    throw new VornError('Unsupported scrypt parameters.');
  }
  if (128 * r * 2 ** logN > MAX_SCRYPT_BYTES) throw new VornError('Unsupported scrypt parameters.');
}

function kdf(password, salt, logN, r, p) {
  const pw = asBytes(password, 'password');
  if (pw.length === 0) throw new VornError('Password must not be empty.');
  const N = 2 ** logN;
  return new Uint8Array(
    scryptSync(pw, salt, KEY_LEN, { N, r, p, maxmem: 2 * 128 * r * N + (1 << 24) }),
  );
}

/**
 * Encrypt with a password. Returns a Uint8Array, or a base64url string when armor is true.
 * Blob layout: "VRN2" | log2(n) | r | p | salt(16) | nonce(16) | ciphertext | tag(16).
 * The whole header and any extra `aad` are authenticated.
 */
export function encrypt(data, password, { aad = new Uint8Array(0), logN = DEFAULT_LOG_N, r = 8, p = 1, armor = false } = {}) {
  checkScryptParams(logN, r, p);
  const plain = asBytes(data, 'data');
  const extra = asBytes(aad, 'aad');
  const salt = new Uint8Array(randomBytes(SALT_LEN));
  const nonce = new Uint8Array(randomBytes(NONCE_LEN));
  const header = new Uint8Array(HEADER_LEN);
  header.set(MAGIC, 0);
  header.set([logN, r, p], 4);
  header.set(salt, 7);
  header.set(nonce, 7 + SALT_LEN);
  const key = kdf(password, salt, logN, r, p);
  const ad = new Uint8Array(header.length + extra.length);
  ad.set(header, 0);
  ad.set(extra, header.length);
  const body = seal(key, nonce, plain, ad);
  const blob = new Uint8Array(header.length + body.length);
  blob.set(header, 0);
  blob.set(body, header.length);
  return armor ? Buffer.from(blob).toString('base64url') : blob;
}

/** Decrypt the output of encrypt() (Uint8Array or the armored base64url string). */
export function decrypt(blob, password, { aad = new Uint8Array(0) } = {}) {
  if (typeof blob === 'string') {
    const text = blob.trim();
    if (!/^[A-Za-z0-9_-]*$/.test(text)) throw new VornError('Malformed ciphertext.');
    blob = new Uint8Array(Buffer.from(text, 'base64url'));
  }
  blob = asBytes(blob, 'blob');
  const extra = asBytes(aad, 'aad');
  if (blob.length < HEADER_LEN + TAG_LEN) throw new VornError('Malformed ciphertext.');
  for (let i = 0; i < MAGIC.length; i++) if (blob[i] !== MAGIC[i]) throw new VornError('Malformed ciphertext.');
  const [logN, r, p] = [blob[4], blob[5], blob[6]];
  checkScryptParams(logN, r, p);
  const salt = blob.subarray(7, 7 + SALT_LEN);
  const nonce = blob.subarray(7 + SALT_LEN, HEADER_LEN);
  const header = blob.subarray(0, HEADER_LEN);
  const key = kdf(password, salt, logN, r, p);
  const ad = new Uint8Array(header.length + extra.length);
  ad.set(header, 0);
  ad.set(extra, header.length);
  return unseal(key, nonce, blob.subarray(HEADER_LEN), ad);
}
