import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

import { ROUND_CONSTANTS, VornError, decrypt, encrypt, permute, seal, unseal } from '../src/index.js';

const vectors = JSON.parse(readFileSync(new URL('../../vectors/vectors.json', import.meta.url), 'utf8'));
const hex = (u8) => Buffer.from(u8).toString('hex');
const fromHex = (s) => new Uint8Array(Buffer.from(s, 'hex'));
const LOG_N = 4; // tiny scrypt cost, tests only

test('round constants are the SHA-256 style sqrt-of-prime words', () => {
  assert.deepEqual(ROUND_CONSTANTS.slice(0, 4), [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a]);
  assert.equal(ROUND_CONSTANTS.length, 20);
});

test('permutation known answer (shared with the Python reference)', () => {
  const st = new Uint8Array(64);
  permute(st);
  assert.equal(hex(st), vectors.permutationZeroState);
});

for (const [i, v] of vectors.aead.entries()) {
  test(`AEAD known answer ${i + 1} (shared with the Python reference)`, () => {
    const key = fromHex(v.key), nonce = fromHex(v.nonce), aad = fromHex(v.aad), pt = fromHex(v.pt);
    assert.equal(hex(seal(key, nonce, pt, aad)), v.out);
    assert.equal(hex(unseal(key, nonce, fromHex(v.out), aad)), v.pt);
  });
}

for (const [i, v] of vectors.password.entries()) {
  test(`password container known answer ${i + 1} (produced by Python)`, () => {
    const out = decrypt(fromHex(v.blob), v.password, { aad: fromHex(v.aad) });
    assert.equal(hex(out), v.plaintext);
  });
}

test('AEAD roundtrip and lengths', () => {
  const key = randomBytes(32), nonce = randomBytes(16);
  for (const n of [0, 1, 31, 32, 33, 64, 65, 1000]) {
    const pt = new Uint8Array(randomBytes(n));
    const sealed = seal(key, nonce, pt, 'ad');
    assert.equal(sealed.length, n + 16);
    assert.deepEqual(unseal(key, nonce, sealed, 'ad'), pt);
  }
});

test('AEAD rejects every single-bit modification', () => {
  const key = randomBytes(32), nonce = randomBytes(16);
  const sealed = seal(key, nonce, randomBytes(70), 'aad');
  for (let i = 0; i < sealed.length; i++) {
    for (const bit of [0, 7]) {
      const bad = Uint8Array.from(sealed);
      bad[i] ^= 1 << bit;
      assert.throws(() => unseal(key, nonce, bad, 'aad'), VornError);
    }
  }
});

test('AEAD binds aad, key and nonce, and rejects truncation', () => {
  const key = randomBytes(32), nonce = randomBytes(16);
  const sealed = seal(key, nonce, 'payload', 'aad');
  assert.throws(() => unseal(key, nonce, sealed, 'other'), VornError);
  assert.throws(() => unseal(randomBytes(32), nonce, sealed, 'aad'), VornError);
  assert.throws(() => unseal(key, randomBytes(16), sealed, 'aad'), VornError);
  for (const bad of [sealed.subarray(0, -1), sealed.subarray(1), new Uint8Array(0), sealed.subarray(0, 15)]) {
    assert.throws(() => unseal(key, nonce, bad, 'aad'), VornError);
  }
});

test('bad key and nonce sizes', () => {
  assert.throws(() => seal(new Uint8Array(5), new Uint8Array(16), 'x'), VornError);
  assert.throws(() => seal(new Uint8Array(32), new Uint8Array(5), 'x'), VornError);
});

test('password roundtrip: text, unicode, binary, empty', () => {
  for (const data of ['merhaba dünya 🌍', 'x'.repeat(5000), new Uint8Array(256).map((_, i) => i), new Uint8Array(0)]) {
    const blob = encrypt(data, 'pw-ğüşiöç', { logN: LOG_N });
    const expected = typeof data === 'string' ? new TextEncoder().encode(data) : data;
    assert.deepEqual(decrypt(blob, 'pw-ğüşiöç'), expected);
  }
});

test('armor, whitespace and user aad', () => {
  const text = encrypt('armored', 'pw', { logN: LOG_N, armor: true });
  assert.equal(typeof text, 'string');
  assert.ok(!text.includes('='));
  assert.equal(Buffer.from(decrypt(`  ${text}\n`, 'pw')).toString(), 'armored');
  const blob = encrypt('data', 'pw', { logN: LOG_N, aad: 'context-1' });
  assert.equal(Buffer.from(decrypt(blob, 'pw', { aad: 'context-1' })).toString(), 'data');
  assert.throws(() => decrypt(blob, 'pw', { aad: 'context-2' }), VornError);
});

test('wrong, empty password and malformed input', () => {
  const blob = encrypt('secret', 'right', { logN: LOG_N });
  assert.throws(() => decrypt(blob, 'wrong'), VornError);
  assert.throws(() => decrypt(blob, ''), VornError);
  assert.throws(() => encrypt('x', '', { logN: LOG_N }), VornError);
  for (const bad of [new Uint8Array(0), Buffer.from('VRN2'), new Uint8Array(80), '!!!notbase64!!!', 'A'.repeat(10)]) {
    assert.throws(() => decrypt(bad, 'pw'), VornError);
  }
});

test('every byte of the password blob is authenticated', () => {
  const blob = encrypt('authenticated', 'pw', { logN: LOG_N });
  for (let i = 0; i < blob.length; i++) {
    const bad = Uint8Array.from(blob);
    bad[i] ^= 1;
    assert.throws(() => decrypt(bad, 'pw'), VornError);
  }
});

test('fresh salt and nonce every time', () => {
  const a = encrypt('same', 'pw', { logN: LOG_N });
  const b = encrypt('same', 'pw', { logN: LOG_N });
  assert.notDeepEqual(a, b);
  assert.notDeepEqual(a.subarray(7, 39), b.subarray(7, 39));
});

test('unreasonable scrypt parameters are rejected', () => {
  const blob = Uint8Array.from(encrypt('x', 'pw', { logN: LOG_N }));
  blob[4] = 30;
  assert.throws(() => decrypt(blob, 'pw'), VornError);
  assert.throws(() => encrypt('x', 'pw', { logN: 30 }), VornError);
});

test('large message', () => {
  const key = randomBytes(32), nonce = randomBytes(16);
  const data = new Uint8Array(randomBytes(200_000));
  assert.deepEqual(unseal(key, nonce, seal(key, nonce, data)), data);
});
