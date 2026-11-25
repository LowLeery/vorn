import hashlib
import hmac
import secrets

__version__ = "0.1.0"
__all__ = ["encrypt", "decrypt", "VornError"]


class VornError(Exception):
    pass


def _generate_primes(limit: int = 120) -> tuple[int, ...]:
    primes: list[int] = []
    num = 2
    while len(primes) < limit:
        if all(num % p != 0 for p in primes if p * p <= num):
            primes.append(num)
        num += 1
    return tuple(primes)


_PRIMES = _generate_primes(120)


def _ct_lookup(table, target_idx: int) -> int:
    result = 0
    for i, val in enumerate(table):
        mask = -int(i == target_idx)
        result |= val & mask
    return result


def _ct_prime_index(prime_val: int) -> int:
    result = -1
    for i in range(100):
        mask = -int(_PRIMES[i] == prime_val)
        result = (result & ~mask) | (i & mask)
    if result == -1:
        raise VornError("Invalid state encountered during decryption.")
    return result


def _derive_keys(password: str, nonce: bytes, scrypt_n: int = 16384):
    if not password:
        raise VornError("Password must not be empty.")

    master_key = hashlib.scrypt(
        password.encode("utf-8"),
        salt=nonce,
        n=scrypt_n,
        r=8,
        p=1,
        dklen=64,
    )

    enc_seed = master_key[:24]
    pbox_seed = master_key[24:32]
    mac_key = master_key[32:]

    a = ((enc_seed[0] % 6) + 2) * 8

    valid_b = (3, 5, 7, 9, 11, 13, 15, 17, 19)
    filtered_b = [val for val in valid_b if a % val != 0]
    b = filtered_b[enc_seed[1] % len(filtered_b)]

    x = (1, 2, 4, 8)[enc_seed[2] % 4]
    c = a // x
    d = enc_seed[3] % 2

    s0_forward = (int.from_bytes(enc_seed[4:6], "big") % 900) + 100
    s0_backward = (int.from_bytes(enc_seed[6:8], "big") % 900) + 100

    sbox = list(range(16))
    for i in range(15, 0, -1):
        j = enc_seed[8 + (15 - i)] % (i + 1)
        sbox[i], sbox[j] = sbox[j], sbox[i]

    inv_sbox = [0] * 16
    for idx, val in enumerate(sbox):
        inv_sbox[val] = idx

    return a, b, c, d, s0_forward, s0_backward, sbox, inv_sbox, pbox_seed, mac_key


def _permute_bits(data: bytes, pbox_seed: bytes, inverse: bool = False) -> bytes:
    total_bits = len(data) * 8
    if total_bits == 0:
        return data

    perm = list(range(total_bits))
    stream = bytearray()
    counter = 0
    needed_bytes = total_bits * 4
    while len(stream) < needed_bytes:
        stream.extend(
            hashlib.blake2b(pbox_seed + counter.to_bytes(4, "big"), digest_size=64).digest()
        )
        counter += 1

    for i in range(total_bits - 1, 0, -1):
        offset = (total_bits - 1 - i) * 4
        rand_val = int.from_bytes(stream[offset : offset + 4], "big")
        j = rand_val % (i + 1)
        perm[i], perm[j] = perm[j], perm[i]

    bits = [(data[idx // 8] >> (7 - (idx % 8))) & 1 for idx in range(total_bits)]
    out_bits = [0] * total_bits

    if not inverse:
        for dst, src in enumerate(perm):
            out_bits[dst] = bits[src]
    else:
        for dst, src in enumerate(perm):
            out_bits[src] = bits[dst]

    out_bytes = bytearray(len(data))
    for i, bit in enumerate(out_bits):
        if bit:
            out_bytes[i // 8] |= 1 << (7 - (i % 8))

    return bytes(out_bytes)


def _sign(i: int, c: int, d: int) -> int:
    block_parity = (i // c) % 2
    if d == 0:
        return -1 if block_parity == 0 else 1
    return 1 if block_parity == 0 else -1


def _prime_pass_encrypt(symbols, a: int, b: int, c: int, d: int, s0: int) -> list[int]:
    prev = s0
    out = []
    for i, sym in enumerate(symbols):
        jump = a + (prev % 16)
        jumped_prime = _ct_lookup(_PRIMES, sym + jump)
        offset = (a % b) + (prev % b)
        cipher_val = jumped_prime + _sign(i, c, d) * offset
        out.append(cipher_val)
        prev = cipher_val
    return out


def _prime_pass_decrypt(cipher_vals, a: int, b: int, c: int, d: int, s0: int) -> list[int]:
    prev = s0
    out = []
    for i, c_val in enumerate(cipher_vals):
        offset = (a % b) + (prev % b)
        jumped_prime = c_val - _sign(i, c, d) * offset
        jumped_idx = _ct_prime_index(jumped_prime)
        jump = a + (prev % 16)
        out.append(jumped_idx - jump)
        prev = c_val
    return out


def encrypt(data: bytes | str, password: str, *, _scrypt_n: int = 16384) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")

    nonce = secrets.token_bytes(16)
    a, b, c, d, s0_f, s0_b, sbox, _, pbox_seed, mac_key = _derive_keys(password, nonce, _scrypt_n)

    nibbles = []
    for byte in data:
        nibbles.append(_ct_lookup(sbox, (byte >> 4) & 0x0F))
        nibbles.append(_ct_lookup(sbox, byte & 0x0F))

    pass1 = _prime_pass_encrypt(nibbles, a, b, c, d, s0_f)

    pass1_bytes = b"".join(val.to_bytes(2, "big") for val in pass1)
    permuted_bytes = _permute_bits(pass1_bytes, pbox_seed, inverse=False)

    mid_nibbles = []
    for byte in reversed(permuted_bytes):
        mid_nibbles.append((byte >> 4) & 0x0F)
        mid_nibbles.append(byte & 0x0F)

    pass2 = _prime_pass_encrypt(mid_nibbles, a, b, c, d, s0_b)

    nonce_str = "".join(f"{byte:03d}" for byte in nonce)
    cipher_str = "".join(f"{val:03d}" for val in pass2)
    payload = nonce_str + cipher_str

    mac_digest = hmac.new(mac_key, payload.encode("ascii"), hashlib.sha256).digest()
    mac_str = "".join(f"{byte:03d}" for byte in mac_digest)

    return payload + mac_str


def decrypt(ciphertext: str, password: str, *, _scrypt_n: int = 16384) -> bytes:
    if (
        not isinstance(ciphertext, str)
        or len(ciphertext) < 144
        or len(ciphertext) % 3 != 0
        or not (ciphertext.isascii() and ciphertext.isdigit())
    ):
        raise VornError("Malformed ciphertext packet.")

    nonce_str = ciphertext[:48]
    mac_str = ciphertext[-96:]
    cipher_str = ciphertext[48:-96]

    try:
        nonce = bytes(int(nonce_str[i : i + 3]) for i in range(0, 48, 3))
    except ValueError as exc:
        raise VornError("Corrupted nonce block.") from exc

    a, b, c, d, s0_f, s0_b, _, inv_sbox, pbox_seed, mac_key = _derive_keys(
        password, nonce, _scrypt_n
    )

    expected_mac = hmac.new(mac_key, (nonce_str + cipher_str).encode("ascii"), hashlib.sha256).digest()
    expected_mac_str = "".join(f"{byte:03d}" for byte in expected_mac)
    if not hmac.compare_digest(mac_str, expected_mac_str):
        raise VornError("Authentication failed: invalid password or tampered payload.")

    pass2 = [int(cipher_str[i : i + 3]) for i in range(0, len(cipher_str), 3)]
    if len(pass2) % 8 != 0:
        raise VornError("Malformed ciphertext packet.")

    mid_nibbles = _prime_pass_decrypt(pass2, a, b, c, d, s0_b)

    reversed_permuted = bytearray()
    for i in range(0, len(mid_nibbles), 2):
        reversed_permuted.append((mid_nibbles[i] << 4) | mid_nibbles[i + 1])

    permuted_bytes = bytes(reversed(reversed_permuted))
    pass1_bytes = _permute_bits(permuted_bytes, pbox_seed, inverse=True)

    pass1 = [int.from_bytes(pass1_bytes[i : i + 2], "big") for i in range(0, len(pass1_bytes), 2)]

    mapped_nibbles = _prime_pass_decrypt(pass1, a, b, c, d, s0_f)
    raw_nibbles = [_ct_lookup(inv_sbox, n) for n in mapped_nibbles]

    result = bytearray()
    for i in range(0, len(raw_nibbles), 2):
        result.append((raw_nibbles[i] << 4) | raw_nibbles[i + 1])

    return bytes(result)
