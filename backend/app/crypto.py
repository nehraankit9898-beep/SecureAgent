"""Small, dependency-free authenticated encryption for local secret storage.

Why this exists: SecureAgent must never keep raw API keys in logs, memory,
prompts, task history, frontend state or plain configuration. The preferred
store is the operating system credential vault (``keyring``); when that is not
available the fallback is an encrypted file written with ``0600`` permissions.

The fallback uses standard, well-specified primitives implemented here from the
RFCs (no third-party dependency is available in the offline install):
``ChaCha20`` (RFC 8439 §2.3) keystream encryption + ``HMAC-SHA256`` in an
encrypt-then-MAC construction, with a key derived through ``scrypt``. The
module ships an RFC 8439 test vector in the test suite, so the cipher is
verified rather than assumed.

Honest limitation (documented, not hidden): this protects secrets at rest
against accidental disclosure (backups, file reads, cloud-sync of the data
directory, logs). It does not protect against an attacker who already has code
execution as the same OS user — no local secret store can.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import struct

MASK32 = 0xFFFFFFFF
CONSTANTS = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)  # "expand 32-byte k"


def _rotl(value: int, shift: int) -> int:
    return ((value << shift) & MASK32) | (value >> (32 - shift))


def _quarter_round(state: list[int], a: int, b: int, c: int, d: int) -> None:
    state[a] = (state[a] + state[b]) & MASK32
    state[d] = _rotl(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & MASK32
    state[b] = _rotl(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b]) & MASK32
    state[d] = _rotl(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & MASK32
    state[b] = _rotl(state[b] ^ state[c], 7)


def chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    """RFC 8439 §2.3.2 block function (64-byte keystream block)."""
    if len(key) != 32 or len(nonce) != 12:
        raise ValueError("ChaCha20 requires a 32-byte key and a 12-byte nonce")
    state = list(CONSTANTS) + list(struct.unpack("<8I", key)) + [counter & MASK32] + list(
        struct.unpack("<3I", nonce))
    working = list(state)
    for _ in range(10):
        _quarter_round(working, 0, 4, 8, 12)
        _quarter_round(working, 1, 5, 9, 13)
        _quarter_round(working, 2, 6, 10, 14)
        _quarter_round(working, 3, 7, 11, 15)
        _quarter_round(working, 0, 5, 10, 15)
        _quarter_round(working, 1, 6, 11, 12)
        _quarter_round(working, 2, 7, 8, 13)
        _quarter_round(working, 3, 4, 9, 14)
    return struct.pack("<16I", *[(working[i] + state[i]) & MASK32 for i in range(16)])


def chacha20_xor(key: bytes, nonce: bytes, data: bytes, *, counter: int = 1) -> bytes:
    output = bytearray(len(data))
    for offset in range(0, len(data), 64):
        block = chacha20_block(key, counter + offset // 64, nonce)
        chunk = data[offset:offset + 64]
        for index, byte in enumerate(chunk):
            output[offset + index] = byte ^ block[index]
    return bytes(output)


def derive_key(secret: bytes, salt: bytes, *, length: int = 32,
               n: int = 2 ** 14, r: int = 8, p: int = 1) -> bytes:
    return hashlib.scrypt(secret, salt=salt, n=n, r=r, p=p, dklen=length)


def encrypt(master_key: bytes, plaintext: bytes, *, associated_data: bytes = b"") -> bytes:
    """Encrypt-then-MAC. Returns ``nonce || ciphertext || tag``."""
    nonce = secrets.token_bytes(12)
    ciphertext = chacha20_xor(master_key, nonce, plaintext)
    tag = hmac.new(master_key, nonce + ciphertext + associated_data, hashlib.sha256).digest()
    return nonce + ciphertext + tag


def decrypt(master_key: bytes, payload: bytes, *, associated_data: bytes = b"") -> bytes:
    if len(payload) < 12 + 32:
        raise ValueError("ciphertext is truncated")
    nonce, ciphertext, tag = payload[:12], payload[12:-32], payload[-32:]
    expected = hmac.new(master_key, nonce + ciphertext + associated_data, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, tag):
        raise ValueError("authentication failed")
    return chacha20_xor(master_key, nonce, ciphertext)


def new_master_key() -> bytes:
    return secrets.token_bytes(32)


def load_or_create_key(path) -> bytes:
    """Read (or create) a 0600 master-key file; the key never leaves the disk."""
    from pathlib import Path
    target = Path(path)
    if target.exists():
        raw = target.read_bytes()
        if len(raw) != 32:
            raise ValueError("master key file is corrupt")
        return raw
    target.parent.mkdir(parents=True, exist_ok=True)
    key = new_master_key()
    descriptor = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(descriptor, key)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return key
