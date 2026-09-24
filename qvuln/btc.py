"""Bitcoin primitives: hashes, varints, amount (de)compression, script analysis.

All functions accept any bytes-like object (bytes, memoryview, mmap) plus an
offset, so callers can parse in-place without copying.
"""
from __future__ import annotations

import hashlib
import struct


def sha256(b) -> bytes:
    return hashlib.sha256(b).digest()


def hash160(b) -> bytes:
    return hashlib.new("ripemd160", hashlib.sha256(b).digest()).digest()


# ---------------------------------------------------------------------------
# Varints
# ---------------------------------------------------------------------------

def read_compact_size(buf, off: int):
    """Bitcoin CompactSize (used for tx counts, script lengths, ...)."""
    b0 = buf[off]
    if b0 < 0xFD:
        return b0, off + 1
    if b0 == 0xFD:
        return struct.unpack_from("<H", buf, off + 1)[0], off + 3
    if b0 == 0xFE:
        return struct.unpack_from("<I", buf, off + 1)[0], off + 5
    return struct.unpack_from("<Q", buf, off + 1)[0], off + 9


def write_compact_size(n: int) -> bytes:
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


def read_varint(buf, off: int):
    """Bitcoin's custom base-128 MSB-first VARINT (serialize.h, VARINT mode).

    Used inside the chainstate / UTXO-snapshot coin serialization.
    """
    n = 0
    while True:
        b = buf[off]
        off += 1
        n = (n << 7) | (b & 0x7F)
        if b & 0x80:
            n += 1
        else:
            return n, off


def write_varint(n: int) -> bytes:
    tmp = bytearray()
    while True:
        tmp.append((n & 0x7F) | (0x80 if tmp else 0x00))
        if n <= 0x7F:
            break
        n = (n >> 7) - 1
    tmp.reverse()
    return bytes(tmp)


# ---------------------------------------------------------------------------
# Amount compression (bitcoin-core src/compressor.cpp)
# ---------------------------------------------------------------------------

def decompress_amount(x: int) -> int:
    if x == 0:
        return 0
    x -= 1
    e = x % 10
    x //= 10
    if e < 9:
        d = (x % 9) + 1
        x //= 9
        n = x * 10 + d
    else:
        n = x + 1
    return n * (10 ** e)


def compress_amount(n: int) -> int:
    if n == 0:
        return 0
    e = 0
    while n % 10 == 0 and e < 9:
        n //= 10
        e += 1
    if e < 9:
        d = n % 10
        n //= 10
        return 1 + (n * 9 + d - 1) * 10 + e
    return 1 + (n - 1) * 10 + 9


# ---------------------------------------------------------------------------
# Script analysis
# ---------------------------------------------------------------------------

def is_pubkey_at(buf, off: int, ln: int) -> bool:
    if ln == 33:
        return buf[off] == 2 or buf[off] == 3
    if ln == 65:
        return buf[off] == 4
    return False


def classify_spk(buf, off: int, ln: int):
    """Classify a scriptPubKey located at buf[off:off+ln].

    Returns (kind, payload) where kind is one of
    p2pk, p2ms, p2pkh, p2sh, p2wpkh, p2wsh, p2tr, other
    and payload is:
      - (offset, length) of the hash / pubkey for single-item types
      - list of (offset, length) for p2ms
      - None for 'other'
    """
    if ln == 25 and buf[off] == 0x76 and buf[off + 1] == 0xA9 and buf[off + 2] == 0x14 \
            and buf[off + 23] == 0x88 and buf[off + 24] == 0xAC:
        return "p2pkh", (off + 3, 20)
    if ln == 23 and buf[off] == 0xA9 and buf[off + 1] == 0x14 and buf[off + 22] == 0x87:
        return "p2sh", (off + 2, 20)
    if ln == 22 and buf[off] == 0x00 and buf[off + 1] == 0x14:
        return "p2wpkh", (off + 2, 20)
    if ln == 34 and buf[off + 1] == 0x20:
        if buf[off] == 0x00:
            return "p2wsh", (off + 2, 32)
        if buf[off] == 0x51:
            return "p2tr", (off + 2, 32)
    if ln == 35 and buf[off] == 0x21 and buf[off + 34] == 0xAC and buf[off + 1] in (2, 3):
        return "p2pk", (off + 1, 33)
    if ln == 67 and buf[off] == 0x41 and buf[off + 66] == 0xAC and buf[off + 1] == 4:
        return "p2pk", (off + 1, 65)
    if ln >= 37 and 0x51 <= buf[off] <= 0x60 and buf[off + ln - 1] == 0xAE \
            and 0x51 <= buf[off + ln - 2] <= 0x60:
        pubs = _bare_multisig_pubs(buf, off, ln)
        if pubs is not None:
            return "p2ms", pubs
    return "other", None


def _bare_multisig_pubs(buf, off: int, ln: int):
    """Validate OP_m <pub...> OP_n OP_CHECKMULTISIG; return pubkey spans or None."""
    end = off + ln - 2  # position of OP_n
    cur = off + 1
    pubs = []
    while cur < end:
        l = buf[cur]
        if l != 33 and l != 65:
            return None
        pk_off = cur + 1
        if pk_off + l > end:
            return None
        if not is_pubkey_at(buf, pk_off, l):
            return None
        pubs.append((pk_off, l))
        cur = pk_off + l
    if cur != end:
        return None
    m = buf[off] - 0x50
    n = buf[off + ln - 2] - 0x50
    if n != len(pubs) or m < 1 or m > n:
        return None
    return pubs


def parse_one_push(buf, off: int, end: int):
    """Parse one push-only data item starting at off.

    Returns (data_off, data_len, next_off) or None if the opcode is not a
    push or the data overruns end.
    """
    if off >= end:
        return None
    op = buf[off]
    if op <= 75:
        l = op
        off += 1
    elif op == 0x4C:  # OP_PUSHDATA1
        if off + 2 > end:
            return None
        l = buf[off + 1]
        off += 2
    elif op == 0x4D:  # OP_PUSHDATA2
        if off + 3 > end:
            return None
        l = struct.unpack_from("<H", buf, off + 1)[0]
        off += 3
    elif op == 0x4E:  # OP_PUSHDATA4
        if off + 5 > end:
            return None
        l = struct.unpack_from("<I", buf, off + 1)[0]
        off += 5
    else:
        return None
    if off + l > end:
        return None
    return (off, l, off + l)


def script_pubkeys(buf, off: int, ln: int):
    """Extract all pubkey-looking pushes from an arbitrary script.

    Returns a list of (offset, length) (empty if none), or None if the
    script is malformed (push overruns the end).
    """
    end = off + ln
    cur = off
    pubs = []
    while cur < end:
        op = buf[cur]
        if op <= 75:
            l = op
            cur += 1
        elif op == 0x4C:
            if cur + 2 > end:
                return None
            l = buf[cur + 1]
            cur += 2
        elif op == 0x4D:
            if cur + 3 > end:
                return None
            l = struct.unpack_from("<H", buf, cur + 1)[0]
            cur += 3
        elif op == 0x4E:
            if cur + 5 > end:
                return None
            l = struct.unpack_from("<I", buf, cur + 1)[0]
            cur += 5
        else:
            cur += 1
            continue
        if cur + l > end:
            return None
        if is_pubkey_at(buf, cur, l):
            pubs.append((cur, l))
        cur += l
    return pubs
