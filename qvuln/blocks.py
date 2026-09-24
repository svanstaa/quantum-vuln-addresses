"""Helpers for Bitcoin Core blk*.dat files."""
from __future__ import annotations

import os
import re

import numpy as np

BLK_MAGIC = b"\xf9\xbe\xb4\xd9"  # mainnet

_BLK_RE = re.compile(r"blk(\d{5})\.dat$")


def load_xor_key(blocks_dir: str):
    """Bitcoin Core >= v28 obfuscates blk/rev files by XORing them with the
    8-byte key in blocks/xor.dat. Return the key, or None if unobfuscated."""
    p = os.path.join(blocks_dir, "xor.dat")
    if not os.path.exists(p):
        return None
    with open(p, "rb") as f:
        key = f.read()
    if len(key) != 8 or key == b"\x00" * 8:
        return None
    return key


def read_blk_file(path: str, xor_key):
    """Read a blk file and return a deobfuscated buffer (memoryview)."""
    with open(path, "rb") as f:
        data = bytearray(f.read())
    if xor_key:
        arr = np.frombuffer(data, dtype=np.uint8)  # writable view
        n8 = len(arr) // 8 * 8
        arr[:n8].view("<u8").__ixor__(
            np.uint64(int.from_bytes(xor_key, "little")))
        for i in range(n8, len(arr)):
            arr[i] ^= xor_key[i % 8]
    return memoryview(data)


def list_blk_files(blocks_dir: str):
    """Return the sorted list of blk*.dat paths; raises if numbering is not
    contiguous from blk00000.dat (e.g. pruned node)."""
    names = {}
    for f in os.listdir(blocks_dir):
        m = _BLK_RE.fullmatch(f)
        if m:
            names[int(m.group(1))] = f
    if not names:
        raise FileNotFoundError(f"no blk*.dat files in {blocks_dir}")
    mx = max(names)
    missing = [i for i in range(mx + 1) if i not in names]
    if missing:
        raise FileNotFoundError(
            f"blk file numbering not contiguous (missing e.g. blk{missing[0]:05d}.dat); "
            "is this a pruned node?"
        )
    return [os.path.join(blocks_dir, names[i]) for i in range(mx + 1)]
