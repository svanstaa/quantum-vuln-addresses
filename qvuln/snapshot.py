"""Parser for Bitcoin Core `dumptxoutset` snapshot files.

Format (verified against Bitcoin Core v31.1, src/node/utxo_snapshot.h and
src/rpc/blockchain.cpp::WriteUTXOSnapshot):

  Header (SnapshotMetadata, version 2):
    5 bytes  magic "utxo\\xff"
    2 bytes  uint16 LE version (= 2)
    4 bytes  network magic (mainnet f9beb4d9)
    32 bytes base blockhash (internal / little-endian byte order)
    8 bytes  uint64 LE coins_count

  Body: coins grouped by txid (leveldb lexicographic key order):
    32 bytes txid (internal byte order)
    CompactSize  number of coins for this txid
    per coin:
      CompactSize  vout
      VARINT       code = height*2 + coinbase_flag
      VARINT       compressed amount (compressor.cpp)
      compressed script:
        VARINT nsize
        nsize == 0          -> 20 bytes follow: P2PKH hash160
        nsize == 1          -> 20 bytes follow: P2SH hash160
        nsize == 2 or 3     -> 32 bytes follow: P2PK, compressed pubkey x
                               (full pubkey = bytes([nsize]) + x)
        nsize == 4 or 5     -> 32 bytes follow: P2PK, uncompressed pubkey x
                               (y parity = nsize - 4)
        nsize >= 6          -> (nsize - 6) raw scriptPubKey bytes follow
"""
from __future__ import annotations

import mmap
import struct

from .btc import classify_spk, decompress_amount, read_compact_size, read_varint

SNAPSHOT_MAGIC = b"utxo\xff"
HEADER_LEN = 5 + 2 + 4 + 32 + 8
MAINNET_MAGIC = b"\xf9\xbe\xb4\xd9"


class SnapshotError(Exception):
    pass


def open_snapshot(path: str):
    f = open(path, "rb")
    mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
    return f, mm


def parse_header(mm) -> dict:
    if len(mm) < HEADER_LEN:
        raise SnapshotError("file too small for snapshot header")
    if bytes(mm[:5]) != SNAPSHOT_MAGIC:
        raise SnapshotError("bad snapshot magic bytes")
    version = struct.unpack_from("<H", mm, 5)[0]
    if version != 2:
        raise SnapshotError(f"unsupported snapshot version {version}")
    return {
        "version": version,
        "network_magic": bytes(mm[7:11]),
        "base_hash": bytes(mm[11:43])[::-1].hex(),  # to display byte order
        "coins_count": struct.unpack_from("<Q", mm, 43)[0],
    }


def read_compressed_script(mm, off: int):
    """Classify the compressed script starting at off.

    Returns (kind, payload, new_off). payload is (offset, length) into mm
    for hash/pubkey-like kinds (for compressed p2pk it points at the
    33-byte reconstructed compressed pubkey, reusing the nsize byte as the
    prefix), or whatever classify_spk returned for raw scripts.
    """
    nsize, off = read_varint(mm, off)
    if nsize == 0:
        return "p2pkh", (off, 20), off + 20
    if nsize == 1:
        return "p2sh", (off, 20), off + 20
    if nsize == 2 or nsize == 3:
        # nsize byte doubles as the compressed-pubkey prefix byte
        return "p2pk", (off - 1, 33), off + 32
    if nsize == 4 or nsize == 5:
        # uncompressed p2pk: only the x coordinate is stored; we never need
        # the full pubkey from the snapshot, so just point at the x bytes.
        return "p2pk", (off, 32), off + 32
    rawlen = nsize - 6
    if rawlen < 0:
        raise SnapshotError(f"invalid compressed script size {nsize}")
    kind, payload = classify_spk(mm, off, rawlen)
    return kind, payload, off + rawlen


def iter_coins(mm, start: int = HEADER_LEN):
    """Reference coin iterator (used by tests). Yields
    (height, coinbase, vout, amount_sat, kind, payload) for every coin."""
    off = start
    n = len(mm)
    while off < n:
        off += 32  # txid
        ng, off = read_compact_size(mm, off)
        for _ in range(ng):
            vout, off = read_compact_size(mm, off)
            code, off = read_varint(mm, off)
            camt, off = read_varint(mm, off)
            amt = decompress_amount(camt)
            kind, payload, off = read_compressed_script(mm, off)
            yield code >> 1, code & 1, vout, amt, kind, payload
