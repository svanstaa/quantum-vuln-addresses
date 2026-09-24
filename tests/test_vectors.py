"""Unit tests for qvuln.btc primitives."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from qvuln.btc import (classify_spk, compress_amount, decompress_amount,
                       hash160, parse_one_push, read_compact_size,
                       read_varint, script_pubkeys, sha256,
                       write_compact_size, write_varint)


def test_varint_vectors():
    # serialize.h VARINT round-trips and known encodings
    assert write_varint(0) == b"\x00"
    assert write_varint(0x7F) == b"\x7f"
    assert write_varint(0x80) == b"\x80\x00"
    assert write_varint(0x4000) == b"\xff\x00"
    for n in [0, 1, 2, 127, 128, 129, 255, 256, 16383, 16384, 2**32 - 1,
              2**32, 968431 * 2 + 1, 2**60]:
        enc = write_varint(n)
        dec, off = read_varint(enc, 0)
        assert dec == n and off == len(enc), (n, enc.hex(), dec)


def test_compact_size():
    for n in [0, 1, 252, 253, 254, 65535, 65536, 2**32 - 1, 2**32, 10**12]:
        enc = write_compact_size(n)
        dec, off = read_compact_size(enc, 0)
        assert dec == n and off == len(enc)


def test_amount_codec():
    # vectors verified against bitcoin-core compressor.cpp semantics
    assert decompress_amount(0) == 0
    assert decompress_amount(1) == 1
    assert decompress_amount(9) == 100_000_000          # 1 BTC
    assert decompress_amount(50) == 5_000_000_000       # 50 BTC
    assert compress_amount(0) == 0
    assert compress_amount(1) == 1
    assert compress_amount(100_000_000) == 9
    assert compress_amount(5_000_000_000) == 50
    for n in [0, 1, 7, 10, 100, 12345, 21_000_000 * 100_000_000,
              5_768_234, 99_999_999_999]:
        assert decompress_amount(compress_amount(n)) == n


def _pk33(tag=b"\x02"):
    return tag + bytes(range(1, 33))


def _pk65():
    return b"\x04" + bytes(range(1, 65))


def test_classify_spk():
    h20 = bytes(range(20))
    h32 = bytes(range(32))
    # p2pkh
    s = b"\x76\xa9\x14" + h20 + b"\x88\xac"
    k, p = classify_spk(s, 0, len(s))
    assert k == "p2pkh" and bytes(s[p[0]:p[0] + p[1]]) == h20
    # p2sh
    s = b"\xa9\x14" + h20 + b"\x87"
    k, p = classify_spk(s, 0, len(s))
    assert k == "p2sh"
    # p2wpkh
    s = b"\x00\x14" + h20
    k, p = classify_spk(s, 0, len(s))
    assert k == "p2wpkh"
    # p2wsh
    s = b"\x00\x20" + h32
    k, p = classify_spk(s, 0, len(s))
    assert k == "p2wsh"
    # p2tr
    s = b"\x51\x20" + h32
    k, p = classify_spk(s, 0, len(s))
    assert k == "p2tr"
    # p2pk compressed / uncompressed
    s = b"\x21" + _pk33() + b"\xac"
    k, p = classify_spk(s, 0, len(s))
    assert k == "p2pk" and p == (1, 33)
    s = b"\x41" + _pk65() + b"\xac"
    k, p = classify_spk(s, 0, len(s))
    assert k == "p2pk" and p == (1, 65)
    # bare multisig 2-of-3
    pubs = [_pk33(b"\x02"), _pk33(b"\x03"), _pk33(b"\x02")]
    s = b"\x52" + b"".join(bytes([len(p)]) + p for p in pubs) + b"\x53\xae"
    k, p = classify_spk(s, 0, len(s))
    assert k == "p2ms" and len(p) == 3
    # invalid: m > n
    s = b"\x53" + b"".join(bytes([len(p)]) + p for p in pubs) + b"\x52\xae"
    k, _ = classify_spk(s, 0, len(s))
    assert k == "other"
    # op_return
    s = b"\x6a\x04dead"
    k, _ = classify_spk(s, 0, len(s))
    assert k == "other"


def test_script_pubkeys():
    pk = _pk33()
    # 1-of-1 multisig script
    s = b"\x51" + bytes([33]) + pk + b"\x51\xae"
    pubs = script_pubkeys(s, 0, len(s))
    assert pubs and len(pubs) == 1
    # malformed: push overruns
    assert script_pubkeys(b"\x21\x02\x03", 0, 3) is None
    # no pubkeys
    assert script_pubkeys(b"\x51\x51\x52", 0, 3) == []


def test_parse_one_push():
    sig = b"\x30" + bytes(70)
    pk = _pk33()
    s = bytes([len(sig)]) + sig + bytes([33]) + pk
    end = len(s)
    p1 = parse_one_push(s, 0, end)
    assert p1 == (1, len(sig), 1 + len(sig))
    p2 = parse_one_push(s, p1[2], end)
    assert p2 == (1 + len(sig) + 1, 33, end)
    # non-push opcode
    assert parse_one_push(b"\xac", 0, 1) is None


def test_hashes():
    # known hash160 of empty-ish input sanity via hashlib
    assert len(sha256(b"x")) == 32
    assert len(hash160(b"x")) == 20


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"ok {fn.__name__}")
    print("all unit tests passed")
