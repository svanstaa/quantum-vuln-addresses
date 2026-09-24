"""End-to-end pipeline test on synthetic snapshot + block files.

Builds a miniature dumptxoutset-format snapshot and a miniature blk file,
runs prepare -> scan -> report, and checks the resulting sums.
"""
import json
import os
import shutil
import struct
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from qvuln.btc import (compress_amount, hash160, write_compact_size,
                       write_varint)
from qvuln.prepare import run_prepare
from qvuln.report import run_report
from qvuln.scan import Funded, Ctx, scan_buffer, flush_cands, _write_hits

# ---------------------------------------------------------------------------
# synthetic key material
# ---------------------------------------------------------------------------
P1 = b"\x02" + bytes(range(1, 33))          # pubkey behind funded P2PKH (reused)
P2 = b"\x03" + bytes(range(33, 65))         # pubkey behind funded P2WPKH (reused)
P4 = b"\x02" + bytes(range(65, 97))         # pubkey behind funded P2PKH (NOT revealed)
PA = b"\x02" + bytes(range(97, 129))        # multisig key A
PB = b"\x03" + bytes(range(129, 161))       # multisig key B
PCB = b"\x04" + bytes(range(1, 65))         # coinbase P2PK pubkey (unfunded)

H1 = hash160(P1)
H2 = hash160(P2)
H4 = hash160(P4)

REDEEM = (b"\x52" + bytes([33]) + PA + bytes([33]) + PB + b"\x52\xae")
H3 = hash160(REDEEM)

TR_KEY = bytes(range(200, 232))

BTC = 100_000_000


def push(b):
    assert len(b) <= 75
    return bytes([len(b)]) + b


# ---------------------------------------------------------------------------
# snapshot builder
# ---------------------------------------------------------------------------

def coin(vout, height, cb, amt_sat, script_enc):
    return (write_compact_size(vout) + write_varint(height * 2 + cb)
            + write_varint(compress_amount(amt_sat)) + script_enc)


def enc_p2pkh(h20):
    return write_varint(0) + h20


def enc_p2sh(h20):
    return write_varint(1) + h20


def enc_p2pk_comp(prefix, x32):
    return write_varint(prefix) + x32


def enc_raw(script):
    return write_varint(len(script) + 6) + script


def build_snapshot(path):
    groups = [
        (b"\xaa" * 32, [
            coin(0, 100, 1, 1 * BTC, enc_p2pkh(H1)),                 # reused later
            coin(1, 100, 1, 2 * BTC, enc_raw(b"\x51\x20" + TR_KEY)),  # p2tr
        ]),
        (b"\xbb" * 32, [
            coin(0, 200, 1, 50 * BTC, enc_p2pk_comp(2, bytes(range(32)))),  # p2pk
            coin(1, 200, 1, BTC // 2, enc_raw(b"\x00\x14" + H2)),     # reused wpkh
            coin(2, 200, 1, 3 * BTC, enc_p2sh(H3)),                   # revealed sh
        ]),
        (b"\xcc" * 32, [
            coin(0, 300, 0, 4 * BTC, enc_p2pkh(H4)),                  # NOT vulnerable
        ]),
    ]
    body = bytearray()
    ncoins = 0
    for txid, coins in groups:
        body += txid
        body += write_compact_size(len(coins))
        for c in coins:
            body += c
            ncoins += 1
    hdr = (b"utxo\xff" + struct.pack("<H", 2) + b"\xf9\xbe\xb4\xd9"
           + b"\x11" * 32 + struct.pack("<Q", ncoins))
    with open(path, "wb") as f:
        f.write(hdr + body)
    return ncoins


# ---------------------------------------------------------------------------
# blk file builder
# ---------------------------------------------------------------------------

def tx(inputs, outputs, witnesses=None):
    """inputs: list of scriptSig bytes; outputs: list of (sat, spk);
    witnesses: None or list (per input) of item lists."""
    out = b"\x02\x00\x00\x00"
    if witnesses is not None:
        out += b"\x00\x01"
    out += write_compact_size(len(inputs))
    for ss in inputs:
        out += b"\x11" * 32 + struct.pack("<I", 0)
        out += write_compact_size(len(ss)) + ss + b"\xff" * 4
    out += write_compact_size(len(outputs))
    for sat, spk in outputs:
        out += struct.pack("<Q", sat) + write_compact_size(len(spk)) + spk
    if witnesses is not None:
        for items in witnesses:
            out += write_compact_size(len(items))
            for it in items:
                out += write_compact_size(len(it)) + it
    out += b"\x00" * 4
    return out


def build_blk(path):
    cb = tx([b"\x03abc"], [(5 * BTC, b"\x41" + PCB + b"\xac")])
    sig = b"\x30" + bytes(70)
    t1 = tx([push(sig) + push(P1)], [])                       # reveals H1 (p2pkh)
    t2 = tx([b""], [], witnesses=[[sig, P2]])                 # reveals H2 (wpkh)
    t3 = tx([push(sig) + push(REDEEM)], [])                   # reveals H3 (p2sh msig)
    t4 = tx([push(sig)], [(1 * BTC, b"\x51\x20" + TR_KEY)])   # p2tr output, no reveal
    block = b"\x00" * 80 + write_compact_size(5) + cb + t1 + t2 + t3 + t4
    data = b"\xf9\xbe\xb4\xd9" + struct.pack("<I", len(block)) + block
    with open(path, "wb") as f:
        f.write(data)


# ---------------------------------------------------------------------------
# the test
# ---------------------------------------------------------------------------

def main():
    tmp = tempfile.mkdtemp(prefix="qvuln_test_")
    try:
        snap = os.path.join(tmp, "snap.dat")
        ncoins = build_snapshot(snap)
        blk = os.path.join(tmp, "blk00000.dat")
        build_blk(blk)
        work = os.path.join(tmp, "work")

        prep = run_prepare(work, snap, log=lambda *a: None)
        assert prep["coins_parsed"] == ncoins == 6
        assert prep["total_sat"] == (1 + 2 + 50 + 0.5 + 3 + 4) * BTC
        assert prep["direct"]["p2pk"]["sat"] == 50 * BTC
        assert prep["direct"]["p2tr"]["sat"] == 2 * BTC

        # phase 1 (single process, no pool)
        F = Funded(work)
        C = Ctx()
        with open(blk, "rb") as f:
            buf = memoryview(f.read())
        scan_buffer(buf, C)
        assert C.stats["txs"] == 5
        assert C.stats["blocks"] == 1
        flush_cands(C, F)
        n_hits = {
            "hits160": _write_hits(work, "hits160", C.hits160, "V20",
                                   lambda *a: None),
            "hitsh160": _write_hits(work, "hitsh160", C.hitsh160, "V20",
                                    lambda *a: None),
            "hitsh256": _write_hits(work, "hitsh256", C.hitsh256, "V32",
                                    lambda *a: None),
        }
        assert n_hits["hits160"] == 2, n_hits       # H1, H2
        assert n_hits["hitsh160"] == 1              # H3
        assert n_hits["hitsh256"] == 0

        rep = run_report(work, log=lambda *a: None)
        cats = rep["categories"]
        assert cats["p2pk"]["sat"] == 50 * BTC
        assert cats["p2tr"]["sat"] == 2 * BTC
        assert cats["p2pkh_reused"]["sat"] == 1 * BTC
        assert cats["p2wpkh_reused"]["sat"] == BTC // 2
        assert cats["p2sh_revealed"]["sat"] == 3 * BTC
        assert cats["p2wsh_revealed"]["sat"] == 0
        assert rep["quantum_vulnerable"]["sat"] == (50 + 2 + 1 + 0.5 + 3) * BTC
        assert rep["not_vulnerable"]["sat"] == 4 * BTC
        print("end-to-end test passed")
        print(json.dumps({k: v["sat"] / 1e8 for k, v in cats.items()}, indent=2))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
