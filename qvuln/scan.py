"""Phase 1: scan all blk*.dat files for revealed public keys / scripts.

A pubkey is "revealed" when it appears on-chain in a spend (scriptSig or
witness) or directly in an output (P2PK / bare multisig). A script is
"revealed" when a P2SH redeemScript or P2WSH witnessScript appears in a
spend. Revealed items are matched against the funded scripthash index from
Phase 0; matches ("hits") are the currently-funded, quantum-vulnerable
addresses.

What we extract per input (coinbase inputs skipped):
  scriptSig exactly <sig> <pubkey>          -> hash160(pubkey)      [P2PKH spend]
  scriptSig last push = 0014{h} / 0020{h}   -> hash160(redeem)      [nested segwit]
  scriptSig last push = script with pubkeys -> hash160(script) + hash160(each pubkey)
                                                                   [P2SH reveal]
  witness exactly [sig, pubkey]             -> hash160(pubkey)      [P2WPKH spend]
  witness last item = script with pubkeys   -> sha256(script) + hash160(each pubkey)
                                                                   [P2WSH reveal]
  witness last item = taproot control block -> skipped (all P2TR outputs are
                                               counted wholesale in Phase 0)
Per output:
  P2PK / bare P2MS                          -> hash160(each pubkey)
"""
from __future__ import annotations

import json
import multiprocessing as mp
import os
import struct
import time
from collections import Counter

import numpy as np

from .btc import (classify_spk, hash160, parse_one_push, read_compact_size,
                  script_pubkeys, sha256)
from .blocks import list_blk_files, load_xor_key, read_blk_file

# ---------------------------------------------------------------------------
# Funded scripthash index (256 shards of sorted numpy void arrays)
# ---------------------------------------------------------------------------


class Funded:
    def __init__(self, workdir: str):
        self.f160 = self._load(os.path.join(workdir, "fund160"), "V20")
        self.fsh160 = self._load(os.path.join(workdir, "fundsh160"), "V20")
        self.fsh256 = self._load(os.path.join(workdir, "fundsh256"), "V32")

    @staticmethod
    def _load(d: str, dt):
        out = []
        for s in range(256):
            p = os.path.join(d, f"{s:02x}.bin")
            if os.path.exists(p) and os.path.getsize(p):
                out.append(np.memmap(p, dtype=dt, mode="r"))
            else:
                out.append(np.empty(0, dtype=dt))
        return out


class Ctx:
    __slots__ = ("cand160", "candsh160", "candsh256",
                 "hits160", "hitsh160", "hitsh256", "stats")

    def __init__(self):
        self.cand160 = [bytearray() for _ in range(256)]
        self.candsh160 = [bytearray() for _ in range(256)]
        self.candsh256 = [bytearray() for _ in range(256)]
        self.hits160 = [bytearray() for _ in range(256)]
        self.hitsh160 = [bytearray() for _ in range(256)]
        self.hitsh256 = [bytearray() for _ in range(256)]
        self.stats = Counter()


# ---------------------------------------------------------------------------
# Per-transaction analysis
# ---------------------------------------------------------------------------

def _scriptsig(buf, off: int, ln: int, C: Ctx, st):
    end = off + ln
    p1 = parse_one_push(buf, off, end)
    if p1 is None:
        return
    p2 = parse_one_push(buf, p1[2], end)
    if p2 is not None and p2[2] == end:
        # exactly two pushes: <sig> <pubkey> -> P2PKH spend
        po, pl = p2[0], p2[1]
        if (pl == 33 and buf[po] in (2, 3)) or (pl == 65 and buf[po] == 4):
            h = hash160(buf[po:po + pl])
            C.cand160[h[0]] += h
            st["rev_pkh_spend"] += 1
            return
    # general path: locate the last push (potential redeemScript)
    last = p1
    cur = p1[2]
    while cur < end:
        p = parse_one_push(buf, cur, end)
        if p is None:
            break
        last = p
        cur = p[2]
    lo, ll = last[0], last[1]
    if ll == 22 and buf[lo] == 0 and buf[lo + 1] == 0x14:
        # nested P2SH-P2WPKH redeemScript (pubkey comes from the witness)
        h = hash160(buf[lo:lo + 22])
        C.candsh160[h[0]] += h
        st["rev_nested_wpkh"] += 1
        return
    if ll == 34 and buf[lo] == 0 and buf[lo + 1] == 0x20:
        # nested P2SH-P2WSH redeemScript
        h = hash160(buf[lo:lo + 34])
        C.candsh160[h[0]] += h
        st["rev_nested_wsh"] += 1
        return
    pubs = script_pubkeys(buf, lo, ll)
    if pubs:
        h = hash160(buf[lo:lo + ll])
        C.candsh160[h[0]] += h
        st["rev_sh"] += 1
        for po, pl in pubs:
            hh = hash160(buf[po:po + pl])
            C.cand160[hh[0]] += hh


def scan_tx(buf, off: int, is_cb: bool, C: Ctx) -> int:
    st = C.stats
    st["txs"] += 1
    off += 4  # version
    segwit = False
    if buf[off] == 0 and buf[off + 1] != 0:
        segwit = True
        off += 2
    nin, off = read_compact_size(buf, off)
    st["inputs"] += nin
    if is_cb:
        for _ in range(nin):
            off += 36
            sl, off = read_compact_size(buf, off)
            off += sl + 4
    else:
        for _ in range(nin):
            off += 36
            sl, off = read_compact_size(buf, off)
            if sl:
                _scriptsig(buf, off, sl, C, st)
            off += sl + 4
    nout, off = read_compact_size(buf, off)
    for _ in range(nout):
        off += 8  # value
        sl, off = read_compact_size(buf, off)
        kind, payload = classify_spk(buf, off, sl)
        st["out_" + kind] += 1
        if kind == "p2pk":
            h = hash160(buf[payload[0]:payload[0] + payload[1]])
            C.cand160[h[0]] += h
        elif kind == "p2ms":
            for po, pl in payload:
                h = hash160(buf[po:po + pl])
                C.cand160[h[0]] += h
        off += sl
    if segwit:
        for _ in range(nin):
            nw, off = read_compact_size(buf, off)
            if nw == 0 or is_cb:
                for _ in range(nw):
                    il, off = read_compact_size(buf, off)
                    off += il
                continue
            second = None
            lo = ll = 0
            for k in range(nw):
                il, off = read_compact_size(buf, off)
                if k == 1:
                    second = (off, il)
                lo, ll = off, il
                off += il
            if nw == 2 and second is not None and (
                (second[1] == 33 and buf[second[0]] in (2, 3))
                or (second[1] == 65 and buf[second[0]] == 4)
            ):
                # [sig, pubkey] -> P2WPKH spend
                h = hash160(buf[second[0]:second[0] + second[1]])
                C.cand160[h[0]] += h
                st["rev_wpkh_spend"] += 1
            elif nw >= 2:
                if ll in (33, 65, 97, 129) and (buf[lo] & 0xFE) == 0xC0:
                    # taproot script-path control block: nothing to do
                    # (P2TR outputs are all counted in Phase 0)
                    st["tr_script_path"] += 1
                else:
                    pubs = script_pubkeys(buf, lo, ll)
                    if pubs:
                        h = sha256(buf[lo:lo + ll])
                        C.candsh256[h[0]] += h
                        st["rev_wsh"] += 1
                        for po, pl in pubs:
                            hh = hash160(buf[po:po + pl])
                            C.cand160[hh[0]] += hh
    off += 4  # locktime
    return off


def scan_buffer(buf, C: Ctx) -> None:
    """Walk one blk*.dat buffer (memoryview of the whole file)."""
    off = 0
    n = len(buf)
    blocks = 0
    while off + 8 <= n:
        if buf[off] != 0xF9 or buf[off + 1] != 0xBE or buf[off + 2] != 0xB4 \
                or buf[off + 3] != 0xD9:
            break  # not mainnet magic: stop (trailing garbage)
        size = struct.unpack_from("<I", buf, off + 4)[0]
        bend = off + 8 + size
        if bend > n:
            break  # partially written block at tail
        toff = off + 88  # 8 (message header) + 80 (block header)
        ntx, toff = read_compact_size(buf, toff)
        for txi in range(ntx):
            toff = scan_tx(buf, toff, txi == 0, C)
        if toff != bend:
            raise ValueError(
                f"block parse desync: ended at {toff}, block ends at {bend}")
        blocks += 1
        off = bend
    C.stats["blocks"] += blocks


# ---------------------------------------------------------------------------
# Candidate flushing: probe against funded index, keep hits
# ---------------------------------------------------------------------------

def _flush_one(cands, funded, hits):
    for s in range(256):
        b = cands[s]
        if not b:
            continue
        arr = np.unique(np.frombuffer(bytes(b), dtype=funded[s].dtype))
        b.clear()
        fa = funded[s]
        if len(arr) == 0 or len(fa) == 0:
            continue
        idx = np.searchsorted(fa, arr)
        np.minimum(idx, len(fa) - 1, out=idx)
        m = fa[idx] == arr
        if m.any():
            hits[s] += arr[m].tobytes()


def flush_cands(C: Ctx, F: Funded):
    _flush_one(C.cand160, F.f160, C.hits160)
    _flush_one(C.candsh160, F.fsh160, C.hitsh160)
    _flush_one(C.candsh256, F.fsh256, C.hitsh256)


# ---------------------------------------------------------------------------
# Multiprocessing driver
# ---------------------------------------------------------------------------

_F = None
_KEY = None


def _init_worker(workdir: str, xor_key):
    global _F, _KEY
    _F = Funded(workdir)
    _KEY = xor_key


def _scan_one(path: str):
    C = Ctx()
    buf = read_blk_file(path, _KEY)
    scan_buffer(buf, C)
    flush_cands(C, _F)
    h160 = {s: bytes(b) for s, b in enumerate(C.hits160) if b}
    hsh160 = {s: bytes(b) for s, b in enumerate(C.hitsh160) if b}
    hsh256 = {s: bytes(b) for s, b in enumerate(C.hitsh256) if b}
    return os.path.basename(path), dict(C.stats), h160, hsh160, hsh256


def _merge_hits(agg, d):
    for s, data in d.items():
        agg[s] += data


def _compact(agg, dt):
    for s in range(256):
        b = agg[s]
        if len(b) >= (1 << 22):  # > 4 MB
            arr = np.unique(np.frombuffer(bytes(b), dtype=dt))
            agg[s] = bytearray(arr.tobytes())


def _write_hits(workdir, name, agg, dt, log):
    outdir = os.path.join(workdir, name)
    os.makedirs(outdir, exist_ok=True)
    total = 0
    for s in range(256):
        b = agg[s]
        if not b:
            continue
        arr = np.unique(np.frombuffer(bytes(b), dtype=dt))
        total += len(arr)
        arr.tofile(os.path.join(outdir, f"{s:02x}.bin"))
    log(f"  {name}: {total:,} unique funded+revealed hashes")
    return total


def run_scan(workdir: str, blocks_dir: str, workers: int, log=print) -> dict:
    files = list_blk_files(blocks_dir)
    xor_key = load_xor_key(blocks_dir)
    total_bytes = sum(os.path.getsize(f) for f in files)
    log(f"scanning {len(files)} blk files ({total_bytes / 1e9:.1f} GB) "
        f"with {workers} workers (xor obfuscation: {'yes' if xor_key else 'no'})")

    agg160 = [bytearray() for _ in range(256)]
    aggsh160 = [bytearray() for _ in range(256)]
    aggsh256 = [bytearray() for _ in range(256)]
    stats = Counter()
    t0 = time.time()
    done = 0
    ctx = mp.get_context("forkserver")
    with ctx.Pool(workers, initializer=_init_worker,
                  initargs=(workdir, xor_key)) as pool:
        for fname, st, h160, hsh160, hsh256 in pool.imap_unordered(
                _scan_one, files, chunksize=1):
            done += 1
            stats.update(st)
            _merge_hits(agg160, h160)
            _merge_hits(aggsh160, hsh160)
            _merge_hits(aggsh256, hsh256)
            if done % 256 == 0:
                _compact(agg160, "V20")
                _compact(aggsh160, "V20")
                _compact(aggsh256, "V32")
            if done % 32 == 0 or done == len(files):
                el = time.time() - t0
                rate = done / el if el else 0
                eta = (len(files) - done) / rate if rate else 0
                log(f"[{done}/{len(files)}] {rate:.2f} files/s, "
                    f"elapsed {el / 60:.1f}m, ETA {eta / 60:.1f}m, "
                    f"txs={stats['txs']:,}")

    log("writing hit sets:")
    n_hits = {
        "hits160": _write_hits(workdir, "hits160", agg160, "V20", log),
        "hitsh160": _write_hits(workdir, "hitsh160", aggsh160, "V20", log),
        "hitsh256": _write_hits(workdir, "hitsh256", aggsh256, "V32", log),
    }
    out = {
        "stats": dict(stats),
        "n_hits": n_hits,
        "files": len(files),
        "elapsed_sec": time.time() - t0,
    }
    with open(os.path.join(workdir, "scan_stats.json"), "w") as fp:
        json.dump(out, fp, indent=2)
    log(f"phase 1 done in {(time.time() - t0) / 60:.1f}m: "
        f"{stats['txs']:,} txs, {stats['blocks']:,} blocks")
    return out
