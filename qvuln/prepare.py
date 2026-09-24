"""Phase 0: stream the UTXO snapshot once and build

  - coins_pkh/xx.bin   records [20B hash160][8B sat LE]   (P2PKH UTXOs)
  - coins_wpkh/xx.bin  records [20B hash160][8B sat LE]   (P2WPKH UTXOs)
  - coins_sh/xx.bin    records [20B hash160][8B sat LE]   (P2SH UTXOs)
  - coins_wsh/xx.bin   records [32B sha256][8B sat LE]    (P2WSH UTXOs)
  - fund160/xx.bin     sorted unique hash160 set = funded P2PKH + P2WPKH
  - fundsh160/xx.bin   sorted unique hash160 set = funded P2SH
  - fundsh256/xx.bin   sorted unique sha256 set  = funded P2WSH
  - direct.json        sums/counts for P2PK, P2MS, P2TR, other + totals

Files are sharded by the first byte of the hash (xx = 00..ff).
"""
from __future__ import annotations

import json
import os
import time

import numpy as np

from .btc import classify_spk, decompress_amount, read_compact_size, read_varint
from .snapshot import HEADER_LEN, MAINNET_MAGIC, open_snapshot, parse_header

DT20 = np.dtype([("h", "V20"), ("amt", "<u8")])
DT32 = np.dtype([("h", "V32"), ("amt", "<u8")])


def _write_shards(workdir: str, name: str, shards, itemsize: int, log):
    """Write shard bytearrays to name/xx.bin; return (total_n, total_sat)."""
    outdir = os.path.join(workdir, name)
    os.makedirs(outdir, exist_ok=True)
    dt = DT20 if itemsize == 20 else DT32
    total_n = 0
    total_sat = 0
    for s in range(256):
        b = shards[s]
        if not b:
            continue
        arr = np.frombuffer(bytes(b), dtype=dt)
        total_n += len(arr)
        total_sat += int(arr["amt"].sum())
        with open(os.path.join(outdir, f"{s:02x}.bin"), "wb") as f:
            f.write(b)
    log(f"  {name}: {total_n:,} UTXOs, {total_sat / 1e8:,.8f} BTC")
    return total_n, total_sat


def _build_funded(workdir: str, src_names, out_name: str, dt, log):
    """Build sorted-unique hash sets per shard from one or more coin sets."""
    outdir = os.path.join(workdir, out_name)
    os.makedirs(outdir, exist_ok=True)
    total = 0
    for s in range(256):
        parts = []
        for name in src_names:
            p = os.path.join(workdir, name, f"{s:02x}.bin")
            if os.path.exists(p) and os.path.getsize(p):
                parts.append(np.fromfile(p, dtype=dt)["h"])
        if not parts:
            continue
        u = np.unique(np.concatenate(parts))
        total += len(u)
        u.tofile(os.path.join(outdir, f"{s:02x}.bin"))
    log(f"  {out_name}: {total:,} distinct funded scripthashes")
    return total


def run_prepare(workdir: str, snapshot_path: str, log=print) -> dict:
    t0 = time.time()
    f, mm = open_snapshot(snapshot_path)
    try:
        hdr = parse_header(mm)
        if hdr["network_magic"] != MAINNET_MAGIC:
            log(f"WARNING: snapshot network magic {hdr['network_magic'].hex()} != mainnet")
        log(f"snapshot: version={hdr['version']} coins={hdr['coins_count']:,} "
            f"base={hdr['base_hash']}")

        coins_pkh = [bytearray() for _ in range(256)]
        coins_wpkh = [bytearray() for _ in range(256)]
        coins_sh = [bytearray() for _ in range(256)]
        coins_wsh = [bytearray() for _ in range(256)]
        direct = {"p2pk": [0, 0], "p2ms": [0, 0], "p2tr": [0, 0], "other": [0, 0]}

        rcs = read_compact_size
        rv = read_varint
        da = decompress_amount
        cls = classify_spk

        total_sat = 0
        ncoins = 0
        off = HEADER_LEN
        n = len(mm)
        next_report = 20_000_000
        while off < n:
            off += 32  # txid (not needed)
            ng, off = rcs(mm, off)
            for _ in range(ng):
                _vout, off = rcs(mm, off)
                _code, off = rv(mm, off)  # height*2+coinbase, unused
                camt, off = rv(mm, off)
                amt = da(camt)
                nsize, off = rv(mm, off)
                total_sat += amt
                ncoins += 1
                if nsize == 0:  # p2pkh
                    h = mm[off:off + 20]
                    off += 20
                    b = coins_pkh[h[0]]
                    b += h
                    b += amt.to_bytes(8, "little")
                elif nsize == 1:  # p2sh
                    h = mm[off:off + 20]
                    off += 20
                    b = coins_sh[h[0]]
                    b += h
                    b += amt.to_bytes(8, "little")
                elif nsize <= 5:  # p2pk (compressed or uncompressed)
                    off += 32
                    d = direct["p2pk"]
                    d[0] += amt
                    d[1] += 1
                else:
                    rl = nsize - 6
                    if rl == 22 and mm[off] == 0 and mm[off + 1] == 0x14:  # p2wpkh
                        h = mm[off + 2:off + 22]
                        b = coins_wpkh[h[0]]
                        b += h
                        b += amt.to_bytes(8, "little")
                    elif rl == 34 and mm[off] == 0x51 and mm[off + 1] == 0x20:  # p2tr
                        d = direct["p2tr"]
                        d[0] += amt
                        d[1] += 1
                    elif rl == 34 and mm[off] == 0 and mm[off + 1] == 0x20:  # p2wsh
                        h = mm[off + 2:off + 34]
                        b = coins_wsh[h[0]]
                        b += h
                        b += amt.to_bytes(8, "little")
                    else:
                        kind, payload = cls(mm, off, rl)
                        if kind == "p2ms":
                            d = direct["p2ms"]
                            d[0] += amt
                            d[1] += 1
                        elif kind == "p2pk":
                            d = direct["p2pk"]
                            d[0] += amt
                            d[1] += 1
                        elif kind == "p2pkh":
                            ho, _hl = payload
                            h = mm[ho:ho + 20]
                            b = coins_pkh[h[0]]
                            b += h
                            b += amt.to_bytes(8, "little")
                        elif kind == "p2sh":
                            ho, _hl = payload
                            h = mm[ho:ho + 20]
                            b = coins_sh[h[0]]
                            b += h
                            b += amt.to_bytes(8, "little")
                        elif kind == "p2wpkh":
                            ho, _hl = payload
                            h = mm[ho:ho + 20]
                            b = coins_wpkh[h[0]]
                            b += h
                            b += amt.to_bytes(8, "little")
                        elif kind == "p2wsh":
                            ho, _hl = payload
                            h = mm[ho:ho + 32]
                            b = coins_wsh[h[0]]
                            b += h
                            b += amt.to_bytes(8, "little")
                        elif kind == "p2tr":
                            d = direct["p2tr"]
                            d[0] += amt
                            d[1] += 1
                        else:
                            d = direct["other"]
                            d[0] += amt
                            d[1] += 1
                    off += rl
                if ncoins >= next_report:
                    el = time.time() - t0
                    rate = ncoins / el
                    log(f"  {ncoins:,} coins ({rate / 1e6:.1f}M/s), "
                        f"elapsed {el / 60:.1f}m")
                    next_report += 20_000_000

        if ncoins != hdr["coins_count"]:
            raise RuntimeError(
                f"parsed {ncoins:,} coins but header says {hdr['coins_count']:,}")
        log(f"parsed all {ncoins:,} coins in {(time.time() - t0) / 60:.1f}m; "
            f"total supply {total_sat / 1e8:,.8f} BTC")

        log("writing coin shards:")
        stats = {"header": {**hdr, "network_magic": hdr["network_magic"].hex()},
                 "total_sat": total_sat, "coins_parsed": ncoins}
        for name, shards, isz in [
            ("coins_pkh", coins_pkh, 20),
            ("coins_wpkh", coins_wpkh, 20),
            ("coins_sh", coins_sh, 20),
            ("coins_wsh", coins_wsh, 32),
        ]:
            tn, ts = _write_shards(workdir, name, shards, isz, log)
            stats[name] = {"n": tn, "sat": ts}

        log("building funded scripthash indexes:")
        stats["fund160"] = _build_funded(workdir, ["coins_pkh", "coins_wpkh"],
                                         "fund160", DT20, log)
        stats["fundsh160"] = _build_funded(workdir, ["coins_sh"], "fundsh160",
                                           DT20, log)
        stats["fundsh256"] = _build_funded(workdir, ["coins_wsh"], "fundsh256",
                                           DT32, log)

        stats["direct"] = {
            k: {"sat": v[0], "n": v[1]} for k, v in direct.items()
        }
        stats["elapsed_sec"] = time.time() - t0
        with open(os.path.join(workdir, "direct.json"), "w") as fp:
            json.dump(stats, fp, indent=2)
        log(f"phase 0 done in {(time.time() - t0) / 60:.1f}m")
        return stats
    finally:
        mm.close()
        f.close()
