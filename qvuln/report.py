"""Phase 2: join funded UTXOs against the revealed-hit sets and sum values.

Produces work/report.json and prints a summary table.
"""
from __future__ import annotations

import json
import os
import time

import numpy as np

from .prepare import DT20, DT32

# (category, coins dir, hits dir, record dtype, hash dtype)
JOBS = [
    ("p2pkh_reused", "coins_pkh", "hits160", DT20, "V20"),
    ("p2wpkh_reused", "coins_wpkh", "hits160", DT20, "V20"),
    ("p2sh_revealed", "coins_sh", "hitsh160", DT20, "V20"),
    ("p2wsh_revealed", "coins_wsh", "hitsh256", DT32, "V32"),
]

DIRECT_VULN = ["p2pk", "p2ms", "p2tr"]  # counted wholesale from Phase 0


def _join_shard(coins_path, hits_path, dt, hdt):
    coins = np.fromfile(coins_path, dtype=dt)
    if len(coins) == 0:
        return 0, 0, 0, 0
    tot_sat = int(coins["amt"].sum())
    tot_n = len(coins)
    if not os.path.exists(hits_path) or os.path.getsize(hits_path) == 0:
        return 0, 0, tot_sat, tot_n
    hits = np.fromfile(hits_path, dtype=hdt)
    idx = np.searchsorted(hits, coins["h"])
    np.minimum(idx, len(hits) - 1, out=idx)
    mask = hits[idx] == coins["h"]
    return int(coins["amt"][mask].sum()), int(mask.sum()), tot_sat, tot_n


def run_report(workdir: str, log=print) -> dict:
    t0 = time.time()
    with open(os.path.join(workdir, "direct.json")) as fp:
        prep = json.load(fp)
    scan_stats = {}
    p = os.path.join(workdir, "scan_stats.json")
    if os.path.exists(p):
        with open(p) as fp:
            scan_stats = json.load(fp)
    meta = {}
    p = os.path.join(workdir, "meta.json")
    if os.path.exists(p):
        try:
            with open(p) as fp:
                meta = json.load(fp)
        except Exception:
            pass

    cats = {}
    for name, cdir, hdir, dt, hdt in JOBS:
        v_sat = v_n = t_sat = t_n = 0
        for s in range(256):
            cp = os.path.join(workdir, cdir, f"{s:02x}.bin")
            if not os.path.exists(cp):
                continue
            a, b, c, d = _join_shard(cp, os.path.join(workdir, hdir, f"{s:02x}.bin"),
                                     dt, hdt)
            v_sat += a
            v_n += b
            t_sat += c
            t_n += d
        cats[name] = {"sat": v_sat, "utxos": v_n,
                      "type_total_sat": t_sat, "type_total_utxos": t_n}
        log(f"  {name}: {v_sat / 1e8:,.8f} BTC in {v_n:,} UTXOs "
            f"(of {t_sat / 1e8:,.8f} BTC / {t_n:,} UTXOs of this type)")

    for k in DIRECT_VULN:
        d = prep["direct"][k]
        cats[k] = {"sat": d["sat"], "utxos": d["n"],
                   "type_total_sat": d["sat"], "type_total_utxos": d["n"]}

    other = prep["direct"]["other"]
    vuln_sat = sum(c["sat"] for c in cats.values())
    vuln_n = sum(c["utxos"] for c in cats.values())
    supply_sat = prep["total_sat"]

    report = {
        "meta": meta,
        "snapshot_base_hash": prep["header"]["base_hash"],
        "coins_count": prep["coins_parsed"],
        "supply_sat": supply_sat,
        "categories": cats,
        "quantum_vulnerable": {"sat": vuln_sat, "utxos": vuln_n},
        "not_vulnerable": {"sat": supply_sat - vuln_sat,
                           "utxos": prep["coins_parsed"] - vuln_n},
        "unclassified_other": {"sat": other["sat"], "utxos": other["n"]},
        "scan": scan_stats,
    }
    with open(os.path.join(workdir, "report.json"), "w") as fp:
        json.dump(report, fp, indent=2)

    # ---- pretty print ----
    btc = lambda s: s / 1e8
    log("")
    log("=" * 74)
    log("QUANTUM-VULNERABLE BITCOIN BALANCE REPORT")
    if meta.get("base_height"):
        log(f"snapshot base height: {meta['base_height']}  ({meta.get('base_hash', '')})")
    log(f"UTXOs parsed: {prep['coins_parsed']:,}   total supply: {btc(supply_sat):,.8f} BTC")
    log("-" * 74)
    log(f"{'category':<22}{'BTC':>18}{'% supply':>10}{'UTXOs':>16}")
    log("-" * 74)
    order = ["p2pk", "p2ms", "p2tr", "p2pkh_reused", "p2wpkh_reused",
             "p2sh_revealed", "p2wsh_revealed"]
    labels = {
        "p2pk": "P2PK (pubkey in output)",
        "p2ms": "bare multisig",
        "p2tr": "Taproot (all)",
        "p2pkh_reused": "P2PKH reused (key revealed)",
        "p2wpkh_reused": "P2WPKH reused (key revealed)",
        "p2sh_revealed": "P2SH script revealed",
        "p2wsh_revealed": "P2WSH script revealed",
    }
    for k in order:
        c = cats[k]
        log(f"{labels[k]:<22}{btc(c['sat']):>18,.8f}{100 * c['sat'] / supply_sat:>9.3f}%"
            f"{c['utxos']:>16,}")
    log("-" * 74)
    log(f"{'TOTAL VULNERABLE':<22}{btc(vuln_sat):>18,.8f}"
        f"{100 * vuln_sat / supply_sat:>9.3f}%{vuln_n:>16,}")
    log(f"{'not vulnerable':<22}{btc(supply_sat - vuln_sat):>18,.8f}"
        f"{100 * (supply_sat - vuln_sat) / supply_sat:>9.3f}%"
        f"{prep['coins_parsed'] - vuln_n:>16,}")
    log("=" * 74)
    log(f"report written to {os.path.join(workdir, 'report.json')} "
        f"(join took {time.time() - t0:.1f}s)")
    return report
