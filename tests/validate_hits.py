"""Closed-loop validation of the hit sets against real chain data.

For every input in recent blocks (via bitcoin-cli, verbosity 3 = prevouts):
if the spent-from address is *currently funded* (present in our coin shards),
it *must* be present in the corresponding hit set (because spending reveals
the key/script). Also checks famous never-spent-from addresses are absent.
"""
import json
import os
import subprocess
import sys

import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from qvuln.btc import hash160, script_pubkeys
from qvuln.prepare import DT20, DT32

WORK = sys.argv[1] if len(sys.argv) > 1 else "work"

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58decode(s):
    n = 0
    for c in s:
        n = n * 58 + B58.index(c)
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return b"\x00" * (len(s) - len(s.lstrip("1"))) + b


def addr_h160(addr):
    raw = b58decode(addr)
    assert len(raw) == 25
    return raw[1:21]


def load_shard(d, h, dt):
    p = os.path.join(WORK, d, f"{h[0]:02x}.bin")
    if not os.path.exists(p):
        return np.empty(0, dtype=dt)
    return np.fromfile(p, dtype=dt)


def in_sorted(arr, key):
    if len(arr) == 0:
        return False
    i = arr.searchsorted(key)
    return i < len(arr) and arr[i] == key


def funded(d, h, dt):
    # coin shards are insertion-ordered (NOT sorted): linear scan
    arr = load_shard(d, h, dt)
    return bool((arr["h"] == np.void(h)).any())


def cli(*args):
    r = subprocess.run(["bitcoin-cli", *args], capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(r.stderr)
    return r.stdout.strip()


def main():
    tip = int(cli("getblockcount"))
    pos = {"p2pkh": 0, "p2wpkh": 0, "p2sh": 0, "p2wsh": 0}
    checked = {"p2pkh": 0, "p2wpkh": 0, "p2sh": 0, "p2wsh": 0}
    target = {"p2pkh": 12, "p2wpkh": 12, "p2sh": 8, "p2wsh": 8}

    for height in range(tip - 30, tip):
        if all(checked[k] >= target[k] for k in target):
            break
        block = json.loads(cli("getblock", cli("getblockhash", str(height)), "3"))
        for t in block["tx"]:
            if "coinbase" in t["vin"][0]:
                continue
            for vin in t["vin"]:
                spk = vin.get("prevout", {}).get("scriptPubKey", {})
                st = spk.get("type")
                hx = spk.get("hex", "")
                if st == "pubkeyhash" and checked["p2pkh"] < target["p2pkh"]:
                    h = bytes.fromhex(hx[6:46])
                    kind = "p2pkh"
                elif st == "witness_v0_keyhash" and checked["p2wpkh"] < target["p2wpkh"]:
                    h = bytes.fromhex(hx[4:])
                    kind = "p2wpkh"
                elif st == "scripthash" and checked["p2sh"] < target["p2sh"]:
                    # only check if redeemScript actually contains a pubkey
                    ss = bytes.fromhex(vin["scriptSig"]["hex"])
                    from qvuln.btc import parse_one_push
                    last = None
                    cur = 0
                    while cur < len(ss):
                        p = parse_one_push(ss, cur, len(ss))
                        if p is None:
                            break
                        last = p
                        cur = p[2]
                    if last is None or not script_pubkeys(ss, last[0], last[1]):
                        continue
                    h = bytes.fromhex(hx[4:44])
                    kind = "p2sh"
                elif st == "witness_v0_scripthash" and checked["p2wsh"] < target["p2wsh"]:
                    wit = vin.get("txinwitness", [])
                    if not wit:
                        continue
                    script = bytes.fromhex(wit[-1])
                    if not script_pubkeys(script, 0, len(script)):
                        continue
                    h = bytes.fromhex(hx[4:])
                    kind = "p2wsh"
                else:
                    continue

                coins_dir = {"p2pkh": "coins_pkh", "p2wpkh": "coins_wpkh",
                             "p2sh": "coins_sh", "p2wsh": "coins_wsh"}[kind]
                hits_dir = {"p2pkh": "hits160", "p2wpkh": "hits160",
                            "p2sh": "hitsh160", "p2wsh": "hitsh256"}[kind]
                dt = "V32" if kind == "p2wsh" else "V20"
                cdt = DT32 if kind == "p2wsh" else DT20

                if funded(coins_dir, h, cdt):
                    hit_arr = load_shard(hits_dir, h, dt)
                    ok = in_sorted(hit_arr, np.void(h))
                    checked[kind] += 1
                    if ok:
                        pos[kind] += 1
                    else:
                        print(f"MISS: {kind} {h.hex()} funded but not in hits!")

    print("positive controls (funded + spent-from => must be in hits):")
    for k in checked:
        print(f"  {k}: {pos[k]}/{checked[k]} in hits")
    assert all(pos[k] == checked[k] for k in checked), "positive control failed"

    # negative control: famous address that received but never spent,
    # so its pubkey never appeared on-chain
    h = addr_h160("1FeexV6bAHb8ybZjqQMjJrcCrHGW9sb6uF")
    is_hit = in_sorted(load_shard("hits160", h, "V20"), np.void(h))
    is_funded = funded("coins_pkh", h, DT20)
    print(f"  MtGox-hacker 1Feex (79,957 BTC, never spent): "
          f"funded={is_funded} in_hits={is_hit} (want True/False)")
    assert is_funded and not is_hit

    # positive control: the genesis address 1A1zP1... never *spent*, but its
    # pubkey is exposed by the genesis block's P2PK output, and people later
    # sent P2PKH coins to the same key -> those UTXOs ARE vulnerable.
    h = addr_h160("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
    is_hit = in_sorted(load_shard("hits160", h, "V20"), np.void(h))
    is_funded = funded("coins_pkh", h, DT20)
    print(f"  genesis address 1A1zP1 (pubkey exposed via P2PK): "
          f"funded={is_funded} in_hits={is_hit} (want True/True)")
    assert is_funded and is_hit

    print("ALL VALIDATION CHECKS PASSED")


if __name__ == "__main__":
    main()
