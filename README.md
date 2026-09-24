# quantum-vuln-addresses

A parser that scans the entire Bitcoin blockchain and sums the value held in
**quantum-vulnerable addresses** — outputs whose public key is exposed on-chain
and could therefore be cracked by a sufficiently powerful quantum computer
running Shor's algorithm against secp256k1.

## Headline result

Measured at block height **968,431** (Sep 24, 2026), against a local Bitcoin
Core v31.1 node:

> **7,161,959.77 BTC — 35.65% of total supply — is quantum-vulnerable**,
> spread over 101.7M of the 165.2M UTXOs.

| Category | Why it's exposed | BTC | % of supply | UTXOs |
|---|---|---:|---:|---:|
| P2WPKH reused | pubkey revealed in witness by a past spend | 2,063,363.24 | 10.27% | 21,671,597 |
| P2PK | full pubkey in the output script (incl. Satoshi-era coinbases) | 1,714,619.05 | 8.53% | 44,564 |
| P2SH revealed | redeemScript with pubkey(s) revealed by a past spend | 1,271,548.54 | 6.33% | 5,525,502 |
| P2PKH reused | pubkey revealed in scriptSig by a past spend | 1,183,532.79 | 5.89% | 17,436,098 |
| P2WSH revealed | witnessScript with pubkey(s) revealed by a past spend | 710,408.61 | 3.54% | 456,148 |
| Taproot (all P2TR) | tweaked x-only pubkey visible in every output | 218,427.36 | 1.09% | 54,088,640 |
| Bare multisig (P2MS) | pubkeys in the output script | 60.18 | 0.0003% | 2,466,247 |
| **Total** | | **7,161,959.77** | **35.65%** | **101,688,796** |

Everything else (12,926,660 BTC) is hash-locked: its pubkey has never appeared
on-chain, so a quantum attacker has nothing to run Shor's algorithm against
(until the moment the coins are spent and the pubkey hits the mempool).

## What counts as "quantum-vulnerable"

A coin is counted if its spending public key is visible on-chain today:

- **P2PK / bare P2MS** — the pubkey is literally in the output script. This
  covers most 2009–2010 coinbase outputs, including the presumed Satoshi coins.
- **Taproot (P2TR)** — every P2TR output commits to a tweaked x-only pubkey
  that is itself a curve point; the tweak is public, so solving the discrete
  log of the output key yields a working spending key. All P2TR is counted.
- **Reused P2PKH / P2WPKH** — spending reveals the pubkey (scriptSig /
  witness). Any *other* still-unspent output to the same address is then
  exposed. Detected exactly: every pubkey ever revealed by any spend is
  matched against the current UTXO set (cross-type reuse included, e.g. a key
  used for both P2PKH and P2WPKH, or revealed inside a multisig script).
- **P2SH / P2WSH with a revealed script** — once a redeemScript /
  witnessScript containing raw pubkeys has been used, all remaining UTXOs at
  that address are exposed. Hashlock-only scripts (no pubkeys) are *not*
  counted.

Not counted: pubkeys known only off-chain (published xpubs, etc.), and the
mempool exposure window of in-flight spends.

## How it works

Three phases over two data sources from your own node (no third-party APIs;
ElectrumX is *not* needed — it doesn't index input scripts):

```
┌─────────────────────────┐     ┌──────────────────────────────┐
│ bitcoin-cli dumptxoutset │     │ ~/.bitcoin/blocks/blk*.dat    │
│ (UTXO snapshot, ~10 GB)  │     │ (full chain, ~820 GB)         │
└───────────┬─────────────┘     └──────────────┬───────────────┘
            │ Phase 0 `prepare`                │ Phase 1 `scan` (parallel)
            │  • sum P2PK/P2MS/P2TR directly   │  • every pubkey revealed in
            │  • index all funded scripthashes │    scriptSigs & witnesses
            │    into 256 sorted shards        │  • every revealed P2SH/P2WSH
            │                                  │    script containing pubkeys
            │                                  │  • every P2PK/P2MS pubkey
            └───────────┬──────────────────────┴── match vs funded index
                        ▼
              Phase 2 `report` — exact sorted-set join,
              per-category BTC sums → work/report.json
```

- Snapshot parsing is byte-accurate to Bitcoin Core's format (tested against
  v31.1: `utxo\xff` magic, metadata header, coins grouped by txid, custom
  base-128 VARINT, base-9 amount decompression, script decompression).
- Block parsing handles the XOR obfuscation Core ≥ v28 applies to blk*.dat
  (`blocks/xor.dat`).
- Memory-bounded by design: everything is sharded by first hash byte; peak
  usage stays in single-digit GB. Full pipeline takes ~15 minutes on a
  32-core machine.

## Requirements

- A synced **Bitcoin Core** node (≥ v26 for `dumptxoutset ... latest`; tested
  on v31.1), **not pruned**, with RPC enabled.
- Python ≥ 3.10 (tested on 3.14) + `numpy` (`pip install -r requirements.txt`).
- ~15 GB free disk for intermediates (snapshot + shards).

## Usage

```bash
# 1. dump the UTXO snapshot (~1 min; safe on a running node)
python -m qvuln snapshot --workdir work

# 2. index funded scripthashes from the snapshot (~3 min)
python -m qvuln prepare --workdir work

# 3. scan all blk*.dat for revealed keys/scripts (~10 min on 28 workers)
python -m qvuln scan --workdir work --workers 28

# 4. join & sum → work/report.json + console table (~1 min)
python -m qvuln report --workdir work

# or 2–4 in one go:
python -m qvuln all --workdir work
```

Options: `--blocks-dir` (default `~/.bitcoin/blocks`), `--snapshot`,
`--bitcoin-cli`, `--workers`.

## Validation

`tests/` contains unit vectors (VARINT / amount / script classification taken
from Bitcoin Core's own semantics), a synthetic end-to-end pipeline test, and
`validate_hits.py`, which checks the produced hit-sets against the live node:

- Total supply matches the issuance schedule to within the ~230 BTC of known
  unspendable coins (genesis output, BIP30 duplicate coinbases, unclaimed
  miner rewards).
- 40/40 closed-loop controls: every funded address that spent from itself in
  the sampled recent blocks is present in the hit set.
- `1FeexV6bAHb8ybZjqQMjJrcCrHGW9sb6uF` (79,957 BTC, never spent) is correctly
  **not** counted; the genesis address `1A1zP1…` **is** counted (its pubkey is
  exposed via the genesis block's P2PK output).

```bash
python tests/test_vectors.py   # unit tests
python tests/test_e2e.py       # synthetic end-to-end
python tests/validate_hits.py work   # closed-loop check vs node (needs RPC)
```

## Caveats

- Taproot is counted wholesale (see above); if you believe key-path-only P2TR
  with NUMS internal keys should be excluded, subtract the P2TR row.
- P2SH/P2WSH are counted only when a revealed script contains ≥1 raw pubkey.
- Snapshot/scan tip drift is a few blocks (~0.001% of supply) — take the
  snapshot right after scanning if you need a tighter bound.
- A handful of unspendable outputs with invalid pubkeys are included in the
  P2PK figure.
- This measures *exposed-key* coins. Coins whose pubkey is revealed only in
  the mempool (in-flight spends) are not included.

## Project structure

```
qvuln/
  btc.py       # hashes, varints, amount codec, script classification
  snapshot.py  # dumptxoutset format parser
  blocks.py    # blk*.dat reading (+ XOR deobfuscation)
  prepare.py   # phase 0: funded scripthash index + direct sums
  scan.py      # phase 1: parallel revealed-key scanner
  report.py    # phase 2: join + sums + report.json
  cli.py       # argparse CLI
tests/
  test_vectors.py, test_e2e.py, validate_hits.py
```
