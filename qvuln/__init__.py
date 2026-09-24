"""qvuln - scan the Bitcoin blockchain for quantum-vulnerable UTXOs.

Quantum-vulnerable = coins spendable via a public key that is exposed on-chain:
  - P2PK / bare P2MS outputs (pubkey in the scriptPubKey itself)
  - P2TR outputs (tweaked x-only pubkey in the scriptPubKey)
  - P2PKH / P2WPKH outputs whose pubkey was revealed by a past spend (address reuse)
  - P2SH / P2WSH outputs whose redeem/witness script (containing pubkeys) was revealed
"""

__version__ = "0.1.0"
