"""Command line interface.

Usage:
  python -m qvuln snapshot [--workdir work]                 # run dumptxoutset
  python -m qvuln prepare  [--workdir work]                 # phase 0
  python -m qvuln scan     [--workdir work] [--workers N]   # phase 1
  python -m qvuln report   [--workdir work]                 # phase 2
  python -m qvuln all      [--workdir work] [--workers N]   # 0+1+2
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys


def _default_workdir():
    return os.path.join(os.getcwd(), "work")


def _add_common(sp, need_blocks=False, need_snapshot=False):
    sp.add_argument("--workdir", default=_default_workdir(),
                    help="working directory for intermediate + final data")
    if need_blocks:
        sp.add_argument("--blocks-dir",
                        default=os.path.expanduser("~/.bitcoin/blocks"),
                        help="directory with blk*.dat files")
        sp.add_argument("--workers", type=int,
                        default=max(1, (os.cpu_count() or 4) - 2))
    if need_snapshot:
        sp.add_argument("--snapshot", default=None,
                        help="path to utxo snapshot (default: <workdir>/utxo_snapshot.dat)")


def main(argv=None):
    p = argparse.ArgumentParser(
        prog="qvuln",
        description="Sum BTC held by quantum-vulnerable (pubkey-exposed) addresses")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("snapshot", help="create UTXO snapshot via bitcoin-cli dumptxoutset")
    _add_common(sp)
    sp.add_argument("--bitcoin-cli", default="bitcoin-cli")

    sp = sub.add_parser("prepare", help="phase 0: index funded scripthashes from snapshot")
    _add_common(sp, need_snapshot=True)

    sp = sub.add_parser("scan", help="phase 1: scan blocks for revealed keys/scripts")
    _add_common(sp, need_blocks=True)

    sp = sub.add_parser("report", help="phase 2: join and sum")
    _add_common(sp)

    sp = sub.add_parser("all", help="prepare + scan + report")
    _add_common(sp, need_blocks=True, need_snapshot=True)

    args = p.parse_args(argv)
    workdir = os.path.abspath(args.workdir)
    os.makedirs(workdir, exist_ok=True)

    if args.cmd in ("snapshot", "all") and args.cmd == "snapshot":
        return _cmd_snapshot(args, workdir)
    if args.cmd in ("prepare", "scan", "report", "all"):
        snapshot_path = getattr(args, "snapshot", None) or os.path.join(
            workdir, "utxo_snapshot.dat")
        if args.cmd in ("prepare", "all"):
            from .prepare import run_prepare
            run_prepare(workdir, snapshot_path)
        if args.cmd in ("scan", "all"):
            from .scan import run_scan
            run_scan(workdir, args.blocks_dir, args.workers)
        if args.cmd in ("report", "all"):
            from .report import run_report
            run_report(workdir)
    return 0


def _cmd_snapshot(args, workdir):
    out = os.path.join(workdir, "utxo_snapshot.dat")
    cmd = [args.bitcoin_cli, "-rpcclienttimeout=0", "dumptxoutset", out, "latest"]
    print("running:", " ".join(cmd), flush=True)
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stderr, file=sys.stderr)
        sys.exit(r.returncode)
    print(r.stdout)
    with open(os.path.join(workdir, "meta.json"), "w") as fp:
        fp.write(r.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
