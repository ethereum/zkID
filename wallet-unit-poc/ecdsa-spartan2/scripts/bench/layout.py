#!/usr/bin/env python3
"""Derive the shared-variable positions of a circuit from its .sym, the way tests/witness_layout.rs does.

Writes layout.json: {"role", "num_public", "shared": [witness indices in `shared()` order]}.
"""
import argparse
import json
import sys

import constraints

SHOW_NAMES = (
    ["main.deviceKeyX", "main.deviceKeyY"],
    ["main.claimValues[{i}]"],
    ["main.claimIdentifierHashes[{i}]"],
    ["main.issuerKeyX", "main.issuerKeyY"],
    ["main.revocationCommitment[0]", "main.revocationCommitment[1]"],
)
PREPARE_NAMES = (
    ["main.KeyBindingX", "main.KeyBindingY"],
    ["main.normalizedClaimValues[{i}]"],
    ["main.claimIdentifierHashes[{i}]"],
    ["main.pubKeyX", "main.pubKeyY"],
    ["main.RevocationCommitment[0]", "main.RevocationCommitment[1]"],
)
# The last group is absent in configurations without revocation; the others are required.
OPTIONAL_GROUPS = {4}


def ordered_names(role, n_claims):
    groups = SHOW_NAMES if role == "show" else PREPARE_NAMES
    out = []
    for gi, g in enumerate(groups):
        names = [t.format(i=i) for t in g for i in (range(n_claims) if "{i}" in t else [0])]
        out.append((gi, names))
    return out


def sym_indices(sym_path, wanted):
    """name -> witness index for each name in `wanted` found in the file; stops once all are found."""
    remaining = set(wanted)
    found = {}
    with open(sym_path, "r") as f:
        for line in f:
            parts = line.rstrip("\n").split(",", 3)
            if len(parts) != 4 or parts[3] not in remaining:
                continue
            idx = int(parts[1])
            if idx < 0:
                raise ValueError(f"{parts[3]} was optimized out of the witness")
            found[parts[3]] = idx
            remaining.discard(parts[3])
            if not remaining:
                break
    return found


def derive(role, sym_path, r1cs_path, n_claims):
    groups = ordered_names(role, n_claims)
    found = sym_indices(sym_path, [n for _, names in groups for n in names])
    shared = []
    for gi, names in groups:
        have = [n in found for n in names]
        if not any(have) and gi in OPTIONAL_GROUPS:
            continue
        if not all(have):
            missing = [n for n, h in zip(names, have) if not h]
            raise ValueError(f"{sym_path}: signals not found: {missing}")
        shared.extend(found[n] for n in names)
    hdr = constraints.parse_header(r1cs_path)
    return {"role": role, "num_public": hdr["outputs"] + hdr["public_inputs"], "shared": shared}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--role", choices=["show", "prepare"], required=True)
    ap.add_argument("--sym", required=True)
    ap.add_argument("--r1cs", required=True)
    ap.add_argument("--n-claims", type=int, default=2)
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    layout = derive(a.role, a.sym, a.r1cs, a.n_claims)
    with open(a.out, "w") as f:
        json.dump(layout, f)
    print(f"{a.role}: {len(layout['shared'])} shared, {layout['num_public']} public", file=sys.stderr)


if __name__ == "__main__":
    main()
