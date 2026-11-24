#!/usr/bin/env python3
"""Read r1cs headers and write CONSTRAINTS rows for the openacplus bench.

The padded-shape model mirrors Spartan2 rev d687dbb (the rev pinned in Cargo.lock):
  src/r1cs/mod.rs  `pad_to_width` and `SplitR1CSShape::new`  (shared/rest padding, power-of-two vars and constraints)
  src/bellpepper/zk_r1cs.rs  `NUM_BLINDS` and the three blind constraints added after `synthesize`
  src/provider/pcs/hyrax_pc.rs  `width()` is 1024
"""
import argparse
import hashlib
import json
import os
import struct
import sys

WIDTH = 1024
NUM_BLINDS = 4
BLIND_CONSTRAINTS = 3


def parse_header(path):
    with open(path, "rb") as f:
        if f.read(4) != b"r1cs":
            raise ValueError(f"{path}: not an r1cs file")
        _version, n_sections = struct.unpack("<II", f.read(8))
        for _ in range(n_sections):
            sec_type, sec_size = struct.unpack("<IQ", f.read(12))
            if sec_type != 1:
                f.seek(sec_size, os.SEEK_CUR)
                continue
            (field_size,) = struct.unpack("<I", f.read(4))
            f.seek(field_size, os.SEEK_CUR)
            wires, pub_out, pub_in, prv_in, labels, cons = struct.unpack("<IIIIQI", f.read(28))
            return {
                "constraints": cons,
                "wires": wires,
                "outputs": pub_out,
                "public_inputs": pub_in,
                "private_inputs": prv_in,
                "labels": labels,
            }
    raise ValueError(f"{path}: no header section")


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 22), b""):
            h.update(chunk)
    return h.hexdigest()


def pad_to_width(width, n):
    if n == 0:
        return 0
    return (n + width - 1) & ~(width - 1)


def next_pow2(n):
    return 1 if n <= 1 else 1 << (n - 1).bit_length()


def padded_shape(num_cons, num_shared, num_aux, num_public, num_challenges=0):
    """Padded sizes Spartan2 uses for a shape with `num_aux` aux variables, `num_shared` of them shared."""
    num_rest = num_aux - num_shared
    shared_p = pad_to_width(WIDTH, num_shared)
    rest_p = pad_to_width(WIDTH, num_rest)
    if shared_p + rest_p < num_public + num_challenges + 1:
        rest_p = num_public + num_challenges + 1 - shared_p
    total = shared_p + rest_p
    if next_pow2(total) != total:
        rest_p = next_pow2(total) - shared_p
    cons_p = next_pow2(num_cons)
    return {
        "cons": num_cons,
        "cons_padded": cons_p,
        "cons_log2": cons_p.bit_length() - 1,
        "shared_padded": shared_p,
        "rest_padded": rest_p,
        "vars_padded": shared_p + rest_p,
        "vars_log2": (shared_p + rest_p).bit_length() - 1,
    }


def shape_from_header(hdr, num_shared):
    """Padded shape of a circuit whose r1cs has this header, wrapped as the prover wraps it:
    `num_shared` shared variables each bound by one constraint, plus the zk blinds."""
    num_public = hdr["outputs"] + hdr["public_inputs"]
    circom_aux = hdr["wires"] - 1 - num_public
    return padded_shape(
        num_cons=hdr["constraints"] + num_shared + BLIND_CONSTRAINTS,
        num_shared=num_shared,
        num_aux=num_shared + circom_aux + NUM_BLINDS,
        num_public=num_public,
    )


def depths_for(config, circuits_json, circuit):
    """(d_iss, d_rev) from the Show template parameters; the last two params are the depths present."""
    entry = circuits_json[circuit]
    if entry.get("template") != "Show":
        return None, None
    extra = entry["params"][4:]
    if config == "combined":
        return tuple(extra[:2]) if len(extra) == 2 else (None, None)
    if config == "issuer":
        return (extra[0], None) if extra else (None, None)
    if config == "revocation":
        return (None, extra[0]) if extra else (None, None)
    return None, None


def jwt_size_of(circuit):
    if circuit.startswith("jwt_"):
        return circuit.split("_", 1)[1]
    return None


def constraints_row(config, circuit, d_iss, d_rev, jwt_size, hdr, r1cs_sha256):
    return {
        "kind": "CONSTRAINTS",
        "config": config,
        "circuit": circuit,
        "d_iss": d_iss,
        "d_rev": d_rev,
        "jwt_size": jwt_size,
        "constraints": hdr["constraints"],
        "wires": hdr["wires"],
        "public_inputs": hdr["public_inputs"],
        "private_inputs": hdr["private_inputs"],
        "outputs": hdr["outputs"],
        "labels": hdr["labels"],
        "r1cs_sha256": r1cs_sha256,
    }


def linear_fit(points):
    """Least-squares-free exact fit through the first two points; `exact` says whether all points lie on it."""
    pts = sorted(points)
    (x0, y0), (x1, y1) = pts[0], pts[1]
    if (y1 - y0) % (x1 - x0):
        return (y1 - y0) / (x1 - x0), y0, False
    slope = (y1 - y0) // (x1 - x0)
    intercept = y0 - slope * x0
    return slope, intercept, all(y == slope * x + intercept for x, y in pts)


def r1cs_path(build_dir, circuit):
    return os.path.join(build_dir, circuit, f"{circuit}.r1cs")


def scan(config, circom_dir):
    with open(os.path.join(circom_dir, "circuits.json")) as f:
        cj = json.load(f)
    build = os.path.join(circom_dir, "build")
    for circuit in sorted(cj):
        path = r1cs_path(build, circuit)
        if not os.path.exists(path):
            continue
        d_iss, d_rev = depths_for(config, cj, circuit)
        yield constraints_row(
            config, circuit, d_iss, d_rev, jwt_size_of(circuit),
            parse_header(path), sha256_file(path),
        )


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--config", required=True, choices=["main", "issuer", "revocation", "combined"])
    ap.add_argument("--circom-dir", required=True, help="wallet-unit-poc/circom of the worktree")
    ap.add_argument("--out", required=True, help="constraints.jsonl; rows are appended")
    ap.add_argument("--only", nargs="*", help="circuit names to include (default: every compiled one)")
    args = ap.parse_args(argv)
    with open(args.out, "a") as out:
        for row in scan(args.config, args.circom_dir):
            if args.only and row["circuit"] not in args.only:
                continue
            out.write(json.dumps(row) + "\n")
            print(row["config"], row["circuit"], row["constraints"], file=sys.stderr)


if __name__ == "__main__":
    main()
