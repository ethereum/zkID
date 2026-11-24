#!/usr/bin/env python3
"""Stage one cell: binary, dylibs, keys, inputs and meta, with no circom/build and no r1cs (unless r1cs-present).

Layout under stage/<config>/<cell>/:
  openac_bench (+ dylibs next to it), meta.json,
  docs/{keys/*.key, jwt_input.json, show_input.json, expected.json}
  circom/build/... only for an r1cs-present cell
Generic cells hold keys/generic_*.key, generic.wtns and layout.json instead of docs/.
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

import stagelib as sl

KEY_FILES = ("prepare_proving.key", "prepare_verifying.key", "show_proving.key", "show_verifying.key")


def external_dylibs(otool_out):
    """Non-system dependencies from `otool -L` output."""
    deps = []
    for line in otool_out.splitlines()[1:]:
        m = re.match(r"\s*(\S+) \(", line)
        if m and not m.group(1).startswith(("/usr/lib/", "/System/")):
            deps.append(m.group(1))
    return deps


def find_libdirs(binary):
    """Where `@rpath` libraries live: the witnesscalc package dirs of the cargo build that made `binary`."""
    import glob
    target = os.path.dirname(os.path.dirname(os.path.abspath(binary)))
    pats = [os.path.join(target, "release", "build", "ecdsa-spartan2-*", "out", "witnesscalc", "package", "lib"),
            os.path.join(target, "release", "build", "ecdsa-spartan2-*", "out", "witnesscalc", "depends", "gmp", "package", "lib")]
    return [d for p in pats for d in sorted(glob.glob(p), key=os.path.getmtime, reverse=True)[:1]]


def bundle_binary(binary, dest_dir, libdirs=None):
    """Copy the binary and its non-system dylibs next to it, repointing install names; returns bytes of the dylibs."""
    dst = os.path.join(dest_dir, sl.BIN_NAME)
    libdirs = libdirs if libdirs is not None else find_libdirs(binary)
    # Replace the file instead of rewriting it: overwriting a code-signed file in place can SIGBUS the next run.
    if os.path.exists(dst):
        os.unlink(dst)
    shutil.copyfile(binary, dst)
    os.chmod(dst, 0o755)
    total = 0
    queue = [dst]
    seen = set()
    while queue:
        target = queue.pop()
        for dep in external_dylibs(sl.sh(["otool", "-L", target])):
            name = os.path.basename(dep)
            src = dep if os.path.isabs(dep) else next(
                (os.path.join(d, name) for d in libdirs if dep.startswith("@rpath/") and os.path.exists(os.path.join(d, name))), None)
            if src is None or not os.path.exists(src):
                raise FileNotFoundError(f"{target} needs {dep}")
            local = os.path.join(dest_dir, name)
            if name not in seen:
                if os.path.exists(local):
                    os.unlink(local)
                shutil.copyfile(src, local)
                os.chmod(local, 0o755)
                seen.add(name)
                total += os.path.getsize(local)
                queue.append(local)
            subprocess.run(["install_name_tool", "-change", dep, f"@executable_path/{name}", target], check=True, capture_output=True)
    for f in [dst] + [os.path.join(dest_dir, n) for n in seen]:
        subprocess.run(["codesign", "--force", "-s", "-", f], check=True, capture_output=True)
    return total


def stage_key(src, dst, store):
    """Hardlink identical key files through a content-addressed store."""
    digest = sl.sha256_file(src)
    blob = os.path.join(store, digest)
    if not os.path.exists(blob):
        sl.hardlink_or_copy(src, blob)
    sl.hardlink_or_copy(blob, dst)
    return digest


def check_runs_standalone(cell):
    """The staged binary must start with no circom/build next to it or in the working directory."""
    meta = json.load(open(os.path.join(cell, "meta.json")))
    if not meta.get("r1cs_present") and os.path.exists(os.path.join(cell, "circom", "build")):
        raise RuntimeError(f"circom/build present in {cell}")
    with tempfile.TemporaryDirectory() as tmp:
        vk = os.path.join(cell, "docs", "keys", "show_verifying.key")
        if not os.path.exists(vk):
            vk = os.path.join(cell, "keys", "generic_verifying.key")
        r = subprocess.run([os.path.join(cell, sl.BIN_NAME), "digest", "--vk", vk], cwd=tmp, capture_output=True, text=True, env={"PATH": "/usr/bin:/bin"})
        if r.returncode != 0 or len(r.stdout.strip()) != 64:
            raise RuntimeError(f"staged binary failed: {r.stderr[-300:]}")
        return r.stdout.strip()


def root_limbs(root):
    """A 256-bit root as the [hi, lo] 128-bit limb pair Show exposes."""
    r = int(root)
    return [str(r >> 128), str(r & ((1 << 128) - 1))]


def apply_registry_roots(expected, roots, d_rev):
    """Check the circuit's evaluated roots against the registry's and keep the registry's.

    Show public values start [expressionResult, issuerRoot hi, lo, revocationRoot hi, lo] (public index = witness - 1).
    """
    want = {1: root_limbs(roots["issuerRoot"])}
    if d_rev:
        want[3] = root_limbs(roots["revocationRoot"])
    for at, limbs in want.items():
        if expected["show_public"][at:at + 2] != limbs:
            raise RuntimeError(f"circuit root at public index {at} differs from the registry root")
        expected["show_public"][at:at + 2] = limbs
    return expected


def emit_expected(cell, size, attempts=3):
    """witnesscalc crashes in about one Mac process in five; a signal-killed attempt is retried."""
    for _ in range(attempts):
        r = subprocess.run([os.path.join(cell, sl.BIN_NAME), "emit-expected", "--dir", cell, "--size", size], cwd=cell)
        if r.returncode >= 0:
            break
    if r.returncode != 0:
        raise RuntimeError(f"emit-expected exited {r.returncode}")


def stage_product(a):
    eco = os.path.join(a.worktree, "wallet-unit-poc", "ecdsa-spartan2")
    cell = sl.cell_dir(a.config, a.cell)
    if os.path.exists(cell):
        shutil.rmtree(cell)
    docs = os.path.join(cell, "docs")
    os.makedirs(os.path.join(docs, "keys"))
    artifacts = bundle_binary(os.path.join(eco, "target", "release", sl.BIN_NAME), cell)
    store = os.path.join(sl.stage_root(), "_store")
    keys = {}
    for k in KEY_FILES:
        keys[f"{a.size}_{k}"] = stage_key(os.path.join(eco, "keys", f"{a.size}_{k}"), os.path.join(docs, "keys", k), store)
    shutil.copy2(a.jwt_input, os.path.join(docs, "jwt_input.json"))
    shutil.copy2(a.show_input, os.path.join(docs, "show_input.json"))
    meta = {
        "config": a.label_config or a.config, "cell": a.cell, "matrix_id": a.matrix_id, "path": "product", "jwt_size": a.size,
        "keys_sha256": keys, "input_sha256": {"jwt": sl.sha256_file(a.jwt_input), "show": sl.sha256_file(a.show_input)},
        "bench_sha": sl.sh(["git", "-C", a.worktree, "rev-parse", "--short", "HEAD"]).strip(),
        "r1cs_present": bool(a.r1cs_present), "witness_artifacts_bytes": artifacts,
        "spartan2_rev": "d687dbb", "d_iss": a.d_iss, "d_rev": a.d_rev,
    }
    meta["iss_path_len"], meta["rev_path_len"] = sl.path_lens(a.show_input)
    meta["show_params"], meta["jwt_params"] = sl.product_params(a.config, a.size)
    if a.label_config and a.label_config != a.config:
        meta["variant_of"] = a.config
    meta["roots_source"] = "registry" if a.roots else "circuit"
    if a.population:
        meta["population"] = json.loads(a.population)
    meta["commit"] = meta["bench_sha"]
    meta.update(json.loads(a.meta or "{}"))
    if a.r1cs_present:
        circom = os.path.join(a.worktree, "wallet-unit-poc", "circom", "build")
        for name, js in (("jwt_" + a.size, "jwt"), ("show", "show")):
            src = os.path.join(circom, name, f"{name}.r1cs")
            dst = os.path.join(cell, "circom", "build", js, f"{js}_js", f"{js}.r1cs")
            os.makedirs(os.path.dirname(dst))
            sl.hardlink_or_copy(src, dst)
            meta.setdefault("r1cs_sha256", {})[js] = sl.sha256_file(src)
    with open(os.path.join(cell, "meta.json"), "w") as f:
        json.dump(meta, f, indent=1)
    emit_expected(cell, a.size)
    if a.roots:
        roots = json.load(open(a.roots))
        if "issuers" in roots:
            meta["population"] = {"issuers": roots["issuers"], "revoked": roots["revoked"]}
        meta["roots_sha256"] = sl.sha256_file(a.roots)
        path = os.path.join(docs, "expected.json")
        expected = apply_registry_roots(json.load(open(path)), roots, a.d_rev)
        json.dump(expected, open(path, "w"))
        json.dump(meta, open(os.path.join(cell, "meta.json"), "w"), indent=1)
    return cell


def stage_generic(a):
    cell = sl.cell_dir("variant", a.cell)
    if os.path.exists(cell):
        shutil.rmtree(cell)
    os.makedirs(os.path.join(cell, "keys"))
    artifacts = bundle_binary(a.binary, cell)
    store = os.path.join(sl.stage_root(), "_store")
    keys = {n: stage_key(os.path.join(a.keys, n), os.path.join(cell, "keys", n), store) for n in ("generic_proving.key", "generic_verifying.key")}
    shutil.copy2(a.wtns, os.path.join(cell, "generic.wtns"))
    shutil.copy2(a.layout, os.path.join(cell, "layout.json"))
    meta = {"config": "variant", "cell": a.cell, "matrix_id": a.matrix_id, "path": "generic", "keys_sha256": keys,
            "input_sha256": sl.sha256_file(a.wtns), "witness_artifacts_bytes": artifacts, "r1cs_present": False}
    meta["iss_path_len"], meta["rev_path_len"] = sl.path_lens(a.show_input) if a.show_input else (0, 0)
    meta.update(json.loads(a.meta or "{}"))
    with open(os.path.join(cell, "meta.json"), "w") as f:
        json.dump(meta, f, indent=1)
    return cell


def stamp_commit(meta_path, worktree, binary):
    """Record the worktree HEAD the binary was built from, and the binary's hash, in meta.json."""
    with open(meta_path) as f:
        meta = json.load(f)
    meta["bench_sha"] = meta["commit"] = sl.sh(["git", "-C", worktree, "rev-parse", "--short", "HEAD"]).strip()
    meta["binary_sha256"] = sl.sha256_file(binary)
    with open(meta_path, "w") as f:
        json.dump(meta, f, indent=1)
    return meta["commit"]


def rebin(root=None):
    """Replace the binary (and its dylibs) in every staged cell with the current build of its worktree."""
    import glob
    for meta in sorted(glob.glob(os.path.join(root or sl.stage_root(), "*", "*", "meta.json"))):
        cell = os.path.dirname(meta)
        cfg = os.path.basename(os.path.dirname(cell))
        wt = sl.worktree(cfg)
        binary = sl.worktree_binary(cfg)
        bundle_binary(binary, cell)
        check_runs_standalone(cell)
        stamp_commit(meta, wt, os.path.join(cell, sl.BIN_NAME))
        print("rebinned", cell, file=sys.stderr)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="mode", required=True)
    p = sub.add_parser("product")
    p.add_argument("--worktree", required=True)
    p.add_argument("--config", required=True)
    p.add_argument("--cell", required=True)
    p.add_argument("--size", required=True)
    p.add_argument("--jwt-input", required=True, dest="jwt_input")
    p.add_argument("--show-input", required=True, dest="show_input")
    p.add_argument("--matrix-id", default="A1")
    p.add_argument("--r1cs-present", action="store_true")
    p.add_argument("--meta")
    p.add_argument("--roots", help="Track B *.roots.json next to the input")
    p.add_argument("--label-config", dest="label_config", help="config written on rows when the cell is a variant of a worktree config")
    p.add_argument("--population", help='JSON {"issuers", "revoked"} for inputs without a roots file')
    p.add_argument("--d-iss", type=int, default=0, dest="d_iss")
    p.add_argument("--d-rev", type=int, default=0, dest="d_rev")
    g = sub.add_parser("generic")
    g.add_argument("--binary", required=True)
    g.add_argument("--cell", required=True)
    g.add_argument("--keys", required=True)
    g.add_argument("--wtns", required=True)
    g.add_argument("--layout", required=True)
    g.add_argument("--show-input", dest="show_input", help="the cell's Show input JSON, for the path lengths")
    g.add_argument("--matrix-id", default="S-D")
    g.add_argument("--meta")
    sub.add_parser("rebin")
    a = ap.parse_args(argv)
    if a.mode == "rebin":
        return rebin()
    cell = stage_product(a) if a.mode == "product" else stage_generic(a)
    digest = check_runs_standalone(cell)
    print(f"staged {cell} (vk digest {digest})", file=sys.stderr)


if __name__ == "__main__":
    main()
