"""The labels the paper must carry, from one list, written as labels.md and one note per table and figure."""
import os

LABELS = {
    "trees": "The registry trees are SHA-256 with no role tags.",
    "revocation": "The revocation value is a signed commitment opened in Show; it is not bound to the issuer.",
    "shared": "The shared vector is 2n+6 elements, not N+4.",
    "names": "Show hashes 2M attribute names, a linear-in-M term that eq. 11 does not have.",
    "scope": "There is no disclosure, no `prepareBatch` and no root check in Rust.",
    "vk": "The VK is as large as the PK.",
    "fixes": "The numbers predate the security-fix batch.",
    "v1": "v1.0.0 is OpenAC as published; its semantics differ from S_GP.",
    "cache": "Mac key loads are page-cache warm.",
    "memstate": "Cold presentation keeps the prepared state in memory (no separate state load from storage) on all targets.",
    "digest": "Mac verify excludes the VK digest; phones restore it from a sidecar (PR #115).",
    "chain": "The chain cells use the branches' default fixture registries.",
    "upper": "Registry `mirror_upper` is an upper bound.",
}

REQUIRED = {
    "T1": ["fixes", "cache", "digest", "scope"], "T1b": ["v1", "fixes", "digest"],
    "T2a": ["v1", "fixes"], "T2b": ["trees", "revocation", "names", "v1"],
    "T3": ["vk", "scope", "fixes"], "T4": ["v1", "chain", "digest", "fixes"],
    "T5": ["trees", "fixes"], "T5b": ["trees", "upper"], "T6": ["cache", "memstate", "fixes"], "T7": ["fixes"],
    "T8": ["scope"], "T9a": ["names", "shared"], "T9b": ["trees", "revocation"],
    "F1": ["trees", "revocation", "fixes"], "F2": ["trees"], "F3": ["v1", "fixes"], "F4": ["names", "scope"],
    "F5": ["shared", "names"], "F6": ["trees", "upper"],
}


def write_labels(outdir):
    os.makedirs(outdir, exist_ok=True)
    lines = ["# Labels the paper must carry", ""]
    lines += [f"- {text}" for text in LABELS.values()]
    lines += ["", "# Labels per table and figure", ""]
    for name, ids in REQUIRED.items():
        lines += [f"## {name}", ""] + [f"- {LABELS[i]}" for i in ids] + [""]
        with open(os.path.join(outdir, f"{name}.note.txt"), "w") as f:
            f.write("\n".join(LABELS[i] for i in ids) + "\n")
    with open(os.path.join(outdir, "labels.md"), "w") as f:
        f.write("\n".join(lines))
