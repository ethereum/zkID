#!/usr/bin/env python3
"""Update the meta.json of staged product cells in place (path lengths, config label, population, roots source).

Generic cells are patched with `stage_generic_all.py --patch-meta`. Keys, state and binaries are not touched.
"""
import glob
import json
import os

import stagelib as sl
from stage_all import CHAIN_POPULATION

for meta in sorted(glob.glob(os.path.join(sl.stage_root(), "*", "*", "meta.json"))):
    cell = os.path.dirname(meta)
    show = os.path.join(cell, "docs", "show_input.json")
    if not os.path.exists(show):
        continue
    stage_dir = os.path.basename(os.path.dirname(cell))
    updates = {"roots_source": "registry" if stage_dir == "headline" else "circuit"}
    if stage_dir == "headline":
        updates.update({"config": "combined", "variant_of": "headline"})
    elif CHAIN_POPULATION.get(stage_dir):
        updates["population"] = CHAIN_POPULATION[stage_dir]
    name = os.path.basename(cell)
    if name.startswith("X2-"):
        updates["base_cell"] = f"A1-{name.split('-')[1]}-2k"
    size = json.load(open(meta))["jwt_size"]
    updates["show_params"], updates["jwt_params"] = sl.product_params(stage_dir, size)
    sl.update_meta(cell, updates)
    print(cell, sl.patch_path_lens(cell, show), updates["roots_source"])
