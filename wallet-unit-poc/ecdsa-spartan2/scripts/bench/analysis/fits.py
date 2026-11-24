"""Linear fits, the eq. 11 cost-model fit and the registry hash-count check."""
from collections import defaultdict, namedtuple

from bench import Dataset  # noqa: F401  (type context only)

Fit = namedtuple("Fit", "slope intercept r2 n")
CostFit = namedtuple("CostFit", "coef r2 residuals n")
TERMS = ("a", "b", "c", "d", "e", "f", "g")
DEPTH_CONFIGS = ("combined", "variant")
REF_PARAMS = [2, 2, 8, 64]


def next_pow2(n):
    return 1 << (n - 1).bit_length()


def linfit(xs, ys):
    n = len(xs)
    if n < 2 or len(set(xs)) < 2:
        return None
    mx, my = sum(xs) / n, sum(ys) / n
    sxx = sum((x - mx) ** 2 for x in xs)
    slope = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / sxx
    icpt = my - slope * mx
    ss_tot = sum((y - my) ** 2 for y in ys)
    ss_res = sum((y - (icpt + slope * x)) ** 2 for x, y in zip(xs, ys))
    return Fit(slope, icpt, 1.0 if ss_tot == 0 else 1 - ss_res / ss_tot, n)


def padding_class(shape):
    return shape.get("padded_constraints") or next_pow2(shape["constraints"])


def fit_by_class(points):
    """points: (x, y, padding class). One fit per class; None when a class has one distinct x."""
    groups = defaultdict(list)
    for x, y, cls in points:
        groups[cls].append((x, y))
    return {cls: linfit([p[0] for p in pts], [p[1] for p in pts]) for cls, pts in sorted(groups.items())}


def per_level(shapes, depth_key, value="constraints"):
    """`value` against `depth_key` ('d_iss' or 'd_rev'), fitted inside each padding class; `fit` is the largest class's."""
    pts = [(r[depth_key], r[value], padding_class(r)) for r in shapes]
    fits = fit_by_class(pts)
    best = max((c for c, f in fits.items() if f), default=None)
    return {"fits": fits, "class": best, "fit": fits.get(best), "points": pts}


def _solve(a, b):
    n = len(b)
    m = [row[:] + [b[i]] for i, row in enumerate(a)]
    for i in range(n):
        p = max(range(i, n), key=lambda r: abs(m[r][i]))
        if abs(m[p][i]) < 1e-9:
            raise ValueError("design matrix is rank deficient")
        m[i], m[p] = m[p], m[i]
        for r in range(n):
            if r != i:
                f = m[r][i] / m[i][i]
                m[r] = [x - f * y for x, y in zip(m[r], m[i])]
    return [m[i][n] / m[i][i] for i in range(n)]


def fit_cost_model(rows, with_t=True):
    """constraints ~ a*M*N + b*M*beta + c*T*M + d*T^2 + e*M + f (+ g*T), with M_D = 0."""
    terms = TERMS if with_t else TERMS[:-1]
    x = [[r["m_pred"] * r["n_claims"], r["m_pred"] * r["beta"], r["t_tok"] * r["m_pred"], r["t_tok"] ** 2,
          r["m_pred"], 1] + ([r["t_tok"]] if with_t else []) for r in rows]
    y = [r["constraints"] for r in rows]
    k = len(terms)
    ata = [[sum(row[i] * row[j] for row in x) for j in range(k)] for i in range(k)]
    atb = [sum(row[i] * v for row, v in zip(x, y)) for i in range(k)]
    coef = _solve(ata, atb)
    pred = [sum(c * v for c, v in zip(coef, row)) for row in x]
    resid = [v - p for v, p in zip(y, pred)]
    my = sum(y) / len(y)
    ss_tot = sum((v - my) ** 2 for v in y)
    r2 = 1.0 if ss_tot == 0 else 1 - sum(r * r for r in resid) / ss_tot
    return CostFit(dict(zip(terms, coef)), r2, resid, len(y))


def per_compression(ds):
    """Constraints of the standalone SHA-256 compression gadget."""
    rows = ds.shape_rows("sha256")
    return rows[0]["constraints"] / (rows[0].get("compressions") or 1) if rows else None


def depth_rows(ds, depth_key):
    """Reference-parameter Show shapes along one depth axis: D_rev at D_iss 8, or D_iss at D_rev 20."""
    fixed = {"d_rev": ("d_iss", 8), "d_iss": ("d_rev", 20)}[depth_key]
    out = {}
    for r in ds.shape_rows("show"):
        sp = r.get("show_params")
        if r.get("config") in DEPTH_CONFIGS and sp and len(sp) == 6 and sp[:4] == REF_PARAMS and r.get(fixed[0]) == fixed[1]:
            out[r[depth_key]] = r
    return [out[d] for d in sorted(out)]


def depth_slope_check(ds):
    """Constraints per level against the standalone compression cost: the paper has two compressions per level."""
    pc, out = per_compression(ds), []
    for tree, key in (("revocation", "d_rev"), ("issuer", "d_iss")):
        rows = depth_rows(ds, key)
        lv = per_level(rows, key) if len(rows) >= 2 else None
        if lv and lv["fit"]:
            out.append({"tree": tree, "slope": lv["fit"].slope, "class": lv["class"], "rows": rows,
                        "compressions_per_level": lv["fit"].slope / pc if pc else None})
    return out


def structural(d_iss, d_rev):
    """Compressions fixed by the parameters: 2*D_iss + 2 for the issuer tree, 2*D_rev + 3 for revocation (the secret hash is one block)."""
    return (2 * d_iss + 2 if d_iss else 0) + (2 * d_rev + 3 if d_rev else 0)


def paper_hashes(d_iss, d_rev):
    """The paper's count: D node hashes per tree, plus an entry hash (issuer) or entry and predecessor hashes (revocation)."""
    return (d_iss + 1 if d_iss else 0) + (d_rev + 2 if d_rev else 0)


def hash_count_check(ds):
    """Structural compressions against the paper's hashes at two compressions each.

    `evidence` is (Show - GP-only Show) / standalone gadget constraints, or None without a GP-only row.
    """
    pc = per_compression(ds)
    out, seen = [], set()
    for r in ds.shape_rows("show"):
        sp = r.get("show_params")
        di, dr = r.get("d_iss") or 0, r.get("d_rev") or 0
        if not sp or not (di or dr) or r.get("config") not in ("issuer", "revocation") + DEPTH_CONFIGS:
            continue
        if (r["config"], di, dr, tuple(sp)) in seen:
            continue
        seen.add((r["config"], di, dr, tuple(sp)))
        base = [b for b in ds.shape_rows("show", config="main") if b.get("show_params") == sp[:4]]
        evidence = (r["constraints"] - base[0]["constraints"]) / pc if base and pc else None
        hashes = paper_hashes(di, dr)
        m = structural(di, dr)
        out.append({"config": r["config"], "d_iss": di, "d_rev": dr, "show_params": sp, "constraints": r["constraints"],
                    "measured": m, "evidence": evidence, "paper_hashes": hashes, "paper_compressions": 2 * hashes,
                    "diff": m - 2 * hashes, "row": r, "matrix_id": r.get("matrix_id")})
    return sorted(out, key=lambda x: (x["config"], x["d_iss"], x["d_rev"]))
