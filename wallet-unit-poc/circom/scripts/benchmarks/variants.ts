import * as fs from "fs";
import * as path from "path";

export type Kind = "show" | "show4" | "jwt" | "sha";

export interface Cell {
  name: string;
  matrix: "S-N" | "S-D" | "S-MT" | "S-B" | "X2" | "SHA" | "C0";
  kind: Kind;
  params: number[];
  /** Needs a wasm witness generator (timed on the product path or used for functional checks). */
  wasm: boolean;
  /** Existing build to describe instead of compiling again. */
  reuse?: { r1cs: string; wasm?: string };
  /** At least 24 levels or (16,31): runs alone. */
  heavy?: boolean;
}

const circomDir = path.resolve(__dirname, "..", "..");
export const buildDir = path.join(circomDir, "build", "_bench");

export const REF_SHOW = [2, 2, 8, 64, 8, 20];

const show = (name: string, matrix: Cell["matrix"], params: number[], wasm: boolean, extra: Partial<Cell> = {}): Cell => ({
  name, matrix, kind: "show", params, wasm, ...extra,
});

const headline = {
  r1cs: path.join(buildDir, "headline", "show.r1cs"),
  wasm: path.join(buildDir, "headline", "show_js", "show.wasm"),
};

export function allCells(): Cell[] {
  const cells: Cell[] = [];

  // S-N: capacity N with two active claims; Show nClaims = N, JWT maxMatches = N + 2.
  for (const n of [2, 8, 16, 32, 64]) {
    const p = [n, ...REF_SHOW.slice(1)];
    cells.push(show(`sn_show_n${n}`, "S-N", p, true, n === 2 ? { reuse: headline } : {}));
    cells.push({
      name: `sn_jwt_n${n}`, matrix: "S-N", kind: "jwt", params: [2048, 2000, n + 2, 50, 128], wasm: n <= 16,
      ...(n === 2 ? { reuse: { r1cs: path.join(circomDir, "build", "jwt_2k", "jwt_2k.r1cs"), wasm: path.join(circomDir, "build", "jwt_2k", "jwt_2k_js", "jwt_2k.wasm") } } : {}),
    });
  }

  // S-D: revocation depth at issuer depth 8, issuer depth at revocation depth 20, and the corner.
  const depths: [number, number][] = [[8, 8], [8, 16], [8, 20], [8, 24], [8, 32], [16, 20], [24, 20], [32, 20], [32, 32]];
  for (const [di, dr] of depths) {
    if (di === 8 && dr === 20) continue; // the reference, built by the headline compile
    cells.push(show(`sd_d${di}_r${dr}`, "S-D", [2, 2, 8, 64, di, dr], true, { heavy: di >= 24 || dr >= 24 }));
  }

  // S-MT: (M,T) on the combined 6-param Show and on main's 4-param Show; N stays 2.
  for (const [m, t] of [[1, 1], [4, 7], [8, 15], [16, 31]]) {
    cells.push(show(`smt_c_m${m}_t${t}`, "S-MT", [2, m, t, 64, 8, 20], true, { heavy: m === 16 }));
    cells.push({ name: `smt_m_m${m}_t${t}`, matrix: "S-MT", kind: "show4", params: [2, m, t, 64], wasm: false });
  }

  // S-B: value bit width.
  for (const b of [16, 32, 128]) cells.push(show(`sb_b${b}`, "S-B", [2, 2, 8, b, 8, 20], false));

  // X2: a full grid for the eq. 11 fit. Revocation is compiled out and the issuer tree is one level,
  // so each cell is the shared ECDSA/device part plus the terms under test.
  for (const n of [2, 8, 32]) for (const m of [1, 4, 16]) for (const t of [1, 8, 31]) for (const b of [16, 32, 64]) {
    cells.push(show(`x2_n${n}_m${m}_t${t}_b${b}`, "X2", [n, m, t, b, 1, 0], false));
  }

  cells.push({ name: "sha256_compression", matrix: "SHA", kind: "sha", params: [], wasm: false });
  cells.push({
    name: "jwt_1920", matrix: "C0", kind: "jwt", params: [1920, 1900, 4, 50, 128], wasm: true,
  });
  return cells;
}

export const SHOW_PUBS = [
  "messageHash", "predicateLen", "predicateClaimRefs", "predicateOps", "predicateRhsIsRef", "predicateRhsValues",
  "tokenTypes", "tokenValues", "exprLen", "predicateClaimNames", "predicateClaimNameLens",
  "predicateRhsClaimNames", "predicateRhsClaimNameLens",
];
export const JWT_PUBS = ["decodeFlags", "claimFormats"];

/** The circom main file for a cell; `include` paths resolve through `-l circuits`. */
export function mainSource(c: Cell): string {
  const pubs = (xs: string[]) => `{public[${xs.join(", ")}]}`;
  switch (c.kind) {
    case "show":
    case "show4":
      return `pragma circom 2.2.3;\n\ninclude "show.circom";\n\ncomponent main ${pubs(SHOW_PUBS)} = Show(${c.params.join(", ")});\n`;
    case "jwt":
      return `pragma circom 2.2.3;\n\ninclude "jwt.circom";\n\ncomponent main ${pubs(JWT_PUBS)} = JWT(${c.params.join(", ")});\n`;
    case "sha":
      return `pragma circom 2.2.3;\n\ninclude "sha256/sha256compression.circom";\n\ncomponent main = Sha256compression();\n`;
  }
}

export const exists = (p: string) => fs.existsSync(p);
