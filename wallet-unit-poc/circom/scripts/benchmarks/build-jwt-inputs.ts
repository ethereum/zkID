/**
 * JWT (Prepare) inputs and witnesses for the S-N cells timed at N = 8 and 16. These run standalone:
 * unused claim slots carry whatever the JWT circuit derives, so they are not linked to the padded Show inputs.
 *
 *   npx tsx scripts/benchmarks/build-jwt-inputs.ts [--only sn_jwt_n8,sn_jwt_n16]
 */
import { execSync } from "child_process";
import * as crypto from "crypto";
import * as fs from "fs";
import * as path from "path";
// @ts-ignore - snarkjs ships no types
import * as snarkjs from "snarkjs";
import { generateMockData } from "../../src/mock-vc-generator.ts";
import { PredicateFormat } from "../../src/predicate-types.ts";
import { benchRoot } from "./provenance.ts";
import { readR1cs } from "./r1cs.ts";

const bench = () => path.join(benchRoot(), "variants");
const bigintReplacer = (_k: string, v: unknown) => (typeof v === "bigint" ? v.toString() : v);
const sha = (p: string) => crypto.createHash("sha256").update(fs.readFileSync(p)).digest("hex");

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const only = args.includes("--only") ? args[args.indexOf("--only") + 1].split(",") : ["sn_jwt_n8", "sn_jwt_n16"];
  const shapes = new Map(fs.readFileSync(path.join(bench(), "shape.jsonl"), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l)).map((r) => [r.cell, r]));
  const file = path.join(bench(), "inputs.jsonl");
  for (const cell of only) {
    const shape = shapes.get(cell);
    const symPath = shape.r1cs_path.replace(/\.r1cs$/, ".sym");
    const params: number[] = shape.jwt_params;
    const mock = await generateMockData({
      issuer: "https://issuer.example",
      subject: "did:example:holder",
      circuitParams: params,
      targetPayloadLength: Math.floor(params[1] * 0.8),
      claimFormats: [PredicateFormat.STRING_EQ, PredicateFormat.ROC_DATE],
      revocationSecret: new Uint8Array(crypto.createHash("sha256").update("holder|1").digest()),
    });
    const dir = path.join(bench(), "inputs", cell);
    fs.mkdirSync(dir, { recursive: true });
    const inPath = path.join(dir, "prepare.json");
    const wtns = path.join(dir, "prepare.wtns");
    fs.writeFileSync(inPath, JSON.stringify(mock.circuitInputs, bigintReplacer, 2));
    await snarkjs.wtns.calculate(JSON.parse(fs.readFileSync(inPath, "utf8")), shape.wasm_path, wtns);
    const ok = readR1cs(shape.r1cs_path, wtns).satisfied === true;
    const row = {
      kind: "INPUT", cell, matrix_id: "S-N", workload: "prepare", jwt_params: params, show_params: null,
      population: { issuers: 0, revoked: 0 }, seed: 1, expected_result: null,
      input_path: inPath, wtns_path: wtns, input_sha256: sha(inPath), wtns_sha256: sha(wtns),
      r1cs_path: shape.r1cs_path, sym_path: fs.existsSync(symPath) ? symPath : null,
      commit: execSync("git rev-parse HEAD", { cwd: __dirname }).toString().trim(),
      circuit_commit: shape.circuit_commit ?? shape.commit,
      wtns_check: ok, roots_match_circuit: null, result_matches_policy: null, ts: new Date().toISOString(),
    };
    const rows: any[] = fs.existsSync(file) ? fs.readFileSync(file, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l)) : [];
    const i = rows.findIndex((r) => r.cell === cell && r.workload === "prepare");
    if (i === -1) rows.push(row);
    else rows[i] = row;
    fs.writeFileSync(file, rows.map((r) => JSON.stringify(r)).join("\n") + "\n");
    console.log(`${ok ? "ok  " : "FAIL"} ${cell}/prepare`);
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
