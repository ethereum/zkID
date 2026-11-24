import { execFileSync, execSync } from "child_process";
import * as fs from "fs";
import * as path from "path";

/** The commit a row claims; a dirty tree is marked so a row never names code it was not built from. */
export const stampCommit = (head: string, dirty: boolean): string => (dirty ? `${head}-dirty` : head);

/** HEAD of the checkout that holds `dir`, with `-dirty` when its working tree differs. */
export function codeCommit(dir: string): string {
  const head = execSync("git rev-parse HEAD", { cwd: dir }).toString().trim();
  return stampCommit(head, execSync("git status --porcelain -- .", { cwd: dir }).toString().trim() !== "");
}

/** A measured run must start each timed region after a collection, so it needs --expose-gc. */
export function requireGc(smoke: boolean, gc: unknown): void {
  if (!smoke && typeof gc !== "function") throw new Error("measured runs need node --expose-gc (NODE_OPTIONS=--expose-gc)");
}

export const e2eFileName = (k: number, revoked: number): string => `e2e-k${k}-r${revoked}.jsonl`;

/** An E2E output file holds one k and one population. */
export function assertSingleSetting(file: string, k: number, revoked: number): void {
  if (!fs.existsSync(file)) return;
  const first = fs.readFileSync(file, "utf8").split("\n").find(Boolean);
  if (!first) return;
  const row = JSON.parse(first);
  if (row.k !== k || row.revoked !== revoked) throw new Error(`${file} holds one k and one population (k=${row.k}, revoked=${row.revoked})`);
}

function nearestExisting(p: string): string {
  let probe = p;
  while (!fs.existsSync(probe)) probe = path.dirname(probe);
  return probe;
}

/** True when `dir`, or its nearest existing ancestor if it is not created yet, is inside a git work tree. */
function insideGitWorkTree(dir: string): boolean {
  try {
    return execFileSync("git", ["rev-parse", "--is-inside-work-tree"], { cwd: nearestExisting(dir), stdio: ["ignore", "pipe", "ignore"] }).toString().trim() === "true";
  } catch (e) {
    // git exits 128 outside a repository; anything else is a real failure.
    if ((e as { status?: number }).status === 128) return false;
    throw e;
  }
}

/** The directory benchmark output goes under, from OPENACPLUS_BENCH_ROOT. Results must never land in a checkout. */
export function benchRoot(env: NodeJS.ProcessEnv = process.env): string {
  const raw = env.OPENACPLUS_BENCH_ROOT;
  if (!raw) throw new Error("OPENACPLUS_BENCH_ROOT is required: set it to the directory that holds registry/ and e2e/ output");
  const resolved = path.resolve(raw);
  const probe = nearestExisting(resolved);
  const root = path.join(fs.realpathSync(probe), path.relative(probe, resolved));
  if (insideGitWorkTree(root)) throw new Error(`OPENACPLUS_BENCH_ROOT=${root} is inside a git work tree; choose a directory outside any checkout`);
  return root;
}
