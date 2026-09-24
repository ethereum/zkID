// Wraps the ecdsa-spartan2 Rust CLI binary for heavy operations
// (setup, prove, reblind) that are impractical in WASM due to 420MB key sizes.
// Node.js only.

import { execFile } from "child_process";
import { readFile } from "fs/promises";
import { join, dirname } from "path";
import { existsSync, readdirSync } from "fs";
import { promisify } from "util";
import { SetupError, ProofError } from "./errors.js";
import type { KeySet, VerifyingKeys, SerializedKeySet } from "./types.js";

export interface NativeVerificationResult {
  valid: boolean;
  output: string;
}

interface RunResult {
  stdout: string;
  stderr: string;
}

const execFileAsync = promisify(execFile);

export interface NativeBackendTimeouts {
  defaultMs?: number;
  setupPrepareMs?: number;
  setupShowMs?: number;
  provePrepareMs?: number;
  proveShowMs?: number;
  reblindPrepareMs?: number;
  reblindShowMs?: number;
  benchmarkMs?: number;
}

export interface NativeBackendConfig {
  binaryPath?: string;
  workDir?: string;
  inputDir?: string;
  env?: Record<string, string>;
  timeouts?: NativeBackendTimeouts;
}

const DEFAULT_TIMEOUTS: Required<NativeBackendTimeouts> = {
  defaultMs: 600_000,
  setupPrepareMs: 1_200_000,
  setupShowMs: 600_000,
  provePrepareMs: 300_000,
  proveShowMs: 120_000,
  reblindPrepareMs: 300_000,
  reblindShowMs: 120_000,
  benchmarkMs: 1_800_000,
};

export class NativeBackend {
  private binaryPath: string;
  private workDir: string;
  private inputDir: string;
  private env: Record<string, string>;
  private timeouts: Required<NativeBackendTimeouts>;

  constructor(config: NativeBackendConfig = {}) {
    this.binaryPath = config.binaryPath ?? this.findBinary();
    this.workDir = config.workDir ?? this.findWorkDir();
    this.inputDir = config.inputDir ?? join(this.workDir, "..", "circom", "inputs");
    this.env = {
      RUST_LOG: "info",
      ...this.buildDylibEnv(),
      ...config.env,
    };
    this.timeouts = { ...DEFAULT_TIMEOUTS, ...config.timeouts };
  }

  private findBinary(): string {
    const candidates = [
      // ecdsa-spartan2 is a member of the root Cargo workspace, so it builds into <repo>/target.
      join(dirname(new URL(import.meta.url).pathname), "..", "..", "..", "target", "release", "ecdsa-spartan2"),
      join(process.cwd(), "target", "release", "ecdsa-spartan2"),
    ];

    for (const path of candidates) {
      if (existsSync(path)) return path;
    }

    throw new SetupError(
      "KEYS_NOT_FOUND",
      "Could not find ecdsa-spartan2 binary. Build with: cargo build --release"
    );
  }

  private findWorkDir(): string {
    const candidates = [
      join(dirname(new URL(import.meta.url).pathname), "..", "..", "ecdsa-spartan2"),
      process.cwd(),
    ];

    for (const path of candidates) {
      if (existsSync(join(path, "Cargo.toml"))) return path;
    }

    return process.cwd();
  }

  // The binary links @rpath/libwitnesscalc_*.dylib but cargo doesn't embed an rpath.
  // When running via `cargo run`, Cargo sets DYLD_LIBRARY_PATH automatically;
  // when invoking via execFile we must set it ourselves.
  private buildDylibEnv(): Record<string, string> {
    // Build-script output sits beside the binary in <target>/<profile>/build; a binary
    // outside Cargo's target dir gets no library path.
    const buildDir = join(dirname(this.binaryPath), "build");
    if (!existsSync(buildDir)) return {};

    const entries = readdirSync(buildDir);
    for (const entry of entries) {
      if (!entry.startsWith("ecdsa-spartan2-")) continue;
      const dylibDir = join(buildDir, entry, "out", "witnesscalc", "build_witnesscalc", "src");
      if (existsSync(join(dylibDir, "libwitnesscalc_jwt.dylib"))) {
        const existing = process.env.DYLD_LIBRARY_PATH ?? "";
        return { DYLD_LIBRARY_PATH: existing ? `${dylibDir}:${existing}` : dylibDir };
      }
    }

    return {};
  }

  private async run(args: string[], timeoutMs?: number): Promise<RunResult> {
    const effectiveTimeout = timeoutMs ?? this.timeouts.defaultMs;
    try {
      const { stdout, stderr } = await execFileAsync(this.binaryPath, args, {
        cwd: this.workDir,
        env: { ...process.env, ...this.env },
        timeout: effectiveTimeout,
        maxBuffer: 10 * 1024 * 1024,
      });
      return { stdout, stderr };
    } catch (error: unknown) {
      const execError = error as { code?: number; stderr?: string; stdout?: string; message?: string };
      throw new ProofError(
        "PROOF_GENERATION_FAILED",
        `Command failed (exit ${execError.code ?? "unknown"}): ${execError.stderr || execError.message || "Unknown error"}`,
        error
      );
    }
  }

  async setupPrepare(inputPath?: string): Promise<void> {
    const args = ["prepare", "setup"];
    if (inputPath) args.push("--input", inputPath);
    await this.run(args, this.timeouts.setupPrepareMs);
  }

  async setupShow(inputPath?: string): Promise<void> {
    const args = ["show", "setup"];
    if (inputPath) args.push("--input", inputPath);
    await this.run(args, this.timeouts.setupShowMs);
  }

  async setup(inputPath?: string): Promise<void> {
    await this.setupPrepare(inputPath);
    await this.setupShow(inputPath);
  }

  async provePrepare(inputPath?: string): Promise<void> {
    const args = ["prepare", "prove"];
    if (inputPath) args.push("--input", inputPath);
    await this.run(args, this.timeouts.provePrepareMs);
  }

  async proveShow(inputPath?: string): Promise<void> {
    const args = ["show", "prove"];
    if (inputPath) args.push("--input", inputPath);
    await this.run(args, this.timeouts.proveShowMs);
  }

  async generateSharedBlinds(): Promise<void> {
    await this.run(["generate_shared_blinds"]);
  }

  async reblindPrepare(): Promise<void> {
    await this.run(["prepare", "reblind"], this.timeouts.reblindPrepareMs);
  }

  async reblindShow(): Promise<void> {
    await this.run(["show", "reblind"], this.timeouts.reblindShowMs);
  }

  async verifyPrepare(): Promise<NativeVerificationResult> {
    const { stdout, stderr } = await this.run(["prepare", "verify"]);
    const output = stdout + stderr;
    return {
      valid: output.includes("Verification successful"),
      output,
    };
  }

  async verifyShow(): Promise<NativeVerificationResult> {
    const { stdout, stderr } = await this.run(["show", "verify"]);
    const output = stdout + stderr;
    return {
      valid: output.includes("Verification successful"),
      output,
    };
  }

  async runBenchmark(inputPath?: string): Promise<string> {
    const args = ["benchmark"];
    if (inputPath) args.push("--input", inputPath);
    const { stdout, stderr } = await this.run(args, this.timeouts.benchmarkMs);
    return stdout + stderr;
  }

  async proveAll(jwtInputPath?: string, showInputPath?: string): Promise<void> {
    await this.generateSharedBlinds();
    await this.provePrepare(jwtInputPath);
    await this.reblindPrepare();
    await this.proveShow(showInputPath);
    await this.reblindShow();
  }

  async loadArtifact(filename: string): Promise<Uint8Array> {
    const path = join(this.workDir, "keys", filename);
    return new Uint8Array(await readFile(path));
  }

  async loadKeys(): Promise<KeySet> {
    const [ppk, pvk, spk, svk] = await Promise.all([
      this.loadArtifact("prepare_proving.key"),
      this.loadArtifact("prepare_verifying.key"),
      this.loadArtifact("show_proving.key"),
      this.loadArtifact("show_verifying.key"),
    ]);

    return {
      prepareProvingKey: ppk,
      prepareVerifyingKey: pvk,
      showProvingKey: spk,
      showVerifyingKey: svk,
      verifyingKeys(): VerifyingKeys {
        return { prepareVerifyingKey: pvk, showVerifyingKey: svk };
      },
      serialize(): SerializedKeySet {
        return { prepareProvingKey: ppk, prepareVerifyingKey: pvk, showProvingKey: spk, showVerifyingKey: svk };
      },
    };
  }

  async loadProofs(): Promise<{
    prepareProof: Uint8Array;
    showProof: Uint8Array;
    prepareInstance: Uint8Array;
    showInstance: Uint8Array;
    prepareWitness: Uint8Array;
    showWitness: Uint8Array;
    sharedBlinds: Uint8Array;
  }> {
    const [pp, sp, pi, si, pw, sw, sb] = await Promise.all([
      this.loadArtifact("prepare_proof.bin"),
      this.loadArtifact("show_proof.bin"),
      this.loadArtifact("prepare_instance.bin"),
      this.loadArtifact("show_instance.bin"),
      this.loadArtifact("prepare_witness.bin"),
      this.loadArtifact("show_witness.bin"),
      this.loadArtifact("shared_blinds.bin"),
    ]);

    return {
      prepareProof: pp,
      showProof: sp,
      prepareInstance: pi,
      showInstance: si,
      prepareWitness: pw,
      showWitness: sw,
      sharedBlinds: sb,
    };
  }

  get keysExist(): boolean {
    return (
      existsSync(join(this.workDir, "keys", "prepare_proving.key")) &&
      existsSync(join(this.workDir, "keys", "show_proving.key"))
    );
  }

  get proofsExist(): boolean {
    return (
      existsSync(join(this.workDir, "keys", "prepare_proof.bin")) &&
      existsSync(join(this.workDir, "keys", "show_proof.bin"))
    );
  }
}
