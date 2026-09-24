import { existsSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import { execSync } from "child_process";

const __dirname = dirname(fileURLToPath(import.meta.url));
const SDK_DIR = join(__dirname, "..");

export default function globalSetup() {
  const distDir = join(SDK_DIR, "dist");

  if (!existsSync(distDir)) {
    console.log("\n[global-setup] dist/ not found: running pnpm build...");
    execSync("pnpm build", { cwd: SDK_DIR, stdio: "inherit" });
    console.log("[global-setup] Build complete.\n");
  }
}
