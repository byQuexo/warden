// Builds the Rust engine for WebAssembly and generates Node bindings into ./wasm.
// Requires: rustup target wasm32-unknown-unknown, wasm-bindgen-cli matching Cargo.lock.
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const pkg = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const root = path.resolve(pkg, "../..");
const target = process.env.CARGO_TARGET_DIR || path.join(root, "target");

execFileSync("cargo", ["build", "--profile", "wasm", "--target", "wasm32-unknown-unknown", "-p", "warden-wasm"], {
  cwd: root,
  stdio: "inherit",
});
const wasm = path.join(target, "wasm32-unknown-unknown", "wasm", "warden_wasm.wasm");
if (!existsSync(wasm)) throw new Error(`missing ${wasm}`);
mkdirSync(path.join(pkg, "wasm"), { recursive: true });
execFileSync("wasm-bindgen", ["--target", "nodejs", "--out-dir", "wasm", wasm], { cwd: pkg, stdio: "inherit" });
console.log("wasm bindings written to packages/warden/wasm");
