import { fileURLToPath } from "node:url";
import { dirname } from "node:path";
import type { NextConfig } from "next";

const config: NextConfig = {
  // better-sqlite3 is a native module; it must stay external to the server bundle.
  serverExternalPackages: ["better-sqlite3"],
  // Pinned because an unrelated lockfile higher up the tree makes Next infer the
  // wrong workspace root, which breaks file tracing.
  outputFileTracingRoot: dirname(fileURLToPath(import.meta.url)),
};

export default config;
