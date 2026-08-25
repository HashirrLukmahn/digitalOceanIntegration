import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

const here = (relative: string) => fileURLToPath(new URL(relative, import.meta.url));

export default defineConfig({
  test: {
    include: ["tests/**/*.test.ts"],
    environment: "node",
  },
  resolve: {
    alias: {
      "@": here("./src/"),
      // `server-only` throws unless resolved through Next's server condition. The
      // guard exists to fail a client import at build time; under test there is no
      // client, so stub it rather than drop the guard from the app.
      "server-only": here("./tests/helpers/server-only-stub.ts"),
    },
  },
});
