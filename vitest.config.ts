import { defineConfig } from "vitest/config";

// One Vitest run covers every workspace package. Each package has its own vitest.config.ts.
export default defineConfig({
  test: {
    projects: ["base/*/vitest.config.ts", "apps/*/vitest.config.ts"],
  },
});
