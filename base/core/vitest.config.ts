import { defineProject } from "vitest/config";

export const config = defineProject({
  test: {
    name: "core",
    include: ["src/**/*.test.ts"],
    setupFiles: ["../../test/fast-check.setup.ts"],
  },
});

// Vitest loads the default export. This is the only default export allowed (biome.json override).
export default config;
