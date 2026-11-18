import { defineProject } from "vitest/config";

export const config = defineProject({
  test: {
    name: "hooks",
    include: ["scripts/**/*.test.mjs"],
    setupFiles: ["../../test/fast-check.setup.ts"],
  },
});

export default config;
