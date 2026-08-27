export default {
  run: {
    tasks: {
      build: {
        command: "tsc",
        input: [{ auto: true }, { pattern: "!dist/**", base: "package" }],
        output: ["dist/**"],
      },
      test: {
        command: "vitest run",
        input: [{ auto: true }, { pattern: "!dist/**", base: "package" }, { pattern: "!**/.wrangler/**", base: "workspace" }],
        output: [{ auto: true }, { pattern: "!dist/**", base: "package" }, { pattern: "!**/.wrangler/**", base: "workspace" }],
      },
    },
  },
};
