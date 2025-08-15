import { defineConfig } from "tsup";

export default defineConfig((ctx) => ({
  entry: ["src/index.ts", "src/client.ts", "src/schema.ts", "src/types.ts"],
  format: ["esm", "cjs"],
  dts: true,
  clean: true,
  outDir: "dist",
  outExtension: ({ format }) => ({
    js: format === "esm" ? ".mjs" : ".cjs",
  }),
}));
