import path from "path";
import { defineConfig } from "rollup";
import terser from "@rollup/plugin-terser";

export default defineConfig({
    input: path.join("node_modules", "frida-compile", "ext", "typescript.js"),
    output: {
        file: "typescript.js",
        format: "umd",
        name: "ts",
        generatedCode: {
            preset: "es2015",
            constBindings: true,
        },
        strict: false,
    },
    plugins: [
        terser({ ecma: 2020 }),
    ],
});
