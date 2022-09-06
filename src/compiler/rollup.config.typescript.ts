import path from "path";
import { defineConfig } from "rollup";

export default defineConfig({
    input: path.join("node_modules", "frida-compile", "ext", "typescript.js"),
    output: {
        file: "typescript.js",
        format: "umd",
        name: "ts",
        generatedCode: {
            preset: "es2015",
        },
        strict: false,
    },
});
