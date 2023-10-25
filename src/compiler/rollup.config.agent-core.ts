import crosspath from "@frida/crosspath";
import fs from "fs";
import { sync as glob } from "glob";
import replace from "@rollup/plugin-replace";
import resolve from "@rollup/plugin-node-resolve";
import typescript from "@rollup/plugin-typescript";
import polyfills from "@frida/rollup-plugin-node-polyfills";
import { terser } from "rollup-plugin-terser";
import { defineConfig } from "rollup";
import type rollup from "rollup";

export default defineConfig({
    input: "agent-core.ts",
    output: {
        file: "agent-core.js",
        format: "umd",
        name: "FridaCompilerAgentCore",
        generatedCode: {
            preset: "es2015",
        },
        strict: false,
        interop: "default",
        globals: {
            "typescript": "ts",
        },
    },
    plugins: [
        typescript(),
        replace({
            preventAssignment: true,
            values: computeSubstitutionValues(),
        }),
        stubTsImportPlugin(),
        polyfills(),
        resolve(),
        /*
        terser({
            ecma: 2020,
            compress: {
                module: true,
                global_defs: {
                    "process.env.FRIDA_COMPILE": true
                },
            },
            mangle: {
                module: true,
            },
        }),
        */
    ],
});

function computeSubstitutionValues() {
    const hostOsFamily = process.env.FRIDA_HOST_OS_FAMILY;
    if (hostOsFamily === undefined) {
      throw new Error("missing FRIDA_HOST_OS_FAMILY");
    }

    const hostArch = process.env.FRIDA_HOST_ARCH;
    if (hostArch === undefined) {
      throw new Error("missing FRIDA_HOST_ARCH");
    }

    const hostCpuMode = process.env.FRIDA_HOST_CPU_MODE;
    if (hostCpuMode === undefined) {
      throw new Error("missing FRIDA_HOST_CPU_MODE");
    }

    const outputDir = __dirname;

    const compilerDir = crosspath.join(__dirname, "node_modules", "frida-compile");
    let usingLinkedCompiler = false;
    try {
        usingLinkedCompiler = fs.statSync(crosspath.join(compilerDir, "node_modules")).isDirectory();
    } catch (e) {
    }

    const assetParentDir = usingLinkedCompiler ? compilerDir : outputDir;
    const assetModulesDir = crosspath.join(assetParentDir, "node_modules");

    const shimDirs = [
        ["@frida", "assert"],
        ["@frida", "base64-js"],
        ["@frida", "buffer"],
        ["@frida", "crypto"],
        ["@frida", "diagnostics_channel"],
        ["@frida", "events"],
        ["@frida", "http"],
        ["@frida", "http-parser-js"],
        ["@frida", "https"],
        ["@frida", "ieee754"],
        ["@frida", "net"],
        ["@frida", "os"],
        ["@frida", "path"],
        ["@frida", "process"],
        ["@frida", "punycode"],
        ["@frida", "querystring"],
        ["@frida", "readable-stream"],
        ["@frida", "stream"],
        ["@frida", "string_decoder"],
        ["@frida", "timers"],
        ["@frida", "tty"],
        ["@frida", "url"],
        ["@frida", "util"],
        ["@frida", "vm"],
        ["frida-fs"],
    ];
    const typeDirs = [
        ["@types", "node"],
        ["@types", "frida-gum"],
    ];

    const assets: string[] = [];
    for (const shimDir of shimDirs) {
        assets.push(...glob(crosspath.join(assetModulesDir, ...shimDir, "package.json")));
        assets.push(...glob(crosspath.join(assetModulesDir, ...shimDir, "**", "*.js")));
    }
    for (const typeDir of typeDirs) {
        assets.push(...glob(crosspath.join(assetModulesDir, ...typeDir, "package.json")));
        assets.push(...glob(crosspath.join(assetModulesDir, ...typeDir, "**", "*.d.ts")));
    }
    assets.push(...glob(crosspath.join(compilerDir, "ext", "lib.es*.d.ts")));
    assets.push(...glob(crosspath.join(compilerDir, "ext", "lib.decorators*.d.ts")));

    const ignoredAssetFiles = new Set([
        "@frida/process/browser.js",
    ]);

    const agentDirectories = new Set<string>();
    const agentFiles = new Map<string, string>();
    for (const assetPath of assets) {
        let assetRelpath = assetPath.substring(assetParentDir.length);
        if (usingLinkedCompiler && assetRelpath.startsWith("/ext/")) {
            assetRelpath = crosspath.join("/", "node_modules", "frida-compile", assetRelpath.substring(1));
        }

        const identifier = assetRelpath.split("/").slice(2).join("/");
        if (ignoredAssetFiles.has(identifier)) {
            continue;
        }

        let currentDir = crosspath.dirname(assetRelpath);
        do {
            agentDirectories.add(currentDir);
            currentDir = crosspath.dirname(currentDir);
        } while (currentDir !== "/");
        agentFiles.set(assetRelpath, fs.readFileSync(assetPath, "utf-8"));
    }

    const orderedAgentDirectories = Array.from(agentDirectories);
    orderedAgentDirectories.sort();

    const orderedAgentFiles = Array.from(agentFiles);
    orderedAgentFiles.sort((a, b) => a[0].localeCompare(b[0]));

    return {
        "Frida.version": "'0.0.0'",
        "Process.id": "1",
        "Process.platform": `'${hostOsFamily}'`,
        "Process.arch": `'${hostArch}'`,
        "Process.pointerSize": (hostCpuMode === "64") ? "8" : "4",
        "__agentDirectories__": JSON.stringify(orderedAgentDirectories, null, 4),
        "__agentFiles__": JSON.stringify(orderedAgentFiles, null, 4),
    };
}

function stubTsImportPlugin(): rollup.Plugin {
    return {
        name: "stub-ts-import",
        async resolveId(source, importer, options) {
            if (crosspath.basename(source) === "typescript.js") {
                return {
                    id: "typescript",
                    external: true,
                    meta: {},
                    moduleSideEffects: false,
                    syntheticNamedExports: false
                };
            }

            return this.resolve(source, importer, { skipSelf: true, ...options });
        }
    };
}
