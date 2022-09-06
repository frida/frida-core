import * as crosspath from "@frida/crosspath";
import type * as backend from "frida-compile";
import {
    makeDefaultCompilerOptions,
    build as _build,
    watch as _watch,
    queryDefaultAssets as _queryDefaultAssets,
} from "frida-compile";
import ts from "frida-compile/ext/typescript.js";
import fridaFs from "frida-fs";
import fs from "fs";

const { DiagnosticCategory, FileWatcherEventKind } = ts;

const { S_IFDIR } = fs.constants;

export const compilerRoot = "/frida-compile";
export const compilerNodeModules = compilerRoot + "/node_modules";

export const agentDirectories = new Set<string>(__agentDirectories__);
export const agentFiles = new Map<string, string>(__agentFiles__);
const cachedSourceFiles = new Map<string, ts.SourceFile>();

declare const __agentDirectories__: string[];
declare const __agentFiles__: [string, string][];

const pendingDiagnostics: ts.Diagnostic[] = [];

const fileWatchers = new Map<WatcherId, WatcherCallback>();
let nextWatcherId: WatcherId = 1;

populateSourceFileCache();

function populateSourceFileCache() {
    const config = makeDefaultCompilerOptions();
    for (const [name, contents] of agentFiles) {
        if (name.endsWith(".d.ts")) {
            const sf = ts.createSourceFile(name, contents, config.target!);
            ts.prebindSourceFile(sf, config);
            cachedSourceFiles.set(name, sf);
        }
    }
}

export function init(): void {
    function onChange(message: WatchChangeMessage): void {
        const callback = fileWatchers.get(message.id);
        callback?.(fileWatcherEventKindFromFileState(message.state));

        recv("watch:change", onChange);
    }
    recv("watch:change", onChange);

    const origCreateCompilerHostFromProgramHost = (ts as any).createCompilerHostFromProgramHost;
    (ts as any).createCompilerHostFromProgramHost = (...args: any[]): ts.CompilerHost => {
        const host = origCreateCompilerHostFromProgramHost(...args);
        patchCompilerHost(host);
        return host;
    };
}

export function build(projectRoot: string, entrypoint: string, sourceMaps: backend.SourceMaps, compression: backend.Compression): string {
    const system = new FridaSystem(projectRoot);
    const assets = _queryDefaultAssets(projectRoot, system);

    try {
        return _build({
            projectRoot,
            entrypoint,
            assets,
            system,
            sourceMaps,
            compression,
            onDiagnostic,
            onCompilerHostCreated: patchCompilerHost,
        });
    } finally {
        flushDiagnostics();
    }
}

export function watch(projectRoot: string, entrypoint: string, sourceMaps: backend.SourceMaps, compression: backend.Compression): void {
    const system = new FridaSystem(projectRoot);
    const assets = _queryDefaultAssets(projectRoot, system);
    _watch({
        projectRoot,
        entrypoint,
        assets,
        system,
        sourceMaps,
        compression,
        onDiagnostic,
    })
        .on("compilationStarting", () => {
            send(["watch:compilation-starting"]);
        })
        .on("compilationFinished", () => {
            send(["watch:compilation-finished"]);
        })
        .on("bundleUpdated", bundle => {
            send(["watch:bundle-updated", bundle]);
        });
}

function patchCompilerHost(host: ts.CompilerHost) {
    const origGetSourceFile = host.getSourceFile;
    host.getSourceFile = (fileName, ...args) => {
        const compilerPath = nativePathToCompilerPath(fileName);
        if (compilerPath !== null) {
            const sf = cachedSourceFiles.get(compilerPath);
            if (sf !== undefined) {
                return sf;
            }
        } else {
            const startPos = fileName.indexOf("/node_modules/@types/");
            if (startPos !== -1) {
                const builtinsPath = fileName.substring(startPos);
                const sf = cachedSourceFiles.get(builtinsPath);
                if (sf !== undefined) {
                    return sf;
                }
            }
        }

        return origGetSourceFile(fileName, ...args);
    };
}

export { _build, _watch, _queryDefaultAssets };

type DiagnosticFile = [path: string, line: number, character: number];

function onDiagnostic(diagnostic: ts.Diagnostic): void {
    pendingDiagnostics.push(diagnostic);
    if (pendingDiagnostics.length === 1) {
        Script.nextTick(flushDiagnostics);
    }
}

function flushDiagnostics(): void {
    const pending = pendingDiagnostics.splice(0, pendingDiagnostics.length);
    if (pending.length === 0) {
        return;
    }

    send([
        "diagnostics",
        pending.map(({
            category,
            code,
            file: tsFile,
            start,
            messageText
        }) => {
            let file: DiagnosticFile | null = null;
            if (tsFile !== undefined) {
                const { line, character } = ts.getLineAndCharacterOfPosition(tsFile, start!);
                file = [tsFile.fileName, line, character];
            }
            return [
                diagnosticCategoryToString(category),
                code,
                file,
                ts.flattenDiagnosticMessageText(messageText, "\n")
            ];
        }),
    ]);
}

function diagnosticCategoryToString(category: ts.DiagnosticCategory): string {
    switch (category) {
        case DiagnosticCategory.Warning:
            return "warning";
        case DiagnosticCategory.Error:
            return "error";
        case DiagnosticCategory.Suggestion:
            return "suggestion";
        case DiagnosticCategory.Message:
            return "message";
    }
}

class FridaSystem implements ts.System {
    args = [];
    newLine = "\n";
    useCaseSensitiveFileNames = true;

    #projectRoot: string;
    #projectNodeModules: string;

    constructor(projectRoot: string) {
        this.#projectRoot = crosspath.ensurePosix(projectRoot);
        this.#projectNodeModules = crosspath.join(this.#projectRoot, "node_modules");
    }

    write(s: string): void {
    }

    writeOutputIsTTY(): boolean {
        return true;
    }

    readFile(path: string, encoding?: string): string | undefined {
        let result: string | undefined;
        if (path.startsWith(this.#projectRoot)) {
            try {
                result = File.readAllText(path);
            } catch (e) {
            }
        }

        if (result === undefined) {
            const agentZipPath = this.#nativePathToAgentZipPath(path);
            if (agentZipPath !== null) {
                result = agentFiles.get(agentZipPath);
            }
        }

        return result;
    }

    getFileSize(path: string): number {
        throw new Error("not implemented");
    }

    writeFile(path: string, data: string, writeByteOrderMark?: boolean): void {
        File.writeAllText(path, data);
    }

    watchFile(path: string, callback: ts.FileWatcherCallback, pollingInterval?: number, options?: ts.WatchOptions): ts.FileWatcher {
        if (path.startsWith(compilerRoot)) {
            return makeDummyWatcher();
        }

        return makeFileWatcher(path, "file", pollingInterval ?? 0, kind => {
            callback(path, kind);
        });
    }

    watchDirectory(path: string, callback: ts.DirectoryWatcherCallback, recursive?: boolean, options?: ts.WatchOptions): ts.FileWatcher {
        if (path.startsWith(compilerRoot)) {
            return makeDummyWatcher();
        }

        return makeFileWatcher(path, "directory", 0, kind => {
            callback(path);
        });
    }

    resolvePath(path: string): string {
        return path;
    }

    fileExists(path: string): boolean {
        if (path.startsWith(this.#projectRoot)) {
            try {
                const st = fs.statSync(path);
                return !st.isDirectory();
            } catch (e) {
            }
        }

        const agentZipPath = this.#nativePathToAgentZipPath(path);
        if (agentZipPath === null) {
            return false;
        }
        return agentFiles.has(agentZipPath);
    }

    directoryExists(path: string): boolean {
        if (path === compilerNodeModules) {
            return true;
        }

        if (path.startsWith(this.#projectRoot)) {
            try {
                const st = fs.statSync(path);
                return st.isDirectory();
            } catch (e) {
            }
        }

        const agentZipPath = this.#nativePathToAgentZipPath(path);
        if (agentZipPath === null) {
            return false;
        }
        return agentDirectories.has(agentZipPath);
    }

    createDirectory(path: string): void {
        throw new Error("not implemented");
    }

    getExecutingFilePath(): string {
        return [compilerRoot, "ext", "typescript.js"].join("/");
    }

    getCurrentDirectory(): string {
        return this.#projectRoot;
    }

    getDirectories(path: string): string[] {
        const result = new Set<string>();

        if (path.startsWith(this.#projectRoot)) {
            try {
                for (const entry of fridaFs.list(path).filter(entry => entry.type === S_IFDIR)) {
                    result.add(entry.name);
                }
            } catch (e) {
            }
        }

        const agentZipPath = this.#nativePathToAgentZipPath(path);
        if (agentZipPath !== null) {
            for (const dir of agentDirectories) {
                const slashIndex = dir.lastIndexOf("/");
                const parent = dir.substring(0, slashIndex);
                if (parent === agentZipPath) {
                    const basename = dir.substring(slashIndex + 1);
                    result.add(basename);
                }
            }
        }

        return Array.from(result);
    }

    readDirectory(path: string, extensions?: readonly string[], exclude?: readonly string[], include?: readonly string[], depth?: number): string[] {
        return [];
    }

    getModifiedTime(path: string): Date | undefined {
        return undefined;
    }

    setModifiedTime(path: string, time: Date): void {
    }

    deleteFile(path: string): void {
    }

    createHash(data: string): string {
        return this.createSHA256Hash(data);
    }

    createSHA256Hash(data: string): string {
        return Checksum.compute("sha256", data);
    }

    getMemoryUsage(): number {
        return Frida.heapSize;
    }

    exit(exitCode?: number): void {
    }

    realpath(path: string): string {
        return path;
    }

    getEnvironmentVariable(name: string): string {
        return "";
    }

    setTimeout(callback: (...args: any[]) => void, ms: number, ...args: any[]): any {
        return setTimeout(callback);
    }

    clearTimeout(timeoutId: any): void {
        return clearTimeout(timeoutId);
    }

    clearScreen(): void {
    }

    base64decode(input: string): string {
        throw new Error("not implemented");
    }

    base64encode(input: string): string {
        throw new Error("not implemented");
    }

    #nativePathToAgentZipPath(path: string): string | null {
        const compilerPath = nativePathToCompilerPath(path);
        if (compilerPath !== null) {
            return compilerPath;
        }

        if (path.startsWith(this.#projectNodeModules)) {
            return "/node_modules" + path.substring(this.#projectNodeModules.length);
        }

        return null;
    }
}

function nativePathToCompilerPath(path: string): string | null {
    if (!path.startsWith(compilerRoot)) {
        return null;
    }

    const subPath = path.substring(compilerRoot.length);
    if (subPath.startsWith("/node_modules")) {
        return subPath;
    }

    return "/node_modules/frida-compile" + subPath;
}

type WatcherId = number;
type WatcherCallback = (eventKind: ts.FileWatcherEventKind) => void;
type FileState = "pristine" | "modified" | "deleted";

interface WatchChangeMessage {
    id: WatcherId;
    state: FileState;
}

function makeFileWatcher(path: string, type: "file" | "directory", pollingInterval: number, callback: WatcherCallback): ts.FileWatcher {
    if (nextWatcherId === 0xffffffff) {
        nextWatcherId = 1;
    }
    let id: WatcherId = nextWatcherId++;
    while (fileWatchers.has(id)) {
        id = nextWatcherId++;
    }

    fileWatchers.set(id, callback);

    send(["watch:add", id, path, type, pollingInterval ?? 0]);

    return {
        close() {
            send(["watch:remove", id]);

            fileWatchers.delete(id);
        }
    };
}

function makeDummyWatcher(): ts.FileWatcher {
    return {
        close() {
        }
    };
}

function fileWatcherEventKindFromFileState(state: FileState): ts.FileWatcherEventKind {
    switch (state) {
        case "pristine": return FileWatcherEventKind.Created;
        case "modified": return FileWatcherEventKind.Changed;
        case "deleted": return FileWatcherEventKind.Deleted;
    }
}
