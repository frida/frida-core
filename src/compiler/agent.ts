import * as crosspath from "@frida/crosspath";
import * as backend from "frida-compile";
import ts from "frida-compile/ext/typescript.js";
import fs from "node:fs";
import fridaFs from "frida-fs";

const { DiagnosticCategory, FileWatcherEventKind } = ts;

const { S_IFDIR } = fs.constants;

const compilerRoot = "/frida-compile";
const compilerNodeModules = compilerRoot + "/node_modules";

const agentDirectories = new Set<string>();
const agentFiles = new Map<string, string>();

const pendingDiagnostics: ts.Diagnostic[] = [];

const fileWatchers = new Map<WatcherId, WatcherCallback>();
let nextWatcherId: WatcherId = 1;

rpc.exports = {
    init(directories: string[], files: FileInfo[]): void {
        for (const dir of directories) {
            agentDirectories.add(dir);
        }

        for (const [name, address] of files) {
            agentFiles.set(name, address);
        }
    },

    async build(projectRoot: string, entrypoint: string, sourceMaps: backend.SourceMaps, compression: backend.Compression): Promise<string> {
        const system = new FridaSystem(projectRoot);
        const assets = backend.queryDefaultAssets(projectRoot, system);
        try {
            return await backend.build({
                projectRoot,
                entrypoint,
                assets,
                system,
                sourceMaps,
                compression,
                onDiagnostic,
            });
        } finally {
            flushDiagnostics();
        }
    },

    async watch(projectRoot: string, entrypoint: string, sourceMaps: backend.SourceMaps, compression: backend.Compression): Promise<void> {
        const system = new FridaSystem(projectRoot);
        const assets = backend.queryDefaultAssets(projectRoot, system);
        backend.watch({
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
    },
};

type FileInfo = [name: string, address: string];

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
                const contentsAddress = agentFiles.get(agentZipPath);
                if (contentsAddress !== undefined) {
                    result = ptr(contentsAddress).readUtf8String()!;
                }
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
        if (path.startsWith(compilerRoot)) {
            const subPath = path.substring(compilerRoot.length);
            if (subPath.startsWith("/node_modules")) {
                return subPath;
            }
            return "/node_modules/frida-compile" + subPath;
        }

        if (path.startsWith(this.#projectNodeModules)) {
            return "/node_modules" + path.substring(this.#projectNodeModules.length);
        }

        return null;
    }
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

function onChange(message: WatchChangeMessage): void {
    const callback = fileWatchers.get(message.id);
    callback?.(fileWatcherEventKindFromFileState(message.state));

    recv("watch:change", onChange);
}
recv("watch:change", onChange);

function fileWatcherEventKindFromFileState(state: FileState): ts.FileWatcherEventKind {
    switch (state) {
        case "pristine": return FileWatcherEventKind.Created;
        case "modified": return FileWatcherEventKind.Changed;
        case "deleted": return FileWatcherEventKind.Deleted;
    }
}
