const {
  compilerRoot,
  compilerNodeModules,
  agentDirectories,
  agentFiles,
  _build,
  _queryDefaultAssets,
} = FridaCompilerAgentCore;

const projectRoot = '/agent';
const projectNodeModules = '/agent/node_modules';
const entrypoint = 'index.ts';
const sourceMaps = 'included';
const compression = 'none';

const hashes = new Map();
let nextHashId = 1;

function main() {
  const system = new StubSystem();
  const assets = _queryDefaultAssets(projectRoot, system);
  _build({
    projectRoot,
    entrypoint,
    assets,
    system,
    sourceMaps,
    compression,
    onDiagnostic,
  });
}

function onDiagnostic(diagnostic) {
  throwNotImplemented('diagnostic', ts.flattenDiagnosticMessageText(diagnostic, '\n'));
}

class StubSystem {
  args = [];
  newLine = '\n';
  useCaseSensitiveFileNames = true;

  write(s) {
  }

  writeOutputIsTTY() {
    return true;
  }

  readFile(path, encoding) {
    if (path === '/agent/tsconfig.json')
      return '{}';

    if (path === '/agent/index.ts')
      return 'Interceptor.attach(ptr(1234), { onEnter(args) {} });'

    const agentZipPath = this.#nativePathToAgentZipPath(path);
    if (agentZipPath !== null) {
      return agentFiles.get(agentZipPath);
    }

    throwNotImplemented('readFile', path);
  }

  getFileSize(path) {
    throwNotImplemented('getFileSize');
  }

  writeFile(path, data, writeByteOrderMark) {
    throwNotImplemented('writeFile');
  }

  watchFile(path, callback, pollingInterval, options) {
    throwNotImplemented('watchFile');
  }

  watchDirectory(path, callback, recursive, options) {
    throwNotImplemented('watchDirectory');
  }

  resolvePath(path) {
    throwNotImplemented('resolvePath');
  }

  fileExists(path) {
    const agentZipPath = this.#nativePathToAgentZipPath(path);
    if (agentZipPath !== null)
      return agentFiles.has(agentZipPath);

    throwNotImplemented('fileExists', path);
  }

  directoryExists(path) {
    if (path === compilerNodeModules)
      return true;

    const agentZipPath = this.#nativePathToAgentZipPath(path);
    if (agentZipPath !== null)
      return agentDirectories.has(agentZipPath);

    if (path === '/node_modules/@types' || path === '/node_modules')
      return false;

    throwNotImplemented('directoryExists', path);
  }

  createDirectory(path) {
    throwNotImplemented('createDirectory');
  }

  getExecutingFilePath() {
    return [compilerRoot, 'ext', 'typescript.js'].join('/');
  }

  getCurrentDirectory() {
    return '/';
  }

  getDirectories(path) {
    const agentZipPath = this.#nativePathToAgentZipPath(path);
    if (agentZipPath !== null) {
      const result = [];
      for (const dir of agentDirectories) {
        const slashIndex = dir.lastIndexOf('/');
        const parent = dir.substring(0, slashIndex);
        if (parent === agentZipPath) {
          const basename = dir.substring(slashIndex + 1);
          result.push(basename);
        }
      }
      return result;
    }

    throwNotImplemented('getDirectories', path);
  }

  readDirectory(path, extensions, exclude, include, depth) {
    if (!extensions.includes('.ts'))
      throwNotImplemented('readDirectory', path, extensions);
    return ['index.ts'];
  }

  getModifiedTime(path) {
  }

  setModifiedTime(path, time) {
  }

  deleteFile(path) {
  }

  createHash(data) {
    let hash = hashes.get(data);
    if (hash === undefined) {
      hash = 'hash' + nextHashId++;
      hashes.set(data, hash);
    }
    return hash;
  }

  createSHA256Hash(data) {
    throwNotImplemented('createSHA256Hash');
  }

  getMemoryUsage() {
    throwNotImplemented('getMemoryUsage');
  }

  exit(exitCode) {
  }

  realpath(path) {
    return path;
  }

  getEnvironmentVariable(name) {
    return '';
  }

  setTimeout(callback, ms, ...args) {
    throwNotImplemented('setTimeout');
  }

  clearTimeout(timeoutId) {
    throwNotImplemented('clearTimeout');
  }

  clearScreen() {
  }

  base64decode(input) {
    throwNotImplemented('base64decode');
  }

  base64encode(input) {
    throwNotImplemented('base64encode');
  }

  #nativePathToAgentZipPath(path) {
    if (path.startsWith(compilerRoot)) {
      const subPath = path.substring(compilerRoot.length);
      if (subPath.startsWith('/node_modules')) {
        return subPath;
      }
      return '/node_modules/frida-compile' + subPath;
    }

    if (path.startsWith(projectNodeModules)) {
      return '/node_modules' + path.substring(projectNodeModules.length);
    }

    return null;
  }
}

function throwNotImplemented(operation, ...details) {
  throw new Error('not implemented: ' + operation + ((details.length > 0) ? ` (${details.join(' ')})` : ''));
}

main();
