rpc.exports.allowPipePath = allowPipePath;

function allowPipePath(path) {
  const addAllowedPath = new NativeFunction(Module.getGlobalExportByName('android_unix_pipes_add_allowed_path'), 'void', ['pointer']);
  addAllowedPath(Memory.allocUtf8String(path));
}
