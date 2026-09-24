recv('allow-pipe-path', onAllowPipePath);

function onAllowPipePath(message) {
  const addAllowedPath = new NativeFunction(Module.getGlobalExportByName('android_unix_pipes_add_allowed_path'), 'void', ['pointer']);
  addAllowedPath(Memory.allocUtf8String(message.path));
}
