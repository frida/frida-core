const sleep = Module.getExportByName('libSystem.B.dylib',
    (Process.arch === 'ia32') ? 'sleep$UNIX2003' : 'sleep');
const exit = new NativeFunction(
    Module.getExportByName('libSystem.B.dylib', 'exit'),
    'void',
    ['int']);

rpc.exports = {
  init() {
    try {
      Interceptor.attach(sleep, {
        onEnter() {
          exit(123);
        }
      });
    } catch (e) {
      console.error(e.message);
    }
  }
};
