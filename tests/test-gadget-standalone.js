var sleep = Module.getExportByName('libSystem.B.dylib',
    (Process.arch === 'ia32') ? 'sleep$UNIX2003' : 'sleep');
var exit = new NativeFunction(
    Module.getExportByName('libSystem.B.dylib', 'exit'),
    'void',
    ['int']);

rpc.exports = {
  init: function () {
    try {
      Interceptor.attach(sleep, {
        onEnter: function () {
          exit(123);
        }
      });
    } catch (e) {
      console.error(e.message);
    }
  }
};
