'use strict';

var exit = new NativeFunction(
    Module.findExportByName('libSystem.B.dylib', 'exit'),
    'void',
    ['int']);

rpc.exports = {
  init: function () {
    try {
      Interceptor.attach(Module.findExportByName('libSystem.B.dylib', 'sleep'), {
        onEnter: function () {
          exit(123);
        }
      });
    } catch (e) {
      console.error(e.message);
    }
  }
};
