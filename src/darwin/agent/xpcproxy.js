'use strict';

var POSIX_SPAWN_START_SUSPENDED = 0x0080;

var jbdCallImpl = Module.findExportByName(null, 'jbd_call');
var runningOnElectra = jbdCallImpl !== null;

Interceptor.attach(Module.findExportByName('/usr/lib/system/libsystem_kernel.dylib', '__posix_spawn'), {
  onEnter: function (args) {
    var attrs = Memory.readPointer(args[2].add(Process.pointerSize));

    var flags = Memory.readU16(attrs);
    flags |= POSIX_SPAWN_START_SUSPENDED;
    Memory.writeU16(attrs, flags);
  }
});

if (runningOnElectra) {
  sabotageJbdCall();
}

function sabotageJbdCall() {
  var retType = 'int';
  var argTypes = ['uint', 'uint', 'uint'];

  var jbdCall = new NativeFunction(jbdCallImpl, retType, argTypes);

  Interceptor.replace(jbdCall, new NativeCallback(function (port, command, pid) {
    return 0;
  }, retType, argTypes));
}
