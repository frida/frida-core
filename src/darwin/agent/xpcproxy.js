'use strict';

var POSIX_SPAWN_START_SUSPENDED = 0x0080;

Interceptor.attach(Module.findExportByName('/usr/lib/system/libsystem_kernel.dylib', '__posix_spawn'), {
  onEnter: function (args) {
    var attrs = Memory.readPointer(args[2].add(Process.pointerSize));

    var flags = Memory.readU16(attrs);
    flags |= POSIX_SPAWN_START_SUSPENDED;
    Memory.writeU16(attrs, flags);
  }
});
