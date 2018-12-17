'use strict';

var LIBSYSTEM_KERNEL_PATH = '/usr/lib/system/libsystem_kernel.dylib';

var pidForTask = new NativeFunction(
    Module.findExportByName(LIBSYSTEM_KERNEL_PATH, 'pid_for_task'),
    'int',
    ['uint', 'pointer']
);

var pid = -1;
var logFd = null;
var logChunks = [];

var CrashReport = ObjC.classes.CrashReport;
if (CrashReport !== undefined) {
  var initMethod = CrashReport['- initWithTask:exceptionType:thread:threadStateFlavor:threadState:threadStateCount:'];
  if (initMethod !== undefined) {
    Interceptor.attach(initMethod.implementation, function (args) {
      var task = args[2].toUInt32();

      var pidBuf = Memory.alloc(4);
      pidForTask(task, pidBuf);
      pid = Memory.readU32(pidBuf);
      send(['crash-detected', pid]);
    });
  }
}

Interceptor.attach(Module.findExportByName(LIBSYSTEM_KERNEL_PATH, 'open_dprotected_np'), {
  onEnter: function (args) {
    var path = Memory.readUtf8String(args[0]);
    this.isCrashLog = /\.ips$/.test(path);
  },
  onLeave: function (retval) {
    if (this.isCrashLog)
      logFd = retval.toInt32();
  }
});

Interceptor.attach(Module.findExportByName(LIBSYSTEM_KERNEL_PATH, 'close'), {
  onEnter: function (args) {
    var fd = args[0].toInt32();
    if (fd !== logFd)
      return;

    if (pid !== -1) {
      send(['crash-received', pid, logChunks.join('')]);
      pid = -1;
    }
    logFd = null;
    logChunks = [];
  },
});

Interceptor.attach(Module.findExportByName(LIBSYSTEM_KERNEL_PATH, 'write'), {
  onEnter: function (args) {
    var fd = args[0].toInt32();
    this.isCrashLog = (fd === logFd);
    this.buf = args[1];
  },
  onLeave: function (retval) {
    if (!this.isCrashLog)
      return;

    var n = retval.toInt32();
    if (n === -1)
      return;
    var chunk = Memory.readUtf8String(this.buf, n);
    logChunks.push(chunk);
  }
});
