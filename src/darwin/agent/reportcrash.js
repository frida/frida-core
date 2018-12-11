'use strict';

var LIBSYSTEM_KERNEL_PATH = '/usr/lib/system/libsystem_kernel.dylib';

var pidForTask = new NativeFunction(
    Module.findExportByName(LIBSYSTEM_KERNEL_PATH, 'pid_for_task'),
    'int',
    ['uint', 'pointer']
);

var crashLogFd = null;
var crashLogChunks = [];

rpc.exports = {
  start: function () {
  },
};

var CrashReport = ObjC.classes.CrashReport;
if (CrashReport !== undefined) {
  var initMethod = CrashReport['- initWithTask:exceptionType:thread:threadStateFlavor:threadState:threadStateCount:'];
  if (initMethod !== undefined) {
    Interceptor.attach(initMethod.implementation, function (args) {
      var task = args[2].toUInt32();

      var pidBuf = Memory.alloc(4);
      pidForTask(task, pidBuf);
      var pid = Memory.readU32(pidBuf);

      console.log('w00t, PID=' + pid);
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
      crashLogFd = retval.toInt32();
  }
});

Interceptor.attach(Module.findExportByName(LIBSYSTEM_KERNEL_PATH, 'close'), {
  onEnter: function (args) {
    var fd = args[0].toInt32();
    if (fd === crashLogFd) {
      send(['report', crashLogChunks.join('')]);
      crashLogFd = null;
      crashLogChunks = [];
    }
  },
});

Interceptor.attach(Module.findExportByName(LIBSYSTEM_KERNEL_PATH, 'write'), {
  onEnter: function (args) {
    var fd = args[0].toInt32();
    this.isCrashLog = (fd === crashLogFd);
    this.buf = args[1];
  },
  onLeave: function (retval) {
    if (!this.isCrashLog)
      return;

    var n = retval.toInt32();
    if (n === -1)
      return;
    var chunk = Memory.readUtf8String(this.buf, n);
    crashLogChunks.push(chunk);
  }
});


var addresses = {};

var objcResolver = new ApiResolver('objc');
['AppleErrorReport', 'CrashReport'].forEach(function (className) {
  objcResolver.enumerateMatchesSync('*[' + className + ' *]').forEach(function (match) {
    hook(match.name, match.address, false);
  });
});

function hook(name, address, skipNested) {
  var id = address.toString();
  if (addresses[id] !== undefined)
    return;
  addresses[id] = id;

  Interceptor.attach(address, {
    onEnter: function () {
      if (skipNested && this.depth > 0)
        return;

      console.log(makeIndent(this.depth) + name);
    }
  });
}

function makeIndent(level) {
  var indent = [];
  var n = level;
  while (n-- > 0)
    indent.push('\t');
  return indent.join('');
}
