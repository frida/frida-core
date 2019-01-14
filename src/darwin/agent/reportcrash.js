'use strict';

var LIBSYSTEM_KERNEL_PATH = '/usr/lib/system/libsystem_kernel.dylib';
var CRASH_REPORTER_SUPPORT_PATH = '/System/Library/PrivateFrameworks/CrashReporterSupport.framework/CrashReporterSupport';

var pidForTask = new NativeFunction(
    Module.findExportByName(LIBSYSTEM_KERNEL_PATH, 'pid_for_task'),
    'int',
    ['uint', 'pointer']
);
var unlink = new NativeFunction(
    Module.findExportByName(LIBSYSTEM_KERNEL_PATH, 'unlink'),
    'int',
    ['pointer']
);

var AppleErrorReport = ObjC.classes.AppleErrorReport;
var CrashReport = ObjC.classes.CrashReport;
var NSMutableDictionary = ObjC.classes.NSMutableDictionary;

var pid = -1;
var forcedByUs = false;
var logPath = null;
var logFd = null;
var logChunks = [];

Interceptor.attach(CrashReport['- initWithTask:exceptionType:thread:threadStateFlavor:threadState:threadStateCount:'].implementation, function (args) {
  var task = args[2].toUInt32();

  var pidBuf = Memory.alloc(4);
  pidForTask(task, pidBuf);
  pid = Memory.readU32(pidBuf);
  send(['crash-detected', pid]);
});

Interceptor.attach(CrashReport['- isActionable'].implementation, {
  onLeave: function (retval) {
    var isActionable = !!retval.toInt32();
    if (!isActionable) {
      retval.replace(ptr(1));
      forcedByUs = true;
    }
  }
});

Interceptor.attach(NSMutableDictionary['- logCounter_isLog:byKey:count:withinLimit:withOptions:'].implementation, {
  onLeave: function (retval) {
    var isLogWithinLimit = !!retval.toInt32();
    if (!isLogWithinLimit) {
      retval.replace(ptr(1));
      forcedByUs = true;
    }
  },
});

Interceptor.attach(Module.findExportByName(LIBSYSTEM_KERNEL_PATH, 'rename'), {
  onEnter: function (args) {
    var newPath = Memory.readUtf8String(args[1]);
    if (/\.ips$/.test(newPath)) {
      logPath = newPath;
    }
  },
});

Interceptor.attach(AppleErrorReport['- saveToDir:'].implementation, {
  onLeave: function (retval) {
    if (forcedByUs) {
      unlink(Memory.allocUtf8String(logPath));
      logPath = null;
      forcedByUs = false;
    }
  }
});

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

Interceptor.attach(Module.findExportByName(CRASH_REPORTER_SUPPORT_PATH, 'OSAPreferencesGetBoolValue'), {
  onEnter: function (args) {
    this.name = new ObjC.Object(args[0]).toString();
    this.domain = new ObjC.Object(args[1]).toString();
    this.successPtr = args[2];
  },
  onLeave: function (retval) {
    if (this.name === 'SymbolicateCrashes' && this.domain === 'com.apple.CrashReporter') {
      if (!this.successPtr.isNull())
        Memory.writeU8(this.successPtr, 1);
      retval.replace(ptr(1));
    }
  }
});
