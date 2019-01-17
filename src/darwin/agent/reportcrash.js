'use strict';

var LIBDYLD_PATH = '/usr/lib/system/libdyld.dylib';
var LIBSYSTEM_KERNEL_PATH = '/usr/lib/system/libsystem_kernel.dylib';
var CRASH_REPORTER_SUPPORT_PATH = '/System/Library/PrivateFrameworks/CrashReporterSupport.framework/CrashReporterSupport';
var OBJC_BLOCK_INVOKE_OFFSET = (Process.pointerSize === 8) ? 16 : 12;

var _pidForTask = new NativeFunction(
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

var crashedPid = -1;
var forcedByUs = false;
var logPath = null;
var logFd = null;
var logChunks = [];
var mappedAgents = [];
var procInfoInstances = {};

Interceptor.attach(CrashReport['- initWithTask:exceptionType:thread:threadStateFlavor:threadState:threadStateCount:'].implementation, function (args) {
  var task = args[2].toUInt32();

  crashedPid = pidForTask(task);
  send(['crash-detected', crashedPid]);

  var op = recv('mapped-agents', function (message) {
    mappedAgents = message.payload;
  });
  op.wait();
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

    if (crashedPid !== -1) {
      send(['crash-received', crashedPid, logChunks.join('')]);
      crashedPid = -1;
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

Interceptor.attach(Module.findExportByName(LIBDYLD_PATH, '_dyld_process_info_create'), {
  onEnter: function (args) {
    this.task = args[0].toUInt32();
  },
  onLeave: function (instance) {
    if (instance.isNull())
      return;

    var targetPid = pidForTask(this.task);
    if (targetPid === crashedPid)
      procInfoInstances[instance.toString()] = true;
  }
});

Interceptor.attach(Module.findExportByName(LIBDYLD_PATH, '_dyld_process_info_for_each_image'), {
  onEnter: function (args) {
    var instance = args[0];
    if (procInfoInstances[instance.toString()] === undefined)
      return;

    var block = args[1];
    var invoke = new NativeFunction(Memory.readPointer(block.add(OBJC_BLOCK_INVOKE_OFFSET)), 'void', ['pointer', 'uint64', 'pointer', 'pointer']);

    mappedAgents.forEach(function (agent) {
      var machHeaderAddress = uint64(agent.machHeaderAddress);
      var uuid = parseUUID(agent.uuid);
      var path = Memory.allocUtf8String(agent.path);

      invoke(block, machHeaderAddress, uuid, path);
    });
  }
});

function pidForTask(task) {
  var pidBuf = Memory.alloc(4);
  _pidForTask(task, pidBuf);
  return Memory.readU32(pidBuf);
}

function parseUUID(str) {
  var result = Memory.alloc(16);

  var bareStr = str.replace(/-/g, '');
  for (var offset = 0; offset !== 16; offset++) {
    var hexByte = bareStr.substr(offset * 2, 2);
    Memory.writeU8(result.add(offset), parseInt(hexByte, 16));
  }

  return result;
}
