'use strict';

var LIBSYSTEM_KERNEL_PATH = '/usr/lib/system/libsystem_kernel.dylib';
var CORESYMBOLICATION_PATH = '/System/Library/PrivateFrameworks/CoreSymbolication.framework/CoreSymbolication';
var CRASH_REPORTER_SUPPORT_PATH = '/System/Library/PrivateFrameworks/CrashReporterSupport.framework/CrashReporterSupport';
var TASK_DYLD_INFO = 17;

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

var crashedPid;
var is64Bit;
var forcedByUs;
var logPath;
var logFd;
var logChunks;
var mappedAgents;
var allImageInfoAddr;
var imageArrayAddress;
var imageElementSize;
var imageTrailerSize;
var imageTrailerPaths;

function reset() {
  crashedPid = -1;
  is64Bit = null;
  forcedByUs = false;
  logPath = null;
  logFd = null;
  logChunks = [];
  mappedAgents = [];
  allImageInfoAddr = null;
  imageArrayAddress = null;
  imageElementSize = null;
  imageTrailerSize = null;
  imageTrailerPaths = {};
}

reset();

Interceptor.attach(CrashReport['- initWithTask:exceptionType:thread:threadStateFlavor:threadState:threadStateCount:'].implementation, {
  onEnter: function (args) {
    var task = args[2].toUInt32();

    crashedPid = pidForTask(task);
    send(['crash-detected', crashedPid]);

    var op = recv('mapped-agents', function (message) {
      mappedAgents = message.payload.map(function (agent) {
        return {
          machHeaderAddress: uint64(agent.machHeaderAddress),
          uuid: agent.uuid,
          path: agent.path,
        };
      });
    });
    op.wait();
  },
});

Interceptor.attach(Module.findExportByName(CORESYMBOLICATION_PATH, 'task_is_64bit'), {
  onEnter: function (args) {
    this.pid = pidForTask(args[0].toUInt32());
  },
  onLeave: function (retval) {
    if (this.pid === crashedPid)
      is64Bit = !!retval.toUInt32();
  }
});

Interceptor.attach(CrashReport['- isActionable'].implementation, {
  onLeave: function (retval) {
    var isActionable = !!retval.toInt32();
    if (!isActionable) {
      retval.replace(ptr(1));
      forcedByUs = true;
    }
  },
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
      reset();
    }
  },
});

Interceptor.attach(Module.findExportByName(LIBSYSTEM_KERNEL_PATH, 'open_dprotected_np'), {
  onEnter: function (args) {
    var path = Memory.readUtf8String(args[0]);
    this.isCrashLog = /\.ips$/.test(path);
  },
  onLeave: function (retval) {
    if (this.isCrashLog)
      logFd = retval.toInt32();
  },
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

Interceptor.attach(Module.findExportByName(LIBSYSTEM_KERNEL_PATH, 'task_info'), {
  onEnter: function (args) {
    this.pid = pidForTask(args[0].toUInt32());
    this.flavor = args[1].toUInt32();
    this.info = args[2];
    this.count = args[3];
  },
  onLeave: function (retval) {
    if (this.pid !== crashedPid || this.flavor !== TASK_DYLD_INFO || retval.toUInt32() !== 0)
      return;

    var info = this.info;
    switch (Memory.readUInt(this.count)) {
      case 1:
      case 3:
        allImageInfoAddr = uint64(Memory.readU32(info));
        break;
      case 5:
        allImageInfoAddr = Memory.readU64(info);
        break;
      default:
        throw new Error('Unexpected TASK_DYLD_INFO count');
    }
  }
});

[
  ['mach_vm_read', false, 32],
  ['mach_vm_read_overwrite', true, 64],
].forEach(function (entry) {
  var name = entry[0];
  var inplace = entry[1];
  var sizeWidth = entry[2];

  var readSize = (sizeWidth !== 32) ? Memory['readU' + sizeWidth].bind(Memory) : readSizeFromU32;
  var writeSize = Memory['writeU' + sizeWidth].bind(Memory);

  Interceptor.attach(Module.findExportByName(LIBSYSTEM_KERNEL_PATH, name), {
    onEnter: function (args) {
      var pid = pidForTask(args[0].toUInt32());
      if (pid !== crashedPid)
        return;
      this.instrumented = true;

      var address = uint64(args[1].toString());
      this.address = address;
      var size = uint64(args[2].toString());
      this.size = size;
      this.data = args[3];
      this.dataSize = args[4];

      if (imageArrayAddress !== null && address.equals(imageArrayAddress)) {
        args[2] = ptr(size.sub(imageTrailerSize));
      }
    },
    onLeave: function (retval) {
      if (!this.instrumented || retval.toUInt32() !== 0)
        return;

      var startAddress = this.address;

      if (allImageInfoAddr !== null && startAddress.equals(allImageInfoAddr)) {
        var allImageInfos = getData(this);

        imageArrayAddress = readRemotePointer(allImageInfos.add(8));

        var extraImageCount = mappedAgents.length;

        var imageArrayCountPtr = allImageInfos.add(4);
        var imageArrayCount = Memory.readU32(imageArrayCountPtr);
        Memory.writeU32(imageArrayCountPtr, imageArrayCount + extraImageCount);

        imageElementSize = 3 * (is64Bit ? 8 : 4);
        imageTrailerSize = extraImageCount * imageElementSize;
      } else if (imageArrayAddress !== null && startAddress.equals(imageArrayAddress)) {
        var imageTrailerStart = getData(this).add(this.size).sub(imageTrailerSize);
        mappedAgents.forEach(function (agent, index) {
          var element = imageTrailerStart.add(index * imageElementSize);

          var loadAddress = agent.machHeaderAddress;
          var filePath = loadAddress.sub(4096);
          var modDate = 0;

          if (is64Bit) {
            Memory.writeU64(element, loadAddress);
            Memory.writeU64(element.add(8), filePath);
            Memory.writeU64(element.add(16), modDate);
          } else {
            Memory.writeU32(element, loadAddress);
            Memory.writeU32(element.add(4), filePath);
            Memory.writeU32(element.add(8), modDate);
          }

          imageTrailerPaths[filePath.toString()] = agent;
        });

        var dataSize = readSize(this.dataSize);
        writeSize(this.dataSize, dataSize.add(imageTrailerSize));
      } else {
        var agent = imageTrailerPaths[startAddress.toString()];
        if (agent !== undefined)
          Memory.writeUtf8String(getData(this), agent.path);
      }
    }
  });

  function getData(invocationContext) {
    return inplace ? invocationContext.data : Memory.readPointer(invocationContext.data);
  }
});

function pidForTask(task) {
  var pidBuf = Memory.alloc(4);
  _pidForTask(task, pidBuf);
  return Memory.readU32(pidBuf);
}

function readRemotePointer(address) {
  return is64Bit ? Memory.readU64(address) : uint64(Memory.readU32(address));
}

function readSizeFromU32(address) {
  return uint64(Memory.readU32(address));
}
