'use strict';

var LIBDYLD_PATH = '/usr/lib/system/libdyld.dylib';
var LIBSYSTEM_KERNEL_PATH = '/usr/lib/system/libsystem_kernel.dylib';
var CORESYMBOLICATION_PATH = '/System/Library/PrivateFrameworks/CoreSymbolication.framework/CoreSymbolication';
var CRASH_REPORTER_SUPPORT_PATH = '/System/Library/PrivateFrameworks/CrashReporterSupport.framework/CrashReporterSupport';
var OBJC_BLOCK_INVOKE_OFFSET = (Process.pointerSize === 8) ? 16 : 12;
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
    if (retval.toUInt32() !== 0 || this.pid !== crashedPid || this.flavor !== TASK_DYLD_INFO)
      return;

    var info = this.info;
    var allImageInfoSize = null;
    var allImageInfoFormat = null;
    switch (Memory.readUInt(this.count)) {
      case 1:
        allImageInfoAddr = uint64(Memory.readU32(info));
        break;
      case 3:
        allImageInfoAddr = uint64(Memory.readU32(info));
        allImageInfoSize = Memory.readU32(info.add(4));
        allImageInfoFormat = Memory.readS32(info.add(8));
        break;
      case 5:
        allImageInfoAddr = Memory.readU64(info);
        allImageInfoSize = Memory.readU64(info.add(8));
        allImageInfoFormat = Memory.readS32(info.add(16));
        break;
      default:
        throw new Error('Unexpected TASK_DYLD_INFO count');
    }
  }
});

[
  ['mach_vm_read', 32],
  ['mach_vm_read_overwrite', 64],
].forEach(function (entry) {
  var name = entry[0];
  var sizeWidth = entry[1];

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
      var invocationContext = this;
      if (this.instrumented && retval.toInt32() !== 0) {
        log(invocationContext, 'failed to read: 0x' + this.address.toString(16) + ' size=' + this.size + ' kr=' + retval.toInt32() + ' called from:\n\t' + Thread.backtrace(this.context).map(DebugSymbol.fromAddress).join('\n\t'));
        return;
      }

      if (!this.instrumented || retval.toUInt32() !== 0)
        return;

      if (this.size.equals(32)) {
        log(invocationContext, 'the 32 bytes read from 0x' + this.address.toString(16) + ':\n' + hexdump(this.data, { length: readSize(this.dataSize), ansi: true }));
      }

      var startAddress = this.address;

      if (allImageInfoAddr !== null && startAddress.equals(allImageInfoAddr)) {
        var allImageInfos = this.data;

        imageArrayAddress = readRemotePointer(allImageInfos.add(8));

        var extraImageCount = mappedAgents.length;

        var imageArrayCountPtr = allImageInfos.add(4);
        var imageArrayCount = Memory.readU32(imageArrayCountPtr);
        Memory.writeU32(imageArrayCountPtr, imageArrayCount + extraImageCount);

        imageElementSize = 3 * (is64Bit ? 8 : 4);
        imageTrailerSize = extraImageCount * imageElementSize;
      } else if (imageArrayAddress !== null && startAddress.equals(imageArrayAddress)) {
        var imageTrailerStart = this.data.add(this.size).sub(imageTrailerSize);
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

          log(invocationContext, 'Added fake entry: loadAddress=0x' + loadAddress.toString(16) + ' filePath=0x' + filePath.toString(16));

          imageTrailerPaths[filePath.toString()] = agent;
        });

        var dataSize = readSize(this.dataSize);
        writeSize(this.dataSize, dataSize.add(imageTrailerSize));
      } else {
        var agent = imageTrailerPaths[startAddress.toString()];
        if (agent !== undefined)
          Memory.writeUtf8String(this.data, agent.path);
      }
    }
  });
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

Interceptor.attach(Module.findExportByName(LIBSYSTEM_KERNEL_PATH, 'mach_vm_remap'), {
  onEnter: function (args) {
    this.targetAddress = args[1];
    var size = args[2];
    log(this, 'mach_vm_remap() sourceAddress=' + args[6] + ' size=' + size + ' called from:\n\t' + Thread.backtrace(this.context).map(DebugSymbol.fromAddress).join('\n\t'));
  },
  onLeave: function (retval) {
    log(this, '=> target_address=0x' + Memory.readU64(this.targetAddress).toString(16));
  }
});

/*
var manualHookNames = {
  'dyld_process_info_base::addImage(unsigned int, bool, unsigned long long, unsigned long long, char const*)': true,
  'dyld_process_info_base::copyPath(unsigned int, unsigned long long, int*)': true,
};

var matches = DebugSymbol.findFunctionsMatching('*dyld_process_info_base*')
console.log('matches.length=' + matches.length);
matches.forEach(function (address) {
  var sym = DebugSymbol.fromAddress(address);
  var name = sym.name;
  if (manualHookNames[name] !== undefined)
    return;

  var useFastLog = name.indexOf('dyld_process_info_base::') === 0;

  Interceptor.attach(address, {
    onEnter: function (args) {
      if (useFastLog)
        fastLog(this, name);
      else
        log(this, name);
    }
  });
});

Interceptor.attach(DebugSymbol.getFunctionByName('dyld_process_info_base::addImage(unsigned int, bool, unsigned long long, unsigned long long, char const*)'), {
  onEnter: function (args) {
    fastLog(this, 'dyld_process_info_base::addImage()');
  },
  onLeave: function (retval) {
    fastLog(this, '=> ' + retval);
  }
});

Interceptor.attach(DebugSymbol.getFunctionByName('dyld_process_info_base::copyPath(unsigned int, unsigned long long, int*)'), {
  onEnter: function (args) {
    fastLog(this, 'dyld_process_info_base::copyPath()');
  },
  onLeave: function (retval) {
    var val = !retval.isNull() ? Memory.readUtf8String(retval) : null;
    fastLog(this, '=> ' + JSON.stringify(val));
  }
});
*/

Interceptor.attach(ObjC.classes._NSInlineData['- initWithBytes:length:'].implementation, {
  onEnter: function (args) {
    var bytes = args[2];
    var length = args[3];
    log(this, '-[_NSInlineData initWithBytes:' + bytes + ' length:' + length.toString(10) + '] called from:\n\t' + Thread.backtrace(this.context).map(DebugSymbol.fromAddress).join('\n\t'));
  },
});

function log(context, message) {
  fastLog(context, message);
  Thread.sleep(0.05);
}

function fastLog(context, message) {
  console.log(makeIndent(context.depth) + message);
}

function makeIndent(level) {
  var indent = [];
  var n = level;
  while (n-- > 0)
    indent.push('\t');
  return indent.join('');
}
