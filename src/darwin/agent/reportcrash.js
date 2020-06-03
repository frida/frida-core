var LIBSYSTEM_KERNEL_PATH = '/usr/lib/system/libsystem_kernel.dylib';
var CORESYMBOLICATION_PATH = '/System/Library/PrivateFrameworks/CoreSymbolication.framework/CoreSymbolication';
var CRASH_REPORTER_SUPPORT_PATH = '/System/Library/PrivateFrameworks/CrashReporterSupport.framework/CrashReporterSupport';
var YES = ptr(1);

var CSTypeRef = ['pointer', 'pointer'];
var kCSNow = uint64('0x8000000000000000');
var NSUTF8StringEncoding = 4;

var nativeOptions = {
  scheduling: 'exclusive',
  exceptions: 'propagate'
};
var _pidForTask = new NativeFunction(
    Module.getExportByName(LIBSYSTEM_KERNEL_PATH, 'pid_for_task'),
    'int',
    ['uint', 'pointer'],
    nativeOptions
);
var unlink = new NativeFunction(
    Module.getExportByName(LIBSYSTEM_KERNEL_PATH, 'unlink'),
    'int',
    ['pointer'],
    nativeOptions
);
var CSSymbolicatorGetSymbolWithAddressAtTime = new NativeFunction(
    Module.getExportByName(CORESYMBOLICATION_PATH, 'CSSymbolicatorGetSymbolWithAddressAtTime'),
    CSTypeRef,
    [CSTypeRef, 'uint64', 'uint64'],
    nativeOptions
);
var CSIsNull = new NativeFunction(
    Module.getExportByName(CORESYMBOLICATION_PATH, 'CSIsNull'),
    'int',
    [CSTypeRef],
    nativeOptions
);
var mappedMemoryRead = new NativeFunction(
    Module.getExportByName(CORESYMBOLICATION_PATH, 'mapped_memory_read'),
    'uint',
    ['pointer', 'uint64', 'uint64', 'pointer'],
    nativeOptions
);
var mappedMemoryReadPointer = new NativeFunction(
    Module.getExportByName(CORESYMBOLICATION_PATH, 'mapped_memory_read_pointer'),
    'uint',
    ['pointer', 'uint64', 'pointer'],
    nativeOptions
);

var AppleErrorReport = ObjC.classes.AppleErrorReport;
var CrashReport = ObjC.classes.CrashReport;
var NSMutableDictionary = ObjC.classes.NSMutableDictionary;
var NSString = ObjC.classes.NSString;
var OSALog = ObjC.classes.OSALog;
var OSAReport = ObjC.classes.OSAReport;

var sessions = {};
var osaHookState = 'pending';

function createSession(threadId) {
  var session = {
    crashedPid: -1,
    is64Bit: null,
    forcedByUs: false,
    logPath: null,
    logFd: null,
    logChunks: [],
    mappedAgents: []
  };

  sessions[threadId] = session;

  return session;
}

function terminateSession(threadId) {
  var session = getSession(threadId, 'terminateSession');

  send(['crash-received', session.crashedPid, session.logChunks.join('')]);

  delete sessions[threadId];
}

function getSession(threadId, operation) {
  var session = sessions[threadId];
  if (session === undefined) {
    throw new Error(operation + ': missing session for thread ' + threadId);
  }
  return session;
}

function findSession(threadId) {
  var session = sessions[threadId];
  return (session !== undefined) ? session : null;
}

Interceptor.attach(CrashReport['- initWithTask:exceptionType:thread:threadStateFlavor:threadState:threadStateCount:'].implementation, {
  onEnter: function (args) {
    var session = createSession(this.threadId);

    var task = args[2].toUInt32();

    var crashedPid = pidForTask(task);
    session.crashedPid = crashedPid;

    send(['crash-detected', crashedPid]);
    var op = recv('mapped-agents', function (message) {
      session.mappedAgents = message.payload.map(function (agent) {
        return {
          machHeaderAddress: uint64(agent.machHeaderAddress),
          uuid: agent.uuid,
          path: agent.path,
        };
      });
    });
    op.wait();

    ensureOsaHooked();
  },
});

Interceptor.attach(Module.getExportByName(CORESYMBOLICATION_PATH, 'task_is_64bit'), {
  onEnter: function (args) {
    this.pid = pidForTask(args[0].toUInt32());
  },
  onLeave: function (retval) {
    var session = findSession(this.threadId);
    if (session !== null && this.pid === session.crashedPid)
      session.is64Bit = !!retval.toUInt32();
  }
});

Interceptor.attach(CrashReport['- isActionable'].implementation, {
  onLeave: function (retval) {
    var isActionable = !!retval.toInt32();
    var session = getSession(this.threadId, 'isActionable');
    if (!isActionable) {
      retval.replace(YES);
      session.forcedByUs = true;
    }
  },
});

function ensureOsaHooked() {
  if (osaHookState === 'hooked')
    return;

  var methodName = (OSAReport !== undefined)
      ? '- osa_logCounter_isLog:byKey:count:withinLimit:withOptions:'
      : '- logCounter_isLog:byKey:count:withinLimit:withOptions:';
  Interceptor.attach(NSMutableDictionary[methodName].implementation, {
    onLeave: function (retval) {
      var isWithinLimit = !!retval.toInt32();
      var session = getSession(this.threadId, 'isWithinLimit');
      if (!isWithinLimit) {
        retval.replace(YES);
        session.forcedByUs = true;
      }
    },
  });

  osaHookState = 'hooked';
}

var saveImpl = (OSAReport !== undefined)
    ? OSAReport['- saveWithOptions:'].implementation
    : AppleErrorReport['- saveToDir:'].implementation;
Interceptor.attach(saveImpl, {
  onLeave: function (retval) {
    var session = getSession(this.threadId, 'save');
    if (session.forcedByUs)
      unlink(Memory.allocUtf8String(session.logPath));

    terminateSession(this.threadId);
  },
});

var createForSubmission;
if (OSALog !== undefined)
  createForSubmission = OSALog['+ createForSubmission:metadata:options:error:writing:'];

if (createForSubmission !== undefined) {
  Interceptor.attach(createForSubmission.implementation, {
    onLeave: function (retval) {
      var log = new ObjC.Object(retval);
      var filePath = log.filepath();

      var session = getSession(this.threadId, 'createForSubmission');

      var logPath = filePath.toString();
      session.logPath = logPath;

      if (logPath.indexOf('.forced-by-frida') !== -1)
        session.forcedByUs = true;

      session.logChunks.push(NSString.stringWithContentsOfFile_encoding_error_(filePath, NSUTF8StringEncoding, NULL).toString());
    }
  });
} else {
  Interceptor.attach(Module.getExportByName(LIBSYSTEM_KERNEL_PATH, 'rename'), {
    onEnter: function (args) {
      var newPath = args[1].readUtf8String();
      var session = getSession(this.threadId, 'rename');
      if (/\.ips$/.test(newPath))
        session.logPath = newPath;
    },
  });

  Interceptor.attach(Module.getExportByName(LIBSYSTEM_KERNEL_PATH, 'open_dprotected_np'), {
    onEnter: function (args) {
      var path = args[0].readUtf8String();
      this.isCrashLog = /\.ips$/.test(path);
    },
    onLeave: function (retval) {
      var session = getSession(this.threadId, 'open_dprotected_np');
      if (this.isCrashLog)
        session.logFd = retval.toInt32();
    },
  });

  Interceptor.attach(Module.getExportByName(LIBSYSTEM_KERNEL_PATH, 'write'), {
    onEnter: function (args) {
      var fd = args[0].toInt32();
      this.buf = args[1];

      var session = findSession(this.threadId);
      if (session !== null) {
        this.session = session;
        this.isCrashLog = (fd === session.logFd);
      } else {
        this.isCrashLog = false;
      }
    },
    onLeave: function (retval) {
      if (!this.isCrashLog)
        return;

      var n = retval.toInt32();
      if (n === -1)
        return;

      var chunk = this.buf.readUtf8String(n);
      var session = this.session;
      if (session !== undefined)
        session.logChunks.push(chunk);
    }
  });
}

Interceptor.attach(Module.getExportByName(CRASH_REPORTER_SUPPORT_PATH, 'OSAPreferencesGetBoolValue'), {
  onEnter: function (args) {
    this.name = new ObjC.Object(args[0]).toString();
    this.domain = new ObjC.Object(args[1]).toString();
    this.successPtr = args[2];
  },
  onLeave: function (retval) {
    if (this.name === 'SymbolicateCrashes' && this.domain === 'com.apple.CrashReporter') {
      if (!this.successPtr.isNull())
        this.successPtr.writeU8(1);
      retval.replace(YES);
    }
  }
});

var libdyld = findLibdyldInternals();
if (libdyld !== null) {
  var allImageInfoSizes = {
    15: 320,
    16: 328,
  };
  var imageElementSize = 3 * Process.pointerSize;

  var procInfoInvocations = {};

  Interceptor.attach(libdyld['dyld_process_info_base::make'], {
    onEnter: function (args) {
      var session = getSession(this.threadId, 'dyld_process_info_base::make');

      var pid = pidForTask(args[0].toUInt32());
      if (pid !== session.crashedPid)
        return;
      var allImageInfo = args[1];

      var version = allImageInfo.readU32();
      var count = allImageInfo.add(4).readU32();
      var array = allImageInfo.add(8).readU64();

      var size = allImageInfoSizes[version];
      if (size === undefined) {
        console.error('Unsupported dyld_all_image_infos_64; please add support for version ' + version);
        return;
      }

      var extraCount = session.mappedAgents.length;
      var copy = Memory.dup(allImageInfo, size);
      copy.add(4).writeU32(count + extraCount);
      this.allImageInfo = copy;
      args[1] = copy;

      var realSize = count * imageElementSize;

      procInfoInvocations[this.threadId] = {
        array: array,
        realSize: realSize,
        fakeSize: realSize + (extraCount * imageElementSize),
        agents: session.mappedAgents,
        paths: {}
      };
    },
    onLeave: function (retval) {
      delete procInfoInvocations[this.threadId];
    }
  });

  Interceptor.attach(libdyld.withRemoteBuffer, {
    onEnter: function (args) {
      var invocation = procInfoInvocations[this.threadId];
      if (invocation === undefined)
        return;

      var session = getSession(this.threadId, 'withRemoteBuffer');

      var remoteAddress = uint64(args[1].toString());

      if (remoteAddress.equals(invocation.array)) {
        var realSize = invocation.realSize;

        args[2] = ptr(realSize);

        this.block = wrapBlock(args[6], function (impl, buffer, size) {
          var copy = Memory.alloc(invocation.fakeSize);
          Memory.copy(copy, buffer, realSize);

          var element = copy.add(realSize);
          var paths = invocation.paths;
          invocation.agents.forEach(function (agent) {
            var loadAddress = agent.machHeaderAddress;
            var filePath = loadAddress.sub(4096);
            var modDate = 0;

            if (session.is64Bit) {
              element
                  .writeU64(loadAddress).add(8)
                  .writeU64(filePath).add(8)
                  .writeU64(modDate);
            } else {
              element
                  .writeU32(loadAddress).add(4)
                  .writeU32(filePath).add(4)
                  .writeU32(modDate);
            }

            paths[filePath.toString()] = agent;

            element = element.add(imageElementSize);
          });

          impl(copy, size);
        });

        return;
      }

      var agent = invocation.paths[remoteAddress.toString()];
      if (agent !== undefined) {
        this.block = wrapBlock(args[6], function (impl, buffer, size) {
          var copy = Memory.dup(buffer, size);
          copy.writeUtf8String(agent.path);
          impl(copy, size);
        });
      }
    }
  });
}

function findLibdyldInternals() {
  if (Process.arch !== 'arm64')
    return null;

  var m = Process.getModuleByName('/usr/lib/system/libdyld.dylib');
  var base = m.base;
  var size = m.size;

  /*
   * Verified on:
   * - 12.4
   * - 13.2.2
   * - 13.3
   */
  var prologue = [];

  var isArm64e = !ptr(1).sign().equals(1);
  if (isArm64e) {
    var pacibsp = '7f 23 03 d5';
    prologue.push(pacibsp);
  }

  var signatures = {
    'dyld_process_info_base::make': prologue.concat(['ff c3 04 d1', '?? ?? ?? ?? '.repeat(isArm64e ? 35 : 33), '28 e0 02 91']).join(' '),
    'withRemoteBuffer': prologue.concat(['ff ?? 01 d1 f4 4f ?? a9 fd 7b ?? a9 fd ?? ?? 91 f3 03 06 aa']).join(' '),
  };

  var result = Object.keys(signatures)
      .reduce(function (result, name) {
        var matches = Memory.scanSync(base, size, signatures[name]);
        if (matches.length === 1)
          result.api[name] = matches[0].address;
        else
          result.missing.push(name);
        return result;
      }, { api: {}, missing: [] });
  if (result.missing.length !== 0) {
    console.error('Unsupported version of libdyld.dylib; missing:\n\t' + result.missing.join('\n\t'));
    return null;
  }
  return result.api;
}

function pidForTask(task) {
  var pidBuf = Memory.alloc(4);
  _pidForTask(task, pidBuf);
  return pidBuf.readU32();
}

if (Process.arch === 'arm64') {
  Interceptor.attach(ObjC.classes.VMUSampler['- sampleAllThreadsOnceWithFramePointers:'].implementation, {
    onEnter: function (args) {
      args[2] = YES;
    }
  });

  Interceptor.attach(ObjC.classes.VMUBacktrace['- fixupStackWithSamplingContext:symbolicator:'].implementation, {
    onEnter: function (args) {
      this.self = new ObjC.Object(args[0]);
      this.samplingContext = args[2];
      this.symbolicator = [args[3], args[4]];
    },
    onLeave: function () {
      var session = getSession(this.threadId, 'fixupStackWithSamplingContext');
      if (!session.is64Bit)
        return;

      var callstack = this.self.$ivars._callstack;
      var samplingContext = this.samplingContext;
      var mappedMemory = new MappedMemory(samplingContext.add(8).readPointer());
      var symbolicator = this.symbolicator;

      var frames = callstack[1];
      var framePtrs = callstack[2];
      var length = callstack[3];

      for (var i = 0; i !== length; i++) {
        var frameSlot = frames.add(i * 8);
        var frame = frameSlot.readU64();

        var symbol = CSSymbolicatorGetSymbolWithAddressAtTime(symbolicator, frame, kCSNow);
        if (!CSIsNull(symbol))
          continue;

        var framePtrAbove = (i > 0) ? framePtrs.add((i - 1) * 8).readU64() : null;

        var functionAddress = tryParseInterceptorTrampoline(frame, framePtrAbove, mappedMemory);
        if (functionAddress !== null)
          frameSlot.writeU64(functionAddress);
      }
    },
  });
}

function MappedMemory(handle) {
  this.handle = handle;
}

var pointerBuf = Memory.alloc(8);

MappedMemory.prototype.read = function (address, size) {
  var kr = mappedMemoryRead(this.handle, address, size, pointerBuf);
  if (kr !== 0)
    throw new Error('Invalid address: 0x' + address.toString(16));
  return pointerBuf.readPointer().readByteArray(size);
};

MappedMemory.prototype.readPointer = function (address) {
  var kr = mappedMemoryReadPointer(this.handle, address, pointerBuf);
  if (kr !== 0)
    throw new Error('Invalid address: 0x' + address.toString(16));
  return pointerBuf.readU64();
};

function tryParseInterceptorTrampoline(code, stackFrameAbove, mappedMemory) {
  var instructions;
  try {
    instructions = new Uint32Array(mappedMemory.read(code, 16));
  } catch (e) {
    return null;
  }

  var result = tryParseInterceptorOnLeaveTrampoline(instructions, code, mappedMemory);
  if (result !== null)
    return result;

  return tryParseInterceptorCallbackTrampoline(instructions, code, stackFrameAbove, mappedMemory);
}

function tryParseInterceptorOnLeaveTrampoline(instructions, code, mappedMemory) {
  var ldr;

  ldr = tryParseLdrRegAddress(instructions[0], code);
  if (ldr === null)
    return null;
  if (ldr[0] !== 'x17')
    return null;
  var functionContextDPtr = ldr[1];

  ldr = tryParseLdrRegAddress(instructions[1], code.add(4));
  if (ldr === null)
    return null;
  if (ldr[0] !== 'x16')
    return null;

  var isBrX16 = ((instructions[2] & 0xfffff7e0) >>> 0) === 0xd61f0200;
  if (!isBrX16)
    return null;

  return tryReadInterceptorFunctionContextDoublePointer(functionContextDPtr, mappedMemory);
}

var interceptorCallbackTrampolineSignature = [
  0x910043ff, // add sp, sp, 0x10
  0xa8c103e1, // ldp x1, x0, [sp], 0x10
  0xa8c10be1, // ldp x1, x2, [sp], 0x10
  0xa8c113e3, // ldp x3, x4, [sp], 0x10
];

function tryParseInterceptorCallbackTrampoline(instructions, code, stackFrameAbove, mappedMemory) {
  if (stackFrameAbove === null)
    return null;

  var matches = interceptorCallbackTrampolineSignature.every(function (insn, index) {
    return instructions[index] === insn;
  });
  if (!matches)
    return null;

  var cpuContextStart = stackFrameAbove.add(16 + 8);
  var x17Start = cpuContextStart.add(19 * 8);
  return tryReadInterceptorFunctionContextDoublePointer(x17Start, mappedMemory);
}

function tryReadInterceptorFunctionContextDoublePointer(functionContextDPtr, mappedMemory) {
  try {
    var functionContext = mappedMemory.readPointer(functionContextDPtr);
    var functionAddress = mappedMemory.readPointer(functionContext);
    return functionAddress;
  } catch (e) {
    return null;
  }
}

function tryParseLdrRegAddress(instruction, pc) {
  if ((instruction & 0xff000000) !== 0x58000000)
    return null;

  var reg = instruction & 0x1f;

  var distance = (instruction >>> 5) & 0x7ffff;
  var imm = pc.add(distance * 4);

  return ['x' + reg, imm];
}

function wrapBlock(handle, wrapper) {
  var block = new ObjC.Block(handle);

  var impl = block.implementation;

  block.implementation = function () {
    var n = arguments.length;
    var args = new Array(n + 1);
    args[0] = impl;
    for (var i = 0; i !== n; i++)
      args[1 + i] = arguments[i];

    wrapper.apply(null, args);
  };

  return block;
}
