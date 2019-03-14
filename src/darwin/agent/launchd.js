'use strict';

var pointerSize = Process.pointerSize;

var POSIX_SPAWN_START_SUSPENDED = 0x0080;

var upcoming = {};
var gating = false;

var jbdCallImpl = Module.findExportByName(null, 'jbd_call');
var jbdPidsToIgnore = {};
var runningOnElectra = jbdCallImpl !== null;

var substrateInvocations = {};
var substratePidsPending = {};

rpc.exports = {
  prepareForLaunch: function (identifier) {
    upcoming[identifier] = true;
  },
  cancelLaunch: function (identifier) {
    if (upcoming[identifier] !== undefined)
      delete upcoming[identifier];
  },
  enableSpawnGating: function () {
    gating = true;
  },
  disableSpawnGating: function () {
    gating = false;
  },
};

Interceptor.attach(Module.findExportByName('/usr/lib/system/libsystem_kernel.dylib', '__posix_spawn'), {
  onEnter: function (args) {
    var path = args[1].readUtf8String();
    if (path !== '/usr/libexec/xpcproxy')
      return;

    var rawIdentifier = args[3].add(pointerSize).readPointer().readUtf8String();

    var identifier, event;
    if (rawIdentifier.indexOf('UIKitApplication:') === 0) {
      identifier = rawIdentifier.substring(17, rawIdentifier.indexOf('['));
      if (upcoming[identifier] !== undefined)
        event = 'launch:app';
      else if (gating)
        event = 'spawn';
      else
        return;
    } else if (gating || rawIdentifier === 'com.apple.ReportCrash') {
      identifier = rawIdentifier;
      event = 'spawn';
    } else {
      return;
    }

    var attrs = args[2].add(pointerSize).readPointer();

    var flags = attrs.readU16();
    flags |= POSIX_SPAWN_START_SUSPENDED;
    attrs.writeU16(flags);

    this.event = event;
    this.identifier = identifier;
    this.pidPtr = args[0];
  },
  onLeave: function (retval) {
    var event = this.event;
    if (event === undefined)
      return;

    var identifier = this.identifier;

    if (event === 'launch:app')
      delete upcoming[identifier];

    if (retval.toInt32() < 0)
      return;

    var pid = this.pidPtr.readU32();

    if (runningOnElectra) {
      jbdPidsToIgnore[pid] = true;
    }

    var dealingWithSubstrate = substrateInvocations[this.threadId] === true;
    if (dealingWithSubstrate) {
      substratePidsPending[pid] = notifyFridaBackend;
    } else {
      notifyFridaBackend();
    }

    function notifyFridaBackend() {
      send([event, identifier, pid]);
    }
  }
});

if (runningOnElectra) {
  sabotageJbdCallForOurPids();
}

function sabotageJbdCallForOurPids() {
  var retType = 'int';
  var argTypes = ['uint', 'uint', 'uint'];

  var jbdCall = new NativeFunction(jbdCallImpl, retType, argTypes);

  Interceptor.replace(jbdCall, new NativeCallback(function (port, command, pid) {
    var isIgnored = jbdPidsToIgnore[pid] !== undefined;
    if (isIgnored) {
      delete jbdPidsToIgnore[pid];
      return 0;
    }

    return jbdCall(port, command, pid);
  }, retType, argTypes));
}

var launcher = tryDetectSubstrateLauncher();
if (launcher !== null) {
  instrumentSubstrateLauncher(launcher);
}

function tryDetectSubstrateLauncher() {
  if (Process.arch !== 'arm64')
    return null;

  var LAUNCHER_T_DYLIB_NAME = '4c 61 75 6e 63 68 65 72 2e 74 2e 64 79 6c 69 62';

  var modules = new ModuleMap();
  var ranges = Process.enumerateRanges('r-x')
      .filter(function (r) { return !modules.has(r.base); })
      .filter(function (r) { return (r.base.readU32() & 0xfffffffe) >>> 0 === 0xfeedface; })
      .filter(function (r) { return Memory.scanSync(r.base, 2048, LAUNCHER_T_DYLIB_NAME).length > 0; });
  if (ranges.length === 0)
    return null;
  var launcher = ranges[0];
  var base = launcher.base;
  var size = launcher.size;

  return {
    handlePosixSpawn: resolveFunction('fd 7b bf a9 fd 03 00 91 f4 4f bf a9 f6 57 bf a9 f8 5f bf a9 fa 67 bf a9 fc 6f bf a9 ff 03 04 d1'),
    workerCont: resolveFunction('fd 7b bf a9 fd 03 00 91 f4 4f bf a9 f6 57 bf a9 ff 83 01 d1'),
  };

  function resolveFunction(signature) {
    var matches = Memory.scanSync(base, size, signature);
    if (matches.length !== 1) {
      throw new Error('Unsupported version of Substrate; please file a bug');
    }
    return matches[0].address;
  }
}

function instrumentSubstrateLauncher(launcher) {
  Interceptor.attach(launcher.handlePosixSpawn, {
    onEnter: function () {
      substrateInvocations[this.threadId] = true;
    },
    onLeave: function () {
      delete substrateInvocations[this.threadId];
    }
  });

  Interceptor.attach(launcher.workerCont, {
    onEnter: function (args) {
      var baton = args[0];
      var pid = baton.readS32();

      var notify = substratePidsPending[pid];
      if (notify !== undefined) {
        delete substratePidsPending[pid];

        var startSuspendedPtr = baton.add(4);
        startSuspendedPtr.writeU8(1);

        this.notify = notify;
      }
    },
    onLeave: function (retval) {
      var notify = this.notify;
      if (notify !== undefined)
        notify();
    },
  });
}
