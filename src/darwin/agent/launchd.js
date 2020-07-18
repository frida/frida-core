var pointerSize = Process.pointerSize;

var POSIX_SPAWN_START_SUSPENDED = 0x0080;
var SIGKILL = 9;

var internalAgentServices = {
  'com.apple.ReportCrash': true,
  'com.apple.osanalytics.osanalyticshelper': true,
};

var upcoming = {};
var gating = false;
var suspendedPids = {};

var jbdPidsToIgnore = null;

var substrateInvocations = {};
var substratePidsPending = {};

rpc.exports = {
  dispose: function () {
    var kill = new NativeFunction(Module.getExportByName(null, 'kill'), 'int', ['int', 'int']);
    Object.keys(suspendedPids)
      .forEach(function (pid) {
        kill(suspendedPids[pid], SIGKILL);
      });
  },
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
  claimProcess: function (pid) {
    delete suspendedPids[pid];
  },
  unclaimProcess: function (pid) {
    suspendedPids[pid] = pid;
  },
};

applyJailbreakQuirks();

Interceptor.attach(Module.getExportByName('/usr/lib/system/libsystem_kernel.dylib', '__posix_spawn'), {
  onEnter: function (args) {
    var path = args[1].readUtf8String();

    var rawIdentifier;
    if (path === '/usr/libexec/xpcproxy') {
      rawIdentifier = args[3].add(pointerSize).readPointer().readUtf8String();
    } else {
      rawIdentifier = tryParseXpcServiceName(args[4]);
      if (rawIdentifier === null)
        return;
    }

    var identifier, event;
    if (rawIdentifier.indexOf('UIKitApplication:') === 0) {
      identifier = rawIdentifier.substring(17, rawIdentifier.indexOf('['));
      if (upcoming[identifier] !== undefined)
        event = 'launch:app';
      else if (gating)
        event = 'spawn';
      else
        return;
    } else if (gating || internalAgentServices.hasOwnProperty(rawIdentifier)) {
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
    this.path = path;
    this.identifier = identifier;
    this.pidPtr = args[0];
  },
  onLeave: function (retval) {
    var event = this.event;
    if (event === undefined)
      return;

    var path = this.path;
    var identifier = this.identifier;

    if (event === 'launch:app')
      delete upcoming[identifier];

    if (retval.toInt32() < 0)
      return;

    var pid = this.pidPtr.readU32();

    suspendedPids[pid] = pid;

    if (jbdPidsToIgnore !== null)
      jbdPidsToIgnore[pid] = true;

    var dealingWithSubstrate = substrateInvocations[this.threadId] === true;
    if (dealingWithSubstrate) {
      substratePidsPending[pid] = notifyFridaBackend;
    } else {
      notifyFridaBackend();
    }

    function notifyFridaBackend() {
      send([event, path, identifier, pid]);
    }
  }
});

function tryParseXpcServiceName(envp) {
  if (envp.isNull())
    return null;

  var cur = envp;
  while (true) {
    var elementPtr = cur.readPointer();
    if (elementPtr.isNull())
      break;

    var element = elementPtr.readUtf8String();
    if (element.indexOf('XPC_SERVICE_NAME=') === 0)
      return element.substring(17);

    cur = cur.add(pointerSize);
  }

  return null;
}

function applyJailbreakQuirks() {
  var jbdCallImpl = findJbdCallImpl();
  if (jbdCallImpl !== null) {
    jbdPidsToIgnore = {};
    sabotageJbdCallForOurPids(jbdCallImpl);
    return;
  }

  var launcher = findSubstrateLauncher();
  if (launcher !== null)
    instrumentSubstrateLauncher(launcher);
}

function sabotageJbdCallForOurPids(jbdCallImpl) {
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

function findJbdCallImpl() {
  var impl = Module.findExportByName(null, 'jbd_call');
  if (impl !== null)
    return impl;

  var payload = Process.findModuleByName('/chimera/pspawn_payload.dylib');
  if (payload === null)
    return null;

  var matches = Memory.scanSync(payload.base, payload.size, 'ff 43 01 d1 f4 4f 03 a9 fd 7b 04 a9 fd 03 01 91');
  if (matches.length !== 1)
    throw new Error('Unsupported version of Chimera; please file a bug');

  return matches[0].address;
}

function findSubstrateLauncher() {
  if (Process.arch !== 'arm64')
    return null;

  var imp = Module.enumerateImports('/sbin/launchd')
      .filter(function (imp) { return imp.name === 'posix_spawn'; })[0];
  var impl = imp.slot.readPointer().strip();
  var header = findClosestMachHeader(impl);

  var launcherDylibName = '4c 61 75 6e 63 68 65 72 2e 74 2e 64 79 6c 69 62';
  var isSubstrate = Memory.scanSync(header, 2048, launcherDylibName).length > 0;
  if (!isSubstrate)
    return null;

  return {
    handlePosixSpawn: resolveFunction('fd 7b bf a9 fd 03 00 91 f4 4f bf a9 f6 57 bf a9 f8 5f bf a9 fa 67 bf a9 fc 6f bf a9 ff 83 04 d1'),
    workerCont: resolveFunction('fd 7b bf a9 fd 03 00 91 f4 4f bf a9 f6 57 bf a9 f8 5f bf a9 fa 67 bf a9 fc 6f bf a9 ff 43 01 d1'),
  };

  function resolveFunction(signature) {
    var matches = Memory.scanSync(header, 37056, signature);
    if (matches.length !== 1) {
      throw new Error('Unsupported version of Substrate; please file a bug');
    }
    return matches[0].address;
  }
}

function findClosestMachHeader(address) {
  var cur = address.and(ptr(4095).not());
  while (true) {
    if ((cur.readU32() & 0xfffffffe) >>> 0 === 0xfeedface)
      return cur;
    cur = cur.sub(4096);
  }
}
