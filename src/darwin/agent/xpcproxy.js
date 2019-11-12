var POSIX_SPAWN_START_SUSPENDED = 0x0080;

applyJailbreakQuirks();

Interceptor.attach(Module.getExportByName('/usr/lib/system/libsystem_kernel.dylib', '__posix_spawn'), {
  onEnter: function (args) {
    var attrs = args[2].add(Process.pointerSize).readPointer();

    var flags = attrs.readU16();
    flags |= POSIX_SPAWN_START_SUSPENDED;
    attrs.writeU16(flags);
  }
});

function applyJailbreakQuirks() {
  var bootstrapper = findSubstrateBootstrapper();
  if (bootstrapper !== null) {
    instrumentSubstrateBootstrapper(bootstrapper);
    return;
  }

  var jbdCallImpl = findJbdCallImpl();
  if (jbdCallImpl !== null) {
    sabotageJbdCall(jbdCallImpl);
    return;
  }

  var proxyer = findSubstrateProxyer();
  if (proxyer !== null)
    instrumentSubstrateExec(proxyer.exec);
}

function sabotageJbdCall(jbdCallImpl) {
  var retType = 'int';
  var argTypes = ['uint', 'uint', 'uint'];

  var jbdCall = new NativeFunction(jbdCallImpl, retType, argTypes);

  Interceptor.replace(jbdCall, new NativeCallback(function (port, command, pid) {
    return 0;
  }, retType, argTypes));
}

function instrumentSubstrateBootstrapper(bootstrapper) {
  Interceptor.attach(Module.getExportByName('/usr/lib/system/libdyld.dylib', 'dlopen'), {
    onEnter: function (args) {
      this.path = args[0].readUtf8String();
    },
    onLeave: function (retval) {
      if (!retval.isNull() && this.path === '/usr/lib/substrate/SubstrateInserter.dylib') {
        var inserter = Process.getModuleByName(this.path);
        var exec = resolveSubstrateExec(inserter.base, inserter.size);
        instrumentSubstrateExec(exec);
      }
    }
  });
}

function instrumentSubstrateExec(exec) {
  Interceptor.attach(exec, {
    onEnter: function (args) {
      var startSuspendedYup = ptr(1);
      args[2] = startSuspendedYup;
    }
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

function findSubstrateBootstrapper() {
  if (Process.arch !== 'arm64')
    return null;

  return Process.findModuleByName('/usr/lib/substrate/SubstrateBootstrap.dylib');
}

function findSubstrateProxyer() {
  if (Process.arch !== 'arm64')
    return null;

  var proxyerDylibName = '50 72 6f 78 79 65 72 2e 74 2e 64 79 6c 69 62';

  var modules = new ModuleMap();
  var ranges = Process.enumerateRanges('r-x')
      .filter(function (r) { return !modules.has(r.base); })
      .filter(function (r) { return (r.base.readU32() & 0xfffffffe) >>> 0 === 0xfeedface; })
      .filter(function (r) { return Memory.scanSync(r.base, 2048, proxyerDylibName).length > 0; });
  if (ranges.length === 0)
    return null;
  var proxyer = ranges[0];

  return {
    exec: resolveSubstrateExec(proxyer.base, proxyer.size)
  };
}

function resolveSubstrateExec(base, size) {
  var matches = Memory.scanSync(base, size, 'fd 7b bf a9 fd 03 00 91 f4 4f bf a9 ff 03 01 d1 f3 03 03 aa');
  if (matches.length !== 1) {
    throw new Error('Unsupported version of Substrate; please file a bug');
  }
  return matches[0].address;
}
