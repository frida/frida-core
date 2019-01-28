'use strict';

var readU16 = Memory.readU16;
var writeU16 = Memory.writeU16;
var readU32 = Memory.readU32;
var readPointer = Memory.readPointer;
var readString = Memory.readUtf8String;

var pointerSize = Process.pointerSize;

var POSIX_SPAWN_START_SUSPENDED = 0x0080;

var upcoming = {};
var gating = false;

var jbdCallImpl = Module.findExportByName(null, 'jbd_call');
var jbdPidsToIgnore = {};
var runningOnElectra = jbdCallImpl !== null;

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
    var path = readString(args[1]);
    if (path !== '/usr/libexec/xpcproxy')
      return;

    var rawIdentifier = readString(readPointer(args[3].add(pointerSize)));

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

    var attrs = readPointer(args[2].add(pointerSize));

    var flags = readU16(attrs);
    flags |= POSIX_SPAWN_START_SUSPENDED;
    writeU16(attrs, flags);

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

    var pid = readU32(this.pidPtr);

    send([event, identifier, pid]);

    if (runningOnElectra) {
      jbdPidsToIgnore[pid] = true;
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
