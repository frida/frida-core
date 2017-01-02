'use strict';

var readU16 = Memory.readU16;
var writeU16 = Memory.writeU16;
var readU32 = Memory.readU32;
var readPointer = Memory.readPointer;
var readString = Memory.readUtf8String;

var pointerSize = Process.pointerSize;

var POSIX_SPAWN_START_SUSPENDED = 0x0080;

var upcoming = {};
var active = 0;

rpc.exports = {
  prepareForLaunch: function (identifier) {
    upcoming[identifier] = true;
    active++;
  },
};

Interceptor.attach(Module.findExportByName('/usr/lib/system/libsystem_kernel.dylib', '__posix_spawn'), {
  onEnter: function (args) {
    if (active === 0)
      return;

    var path = readString(args[1]);
    if (path !== '/usr/libexec/xpcproxy')
      return;

    var service = readString(readPointer(args[3].add(pointerSize)));
    if (service.indexOf('UIKitApplication:') === -1)
      return;

    var identifier = service.substring(17, service.lastIndexOf('['));
    if (upcoming[identifier] === undefined)
      return;

    var attrs = readPointer(args[2].add(pointerSize));

    var flags = readU16(attrs);
    flags |= POSIX_SPAWN_START_SUSPENDED;
    writeU16(attrs, flags);

    this.identifier = identifier;
    this.pidPtr = args[0];
  },
  onLeave: function (retval) {
    if (active === 0)
      return;

    var identifier = this.identifier;
    if (identifier === undefined)
      return;

    delete upcoming[identifier];
    active--;

    if (retval.toInt32() < 0)
      return;

    send(['launch:app', identifier, readU32(this.pidPtr)]);
  }
});
