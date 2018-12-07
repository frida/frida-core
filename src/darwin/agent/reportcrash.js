'use strict';

console.log('ReportCrash agent speaking from PID:', Process.id);

rpc.exports = {
  start: function () {
  },
};

var total = 0;
var addresses = {};

var manualHookNames = {
  '/usr/lib/system/libsystem_kernel.dylib!open': true,
  '/usr/lib/system/libsystem_kernel.dylib!open$NOCANCEL': true,
  '/usr/lib/system/libsystem_kernel.dylib!openat': true,
  '/usr/lib/system/libsystem_kernel.dylib!open_dprotected_np': true,
  '/usr/lib/system/libsystem_kernel.dylib!shm_open': true,
};

Interceptor.attach(Module.findExportByName(null, 'open'), {
  onEnter: function (args) {
    var path = Memory.readUtf8String(args[0]);
    onOpen('open', path, this);
  },
});

Interceptor.attach(Module.findExportByName(null, 'open$NOCANCEL'), {
  onEnter: function (args) {
    var path = Memory.readUtf8String(args[0]);
    onOpen('open$NOCANCEL', path, this);
  },
});

Interceptor.attach(Module.findExportByName(null, 'openat'), {
  onEnter: function (args) {
    var path = Memory.readUtf8String(args[1]);
    onOpen('openat', path, this);
  },
});

Interceptor.attach(Module.findExportByName(null, 'open_dprotected_np'), {
  onEnter: function (args) {
    var path = Memory.readUtf8String(args[0]);
    onOpen('open_dprotected_np', path, this);
  },
});

Interceptor.attach(Module.findExportByName(null, 'shm_open'), {
  onEnter: function (args) {
    var name = Memory.readUtf8String(args[0]);
    onOpen('shm_open', name, this);
  },
});

function onOpen(name, path, invocation) {
  var depth = invocation.depth;

  var isInteresting = path.indexOf('/var/mobile/Library/Logs/CrashReporter') === 0;

  var backtrace = '';
  if (isInteresting) {
    var indent = makeIndent(depth + 2);
    backtrace = ' called from:\n' + indent + Thread.backtrace(invocation.context).map(DebugSymbol.fromAddress).join('\n' + indent);
  }

  console.log(makeIndent(depth) + name + '() path="' + path + '"' + backtrace);
}

var moduleResolver = new ApiResolver('module');
moduleResolver.enumerateMatchesSync('exports:libsystem_kernel.dylib!*open*').forEach(function (match) {
  var name = match.name;
  if (manualHookNames[name] === undefined) {
    hook(name, match.address, true);
  }
});

var objcResolver = new ApiResolver('objc');
['AppleErrorReport', 'CrashReport', 'NSFileHandle'].forEach(function (className) {
  objcResolver.enumerateMatchesSync('*[' + className + ' *]').forEach(function (match) {
    hook(match.name, match.address, false);
  });
});

Interceptor.attach(Module.findExportByName(null, 'OSACreateTempSubmittableLogInternal'), {
  onEnter: function () {
    console.log(makeIndent(this.depth) + '>>> OSACreateTempSubmittableLogInternal');
    this.listener = Interceptor.attach(Module.findExportByName(null, 'objc_msgSend'), {
      onEnter: function (args) {
        var indent = makeIndent(this.depth);

        var receiver = new ObjC.Object(args[0]);
        var kind = ((receiver.$kind === 'instance') ? '- ' : '+ ');
        var className = receiver.$className;
        var selector = ObjC.selectorAsString(args[1]);
        console.log(indent + kind + '[' + className + ' ' + selector + ']');

        if (className === '__NSCFDictionary' && selector === 'objectForKey:') {
          var key = new ObjC.Object(args[2]);
          console.log(indent + '\tkey="' + key + '"');
          return;
        }

        if (className === '__NSDictionaryM' && selector === 'objectForKeyedSubscript:') {
          var subscript = new ObjC.Object(args[2]);
          console.log(indent + '\tsubscript="' + subscript + '"');
          return;
        }

        if (className === '__NSCFConstantString' && selector === 'isEqual:') {
          var other = new ObjC.Object(args[2]);
          console.log(indent + '\tother="' + other + '"');
          return;
        }

        this.className = className;
        this.selector = selector;
      },
      onLeave: function (retval) {
        var className = this.className;
        var selector = this.selector;

        if (className === 'NSJSONSerialization' && selector === 'dataWithJSONObject:options:error:') {
          var data = new ObjC.Object(retval);
          logData(data, makeIndent(this.depth));

          return;
        }
      }
    });
  },
  onLeave: function (retval) {
    this.listener.detach();
    console.log(makeIndent(this.depth) + '<<< OSACreateTempSubmittableLogInternal');
  },
});

Interceptor.attach(ObjC.classes.NSConcreteFileHandle['- writeData:'].implementation, {
  onEnter: function (args) {
    var data = new ObjC.Object(args[2]);
    logData(data, makeIndent(this.depth));
  },
});

console.log('Hooked', total, 'methods');

// -[AppleErrorReport saveToDir:]

function hook(name, address, skipNested) {
  var id = address.toString();
  if (addresses[id] !== undefined)
    return;
  addresses[id] = id;

  Interceptor.attach(address, {
    onEnter: function () {
      if (skipNested && this.depth > 0)
        return;

      console.log(makeIndent(this.depth) + name);
    }
  });

  total++;
}

function logData(data, indent) {
  console.log(indent + '\tdata:');
  console.log(indent + '\t' + hexdump(data.bytes(), { length: data.length(), ansi: true }).replace(/\n/g, '\n\t\t' + indent));
}

function makeIndent(level) {
  var indent = [];
  var n = level;
  while (n-- > 0)
    indent.push('\t');
  return indent.join('');
}
