'use strict';

console.log('ReportCrash agent speaking from PID:', Process.id);

rpc.exports = {
  start: function () {
    console.log('start');
  },
};

var resolver = new ApiResolver('objc');

var total = 0;
var addresses = {};

['AppleErrorReport', 'CrashReport'].forEach(function (className) {
  resolver.enumerateMatchesSync('-[' + className + ' *]').forEach(function (match) {
    var id = match.address.toString();
    if (addresses[id] !== undefined)
      return;
    addresses[id] = id;

    var name = match.name;
    Interceptor.attach(match.address, {
      onEnter: function () {
        var indent = [];
        var n = this.depth;
        while (n-- > 0)
          indent.push('\t');
        console.log(indent.join('') + name);
      }
    });

    total++;
  });
});

console.log('Traced', total, 'methods');
