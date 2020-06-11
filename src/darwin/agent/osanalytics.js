var YES = ptr(1);

var NSFileManager = ObjC.classes.NSFileManager;
var NSMutableDictionary = ObjC.classes.NSMutableDictionary;
var OSALog = ObjC.classes.OSALog;

var sessions = {};

Interceptor.attach(OSALog['+ locallyCreateForSubmission:metadata:options:error:writing:'].implementation, {
  onEnter: function (args) {
    sessions[this.threadId] = {
      forcedByUs: false
    };
  },
  onLeave: function (retval) {
    var log = new ObjC.Object(retval);
    var threadId = this.threadId;

    var session = sessions[threadId];
    if (session.forcedByUs) {
      var oldPath = log.filepath().toString();
      var newPath = oldPath + '.forced-by-frida';
      NSFileManager.defaultManager().moveItemAtPath_toPath_error_(oldPath, newPath, NULL);
      log.rename_(newPath);
    }

    delete sessions[threadId];
  },
});

Interceptor.attach(NSMutableDictionary['- osa_logCounter_isLog:byKey:count:withinLimit:withOptions:'].implementation, {
  onLeave: function (retval) {
    var session = sessions[this.threadId];
    if (session === undefined)
      return;

    var isWithinLimit = !!retval.toInt32();
    if (!isWithinLimit) {
      retval.replace(YES);
      session.forcedByUs = true;
    }
  },
});
