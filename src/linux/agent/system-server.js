var ApplicationInfo, ComponentName, ContextWrapper, Intent, RunningAppProcessInfo, RunningTaskInfo, UserHandle, GET_META_DATA, GET_ACTIVITIES, FLAG_ACTIVITY_NEW_TASK;
var context, packageManager, activityManager;

var multiUserSupported;
var pendingLaunches = {};

function init() {
  var ActivityManager = Java.use('android.app.ActivityManager');
  var ActivityThread = Java.use('android.app.ActivityThread');
  ApplicationInfo = Java.use('android.content.pm.ApplicationInfo');
  ComponentName = Java.use('android.content.ComponentName');
  ContextWrapper = Java.use('android.content.ContextWrapper');
  Intent = Java.use('android.content.Intent');
  var Context = Java.use('android.content.Context');
  var PackageManager = Java.use('android.content.pm.PackageManager');
  RunningAppProcessInfo = Java.use('android.app.ActivityManager$RunningAppProcessInfo');
  RunningTaskInfo = Java.use('android.app.ActivityManager$RunningTaskInfo');
  UserHandle = Java.use('android.os.UserHandle');
  var ACTIVITY_SERVICE = Context.ACTIVITY_SERVICE.value;
  GET_META_DATA = PackageManager.GET_META_DATA.value;
  GET_ACTIVITIES = PackageManager.GET_ACTIVITIES.value;
  FLAG_ACTIVITY_NEW_TASK = Intent.FLAG_ACTIVITY_NEW_TASK.value;

  multiUserSupported = 'getApplicationInfoAsUser' in PackageManager;

  context = ActivityThread.currentApplication();

  packageManager = context.getPackageManager();
  activityManager = Java.cast(context.getSystemService(ACTIVITY_SERVICE), ActivityManager);

  installLaunchTimeoutRemovalInstrumentation();
}

rpc.exports = {
  enumerateApplications: function () {
    return performOnJavaVM(function () {
      var result = [];

      var i, pid;

      var appPids = {};
      var processes = activityManager.getRunningAppProcesses();
      var numProcesses = processes.size();
      for (i = 0; i !== numProcesses; i++) {
        var process = Java.cast(processes.get(i), RunningAppProcessInfo);
        pid = process.pid.value;

        var importance = process.importance.value;

        var pkgList = process.pkgList.value;
        pkgList.forEach(function (pkg) {
          var entries = appPids[pkg];
          if (entries === undefined) {
            entries = [];
            appPids[pkg] = entries;
          }
          entries.push([ pid, importance ]);
        });
      }

      var apps = packageManager.getInstalledApplications(GET_META_DATA);
      var numApps = apps.size();
      for (i = 0; i !== numApps; i++) {
        var app = Java.cast(apps.get(i), ApplicationInfo);
        var pkg = app.packageName.value;

        var name = app.loadLabel(packageManager).toString();

        var pid;
        var pids = appPids[pkg];
        if (pids !== undefined) {
          pids.sort(function (a, b) { return a[1] - b[1]; });
          pid = pids[0][0];
        } else {
          pid = 0;
        }

        result.push([pkg, name, pid]);
      }

      return result;
    });
  },
  getProcessName: function (pkg, uid) {
    checkUidOptionSupported(uid);

    return performOnJavaVM(function () {
      try {
        return getAppMetaData(pkg, uid).processName.value;
      } catch (e) {
        throw new Error("Unable to find application with identifier '" + pkg + "'" +
            ((uid !== 0) ? ' belonging to uid ' + uid : ''));
      }
    });
  },
  startActivity: function (pkg, activity, uid) {
    checkUidOptionSupported(uid);

    return performOnJavaVM(function () {
      var user, ctx, pm;
      if (uid !== 0) {
        user = UserHandle.of(uid);
        ctx = context.createPackageContextAsUser(pkg, GET_META_DATA, user);
        pm = ctx.getPackageManager();
      } else {
        user = null;
        ctx = context;
        pm = packageManager;
      }

      var appInstalled = false;
      var apps = (uid !== 0)
          ? pm.getInstalledApplicationsAsUser(GET_META_DATA, uid)
          : pm.getInstalledApplications(GET_META_DATA);
      var numApps = apps.size();
      for (var i = 0; i !== numApps; i++) {
        var appInfo = Java.cast(apps.get(i), ApplicationInfo);
        if (appInfo.packageName.value === pkg) {
          appInstalled = true;
          break;
        }
      }
      if (!appInstalled)
        throw new Error("Unable to find application with identifier '" + pkg + "'");

      var intent = pm.getLaunchIntentForPackage(pkg);
      if (intent === null && 'getLeanbackLaunchIntentForPackage' in pm)
        intent = pm.getLeanbackLaunchIntentForPackage(pkg);
      if (intent === null && activity === null)
        throw new Error('Unable to find a front-door activity');

      if (intent === null) {
        intent = Intent.$new();
        intent.setFlags(FLAG_ACTIVITY_NEW_TASK);
      }

      if (activity !== null) {
        var pkgInfo = (uid !== 0)
            ? pm.getPackageInfoAsUser(pkg, GET_ACTIVITIES, uid)
            : pm.getPackageInfo(pkg, GET_ACTIVITIES);
        var activities = pkgInfo.activities.value.map(function (activityInfo) {
          return activityInfo.name.value;
        });
        if (activities.indexOf(activity) === -1)
          throw new Error("Unable to find activity with identifier '" + activity + "'");

        intent.setClassName(pkg, activity);
      }

      performLaunchOperation(pkg, uid, function () {
        if (user !== null)
          ContextWrapper.$new(ctx).startActivityAsUser(intent, user);
        else
          ctx.startActivity(intent);
      });
    });
  },
  sendBroadcast: function (pkg, receiver, action, uid) {
    checkUidOptionSupported(uid);

    return performOnJavaVM(function () {
      var intent = Intent.$new();
      intent.setComponent(ComponentName.$new(pkg, receiver));
      intent.setAction(action);

      performLaunchOperation(pkg, uid, function () {
        if (uid !== 0)
          ContextWrapper.$new(context).sendBroadcastAsUser(intent, UserHandle.of(uid));
        else
          context.sendBroadcast(intent);
      });
    });
  },
  stopPackage: function (pkg, uid) {
    checkUidOptionSupported(uid);

    return performOnJavaVM(function () {
      if (uid !== 0)
        activityManager.forceStopPackageAsUser(pkg, uid);
      else
        activityManager.forceStopPackage(pkg);
    });
  },
  tryStopPackageByPid: function (pid) {
    return performOnJavaVM(function () {
      var processes = activityManager.getRunningAppProcesses();

      var numProcesses = processes.size();
      for (var i = 0; i !== numProcesses; i++) {
        var process = Java.cast(processes.get(i), RunningAppProcessInfo);
        if (process.pid.value === pid) {
          process.pkgList.value.forEach(function (pkg) {
            activityManager.forceStopPackage(pkg);
          });
          return true;
        }
      }

      return false;
    });
  },
  getFrontmostApplication: function () {
    return performOnJavaVM(function () {
      var result = null;

      var runningTaskInfos = activityManager.getRunningTasks(1);
      if (runningTaskInfos !== null && runningTaskInfos.size() > 0) {
        var runningTaskInfo = Java.cast(runningTaskInfos.get(0), RunningTaskInfo);
        if (runningTaskInfo.topActivity !== undefined) {
          var topActivity = runningTaskInfo.topActivity.value;
          var app = packageManager.getApplicationInfo(topActivity.getPackageName(), GET_META_DATA);
          var pkg = app.packageName.value;
          var name = app.loadLabel(packageManager).toString();

          var processes = activityManager.getRunningAppProcesses();
          var numProcesses = processes.size();
          var pid = 0;
          for (var i = 0; i !== numProcesses; i++) {
            var process = Java.cast(processes.get(i), RunningAppProcessInfo);
            var pkgList = process.pkgList.value;
            if (pkgList.indexOf(pkg) > -1) {
              pid = process.pid.value;
              break;
            }
          }

          result = [pkg, name, pid];
        }
      }

      return result;
    });
  }
};

function getAppMetaData(pkg, uid) {
  return (uid !== 0)
      ? packageManager.getApplicationInfoAsUser(pkg, GET_META_DATA, uid)
      : packageManager.getApplicationInfo(pkg, GET_META_DATA);
}

function checkUidOptionSupported(uid) {
  if (uid !== 0 && !multiUserSupported)
    throw new Error('The “uid” option is not supported on the current Android OS version');
}

function installLaunchTimeoutRemovalInstrumentation() {
  var Handler = Java.use('android.os.Handler');
  var OSProcess = Java.use('android.os.Process');

  var pendingStartRequests = {};

  var start = OSProcess.start;
  start.implementation = function (processClass, niceName) {
    var result = start.apply(this, arguments);

    if (tryFinishLaunch(niceName)) {
      pendingStartRequests[Process.getCurrentThreadId()] = true;
    }

    return result;
  };

  var sendMessageDelayed = Handler.sendMessageDelayed;
  sendMessageDelayed.implementation = function (msg, delayMillis) {
    var tid = Process.getCurrentThreadId();
    if (pendingStartRequests[tid] === true) {
      delete pendingStartRequests[tid];
      msg.recycle();
      return true;
    }

    return sendMessageDelayed.call(this, msg, delayMillis);
  };
}

function performLaunchOperation(pkg, uid, operation) {
  var processName = getAppMetaData(pkg, uid).processName.value;

  tryFinishLaunch(processName);

  var timer = setTimeout(function () {
    if (pendingLaunches[processName] === timer)
      tryFinishLaunch(processName);
  }, 10000);
  pendingLaunches[processName] = timer;

  try {
    return operation();
  } catch (e) {
    tryFinishLaunch(processName);
    throw e;
  }
}

function tryFinishLaunch(processName) {
  var timer = pendingLaunches[processName];
  if (timer === undefined)
    return false;

  delete pendingLaunches[processName];
  clearTimeout(timer);
  return true;
}

function performOnJavaVM(task) {
  return new Promise(function (resolve, reject) {
    Java.perform(function () {
      try {
        var result = task();

        resolve(result);
      } catch (e) {
        reject(e);
      }
    });
  });
}

Java.perform(init);
