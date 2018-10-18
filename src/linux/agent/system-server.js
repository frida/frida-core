'use strict';

var ApplicationInfo, ComponentName, Intent, RunningAppProcessInfo, RunningTaskInfo, GET_META_DATA;
var context, packageManager, activityManager;

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
  getProcessName: function (pkg) {
    return performOnJavaVM(function () {
      try {
        return packageManager.getApplicationInfo(pkg, GET_META_DATA).processName.value;
      } catch (e) {
        throw new Error("Unable to find application with identifier '" + pkg + "'");
      }
    });
  },
  startActivity: function (pkg, activity) {
    return performOnJavaVM(function () {
      var intent = packageManager.getLaunchIntentForPackage(pkg);
      if (intent === null)
        throw new Error("Unable to find application with identifier '" + pkg + "'");

      if (activity !== null)
        intent.setClassName(pkg, activity);

      context.startActivity(intent);
    });
  },
  sendBroadcast: function (pkg, receiver, action) {
    return performOnJavaVM(function () {
      var intent = Intent.$new();
      intent.setComponent(ComponentName.$new(pkg, receiver));
      intent.setAction(action);

      context.sendBroadcast(intent);
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
        if (typeof runningTaskInfo.topActivity !== 'undefined') {
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

Java.perform(function () {
  var ActivityManager = Java.use('android.app.ActivityManager');
  var ActivityThread = Java.use('android.app.ActivityThread');
  ApplicationInfo = Java.use('android.content.pm.ApplicationInfo');
  ComponentName = Java.use('android.content.ComponentName');
  Intent = Java.use('android.content.Intent');
  var Context = Java.use('android.content.Context');
  var PackageManager = Java.use('android.content.pm.PackageManager');
  RunningAppProcessInfo = Java.use('android.app.ActivityManager$RunningAppProcessInfo');
  RunningTaskInfo = Java.use('android.app.ActivityManager$RunningTaskInfo');
  var ACTIVITY_SERVICE = Context.ACTIVITY_SERVICE.value;
  GET_META_DATA = PackageManager.GET_META_DATA.value;

  context = ActivityThread.currentApplication();

  packageManager = context.getPackageManager();
  activityManager = Java.cast(context.getSystemService(ACTIVITY_SERVICE), ActivityManager);
});
