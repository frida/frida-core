let ApplicationInfo, ComponentName, ContextWrapper, Intent, RunningAppProcessInfo, RunningTaskInfo, UserHandle, GET_META_DATA, GET_ACTIVITIES, FLAG_ACTIVITY_NEW_TASK;
let context, packageManager, activityManager;

let multiUserSupported;
const pendingLaunches = new Map();

function init() {
  const ActivityManager = Java.use('android.app.ActivityManager');
  const ActivityThread = Java.use('android.app.ActivityThread');
  ApplicationInfo = Java.use('android.content.pm.ApplicationInfo');
  ComponentName = Java.use('android.content.ComponentName');
  ContextWrapper = Java.use('android.content.ContextWrapper');
  Intent = Java.use('android.content.Intent');
  const Context = Java.use('android.content.Context');
  const PackageManager = Java.use('android.content.pm.PackageManager');
  RunningAppProcessInfo = Java.use('android.app.ActivityManager$RunningAppProcessInfo');
  RunningTaskInfo = Java.use('android.app.ActivityManager$RunningTaskInfo');
  UserHandle = Java.use('android.os.UserHandle');
  const ACTIVITY_SERVICE = Context.ACTIVITY_SERVICE.value;
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
  enumerateApplications() {
    return performOnJavaVM(() => {
      const result = [];

      const appPids = new Map();
      const processes = activityManager.getRunningAppProcesses();
      const numProcesses = processes.size();
      for (let i = 0; i !== numProcesses; i++) {
        const process = Java.cast(processes.get(i), RunningAppProcessInfo);
        const pid = process.pid.value;

        const importance = process.importance.value;

        for (const pkg of process.pkgList.value) {
          let entries = appPids.get(pkg);
          if (entries === undefined) {
            entries = [];
            appPids.set(pkg, entries);
          }
          entries.push([ pid, importance ]);
        }
      }

      const apps = packageManager.getInstalledApplications(GET_META_DATA);
      const numApps = apps.size();
      for (let i = 0; i !== numApps; i++) {
        const app = Java.cast(apps.get(i), ApplicationInfo);
        const pkg = app.packageName.value;

        const name = app.loadLabel(packageManager).toString();

        let pid;
        const pids = appPids.get(pkg);
        if (pids !== undefined) {
          pids.sort((a, b) => a[1] - b[1]);
          pid = pids[0][0];
        } else {
          pid = 0;
        }

        result.push([pkg, name, pid]);
      }

      return result;
    });
  },
  getProcessName(pkg, uid) {
    checkUidOptionSupported(uid);

    return performOnJavaVM(() => {
      try {
        return getAppMetaData(pkg, uid).processName.value;
      } catch (e) {
        throw new Error(`Unable to find application with identifier '${pkg}'${(uid !== 0) ? ' belonging to uid ' + uid : ''}`);
      }
    });
  },
  startActivity(pkg, activity, uid) {
    checkUidOptionSupported(uid);

    return performOnJavaVM(() => {
      let user, ctx, pm;
      if (uid !== 0) {
        user = UserHandle.of(uid);
        ctx = context.createPackageContextAsUser(pkg, GET_META_DATA, user);
        pm = ctx.getPackageManager();
      } else {
        user = null;
        ctx = context;
        pm = packageManager;
      }

      let appInstalled = false;
      const apps = (uid !== 0)
          ? pm.getInstalledApplicationsAsUser(GET_META_DATA, uid)
          : pm.getInstalledApplications(GET_META_DATA);
      const numApps = apps.size();
      for (let i = 0; i !== numApps; i++) {
        const appInfo = Java.cast(apps.get(i), ApplicationInfo);
        if (appInfo.packageName.value === pkg) {
          appInstalled = true;
          break;
        }
      }
      if (!appInstalled)
        throw new Error("Unable to find application with identifier '" + pkg + "'");

      let intent = pm.getLaunchIntentForPackage(pkg);
      if (intent === null && 'getLeanbackLaunchIntentForPackage' in pm)
        intent = pm.getLeanbackLaunchIntentForPackage(pkg);
      if (intent === null && activity === null)
        throw new Error('Unable to find a front-door activity');

      if (intent === null) {
        intent = Intent.$new();
        intent.setFlags(FLAG_ACTIVITY_NEW_TASK);
      }

      if (activity !== null) {
        const pkgInfo = (uid !== 0)
            ? pm.getPackageInfoAsUser(pkg, GET_ACTIVITIES, uid)
            : pm.getPackageInfo(pkg, GET_ACTIVITIES);
        const activities = pkgInfo.activities.value.map(activityInfo => activityInfo.name.value);
        if (!activities.includes(activity))
          throw new Error("Unable to find activity with identifier '" + activity + "'");

        intent.setClassName(pkg, activity);
      }

      performLaunchOperation(pkg, uid, () => {
        if (user !== null)
          ContextWrapper.$new(ctx).startActivityAsUser(intent, user);
        else
          ctx.startActivity(intent);
      });
    });
  },
  sendBroadcast(pkg, receiver, action, uid) {
    checkUidOptionSupported(uid);

    return performOnJavaVM(() => {
      const intent = Intent.$new();
      intent.setComponent(ComponentName.$new(pkg, receiver));
      intent.setAction(action);

      performLaunchOperation(pkg, uid, () => {
        if (uid !== 0)
          ContextWrapper.$new(context).sendBroadcastAsUser(intent, UserHandle.of(uid));
        else
          context.sendBroadcast(intent);
      });
    });
  },
  stopPackage(pkg, uid) {
    checkUidOptionSupported(uid);

    return performOnJavaVM(() => {
      if (uid !== 0)
        activityManager.forceStopPackageAsUser(pkg, uid);
      else
        activityManager.forceStopPackage(pkg);
    });
  },
  tryStopPackageByPid(pid) {
    return performOnJavaVM(() => {
      const processes = activityManager.getRunningAppProcesses();

      const numProcesses = processes.size();
      for (let i = 0; i !== numProcesses; i++) {
        const process = Java.cast(processes.get(i), RunningAppProcessInfo);
        if (process.pid.value === pid) {
          for (const pkg of process.pkgList.value) {
            activityManager.forceStopPackage(pkg);
          }
          return true;
        }
      }

      return false;
    });
  },
  getFrontmostApplication() {
    return performOnJavaVM(() => {
      let result = null;

      const runningTaskInfos = activityManager.getRunningTasks(1);
      if (runningTaskInfos !== null && runningTaskInfos.size() > 0) {
        const runningTaskInfo = Java.cast(runningTaskInfos.get(0), RunningTaskInfo);
        if (runningTaskInfo.topActivity !== undefined) {
          const topActivity = runningTaskInfo.topActivity.value;
          const app = packageManager.getApplicationInfo(topActivity.getPackageName(), GET_META_DATA);
          const pkg = app.packageName.value;
          const name = app.loadLabel(packageManager).toString();

          const processes = activityManager.getRunningAppProcesses();
          const numProcesses = processes.size();
          let pid = 0;
          for (let i = 0; i !== numProcesses; i++) {
            const process = Java.cast(processes.get(i), RunningAppProcessInfo);
            if (process.pkgList.value.includes(pkg)) {
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
  const Handler = Java.use('android.os.Handler');
  const OSProcess = Java.use('android.os.Process');

  const pendingStartRequests = new Set();

  const start = OSProcess.start;
  start.implementation = function (processClass, niceName) {
    const result = start.apply(this, arguments);

    if (tryFinishLaunch(niceName)) {
      pendingStartRequests.add(Process.getCurrentThreadId());
    }

    return result;
  };

  const sendMessageDelayed = Handler.sendMessageDelayed;
  sendMessageDelayed.implementation = function (msg, delayMillis) {
    const tid = Process.getCurrentThreadId();
    if (pendingStartRequests.has(tid)) {
      pendingStartRequests.delete(tid);
      msg.recycle();
      return true;
    }

    return sendMessageDelayed.call(this, msg, delayMillis);
  };
}

function performLaunchOperation(pkg, uid, operation) {
  const processName = getAppMetaData(pkg, uid).processName.value;

  tryFinishLaunch(processName);

  const timer = setTimeout(() => {
    if (pendingLaunches.get(processName) === timer)
      tryFinishLaunch(processName);
  }, 10000);
  pendingLaunches.set(processName, timer);

  try {
    return operation();
  } catch (e) {
    tryFinishLaunch(processName);
    throw e;
  }
}

function tryFinishLaunch(processName) {
  const timer = pendingLaunches.get(processName);
  if (timer === undefined)
    return false;

  pendingLaunches.delete(processName);
  clearTimeout(timer);
  return true;
}

function performOnJavaVM(task) {
  return new Promise((resolve, reject) => {
    Java.perform(() => {
      try {
        const result = task();

        resolve(result);
      } catch (e) {
        reject(e);
      }
    });
  });
}

Java.perform(init);
