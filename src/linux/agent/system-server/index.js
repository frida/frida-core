import Java from 'frida-java-bridge';

let ApplicationInfo, Base64OutputStream, Bitmap, ByteArrayOutputStream, Canvas, ComponentName, ContextWrapper, Intent, ResolveInfo,
  RunningAppProcessInfo, RunningTaskInfo, UserHandle;
let ACTION_MAIN, ARGB_8888, CATEGORY_HOME, CATEGORY_LAUNCHER, GET_ACTIVITIES, FLAG_ACTIVITY_NEW_TASK, FLAG_DEBUGGABLE, NO_WRAP, PNG;
let context, packageManager, activityManager, loadAppLabel, loadResolveInfoLabel;

let multiUserSupported;
let launcherPkgName;
const pendingLaunches = new Map();

function init() {
  const ActivityManager = Java.use('android.app.ActivityManager');
  const ActivityThread = Java.use('android.app.ActivityThread');
  ApplicationInfo = Java.use('android.content.pm.ApplicationInfo');
  const Base64 = Java.use('android.util.Base64');
  Base64OutputStream = Java.use('android.util.Base64OutputStream');
  Bitmap = Java.use('android.graphics.Bitmap');
  const BitmapCompressFormat = Java.use('android.graphics.Bitmap$CompressFormat');
  const BitmapConfig = Java.use('android.graphics.Bitmap$Config');
  ByteArrayOutputStream = Java.use('java.io.ByteArrayOutputStream');
  Canvas = Java.use('android.graphics.Canvas');
  ComponentName = Java.use('android.content.ComponentName');
  ContextWrapper = Java.use('android.content.ContextWrapper');
  Intent = Java.use('android.content.Intent');
  const Context = Java.use('android.content.Context');
  const PackageManager = Java.use('android.content.pm.PackageManager');
  ResolveInfo = Java.use('android.content.pm.ResolveInfo');
  RunningAppProcessInfo = Java.use('android.app.ActivityManager$RunningAppProcessInfo');
  RunningTaskInfo = Java.use('android.app.ActivityManager$RunningTaskInfo');
  UserHandle = Java.use('android.os.UserHandle');
  const ACTIVITY_SERVICE = Context.ACTIVITY_SERVICE.value;
  ACTION_MAIN = Intent.ACTION_MAIN.value;
  ARGB_8888 = BitmapConfig.ARGB_8888.value;
  CATEGORY_HOME = Intent.CATEGORY_HOME.value;
  CATEGORY_LAUNCHER = Intent.CATEGORY_LAUNCHER.value;
  GET_ACTIVITIES = PackageManager.GET_ACTIVITIES.value;
  FLAG_ACTIVITY_NEW_TASK = Intent.FLAG_ACTIVITY_NEW_TASK.value;
  FLAG_DEBUGGABLE = ApplicationInfo.FLAG_DEBUGGABLE.value;
  NO_WRAP = Base64.NO_WRAP.value;
  PNG = BitmapCompressFormat.PNG.value;

  context = ActivityThread.currentApplication();

  packageManager = context.getPackageManager();
  activityManager = Java.cast(context.getSystemService(ACTIVITY_SERVICE), ActivityManager);

  loadAppLabel = ApplicationInfo.loadUnsafeLabel ?? ApplicationInfo.loadLabel;

  multiUserSupported = 'getApplicationInfoAsUser' in PackageManager;
  launcherPkgName = detectLauncherPackageName();

  installLaunchTimeoutRemovalInstrumentation();
}

rpc.exports = {
  getFrontmostApplication(scope) {
    return performOnJavaVM(() => {
      const pkgName = getFrontmostPackageName();
      if (pkgName === null)
        return null;

      const appInfo = packageManager.getApplicationInfo(pkgName, 0);

      const appLabel = loadAppLabel.call(appInfo, packageManager).toString();
      const pid = computeAppPids(getAppProcesses()).get(pkgName) ?? 0;
      const parameters = (scope !== 'minimal') ? fetchAppParameters(pkgName, appInfo, scope) : null;

      return [pkgName, appLabel, pid, parameters];
    });
  },
  enumerateApplications(identifiers, scope) {
    return performOnJavaVM(() => {
      const apps = [];
      if (identifiers.length > 0) {
        for (const pkgName of identifiers) {
          try {
            apps.push([pkgName, packageManager.getApplicationInfo(pkgName, 0)]);
          } catch (e) {
          }
        }
      } else {
        for (const appInfo of getLauncherApplications()) {
          apps.push([appInfo.packageName.value, appInfo]);
        }
      }

      const result = [];

      const pids = computeAppPids(getAppProcesses());
      const includeParameters = scope !== 'minimal';
      const frontmostPkgName = includeParameters ? getFrontmostPackageName() : null;

      for (const [pkgName, appInfo] of apps) {
        const appLabel = loadAppLabel.call(appInfo, packageManager).toString();
        const pid = pids.get(pkgName) ?? 0;
        let parameters = null;

        if (includeParameters) {
          parameters = fetchAppParameters(pkgName, appInfo, scope);

          if (pkgName === frontmostPkgName)
            parameters.frontmost = true;
        }

        result.push([pkgName, appLabel, pid, parameters]);
      }

      return result;
    });
  },
  getProcessName(pkgName, uid) {
    checkUidOptionSupported(uid);

    return performOnJavaVM(() => {
      try {
        return getAppInfo(pkgName, uid).processName.value;
      } catch (e) {
        throw new Error(`Unable to find application with identifier '${pkgName}'${(uid !== 0) ? ' belonging to uid ' + uid : ''}`);
      }
    });
  },
  getProcessParameters(pids, scope) {
    const result = {};

    const appProcesses = getAppProcesses();

    const appPidByPkgName = computeAppPids(appProcesses);

    const appProcessByPid = new Map();
    for (const process of appProcesses)
      appProcessByPid.set(process.pid, process);

    const appInfoByPkgName = new Map();
    for (const appInfo of getLauncherApplications())
      appInfoByPkgName.set(appInfo.packageName.value, appInfo);

    const appInfoByPid = new Map();
    for (const [pkgName, appPid] of appPidByPkgName.entries()) {
      const appInfo = appInfoByPkgName.get(pkgName);
      if (appInfo !== undefined)
        appInfoByPid.set(appPid, appInfo);
    }

    let frontmostPid = -1;
    const frontmostPkgName = getFrontmostPackageName();
    if (frontmostPkgName !== null) {
      frontmostPid = appPidByPkgName.get(frontmostPkgName) ?? -1;
    }

    const includeParameters = scope !== 'minimal';
    const includeIcons = scope === 'full';

    for (const pid of pids) {
      const parameters = {};

      const appInfo = appInfoByPid.get(pid);
      if (appInfo !== undefined) {
        parameters.$name = loadAppLabel.call(appInfo, packageManager).toString()

        if (includeIcons)
          parameters.$icon = fetchAppIcon(appInfo);
      }

      if (includeParameters) {
        const appProcess = appProcessByPid.get(pid);
        if (appProcess !== undefined) {
          parameters.applications = appProcess.pkgList;
        }

        if (pid === frontmostPid) {
          parameters.frontmost = true;
        }
      }

      if (Object.keys(parameters).length !== 0) {
        result[pid] = parameters;
      }
    }

    return result;
  },
  startActivity(pkgName, activity, uid) {
    checkUidOptionSupported(uid);

    return performOnJavaVM(() => {
      let user, ctx, pm;
      if (uid !== 0) {
        user = UserHandle.of(uid);
        ctx = context.createPackageContextAsUser(pkgName, 0, user);
        pm = ctx.getPackageManager();
      } else {
        user = null;
        ctx = context;
        pm = packageManager;
      }

      let appInstalled = false;
      const apps = (uid !== 0)
          ? pm.getInstalledApplicationsAsUser(0, uid)
          : pm.getInstalledApplications(0);
      const numApps = apps.size();
      for (let i = 0; i !== numApps; i++) {
        const appInfo = Java.cast(apps.get(i), ApplicationInfo);
        if (appInfo.packageName.value === pkgName) {
          appInstalled = true;
          break;
        }
      }
      if (!appInstalled)
        throw new Error("Unable to find application with identifier '" + pkgName + "'");

      let intent = pm.getLaunchIntentForPackage(pkgName);
      if (intent === null && 'getLeanbackLaunchIntentForPackage' in pm)
        intent = pm.getLeanbackLaunchIntentForPackage(pkgName);
      if (intent === null && activity === null)
        throw new Error('Unable to find a front-door activity');

      if (intent === null) {
        intent = Intent.$new();
        intent.setFlags(FLAG_ACTIVITY_NEW_TASK);
      }

      if (activity !== null) {
        const pkgInfo = (uid !== 0)
            ? pm.getPackageInfoAsUser(pkgName, GET_ACTIVITIES, uid)
            : pm.getPackageInfo(pkgName, GET_ACTIVITIES);
        const activities = pkgInfo.activities.value.map(activityInfo => activityInfo.name.value);
        if (!activities.includes(activity))
          throw new Error("Unable to find activity with identifier '" + activity + "'");

        intent.setClassName(pkgName, activity);
      }

      performLaunchOperation(pkgName, uid, () => {
        if (user !== null)
          ContextWrapper.$new(ctx).startActivityAsUser(intent, user);
        else
          ctx.startActivity(intent);
      });
    });
  },
  sendBroadcast(pkgName, receiver, action, uid) {
    checkUidOptionSupported(uid);

    return performOnJavaVM(() => {
      const intent = Intent.$new();
      intent.setComponent(ComponentName.$new(pkgName, receiver));
      intent.setAction(action);

      performLaunchOperation(pkgName, uid, () => {
        if (uid !== 0)
          ContextWrapper.$new(context).sendBroadcastAsUser(intent, UserHandle.of(uid));
        else
          context.sendBroadcast(intent);
      });
    });
  },
  stopPackage(pkgName, uid) {
    checkUidOptionSupported(uid);

    return performOnJavaVM(() => {
      if (uid !== 0)
        activityManager.forceStopPackageAsUser(pkgName, uid);
      else
        activityManager.forceStopPackage(pkgName);
    });
  },
  tryStopPackageByPid(pid) {
    return performOnJavaVM(() => {
      const processes = activityManager.getRunningAppProcesses();

      const numProcesses = processes.size();
      for (let i = 0; i !== numProcesses; i++) {
        const process = Java.cast(processes.get(i), RunningAppProcessInfo);
        if (process.pid.value === pid) {
          for (const pkgName of process.pkgList.value) {
            activityManager.forceStopPackage(pkgName);
          }
          return true;
        }
      }

      return false;
    });
  },
};

function getFrontmostPackageName() {
  const tasks = activityManager.getRunningTasks(1);
  if (tasks.isEmpty())
    return null;

  const task = Java.cast(tasks.get(0), RunningTaskInfo);
  if (task.topActivity === undefined)
    return null;

  const name = task.topActivity.value.getPackageName();
  if (name === launcherPkgName)
    return null;

  return name;
}

function getLauncherApplications() {
  const intent = Intent.$new(ACTION_MAIN);
  intent.addCategory(CATEGORY_LAUNCHER);

  const activities = packageManager.queryIntentActivities(intent, 0);

  const result = [];
  const n = activities.size();
  for (let i = 0; i !== n; i++) {
    const resolveInfo = Java.cast(activities.get(i), ResolveInfo);
    result.push(resolveInfo.activityInfo.value.applicationInfo.value);
  }
  return result;
}

function getAppInfo(pkgName, uid) {
  return (uid !== 0)
      ? packageManager.getApplicationInfoAsUser(pkgName, 0, uid)
      : packageManager.getApplicationInfo(pkgName, 0);
}

function fetchAppParameters(pkgName, appInfo, scope) {
  const pkgInfo = packageManager.getPackageInfo(pkgName, 0);

  const parameters = {
    'version': pkgInfo.versionName.value,
    'build': pkgInfo.versionCode.value.toString(),
    'sources': [appInfo.publicSourceDir.value].concat(appInfo.splitPublicSourceDirs?.value ?? []),
    'data-dir': appInfo.dataDir.value,
    'target-sdk': appInfo.targetSdkVersion.value,
  };

  if ((appInfo.flags.value & FLAG_DEBUGGABLE) !== 0)
    parameters.debuggable = true;

  if (scope === 'full')
    parameters.$icon = fetchAppIcon(appInfo);

  return parameters;
}

function fetchAppIcon(appInfo) {
  const icon = packageManager.getApplicationIcon(appInfo);

  const width = icon.getIntrinsicWidth();
  const height = icon.getIntrinsicHeight();

  const bitmap = Bitmap.createBitmap(width, height, ARGB_8888);
  const canvas = Canvas.$new(bitmap);
  icon.setBounds(0, 0, width, height);
  icon.draw(canvas);

  const output = ByteArrayOutputStream.$new();
  bitmap.compress(PNG, 100, Base64OutputStream.$new(output, NO_WRAP));

  return output.toString('US-ASCII');
}

function getAppProcesses() {
  const result = [];

  const processes = activityManager.getRunningAppProcesses();
  const n = processes.size();
  for (let i = 0; i !== n; i++) {
    const process = Java.cast(processes.get(i), RunningAppProcessInfo);

    result.push({
      pid: process.pid.value,
      importance: process.importance.value,
      pkgList: process.pkgList.value
    });
  }

  return result;
}

function computeAppPids(processes) {
  const pids = new Map();

  for (const { pid, importance, pkgList } of processes) {
    for (const pkgName of pkgList) {
      let entries = pids.get(pkgName);
      if (entries === undefined) {
        entries = [];
        pids.set(pkgName, entries);
      }
      entries.push([ pid, importance ]);
      if (entries.length > 1) {
        entries.sort((a, b) => a[1] - b[1]);
      }
    }
  }

  return new Map(Array.from(pids.entries()).map(([k, v]) => [k, v[0][0]]));
}

function detectLauncherPackageName() {
  const intent = Intent.$new(ACTION_MAIN);
  intent.addCategory(CATEGORY_HOME);

  const launchers = packageManager.queryIntentActivities(intent, 0);
  if (launchers.isEmpty())
    return null;

  const launcher = Java.cast(launchers.get(0), ResolveInfo);

  return launcher.activityInfo.value.packageName.value;
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

function performLaunchOperation(pkgName, uid, operation) {
  const processName = getAppInfo(pkgName, uid).processName.value;

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
