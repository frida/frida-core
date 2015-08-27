"use strict";

let ApplicationInfo, RunningAppProcessInfo, GET_META_DATA;
let context, packageManager, activityManager;

const pendingSpawnRequests = {};

rpc.exports = {
    enumerateApplications() {
        const result = [];

        Java.perform(() => {
            const appPids = {};
            const processes = activityManager.getRunningAppProcesses();
            const numProcesses = processes.size();
            for (let i = 0; i !== numProcesses; i++) {
                const process = Java.cast(processes.get(i), RunningAppProcessInfo);
                const pid = process.pid.value;
                const pkgList = process.pkgList.value;
                pkgList.forEach(packageName => {
                    appPids[packageName] = pid;
                });
            }

            const apps = packageManager.getInstalledApplications(GET_META_DATA);
            const numApps = apps.size();
            for (let i = 0; i !== numApps; i++) {
                const app = Java.cast(apps.get(i), ApplicationInfo);
                const packageName = app.packageName.value;
                const name = app.loadLabel(packageManager).toString();
                const pid = appPids[packageName] || 0;
                result.push([packageName, name, pid]);
            }
        });

        return result;
    },
    startActivity(packageName) {
        return new Promise(resolve => {
            pendingSpawnRequests[packageName] = resolve;

            Java.perform(() => {
                const launchIntent = packageManager.getLaunchIntentForPackage(packageName);
                context.startActivity(launchIntent);
            });
        });
    }
};

Java.perform(() => {
    const ActivityManager = Java.use("android.app.ActivityManager");
    const ActivityThread = Java.use("android.app.ActivityThread");
    ApplicationInfo = Java.use("android.content.pm.ApplicationInfo");
    const Context = Java.use("android.content.Context");
    const PackageManager = Java.use("android.content.pm.PackageManager");
    const Process = Java.use("android.os.Process");
    RunningAppProcessInfo = Java.use("android.app.ActivityManager$RunningAppProcessInfo");
    const ACTIVITY_SERVICE = Context.ACTIVITY_SERVICE.value;
    const DEBUG_ENABLE_DEBUGGER = 1;
    GET_META_DATA = PackageManager.GET_META_DATA.value;

    context = ActivityThread.currentApplication();

    packageManager = context.getPackageManager();
    activityManager = Java.cast(context.getSystemService(ACTIVITY_SERVICE), ActivityManager);

    Process.start.implementation = () => {
        const args = Array.prototype.slice.call(arguments);
        const niceName = args[1];

        args[5] |= DEBUG_ENABLE_DEBUGGER;

        const zygoteArgs = args[args.length - 1] || [];
        zygoteArgs.push("-Xrunjdwp:transport=dt_socket,server=y,suspend=y,address=3001");
        args[args.length - 1] = zygoteArgs;

        const result = this.start.apply(this, args);

        const resolve = pendingSpawnRequests[niceName];
        if (resolve) {
            delete pendingSpawnRequests[niceName];
            resolve(result.pid.value);
        }

        return result;
    };
});
