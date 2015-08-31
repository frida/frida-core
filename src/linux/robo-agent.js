"use strict";

let ApplicationInfo, RunningAppProcessInfo, RunningTaskInfo, GET_META_DATA;
let context, packageManager, activityManager;

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
        Java.perform(() => {
            const launchIntent = packageManager.getLaunchIntentForPackage(packageName);
            if (launchIntent !== null) {
                context.startActivity(launchIntent);
            } else {
                throw new Error("Unable to find application with identifier '" + packageName + "'");
            }
        });
    },
    getFrontmostApplication() {
        let result = null;
        Java.perform(() => {
            const runningTaskInfos = activityManager.getRunningTasks(1);
            if (runningTaskInfos != null && runningTaskInfos.size() > 0) {
                const runningTaskInfo = Java.cast(runningTaskInfos.get(0), RunningTaskInfo);
                if (typeof runningTaskInfo.topActivity !== 'undefined') {
                    const topActivity = runningTaskInfo.topActivity.value;
                    const app = packageManager.getApplicationInfo(topActivity.getPackageName(), GET_META_DATA);
                    const packageName = app.packageName.value;
                    const name = app.loadLabel(packageManager).toString();

                    const processes = activityManager.getRunningAppProcesses();
                    const numProcesses = processes.size();
                    let pid = 0;
                    for (let i = 0; i !== numProcesses; i++) {
                        const process = Java.cast(processes.get(i), RunningAppProcessInfo);
                        const pkgList = process.pkgList.value;
                        if (pkgList.indexOf(packageName) > -1) {
                            pid = process.pid.value;
                            break;
                        }
                    }

                    result = [packageName, name, pid];
                }
            }
        });

        return result;
    }
};

Java.perform(() => {
    const ActivityManager = Java.use("android.app.ActivityManager");
    const ActivityThread = Java.use("android.app.ActivityThread");
    ApplicationInfo = Java.use("android.content.pm.ApplicationInfo");
    const Context = Java.use("android.content.Context");
    const PackageManager = Java.use("android.content.pm.PackageManager");
    RunningAppProcessInfo = Java.use("android.app.ActivityManager$RunningAppProcessInfo");
    RunningTaskInfo = Java.use("android.app.ActivityManager$RunningTaskInfo");
    const ACTIVITY_SERVICE = Context.ACTIVITY_SERVICE.value;
    GET_META_DATA = PackageManager.GET_META_DATA.value;

    context = ActivityThread.currentApplication();

    packageManager = context.getPackageManager();
    activityManager = Java.cast(context.getSystemService(ACTIVITY_SERVICE), ActivityManager);
});
