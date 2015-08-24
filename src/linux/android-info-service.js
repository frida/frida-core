"use strict";

let ApplicationInfo, RunningAppProcessInfo, GET_META_DATA;
let app, packageManager, activityManager;

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
    }
};

Java.perform(() => {
    const ActivityManager = Java.use("android.app.ActivityManager");
    const ActivityThread = Java.use("android.app.ActivityThread");
    ApplicationInfo = Java.use("android.content.pm.ApplicationInfo");
    const Context = Java.use("android.content.Context");
    const PackageManager = Java.use("android.content.pm.PackageManager");
    RunningAppProcessInfo = Java.use("android.app.ActivityManager$RunningAppProcessInfo");
    const ACTIVITY_SERVICE = Context.ACTIVITY_SERVICE.value;
    GET_META_DATA = PackageManager.GET_META_DATA.value;

    const context = ActivityThread.currentApplication();

    packageManager = context.getPackageManager();
    activityManager = Java.cast(context.getSystemService(ACTIVITY_SERVICE), ActivityManager);
});
